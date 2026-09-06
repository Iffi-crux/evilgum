"""
Distributed token-bucket rate limiter.

Hardened over V5 (folds in AG-12, medium): global + per-session buckets are now
checked in ONE atomic Lua script (V5 used two separate eval() calls), and every
bucket key gets a TTL so idle sessions don't leak Redis memory forever. Time is
taken from redis.call('TIME') inside the script, so replicas with skewed wall
clocks stay consistent.
"""
from __future__ import annotations

import os
import redis.asyncio as redis

_LUA = """
local capacity   = tonumber(ARGV[1])
local refill     = tonumber(ARGV[2])
local requested  = tonumber(ARGV[3])
local g_capacity = tonumber(ARGV[4])
local g_refill   = tonumber(ARGV[5])
local ttl        = tonumber(ARGV[6])

local t = redis.call('TIME')
local now = tonumber(t[1]) + (tonumber(t[2]) / 1000000)

local function take(tokens_key, time_key, cap, rate, req)
  local cur = tonumber(redis.call('GET', tokens_key) or cap)
  local last = tonumber(redis.call('GET', time_key) or now)
  local passed = math.max(0, now - last)
  cur = math.min(cap, cur + passed * rate)
  if cur < req then return 0 end
  cur = cur - req
  redis.call('SET', tokens_key, cur, 'EX', ttl)
  redis.call('SET', time_key, now, 'EX', ttl)
  return 1
end

-- Peek global first WITHOUT consuming, so a global-limited request doesn't
-- silently drain the session bucket (and vice-versa). Consume both only if both pass.
local g_cur = tonumber(redis.call('GET', KEYS[1]) or g_capacity)
local g_last = tonumber(redis.call('GET', KEYS[2]) or now)
g_cur = math.min(g_capacity, g_cur + math.max(0, now - g_last) * g_refill)
if g_cur < requested then return 0 end

local s = take(KEYS[3], KEYS[4], capacity, refill, requested)
if s == 0 then return 0 end
take(KEYS[1], KEYS[2], g_capacity, g_refill, requested)
return 1
"""


class RedisTokenBucketRateLimiter:
    def __init__(self, capacity: int, refill_rate: float, redis_client=None, key_ttl: int = 3600):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.key_ttl = key_ttl
        if redis_client is not None:
            self.redis = redis_client
        else:
            url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            self.redis = redis.from_url(url, decode_responses=True)
        self._sha = None

    async def consume(self, session_id: str, tokens: int = 1) -> bool:
        keys = ["global_tokens", "global_last", f"tokens:{session_id}", f"last:{session_id}"]
        args = [self.capacity, self.refill_rate, tokens,
                self.capacity * 2, self.refill_rate * 2, self.key_ttl]
        res = await self.redis.eval(_LUA, len(keys), *keys, *args)
        return bool(res)

    async def close(self):
        try:
            await self.redis.aclose()
        except Exception:
            pass
