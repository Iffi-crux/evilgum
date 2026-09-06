"""
Observability (OBS-1): a dependency-free Prometheus metrics collector.

Every security decision the gateway makes is a metric an SRE team wants on a
dashboard and an alert. Rather than pull in a framework, this emits the
Prometheus text exposition format directly from in-process counters, exposed at
`/metrics`. A worker is single-threaded under asyncio, so plain integer counters
are safe without locks.

Deliberately LOW cardinality: decisions are labelled by `outcome` only, never by
tenant or agent — per-tenant breakdowns live in the audit log and the admin
dashboard, where unbounded labels don't blow up a time-series database.
"""
from __future__ import annotations

import time
from typing import Dict, List

# Histogram buckets in seconds — tuned for an in-path proxy (sub-ms to a few s).
_BUCKETS: List[float] = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]


class MetricsCollector:
    def __init__(self, *, namespace: str = "evilgum"):
        self.ns = namespace
        self._decisions: Dict[str, int] = {}          # outcome -> count
        self._requests = 0
        self._bucket_counts = [0] * len(_BUCKETS)
        self._lat_sum = 0.0
        self._lat_count = 0
        self._started = time.time()

    # -- recording -------------------------------------------------------
    def decision(self, outcome: str) -> None:
        self._decisions[outcome] = self._decisions.get(outcome, 0) + 1

    def request(self) -> None:
        self._requests += 1

    def observe_latency(self, seconds: float) -> None:
        self._lat_count += 1
        self._lat_sum += seconds
        for i, b in enumerate(_BUCKETS):
            if seconds <= b:
                self._bucket_counts[i] += 1

    def timer(self) -> "_Timer":
        return _Timer(self)

    # -- exposition ------------------------------------------------------
    def render(self) -> str:
        ns = self.ns
        out: List[str] = []
        out.append(f"# HELP {ns}_up 1 if the gateway is serving.")
        out.append(f"# TYPE {ns}_up gauge")
        out.append(f"{ns}_up 1")

        out.append(f"# HELP {ns}_uptime_seconds Seconds since the collector started.")
        out.append(f"# TYPE {ns}_uptime_seconds gauge")
        out.append(f"{ns}_uptime_seconds {time.time() - self._started:.3f}")

        out.append(f"# HELP {ns}_requests_total Total /rpc requests processed.")
        out.append(f"# TYPE {ns}_requests_total counter")
        out.append(f"{ns}_requests_total {self._requests}")

        out.append(f"# HELP {ns}_decisions_total Security decisions by outcome.")
        out.append(f"# TYPE {ns}_decisions_total counter")
        for outcome in sorted(self._decisions):
            out.append(f'{ns}_decisions_total{{outcome="{_esc(outcome)}"}} {self._decisions[outcome]}')

        # Convenience derived counters (allowed vs blocked vs would-block).
        blocked = sum(v for k, v in self._decisions.items() if k.startswith("deny"))
        would = sum(v for k, v in self._decisions.items() if k.startswith("would_"))
        allowed = self._decisions.get("allow", 0)
        out.append(f"# HELP {ns}_blocked_total Calls blocked by any control (enforce mode).")
        out.append(f"# TYPE {ns}_blocked_total counter")
        out.append(f"{ns}_blocked_total {blocked}")
        out.append(f"# HELP {ns}_would_block_total Calls that WOULD be blocked (shadow mode).")
        out.append(f"# TYPE {ns}_would_block_total counter")
        out.append(f"{ns}_would_block_total {would}")
        out.append(f"# HELP {ns}_allowed_total Calls allowed.")
        out.append(f"# TYPE {ns}_allowed_total counter")
        out.append(f"{ns}_allowed_total {allowed}")

        out.append(f"# HELP {ns}_request_latency_seconds Request handling latency.")
        out.append(f"# TYPE {ns}_request_latency_seconds histogram")
        cumulative = 0
        for i, b in enumerate(_BUCKETS):
            cumulative += self._bucket_counts[i]
            out.append(f'{ns}_request_latency_seconds_bucket{{le="{b}"}} {cumulative}')
        out.append(f'{ns}_request_latency_seconds_bucket{{le="+Inf"}} {self._lat_count}')
        out.append(f"{ns}_request_latency_seconds_sum {self._lat_sum:.6f}")
        out.append(f"{ns}_request_latency_seconds_count {self._lat_count}")
        return "\n".join(out) + "\n"


class _Timer:
    def __init__(self, mc: MetricsCollector):
        self._mc = mc
        self._t0 = 0.0

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self._mc.observe_latency(time.perf_counter() - self._t0)
        return False


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
