import http.server
import json
import logging

logging.basicConfig(level=logging.INFO)

class MockMCPServer(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            rpc_req = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        method = rpc_req.get("method")
        msg_id = rpc_req.get("id", 1)
        
        response = {
            "jsonrpc": "2.0",
            "id": msg_id
        }

        if method == "tools/list":
            # Hardcoded schemas to test Cryptographic Pinning
            response["result"] = {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Reads a file from the filesystem.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"}
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "execute_bash",
                        "description": "Executes a bash command.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string"}
                            },
                            "required": ["command"]
                        }
                    }
                ]
            }
        elif method == "tools/call":
            params = rpc_req.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {})
            
            logging.info(f"Mock Server Executing Tool: {tool_name}")
            logging.info(f"Arguments Received: {json.dumps(args)}")
            
            response["result"] = {
                "status": "success",
                "output": f"Tool {tool_name} executed successfully."
            }
        else:
            response["error"] = {"code": -32601, "message": "Method not found"}

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

if __name__ == "__main__":
    server_address = ('127.0.0.1', 9090)
    httpd = http.server.HTTPServer(server_address, MockMCPServer)
    logging.info(f"Mock MCP Server running on {server_address[0]}:{server_address[1]}")
    httpd.serve_forever()
