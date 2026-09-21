"""Disposable Docker recovery drill. Uses only resources with this run's UUID.



Requires the locally built evilgum-phase1:local image and redis:7-alpine.

On Windows uses Ubuntu WSL Docker. Test keys/data are synthetic and disposable.

"""

import datetime

import hashlib

import json

import os

from pathlib import Path

import secrets

import subprocess

import sys

import time

import urllib.request

import urllib.error

import uuid



import jwt

from cryptography import x509

from cryptography.hazmat.primitives import hashes, serialization

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID



ROOT = Path(__file__).resolve().parents[1]

RUN = "evilgum-p1-" + uuid.uuid4().hex[:8]

FIX = ROOT / ".phase1-runtime" / RUN

IMAGE = os.environ.get("EVILGUM_TEST_IMAGE", "evilgum-phase1:local")

REDIS_IMAGE = "redis@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2"

DOCKER = ["wsl", "-d", "Ubuntu", "--", "docker"] if os.name == "nt" else ["docker"]

resources = {"containers": [], "volumes": [], "networks": []}

report = {"run": RUN, "checks": [], "result": "running"}





def docker(*args):

    p = subprocess.run(DOCKER + list(args), capture_output=True, text=True)

    if p.returncode:

        raise RuntimeError("docker " + args[0] + " failed: " + p.stderr[-2000:])

    return (p.stdout + (p.stderr if args[0] == "logs" else "")).strip()





def mark(name):

    report["checks"].append(name)

    print("PASS " + name, flush=True)





def path_for_docker(path):

    value = str(path.resolve()).replace("\\", "/")

    return "/mnt/" + value[0].lower() + value[2:] if os.name == "nt" else value





def prepare():

    FIX.mkdir(parents=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EvilGum disposable test CA")])

    now = datetime.datetime.now(datetime.timezone.utc)

    ca = x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256())

    (FIX / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    for name, usage in [("upstream", ExtendedKeyUsageOID.SERVER_AUTH), ("client", ExtendedKeyUsageOID.CLIENT_AUTH)]:

        leaf = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).issuer_name(issuer).public_key(leaf.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False).add_extension(x509.ExtendedKeyUsage([usage]), False).sign(key, hashes.SHA256())

        (FIX / (name+".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        (FIX / (name+".key")).write_bytes(leaf.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    definitions = [{"name": n, "description": "Synthetic "+n, "inputSchema": {"type":"object"}} for n in ("calculate_math", "read_file", "http_post")]

    (FIX / "tools.json").write_text(json.dumps(definitions))

    pins = {tool["name"]: hashlib.sha256(json.dumps(tool, sort_keys=True, separators=(",", ":")).encode()).hexdigest() for tool in definitions}

    (FIX / "mcp-lock.json").write_text(json.dumps({"tools": pins}))

    (FIX / "config.yaml").write_bytes((ROOT / "config.yaml").read_bytes())

    (FIX / "upstream.py").write_text('''import json,ssl

from http.server import BaseHTTPRequestHandler,HTTPServer

from pathlib import Path

class Handler(BaseHTTPRequestHandler):

 def log_message(self,*args): pass

 def do_POST(self):

  msg=json.loads(self.rfile.read(int(self.headers['Content-Length'])))

  if 'id' not in msg:

   self.send_response(202);self.end_headers();return

  method=msg['method']

  if method=='initialize': result={'protocolVersion':'2025-11-25','capabilities':{'tools':{}},'serverInfo':{'name':'phase1-fixture','version':'1'}}

  elif method=='tools/list':

   tools=json.loads(Path('/fixture/tools.json').read_text())

   if Path('/fixture/drift').exists(): tools[0]['description']='Changed schema'

   result={'tools':tools}

  else:

   name=msg.get('params',{}).get('name')

   result={'content':[{'type':'text','text':'4111111111111111' if name=='read_file' else '5'}]}

  data=json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':result}).encode()

  self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

server=HTTPServer(('0.0.0.0',9090),Handler)

ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain('/fixture/upstream.pem','/fixture/upstream.key');ctx.load_verify_locations('/fixture/ca.pem');ctx.verify_mode=ssl.CERT_REQUIRED

server.socket=ctx.wrap_socket(server.socket,server_side=True);server.serve_forever()

''')

    return key





def request(port, path, token=None, payload=None):

    data = json.dumps(payload).encode() if payload is not None else None

    headers = {"Content-Type":"application/json", "Accept":"application/json, text/event-stream", "MCP-Protocol-Version":"2025-11-25"}

    if token: headers["Authorization"] = "Bearer " + token

    req = urllib.request.Request(f"http://127.0.0.1:{port}" + path, data=data, headers=headers)

    try:

        with urllib.request.urlopen(req, timeout=5) as response:

            raw=response.read(); return response.status, json.loads(raw) if raw else None

    except urllib.error.HTTPError as exc:

        return exc.code, json.loads(exc.read())





def wait_ready(name, port):

    for _ in range(90):

        try:

            if request(port,"/readyz")[0] == 200: return

        except (OSError, ValueError): pass

        if docker("inspect", "-f", "{{.State.Running}}", name) == "false":

            raise RuntimeError(docker("logs", "--tail", "30", name))

        time.sleep(1)

    raise RuntimeError("Gateway readiness timed out: " + docker("logs", "--tail", "30", name))





def run():

    key=prepare()

    report["image_id"]=docker("image", "inspect", "-f", "{{.Id}}", IMAGE)

    docker("network", "create", RUN); resources["networks"].append(RUN)

    for suffix in ("data", "redis", "restore"):

        name=RUN+"-"+suffix;docker("volume","create",name);resources["volumes"].append(name)

    def start(name, args):

        docker("run","-d","--name",name,*args);resources["containers"].append(name)

    redis_name=RUN+"-redis"

    start(redis_name,["--network",RUN,"--network-alias","redis","-v",redis_name+":/data",REDIS_IMAGE,"redis-server","--appendonly","yes","--appendfsync","always"])

    fixture_mount=path_for_docker(FIX)+":/fixture:ro"

    start(RUN+"-upstream",["--network",RUN,"--network-alias","upstream","-v",fixture_mount,IMAGE,"python","/fixture/upstream.py"])

    init=json.loads(docker("run","--rm","-v",RUN+"-data:/app/data",IMAGE,"python","-m","interceptor.recovery","init","--data-dir","/app/data"))

    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    env={"GATEWAY_ENV":"prod","GATEWAY_JWT_PUBLIC_KEY":public,"GATEWAY_JWT_ISSUER":"phase1-test","GATEWAY_JWT_AUDIENCE":"phase1-test", "MACAROON_ROOT_KEY":secrets.token_hex(32),"UPSTREAM_MCP_URL":"https://upstream:9090/mcp","UPSTREAM_CA_BUNDLE":"/fixture/ca.pem","CLIENT_CERT":"/fixture/client.pem","CLIENT_KEY":"/fixture/client.key","REDIS_URL":"redis://redis:6379/0","SCHEMA_LOCK_PATH":"/fixture/mcp-lock.json"}

    def gateway(name, volume, image=IMAGE):

        args=["--network",RUN,"--read-only","--tmpfs","/tmp","--cap-drop","ALL","-p","127.0.0.1::8080","-v",volume+":/app/data","-v",fixture_mount]

        for k,v in env.items(): args += ["-e",k+"="+v]

        start(name,args+[image])

        port=int(docker("port",name,"8080/tcp").split(":")[-1]);wait_ready(name,port);return port

    def token(epoch):

        now=int(time.time())

        return jwt.encode({"sub":"test-agent","scope":"mcp.admin","sid":"test-session","tenant":"default","iat":now,"exp":now+3600,"iss":"phase1-test","aud":"phase1-test","eg_epoch":epoch},key,algorithm="RS256")

    name=RUN+"-gateway";port=gateway(name,RUN+"-data");tok=token(init["epoch"])

    def rpc(method, params=None, port_=None, token_=None):

        return request(port_ or port,"/mcp",token_ or tok,{"jsonrpc":"2.0","id":1,"method":method,"params":params or {}})

    assert request(port,"/admin/roles/test-agent",tok,["calculate_math","read_file","http_post"])[0]==200

    assert request(port,"/rpc",tok,{"jsonrpc":"2.0","id":1,"method":"ping"})[0]==404

    listing = rpc("tools/list")

    assert "result" in listing[1], str(listing)

    assert "result" in rpc("tools/call",{"name":"calculate_math","arguments":{}})[1]

    mark("non-root read-only gateway boots with writable volumes and verified upstream mTLS")

    source=rpc("tools/call",{"name":"read_file","arguments":{}})[1]

    assert "4111111111111111" not in json.dumps(source) and "REDACTED" in json.dumps(source)

    assert rpc("tools/call",{"name":"http_post","arguments":{}})[1]["error"]["code"]==-32001

    mark("real Presidio redaction and durable coarse-taint denial")

    docker("stop",redis_name)

    assert rpc("ping")[0]==503

    docker("start",redis_name);time.sleep(2)

    docker("exec",redis_name,"redis-cli","FLUSHALL")  # only this isolated test instance

    assert rpc("tools/call",{"name":"http_post","arguments":{}})[1]["error"]["code"]==-32001

    mark("Redis outage fails closed; complete test-Redis state loss cannot clear durable taint")

    (FIX/"drift").write_text("test")

    assert rpc("tools/list")[1]["error"]["code"]==-32002

    (FIX/"drift").unlink()

    docker("kill",name);docker("start",name)

    port=int(docker("port",name,"8080/tcp").split(":")[-1])

    wait_ready(name,port)

    assert request(port,"/admin/roles/test-agent",tok)[1]["allowed_tools"]==["calculate_math","read_file","http_post"]

    assert rpc("tools/list")[1]["error"]["code"]==-32002

    assert rpc("tools/call",{"name":"calculate_math","arguments":{}})[1]["error"]["code"]==-32002

    assert rpc("tools/call",{"name":"http_post","arguments":{}})[1]["error"]["code"]==-32001

    mark("SIGKILL and restart preserve roles, taint, audit chain and schema quarantine")

    docker("stop",name)

    out_mount=path_for_docker(FIX)+":/backup"

    docker("run","--rm","--user","0","-v",RUN+"-data:/app/data","-v",out_mount,IMAGE,"python","-m","interceptor.recovery","backup","--data-dir","/app/data","--output","/backup/state.zip","--policy","/backup/config.yaml","--pins","/backup/mcp-lock.json")

    restored=json.loads(docker("run","--rm","-v",RUN+"-restore:/app/data","-v",out_mount,IMAGE,"python","-m","interceptor.recovery","restore","--input","/backup/state.zip","--destination","/app/data"))

    restored_name=RUN+"-restored";rp=gateway(restored_name,RUN+"-restore",os.environ.get("EVILGUM_ROLLBACK_IMAGE",IMAGE))

    assert request(rp,"/admin/roles/test-agent",tok)[0]==401

    fresh=token(restored["epoch"])

    assert request(rp,"/admin/roles/test-agent",fresh)[0]==200

    assert rpc("tools/list",port_=rp,token_=fresh)[1]["error"]["code"]==-32002

    assert rpc("tools/call",{"name":"http_post","arguments":{}},rp,fresh)[1]["error"]["code"]==-32001

    mark("offline backup restores into fresh volume; old credentials rejected and restored controls retained")

    docker("stop",restored_name)

    verify=docker("run","--rm","-v",RUN+"-restore:/app/data",IMAGE,"python","-c","from interceptor.audit import AuditLog; import json; print(json.dumps(AuditLog.verify('/app/data/audit.log.jsonl')))")

    assert json.loads(verify)["ok"]

    mark("restored audit chain verifies after the recovery workflow")

    docker("run","--rm","-v",RUN+"-restore:/app/data",IMAGE,"python","-c","from pathlib import Path; Path('/app/data/security.db').rename('/app/data/security-missing-test.db')")

    docker("start",restored_name)

    for _ in range(30):

        if docker("inspect","-f","{{.State.Running}}",restored_name)=="false": break

        time.sleep(.5)

    assert docker("inspect","-f","{{.State.Running}}",restored_name)=="false"

    assert "Incomplete durable state" in docker("logs","--tail","30",restored_name)

    mark("missing durable security database refuses startup instead of silently resetting protection")

    report["rollback_image"] = os.environ.get("EVILGUM_ROLLBACK_IMAGE",IMAGE)

    report["result"]="passed"





if __name__=="__main__":

    try:

        run()

    except Exception as exc:

        report["result"]="failed";report["error"]=str(exc)

        for name in resources["containers"]:

            try:

                (FIX/(name+".log")).write_text(docker("logs","--tail","80",name))

            except Exception: pass

        raise

    finally:

        for name in reversed(resources["containers"]):

            try: docker("rm","-f",name)

            except Exception: pass

        for name in resources["volumes"]:

            try: docker("volume","rm",name)

            except Exception: pass

        for name in resources["networks"]:

            try: docker("network","rm",name)

            except Exception: pass

        FIX.mkdir(parents=True,exist_ok=True)

        (FIX/"report.json").write_text(json.dumps(report,indent=2))

        print("Report: "+str(FIX/"report.json"),flush=True)
