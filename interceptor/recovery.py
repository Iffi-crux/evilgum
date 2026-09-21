"""Offline backup/restore. Stop the sole gateway worker before running.

Backups contain security state, not credentials. Restore only to a new empty
directory; never overwrite live state. A fresh IdP epoch claim is required after
restore so pre-restore credentials cannot silently resume against older state.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time
import uuid
import zipfile

from interceptor.audit import AuditLog
from interceptor.durable_state import SingleWorkerLock

FILES = ("admin.db", "security.db", "audit.log.jsonl")


def initialize(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if any((destination / name).exists() for name in (*FILES, "recovery.json")):
        raise RuntimeError("Initialization requires a new data directory")
    epoch = str(uuid.uuid4())
    (destination / "recovery.json").write_text(json.dumps({"epoch": epoch, "created": time.time()}))
    return {"epoch": epoch, "instruction": "Include eg_epoch in signed JWTs for this deployment."}


def backup(data_dir, target, policy, pins):
    data_dir, target = Path(data_dir), Path(target)
    lock = SingleWorkerLock(data_dir)
    lock.acquire()
    try:
        payloads = {name: (data_dir / name).read_bytes() for name in FILES}
        if not AuditLog.verify(str(data_dir / "audit.log.jsonl"))["ok"]:
            raise RuntimeError("Audit integrity check failed")
        payloads["config.yaml"] = Path(policy).read_bytes()
        payloads["mcp-lock.json"] = Path(pins).read_bytes()
        manifest = {"format": 1, "created": time.time(), "sha256": {
            name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}}
        with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
            for name, value in payloads.items():
                archive.writestr(name, value)
            archive.writestr("manifest.json", json.dumps(manifest))
        return manifest
    finally:
        lock.close()


def restore(source, destination):
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError("Restore destination must be empty")
    names = set(FILES) | {"config.yaml", "mcp-lock.json"}
    with zipfile.ZipFile(source) as archive:
        if set(archive.namelist()) != names | {"manifest.json"} or len(archive.namelist()) != len(names)+1:
            raise ValueError("Unexpected or duplicate archive entries")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("format") != 1 or set(manifest.get("sha256", {})) != names:
            raise ValueError("Unsupported manifest")
        payloads = {name: archive.read(name) for name in names}
        for name, value in payloads.items():
            if hashlib.sha256(value).hexdigest() != manifest["sha256"][name]:
                raise ValueError("Backup checksum mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    for name, value in payloads.items():
        (destination / name).write_bytes(value)
    epoch = str(uuid.uuid4())
    (destination / "recovery.json").write_text(json.dumps({"epoch": epoch, "restored_at": time.time()}))
    return {"epoch": epoch, "instruction": "Issue fresh-session JWTs with eg_epoch equal to this value."}


def release_quarantine(data_dir, pins, tool, approved_hash):
    """Explicit offline approval; never called by the running gateway."""
    lock = SingleWorkerLock(data_dir)
    lock.acquire()
    try:
        if json.loads(Path(pins).read_text()).get("tools", {}).get(tool) != approved_hash or len(approved_hash) != 64:
            raise ValueError("Reviewed hash does not match the installed pin")
        import sqlite3
        with sqlite3.connect(str(Path(data_dir) / "security.db")) as db:
            db.execute("PRAGMA synchronous=FULL")
            AuditLog(str(Path(data_dir) / "audit.log.jsonl")).append({"outcome":"operator_schema_approval", "tool":tool,"approved_hash":approved_hash})
            db.execute("DELETE FROM quarantine WHERE tool=?", (tool,))
        return {"tool": tool, "instruction": "Restart and complete tools/list discovery before calling."}
    finally:
        lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    i = sub.add_parser("init")
    i.add_argument("--data-dir", required=True)
    q = sub.add_parser("release-quarantine")
    q.add_argument("--data-dir", required=True); q.add_argument("--pins", required=True)
    q.add_argument("--tool", required=True); q.add_argument("--approved-hash", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--data-dir", required=True); b.add_argument("--output", required=True)
    b.add_argument("--policy", required=True); b.add_argument("--pins", required=True)
    r = sub.add_parser("restore")
    r.add_argument("--input", required=True); r.add_argument("--destination", required=True)
    args = parser.parse_args()
    if args.action == "init":
        result = initialize(args.data_dir)
    elif args.action == "release-quarantine":
        result = release_quarantine(args.data_dir, args.pins, args.tool, args.approved_hash)
    elif args.action == "backup":
        result = backup(args.data_dir, args.output, args.policy, args.pins)
    else:
        result = restore(args.input, args.destination)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
