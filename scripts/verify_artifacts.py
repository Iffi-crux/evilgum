"""Validate release archive contents and report SHA-256 identities."""
import hashlib
import json
from pathlib import Path
import tomllib
import tarfile
import zipfile

root = Path(__file__).resolve().parents[1]
artifacts = root / "dist"
report = []
version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
for name in (f"evilgum-{version}-py3-none-any.whl", f"evilgum-{version}.tar.gz"):
    path = artifacts / name
    if name.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            names = archive.namelist()
            assert "interceptor/assets/config.yaml" in names
            assert "interceptor/assets/mcp-lock.json" in names
    else:
        with tarfile.open(path) as archive:
            names = archive.getnames()
            assert all(not member.issym() and not member.islnk() for member in archive)
            assert any(name.endswith("locks/runtime-py311-linux.lock") for name in names)
    forbidden = (".phase1-runtime", ".release-work", "__pycache__", ".env", ".pem", ".key", "security.db", "audit.log.jsonl")
    assert not [name for name in names if any(value in name for value in forbidden)]
    assert not [name for name in names if name.startswith("/") or ".." in Path(name).parts]
    report.append({"file": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "archive_safety": "passed"})
(artifacts / "artifact-checks.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
