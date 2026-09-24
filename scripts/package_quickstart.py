"""Assemble only reviewed public files; never include live state or credentials."""
from pathlib import Path
import tomllib
import hashlib
import zipfile

root = Path(__file__).resolve().parents[1]
dist = root / "dist"
version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
files = {}
for name in (f"evilgum-{version}-py3-none-any.whl", f"evilgum-{version}.tar.gz"):
    files[name] = (dist / name).read_bytes()
for name in ("LICENSE", "SECURITY.md", "CHANGELOG.md", "RELEASE.md", "PHASE1-OPERATIONS.md", "MCP-COMPATIBILITY.md"):
    files[name] = (root / name).read_bytes()
files["config.yaml"] = (root / "interceptor/assets/config.yaml").read_bytes()
files["scripts/verify_phase1.py"] = (root / "scripts/verify_phase1.py").read_bytes()
files["README.md"] = (root / "release/QUICKSTART.md").read_bytes()
files["environment.example"] = (root / "release/environment.example").read_bytes()
for path in sorted((root / "locks").glob("*.lock")):
    files["locks/" + path.name] = path.read_bytes()
for name in list(files):
    if name.endswith(".md"):
        files[name] = files[name].replace(b"0.1.0rc1", version.encode())
files["SHA256SUMS.txt"] = ("\n".join(hashlib.sha256(data).hexdigest() + "  " + name for name, data in sorted(files.items())) + "\n").encode()
with zipfile.ZipFile(dist / f"evilgum-{version}-quickstart.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for name, data in files.items():
        info = zipfile.ZipInfo(f"evilgum-{version}-quickstart/" + name, (2026, 9, 21, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, data)
with zipfile.ZipFile(dist / f"evilgum-{version}-quickstart.zip") as archive:
    assert archive.testzip() is None
print("Packaged quickstart with wheel, source, locks, docs and checksums")
