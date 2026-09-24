"""Rebuild the wheel from the source archive and compare its bytes."""
import hashlib
import json
import os
from pathlib import Path
import tomllib
import subprocess
import sys
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
name = "evilgum-" + tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
expected = (root / "dist" / (name + "-py3-none-any.whl")).read_bytes()
with tempfile.TemporaryDirectory() as work:
    with tarfile.open(root / "dist" / (name + ".tar.gz")) as archive:
        archive.extractall(work, filter="data")
    environment = dict(os.environ, SOURCE_DATE_EPOCH="1789948800")
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(Path(work) / "rebuilt")], cwd=Path(work) / name, env=environment, check=True, stdout=subprocess.DEVNULL)
    rebuilt = (Path(work) / "rebuilt" / (name + "-py3-none-any.whl")).read_bytes()
    assert rebuilt == expected, "Source archive did not reproduce the wheel"
report = {"source_rebuild": "byte-identical wheel", "wheel_sha256": hashlib.sha256(expected).hexdigest()}
(root / "dist" / "source-rebuild.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report))
