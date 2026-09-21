"""Run with the candidate wheel installed, from OUTSIDE the source checkout."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from importlib.metadata import version
import interceptor

assert "site-packages" in str(Path(interceptor.__file__).resolve()), interceptor.__file__
assert version("evilgum") == "0.1.0rc1"
with tempfile.TemporaryDirectory() as directory:
    output = Path(directory) / "deployment"
    subprocess.run([sys.executable, "-m", "interceptor.cli", "init-config", "--directory", str(output)], check=True)
    assert json.loads((output / "mcp-lock.json").read_text()) == {"tools": {}}
    from interceptor.config import load_policy
    assert load_policy(str(output / "config.yaml")).is_source("read_file")
    original = (output / "config.yaml").read_bytes()
    result = subprocess.run([sys.executable, "-m", "interceptor.cli", "init-config", "--directory", str(output)], capture_output=True)
    assert result.returncode != 0 and (output / "config.yaml").read_bytes() == original
    from mesh.semantic_waf import PresidioAnalyzer
    assert PresidioAnalyzer().find("4111111111111111")
print(json.dumps({"installed_package": interceptor.__file__, "version": version("evilgum"), "configuration_assets": "passed", "overwrite_refusal": "passed", "real_dlp_model": "passed"}))
