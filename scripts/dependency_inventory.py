"""Write installed Python dependency and declared-license inventory (not a legal opinion)."""
import importlib.metadata as metadata
import json
import sys
from pathlib import Path
rows = []
for dist in metadata.distributions():
    info = dist.metadata
    licenses = [value for value in info.get_all("Classifier", []) if value.startswith("License ::")]
    rows.append({"name": info["Name"], "version": dist.version, "license_expression": info.get("License-Expression"), "license": (info.get("License") or "")[:1000], "license_classifiers": licenses, "requires": dist.requires or []})
Path(sys.argv[1]).write_text(json.dumps(sorted(rows, key=lambda row: row["name"].lower()), indent=2))
