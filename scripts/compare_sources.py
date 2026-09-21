"""Inventory older sibling Python modules against the canonical core."""
import ast
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
rows = []
missing = []
def symbols(path):
    return {n.name for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
for package in ("interceptor", "mesh", "detector"):
    for old in (root.parent / package).glob("*.py"):
        new = root / package / old.name
        if not new.exists():
            missing.append(str(old.relative_to(root.parent)))
        elif old.read_bytes() != new.read_bytes():
            rows.append({"file":str(new.relative_to(root)), "outer_only_symbols":sorted(symbols(old)-symbols(new))})
print(json.dumps({"changed_modules": rows, "outer_only_modules": missing}, indent=2))
