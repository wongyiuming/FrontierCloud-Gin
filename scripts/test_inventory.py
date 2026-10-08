"""Inventory test definitions and freeze legacy identifiers, never pass counts.

Generated CSV is an audit artifact, not runnable retired application tests.
Replacement candidates require human assertion review before acceptance.
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "7e7b53b144eb134759af5f7ee03b605e4c9c6180"


def methods(source: str) -> list[str]:
    tree = ast.parse(source)
    class_methods = [f"{node.name}.{child.name}" for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")]
    return class_methods + [node.name for node in tree.body
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and node.name.startswith("test_")]


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT).decode("utf-8")


def inventory() -> dict:
    python = {p.relative_to(ROOT).as_posix(): methods(p.read_text(encoding="utf-8"))
              for p in sorted((ROOT / "tests").glob("test_*.py"))}
    go = {p.relative_to(ROOT).as_posix(): re.findall(
        r"(?m)^func (Test\w+)\(t \*testing\.T\)", p.read_text(encoding="utf-8"))
        for directory in ("cmd", "internal") for p in sorted((ROOT / directory).rglob("*_test.go"))}
    return {"definition_counts_only": True, "python": python, "go": go,
            "python_files": len(python), "go_files": len(go),
            "python_definitions": sum(map(len, python.values())),
            "python_class_methods": sum("." in name for names in python.values() for name in names),
            "python_module_functions": sum("." not in name for names in python.values() for name in names),
            "go_top_level_tests": sum(map(len, go.values())),
            "js_smoke": [p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "tests").glob("*smoke.mjs"))]}


def legacy_rows() -> list[dict]:
    current = inventory()["python"]
    paths = git("ls-tree", "-r", "--name-only", BASELINE, "--", "tests").splitlines()
    result = []
    for path in paths:
        if not re.fullmatch(r"tests/test_.*\.py", path):
            continue
        for method in methods(git("show", f"{BASELINE}:{path}")):
            present = method in current.get(path, [])
            result.append({"baseline": BASELINE, "legacy_case": f"{path}::{method}",
                           "definition_present": str(present).lower(),
                           "replacement": f"{path}::{method}" if present else "",
                           "review_status": "pending-assertion-review",
                           "note": "Identifier retention is not assertion equivalence." if present else
                           "Unmapped: distinguish retained business invariant from retired runtime detail."})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-csv", action="store_true", help="Print frozen audit CSV to stdout")
    args = parser.parse_args()
    if args.legacy_csv:
        rows = legacy_rows()
        writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    else:
        print(json.dumps(inventory(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
