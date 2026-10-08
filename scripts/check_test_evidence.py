"""Check saved Go JSON events; an exit-zero log or skipped gate is not a pass."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def inspect(text: str, required: list[str]) -> dict:
    events = [json.loads(line) for line in text.splitlines() if line.strip()]
    terminal = {}
    started = set()
    failures = set()
    for event in events:
        key = event.get("Package", "") + ("::" + event["Test"] if "Test" in event else "")
        if event.get("Action") in {"start", "run"}:
            started.add(key)
        if event.get("Action") == "fail":
            failures.add(key)
        if event.get("Action") in {"pass", "skip", "fail"}:
            terminal[key] = event["Action"]
    failed = sorted(failures)
    incomplete = sorted(started - terminal.keys())
    missing = sorted(key for key in required if terminal.get(key) != "pass")
    packages = [key for key, action in terminal.items() if "::" not in key and action == "pass"]
    return {"passed_packages": len(packages),
            "passed_test_events_including_subtests": sum("::" in key and action == "pass" for key, action in terminal.items()),
            "skipped": sorted(key for key, action in terminal.items() if action == "skip" and "::" in key),
            "skipped_packages": sorted(key for key, action in terminal.items() if action == "skip" and "::" not in key),
            "failed": failed, "mandatory_not_passed": missing,
            "incomplete": incomplete,
            "valid": bool(packages) and not failed and not missing and not incomplete}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("--require", action="append", default=[], help="Exact package::TestName")
    args = parser.parse_args()
    result = inspect(args.events.read_text(encoding="utf-8"), args.require)
    print(json.dumps(result, indent=2))
    if not result["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
