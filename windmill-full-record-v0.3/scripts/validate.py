#!/usr/bin/env python3
"""Full-record JSON Schema gate; schema snapshots are pinned locally."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    "authority-envelope": ROOT / "schemas/authority-envelope.schema.json",
    "recovery-receipt": ROOT / "schemas/recovery-receipt.schema.json",
    "action-authorization-receipt": ROOT / "schemas/action-authorization-receipt.schema.json",
}

def load(path: Path):
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)

def validator(kind: str):
    schema = load(SCHEMAS[kind])
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--type", choices=sorted(SCHEMAS))
    parser.add_argument("--input", type=Path)
    args = parser.parse_args()
    if args.self_test:
        for kind in sorted(SCHEMAS):
            v = validator(kind)
            # Each source schema requires nonempty document fields.
            if not list(v.iter_errors({})):
                raise AssertionError(f"{kind}: empty document unexpectedly passed")
            if not list(v.iter_errors({"unexpected": True})):
                raise AssertionError(f"{kind}: unknown record unexpectedly passed")
            print(f"[PASS] {kind}: schema valid; missing-required and unknown-record cases rejected")
        return 0
    if not args.type or not args.input:
        parser.error("--type and --input are required unless --self-test is selected")
    try:
        record = load(args.input)
        issues = list(validator(args.type).iter_errors(record))
    except (OSError, ValueError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    if issues:
        for issue in sorted(issues, key=lambda e: str(e.absolute_path)):
            location = "/".join(map(str, issue.absolute_path)) or "<root>"
            print(f"[FAIL] {location}: {issue.message}", file=sys.stderr)
        return 1
    print(f"[PASS] {args.type}: full JSON Schema validation successful")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
