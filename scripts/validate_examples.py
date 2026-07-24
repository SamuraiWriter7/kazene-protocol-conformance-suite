#!/usr/bin/env python3
"""Validate v0.1 Kazene Origin–Trace conformance examples."""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
MANIFEST_PATH = ROOT / "manifests" / "core-origin-trace-suite.yaml"
EXAMPLES_DIR = ROOT / "examples"
BUILD_DIR = ROOT / "build"

CASE_SCHEMA_PATH = (
    SCHEMA_DIR / "origin-trace-conformance-case.schema.json"
)
MANIFEST_SCHEMA_PATH = (
    SCHEMA_DIR / "conformance-suite-manifest.schema.json"
)
RESULT_SCHEMA_PATH = (
    SCHEMA_DIR / "conformance-result.schema.json"
)


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: root value must be an object")

    return data


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: root value must be an object")

    return data


def format_path(error_path: Any) -> str:
    parts = [str(part) for part in error_path]
    return ".".join(parts) if parts else "<root>"


def schema_errors(
    instance: dict[str, Any],
    schema: dict[str, Any],
) -> list[str]:
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: list(error.path),
    )

    return [
        f"{format_path(error.path)}: {error.message}"
        for error in errors
    ]


def check_result(
    check_id: str,
    passed: bool,
    message: str,
) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": "passed" if passed else "failed",
        "message": message,
    }


def semantic_checks(
    case: dict[str, Any],
) -> list[dict[str, str]]:
    origins = case["origin_records"]
    traces = case["trace_records"]
    policy = case["policy"]

    origin_ids = [
        record["origin_id"]
        for record in origins
    ]

    trace_ids = [
        record["trace_id"]
        for record in traces
    ]

    origin_index = {
        record["origin_id"]: record
        for record in origins
    }

    results: list[dict[str, str]] = []

    if policy["require_unique_origin_ids"]:
        duplicates = sorted(
            origin_id
            for origin_id, count in Counter(origin_ids).items()
            if count > 1
        )

        results.append(
            check_result(
                "origin_id_unique",
                not duplicates,
                (
                    "All Origin IDs are unique."
                    if not duplicates
                    else (
                        "Duplicate Origin IDs: "
                        + ", ".join(duplicates)
                    )
                ),
            )
        )
    else:
        results.append(
            {
                "check_id": "origin_id_unique",
                "status": "skipped",
                "message": (
                    "Origin ID uniqueness check is "
                    "disabled by policy."
                ),
            }
        )

    if policy["require_unique_trace_ids"]:
        duplicates = sorted(
            trace_id
            for trace_id, count in Counter(trace_ids).items()
            if count > 1
        )

        results.append(
            check_result(
                "trace_id_unique",
                not duplicates,
                (
                    "All Trace IDs are unique."
                    if not duplicates
                    else (
                        "Duplicate Trace IDs: "
                        + ", ".join(duplicates)
                    )
                ),
            )
        )
    else:
        results.append(
            {
                "check_id": "trace_id_unique",
                "status": "skipped",
                "message": (
                    "Trace ID uniqueness check is "
                    "disabled by policy."
                ),
            }
        )

    referenced_origin_ids = sorted(
        {
            origin_ref
            for trace in traces
            for origin_ref in trace.get("origin_refs", [])
        }
    )

    if policy["require_registered_origin"]:
        missing = [
            origin_id
            for origin_id in referenced_origin_ids
            if origin_id not in origin_index
        ]

        results.append(
            check_result(
                "origin_trace_reference_exists",
                not missing,
                (
                    "Every Trace Origin reference resolves "
                    "to a registered Origin."
                    if not missing
                    else (
                        "Unresolved Origin references: "
                        + ", ".join(missing)
                    )
                ),
            )
        )
    else:
        results.append(
            {
                "check_id": "origin_trace_reference_exists",
                "status": "skipped",
                "message": (
                    "Registered Origin resolution check is "
                    "disabled by policy."
                ),
            }
        )

    if policy["require_active_origin"]:
        inactive = [
            (
                f"{origin_id}"
                f"({origin_index[origin_id]['status']})"
            )
            for origin_id in referenced_origin_ids
            if (
                origin_id in origin_index
                and origin_index[origin_id]["status"] != "active"
            )
        ]

        results.append(
            check_result(
                "origin_status_active",
                not inactive,
                (
                    "Every resolved Origin reference is active."
                    if not inactive
                    else (
                        "Inactive Origin references: "
                        + ", ".join(inactive)
                    )
                ),
            )
        )
    else:
        results.append(
            {
                "check_id": "origin_status_active",
                "status": "skipped",
                "message": (
                    "Active Origin status check is "
                    "disabled by policy."
                ),
            }
        )

    return results


def evaluate_case(
    path: Path,
    case: dict[str, Any],
) -> dict[str, Any]:
    checks = semantic_checks(case)

    actual_outcome = (
        "nonconformant"
        if any(
            check["status"] == "failed"
            for check in checks
        )
        else "conformant"
    )

    expected_outcome = case["expected_outcome"]

    return {
        "case_id": case["case_id"],
        "source_file": str(path.relative_to(ROOT)),
        "expected_outcome": expected_outcome,
        "actual_outcome": actual_outcome,
        "matched_expectation": (
            actual_outcome == expected_outcome
        ),
        "check_results": checks,
    }


def main() -> int:
    print(
        "=== Kazene Protocol Conformance "
        "Suite Validation ==="
    )
    print("version : 0.1.0")
    print("scope   : Origin -> Trace linkage")
    print()

    try:
        case_schema = load_json(CASE_SCHEMA_PATH)
        manifest_schema = load_json(
            MANIFEST_SCHEMA_PATH
        )
        result_schema = load_json(RESULT_SCHEMA_PATH)
        manifest = load_yaml(MANIFEST_PATH)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        print(f"[fatal] {exc}")
        return 1

    manifest_errors = schema_errors(
        manifest,
        manifest_schema,
    )

    print(
        "[validate-manifest] "
        f"{MANIFEST_PATH.relative_to(ROOT)}"
    )

    if manifest_errors:
        for error in manifest_errors:
            print(
                f"[manifest-schema-error] {error}"
            )
        return 1

    print("[manifest-schema-ok]")
    print()

    example_paths = sorted(
        EXAMPLES_DIR.glob("pass/*.yaml")
    ) + sorted(
        EXAMPLES_DIR.glob("fail/*.yaml")
    )

    if not example_paths:
        print("[fatal] no examples found")
        return 1

    results: list[dict[str, Any]] = []
    fatal_errors = 0

    for path in example_paths:
        print(
            f"[validate] {path.relative_to(ROOT)}"
        )

        try:
            case = load_yaml(path)
        except (
            OSError,
            ValueError,
            yaml.YAMLError,
        ) as exc:
            print(f"[load-error] {exc}")
            fatal_errors += 1
            print()
            continue

        errors = schema_errors(
            case,
            case_schema,
        )

        if errors:
            for error in errors:
                print(f"[schema-error] {error}")

            fatal_errors += 1
            print()
            continue

        print("[schema-ok]")

        result = evaluate_case(path, case)
        results.append(result)

        for check in result["check_results"]:
            print(
                f"[{check['status']}] "
                f"{check['check_id']}: "
                f"{check['message']}"
            )

        folder_expected = (
            "conformant"
            if path.parent.name == "pass"
            else "nonconformant"
        )

        folder_matches = (
            result["expected_outcome"]
            == folder_expected
        )

        if not folder_matches:
            print(
                "[expectation-error] example folder "
                "and expected_outcome disagree: "
                f"folder={folder_expected}, "
                f"declared={result['expected_outcome']}"
            )
            fatal_errors += 1

        if result["matched_expectation"]:
            print(
                "[expectation-ok] "
                f"{result['actual_outcome']}"
            )
        else:
            print(
                "[expectation-mismatch] "
                f"expected={result['expected_outcome']}, "
                f"actual={result['actual_outcome']}"
            )
            fatal_errors += 1

        print()

    generated_at = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )

    report = {
        "schema_version": "0.1.0",
        "suite_id": manifest["suite_id"],
        "suite_version": manifest["suite_version"],
        "generated_at": generated_at,
        "summary": {
            "total_cases": len(results),
            "conformant_cases": sum(
                result["actual_outcome"]
                == "conformant"
                for result in results
            ),
            "nonconformant_cases": sum(
                result["actual_outcome"]
                == "nonconformant"
                for result in results
            ),
            "matched_expectations": sum(
                result["matched_expectation"]
                for result in results
            ),
            "mismatched_expectations": sum(
                not result["matched_expectation"]
                for result in results
            ),
        },
        "results": results,
    }

    report_errors = schema_errors(
        report,
        result_schema,
    )

    if report_errors:
        for error in report_errors:
            print(
                f"[result-schema-error] {error}"
            )
        return 1

    BUILD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        BUILD_DIR / "conformance-results.json"
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            report,
            handle,
            ensure_ascii=False,
            indent=2,
        )
        handle.write("\n")

    print("=== Summary ===")

    for key, value in report["summary"].items():
        print(f"{key}: {value}")

    print(
        f"result: {output_path.relative_to(ROOT)}"
    )

    if fatal_errors:
        print("\nValidation failed.")
        return 1

    print("\nValidation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
