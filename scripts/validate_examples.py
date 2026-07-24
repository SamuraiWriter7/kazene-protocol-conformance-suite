#!/usr/bin/env python3
"""Validate Kazene cross-protocol conformance examples through v0.2."""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
MANIFEST_DIR = ROOT / "manifests"
EXAMPLES_DIR = ROOT / "examples"
BUILD_DIR = ROOT / "build"

MANIFEST_SCHEMA_PATH = (
    SCHEMA_DIR
    / "conformance-suite-manifest.schema.json"
)

RESULT_SCHEMA_PATH = (
    SCHEMA_DIR
    / "conformance-result.schema.json"
)

SemanticChecker = Callable[
    [dict[str, Any]],
    list[dict[str, str]],
]


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: root value must be an object"
        )

    return data


def load_json(path: Path) -> dict[str, Any]:
    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: root value must be an object"
        )

    return data


def format_path(error_path: Any) -> str:
    parts = [
        str(part)
        for part in error_path
    ]

    return (
        ".".join(parts)
        if parts
        else "<root>"
    )


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
        f"{format_path(error.path)}: "
        f"{error.message}"
        for error in errors
    ]


def passed(
    check_id: str,
    message: str,
) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": "passed",
        "message": message,
    }


def failed(
    check_id: str,
    message: str,
) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": "failed",
        "message": message,
    }


def skipped(
    check_id: str,
    message: str,
) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": "skipped",
        "message": message,
    }


def duplicate_values(
    values: list[str],
) -> list[str]:
    return sorted(
        value
        for value, count
        in Counter(values).items()
        if count > 1
    )


def check_origin_trace(
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
        duplicates = duplicate_values(origin_ids)

        if duplicates:
            results.append(
                failed(
                    "origin_id_unique",
                    "Duplicate Origin IDs: "
                    + ", ".join(duplicates),
                )
            )
        else:
            results.append(
                passed(
                    "origin_id_unique",
                    "All Origin IDs are unique.",
                )
            )
    else:
        results.append(
            skipped(
                "origin_id_unique",
                "Origin ID uniqueness check is "
                "disabled by policy.",
            )
        )

    if policy["require_unique_trace_ids"]:
        duplicates = duplicate_values(trace_ids)

        if duplicates:
            results.append(
                failed(
                    "trace_id_unique",
                    "Duplicate Trace IDs: "
                    + ", ".join(duplicates),
                )
            )
        else:
            results.append(
                passed(
                    "trace_id_unique",
                    "All Trace IDs are unique.",
                )
            )
    else:
        results.append(
            skipped(
                "trace_id_unique",
                "Trace ID uniqueness check is "
                "disabled by policy.",
            )
        )

    referenced_origin_ids = sorted(
        {
            origin_ref
            for trace in traces
            for origin_ref
            in trace.get("origin_refs", [])
        }
    )

    if policy["require_registered_origin"]:
        missing = [
            origin_id
            for origin_id in referenced_origin_ids
            if origin_id not in origin_index
        ]

        if missing:
            results.append(
                failed(
                    "origin_trace_reference_exists",
                    "Unresolved Origin references: "
                    + ", ".join(missing),
                )
            )
        else:
            results.append(
                passed(
                    "origin_trace_reference_exists",
                    "Every Trace Origin reference "
                    "resolves to a registered Origin.",
                )
            )
    else:
        results.append(
            skipped(
                "origin_trace_reference_exists",
                "Registered Origin resolution check "
                "is disabled by policy.",
            )
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
                and origin_index[origin_id]["status"]
                != "active"
            )
        ]

        if inactive:
            results.append(
                failed(
                    "origin_status_active",
                    "Inactive Origin references: "
                    + ", ".join(inactive),
                )
            )
        else:
            results.append(
                passed(
                    "origin_status_active",
                    "Every resolved Origin reference "
                    "is active.",
                )
            )
    else:
        results.append(
            skipped(
                "origin_status_active",
                "Active Origin status check is "
                "disabled by policy.",
            )
        )

    return results


def check_trace_authorization(
    case: dict[str, Any],
) -> list[dict[str, str]]:
    traces = case["trace_records"]
    authorizations = case[
        "authorization_records"
    ]
    policy = case["policy"]

    trace_ids = [
        record["trace_id"]
        for record in traces
    ]

    authorization_ids = [
        record["authorization_id"]
        for record in authorizations
    ]

    trace_index = {
        record["trace_id"]: record
        for record in traces
    }

    results: list[dict[str, str]] = []

    if policy["require_unique_trace_ids"]:
        duplicates = duplicate_values(trace_ids)

        if duplicates:
            results.append(
                failed(
                    "trace_id_unique",
                    "Duplicate Trace IDs: "
                    + ", ".join(duplicates),
                )
            )
        else:
            results.append(
                passed(
                    "trace_id_unique",
                    "All supplied Trace IDs "
                    "are unique.",
                )
            )
    else:
        results.append(
            skipped(
                "trace_id_unique",
                "Trace ID uniqueness check is "
                "disabled by policy.",
            )
        )

    if policy[
        "require_unique_authorization_ids"
    ]:
        duplicates = duplicate_values(
            authorization_ids
        )

        if duplicates:
            results.append(
                failed(
                    "authorization_id_unique",
                    "Duplicate Authorization IDs: "
                    + ", ".join(duplicates),
                )
            )
        else:
            results.append(
                passed(
                    "authorization_id_unique",
                    "All Authorization IDs "
                    "are unique.",
                )
            )
    else:
        results.append(
            skipped(
                "authorization_id_unique",
                "Authorization ID uniqueness check "
                "is disabled by policy.",
            )
        )

    if policy["require_registered_trace"]:
        unresolved: list[str] = []

        for record in authorizations:
            authorization_id = record[
                "authorization_id"
            ]

            for field_name in (
                "request_trace_ref",
                "receipt_trace_ref",
            ):
                trace_ref = record[field_name]

                if trace_ref not in trace_index:
                    unresolved.append(
                        f"{authorization_id}."
                        f"{field_name}="
                        f"{trace_ref}"
                    )

        if unresolved:
            results.append(
                failed(
                    "authorization_trace_reference_exists",
                    "Unresolved Trace references: "
                    + "; ".join(
                        sorted(unresolved)
                    ),
                )
            )
        else:
            results.append(
                passed(
                    "authorization_trace_reference_exists",
                    "Every Authorization Trace "
                    "reference resolves to a "
                    "supplied Trace.",
                )
            )
    else:
        results.append(
            skipped(
                "authorization_trace_reference_exists",
                "Registered Trace resolution check "
                "is disabled by policy.",
            )
        )

    if policy[
        "require_preserved_trace_binding"
    ]:
        substitutions = [
            (
                f"{record['authorization_id']}"
                f"(request="
                f"{record['request_trace_ref']}, "
                f"receipt="
                f"{record['receipt_trace_ref']})"
            )
            for record in authorizations
            if (
                record["request_trace_ref"]
                != record["receipt_trace_ref"]
            )
        ]

        if substitutions:
            results.append(
                failed(
                    "trace_binding_preserved",
                    "Trace substitutions detected: "
                    + "; ".join(substitutions),
                )
            )
        else:
            results.append(
                passed(
                    "trace_binding_preserved",
                    "Every Authorization receipt "
                    "preserves the request Trace "
                    "binding.",
                )
            )
    else:
        results.append(
            skipped(
                "trace_binding_preserved",
                "Trace binding preservation check "
                "is disabled by policy.",
            )
        )

    return results


CASE_CONFIGS: dict[str, dict[str, Any]] = {
    "origin_trace_linkage": {
        "schema_path": (
            SCHEMA_DIR
            / "origin-trace-conformance-case"
            ".schema.json"
        ),
        "suite_id": (
            "kazene:conformance-suite:"
            "core-origin-trace"
        ),
        "semantic_checker": check_origin_trace,
    },
    "trace_authorization_binding": {
        "schema_path": (
            SCHEMA_DIR
            / "trace-authorization-conformance-case"
            ".schema.json"
        ),
        "suite_id": (
            "kazene:conformance-suite:"
            "core-trace-authorization"
        ),
        "semantic_checker": (
            check_trace_authorization
        ),
    },
}


SUPPORTED_STAGE_PAIRS = {
    ("origin", "trace"),
    ("trace", "authorization"),
}


def validate_manifests(
    manifest_schema: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    int,
]:
    manifests: dict[
        str,
        dict[str, Any],
    ] = {}

    errors_found = 0

    for path in sorted(
        MANIFEST_DIR.glob("*.yaml")
    ):
        print(
            "[validate-manifest] "
            f"{path.relative_to(ROOT)}"
        )

        manifest = load_yaml(path)

        errors = schema_errors(
            manifest,
            manifest_schema,
        )

        if errors:
            for error in errors:
                print(
                    "[manifest-schema-error] "
                    f"{error}"
                )

            errors_found += 1
            print()
            continue

        if (
            manifest["schema_version"]
            != manifest["suite_version"]
        ):
            print(
                "[manifest-semantic-error] "
                "schema_version and suite_version "
                "must match"
            )

            errors_found += 1
            print()
            continue

        pair = (
            manifest["stage_pair"][
                "source_stage"
            ],
            manifest["stage_pair"][
                "target_stage"
            ],
        )

        if pair not in SUPPORTED_STAGE_PAIRS:
            print(
                "[manifest-semantic-error] "
                "unsupported stage pair: "
                f"{pair[0]} -> {pair[1]}"
            )

            errors_found += 1
            print()
            continue

        check_ids = [
            check["check_id"]
            for check in manifest["checks"]
        ]

        duplicate_check_ids = (
            duplicate_values(check_ids)
        )

        if duplicate_check_ids:
            print(
                "[manifest-semantic-error] "
                "duplicate check IDs: "
                + ", ".join(
                    duplicate_check_ids
                )
            )

            errors_found += 1
            print()
            continue

        suite_id = manifest["suite_id"]

        if suite_id in manifests:
            print(
                "[manifest-semantic-error] "
                f"duplicate suite ID: {suite_id}"
            )

            errors_found += 1
            print()
            continue

        manifests[suite_id] = manifest

        print("[manifest-schema-ok]")
        print("[manifest-semantic-ok]")
        print()

    return manifests, errors_found


def evaluate_case(
    path: Path,
    case: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    checker: SemanticChecker = config[
        "semantic_checker"
    ]

    checks = checker(case)

    actual_outcome = (
        "nonconformant"
        if any(
            check["status"] == "failed"
            for check in checks
        )
        else "conformant"
    )

    expected_outcome = case[
        "expected_outcome"
    ]

    return {
        "case_id": case["case_id"],
        "case_type": case["case_type"],
        "suite_id": config["suite_id"],
        "source_file": str(
            path.relative_to(ROOT)
        ),
        "expected_outcome": expected_outcome,
        "actual_outcome": actual_outcome,
        "matched_expectation": (
            actual_outcome
            == expected_outcome
        ),
        "check_results": checks,
    }


def main() -> int:
    print(
        "=== Kazene Protocol Conformance "
        "Suite Validation ==="
    )
    print("version : 0.2.0")
    print(
        "scope   : Origin -> Trace "
        "-> Authorization"
    )
    print()

    try:
        manifest_schema = load_json(
            MANIFEST_SCHEMA_PATH
        )

        result_schema = load_json(
            RESULT_SCHEMA_PATH
        )

        case_schemas = {
            case_type: load_json(
                config["schema_path"]
            )
            for case_type, config
            in CASE_CONFIGS.items()
        }

        (
            manifests,
            fatal_errors,
        ) = validate_manifests(
            manifest_schema
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        print(f"[fatal] {exc}")
        return 1

    required_suite_ids = {
        config["suite_id"]
        for config in CASE_CONFIGS.values()
    }

    missing_manifests = sorted(
        required_suite_ids
        - set(manifests)
    )

    if missing_manifests:
        print(
            "[fatal] missing manifests: "
            + ", ".join(missing_manifests)
        )

        return 1

    example_paths = sorted(
        EXAMPLES_DIR.glob("pass/*.yaml")
    ) + sorted(
        EXAMPLES_DIR.glob("fail/*.yaml")
    )

    if not example_paths:
        print("[fatal] no examples found")
        return 1

    results: list[dict[str, Any]] = []

    for path in example_paths:
        print(
            f"[validate] "
            f"{path.relative_to(ROOT)}"
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

        case_type = case.get("case_type")

        if case_type not in CASE_CONFIGS:
            print(
                "[schema-selection-error] "
                "unsupported case_type: "
                f"{case_type!r}"
            )

            fatal_errors += 1
            print()
            continue

        config = CASE_CONFIGS[case_type]

        errors = schema_errors(
            case,
            case_schemas[case_type],
        )

        if errors:
            for error in errors:
                print(
                    f"[schema-error] {error}"
                )

            fatal_errors += 1
            print()
            continue

        print("[schema-ok]")

        result = evaluate_case(
            path,
            case,
            config,
        )

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

        if (
            result["expected_outcome"]
            != folder_expected
        ):
            print(
                "[expectation-error] "
                "example folder and "
                "expected_outcome disagree: "
                f"folder={folder_expected}, "
                f"declared="
                f"{result['expected_outcome']}"
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
                f"expected="
                f"{result['expected_outcome']}, "
                f"actual="
                f"{result['actual_outcome']}"
            )

            fatal_errors += 1

        print()

    generated_at = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )

    report = {
        "schema_version": "0.2.0",
        "suite_id": (
            "kazene:conformance-suite:core"
        ),
        "suite_version": "0.2.0",
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
                not result[
                    "matched_expectation"
                ]
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
                "[result-schema-error] "
                f"{error}"
            )

        return 1

    BUILD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        BUILD_DIR
        / "conformance-results.json"
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

    for key, value in (
        report["summary"].items()
    ):
        print(f"{key}: {value}")

    print(
        f"result: "
        f"{output_path.relative_to(ROOT)}"
    )

    if fatal_errors:
        print("\nValidation failed.")
        return 1

    print("\nValidation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
