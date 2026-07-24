#!/usr/bin/env python3
"""Validate Kazene cross-protocol conformance examples through v0.4."""

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


def result(
    check_id: str,
    status: str,
    message: str,
) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": status,
        "message": message,
    }


def passed(
    check_id: str,
    message: str,
) -> dict[str, str]:
    return result(
        check_id,
        "passed",
        message,
    )


def failed(
    check_id: str,
    message: str,
) -> dict[str, str]:
    return result(
        check_id,
        "failed",
        message,
    )


def skipped(
    check_id: str,
    message: str,
) -> dict[str, str]:
    return result(
        check_id,
        "skipped",
        message,
    )


def duplicate_values(
    values: list[str],
) -> list[str]:
    return sorted(
        value
        for value, count
        in Counter(values).items()
        if count > 1
    )


def parse_datetime(
    value: str,
) -> datetime:
    return datetime.fromisoformat(
        value.replace(
            "Z",
            "+00:00",
        )
    )


def unique_check(
    enabled: bool,
    values: list[str],
    check_id: str,
    label: str,
) -> dict[str, str]:
    if not enabled:
        return skipped(
            check_id,
            (
                f"{label} uniqueness check "
                "is disabled by policy."
            ),
        )

    duplicates = duplicate_values(values)

    if duplicates:
        return failed(
            check_id,
            (
                f"Duplicate {label} IDs: "
                + ", ".join(duplicates)
            ),
        )

    return passed(
        check_id,
        f"All {label} IDs are unique.",
    )


def check_origin_trace(
    case: dict[str, Any],
) -> list[dict[str, str]]:
    origins = case["origin_records"]
    traces = case["trace_records"]
    policy = case["policy"]

    origin_index = {
        record["origin_id"]: record
        for record in origins
    }

    referenced = sorted(
        {
            origin_ref
            for trace in traces
            for origin_ref
            in trace.get("origin_refs", [])
        }
    )

    results = [
        unique_check(
            policy[
                "require_unique_origin_ids"
            ],
            [
                record["origin_id"]
                for record in origins
            ],
            "origin_id_unique",
            "Origin",
        ),
        unique_check(
            policy[
                "require_unique_trace_ids"
            ],
            [
                record["trace_id"]
                for record in traces
            ],
            "trace_id_unique",
            "Trace",
        ),
    ]

    if policy["require_registered_origin"]:
        missing = [
            origin_id
            for origin_id in referenced
            if origin_id not in origin_index
        ]

        results.append(
            failed(
                "origin_trace_reference_exists",
                (
                    "Unresolved Origin references: "
                    + ", ".join(missing)
                ),
            )
            if missing
            else passed(
                "origin_trace_reference_exists",
                (
                    "Every Trace Origin reference "
                    "resolves to a registered Origin."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "origin_trace_reference_exists",
                (
                    "Registered Origin resolution "
                    "check is disabled by policy."
                ),
            )
        )

    if policy["require_active_origin"]:
        inactive = [
            (
                f"{origin_id}"
                f"({origin_index[origin_id]['status']})"
            )
            for origin_id in referenced
            if (
                origin_id in origin_index
                and origin_index[
                    origin_id
                ]["status"] != "active"
            )
        ]

        results.append(
            failed(
                "origin_status_active",
                (
                    "Inactive Origin references: "
                    + ", ".join(inactive)
                ),
            )
            if inactive
            else passed(
                "origin_status_active",
                (
                    "Every resolved Origin reference "
                    "is active."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "origin_status_active",
                (
                    "Active Origin status check "
                    "is disabled by policy."
                ),
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

    trace_index = {
        record["trace_id"]: record
        for record in traces
    }

    results = [
        unique_check(
            policy[
                "require_unique_trace_ids"
            ],
            [
                record["trace_id"]
                for record in traces
            ],
            "trace_id_unique",
            "Trace",
        ),
        unique_check(
            policy[
                "require_unique_authorization_ids"
            ],
            [
                record["authorization_id"]
                for record in authorizations
            ],
            "authorization_id_unique",
            "Authorization",
        ),
    ]

    if policy["require_registered_trace"]:
        unresolved: list[str] = []

        for record in authorizations:
            for field_name in (
                "request_trace_ref",
                "receipt_trace_ref",
            ):
                trace_ref = record[field_name]

                if trace_ref not in trace_index:
                    unresolved.append(
                        f"{record['authorization_id']}."
                        f"{field_name}={trace_ref}"
                    )

        results.append(
            failed(
                "authorization_trace_reference_exists",
                (
                    "Unresolved Trace references: "
                    + "; ".join(
                        sorted(unresolved)
                    )
                ),
            )
            if unresolved
            else passed(
                "authorization_trace_reference_exists",
                (
                    "Every Authorization Trace "
                    "reference resolves to a "
                    "supplied Trace."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "authorization_trace_reference_exists",
                (
                    "Registered Trace resolution "
                    "check is disabled by policy."
                ),
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

        results.append(
            failed(
                "trace_binding_preserved",
                (
                    "Trace substitutions detected: "
                    + "; ".join(substitutions)
                ),
            )
            if substitutions
            else passed(
                "trace_binding_preserved",
                (
                    "Every Authorization receipt "
                    "preserves the request Trace "
                    "binding."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "trace_binding_preserved",
                (
                    "Trace binding preservation "
                    "check is disabled by policy."
                ),
            )
        )

    return results


def check_authorization_execution(
    case: dict[str, Any],
) -> list[dict[str, str]]:
    authorizations = case[
        "authorization_records"
    ]
    executions = case[
        "execution_records"
    ]
    policy = case["policy"]

    authorization_index = {
        record["authorization_id"]: record
        for record in authorizations
    }

    results = [
        unique_check(
            policy[
                "require_unique_authorization_ids"
            ],
            [
                record["authorization_id"]
                for record in authorizations
            ],
            "authorization_id_unique",
            "Authorization",
        ),
        unique_check(
            policy[
                "require_unique_execution_ids"
            ],
            [
                record["execution_id"]
                for record in executions
            ],
            "execution_id_unique",
            "Execution",
        ),
    ]

    if policy[
        "require_registered_authorization"
    ]:
        unresolved = [
            (
                f"{execution['execution_id']}"
                f"->{execution['authorization_ref']}"
            )
            for execution in executions
            if (
                execution["authorization_ref"]
                not in authorization_index
            )
        ]

        results.append(
            failed(
                "execution_authorization_reference_exists",
                (
                    "Unresolved Authorization "
                    "references: "
                    + "; ".join(unresolved)
                ),
            )
            if unresolved
            else passed(
                "execution_authorization_reference_exists",
                (
                    "Every Execution authorization "
                    "reference resolves."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "execution_authorization_reference_exists",
                (
                    "Authorization resolution check "
                    "is disabled by policy."
                ),
            )
        )

    comparable = [
        (
            execution,
            authorization_index.get(
                execution[
                    "authorization_ref"
                ]
            ),
        )
        for execution in executions
    ]

    def scope_check(
        enabled: bool,
        check_id: str,
        disabled_message: str,
        violation_builder: Callable[
            [
                dict[str, Any],
                dict[str, Any],
            ],
            str | None,
        ],
        success_message: str,
        failure_prefix: str,
    ) -> None:
        if not enabled:
            results.append(
                skipped(
                    check_id,
                    disabled_message,
                )
            )
            return

        violations = [
            violation
            for execution, authorization
            in comparable
            if authorization is not None
            for violation in [
                violation_builder(
                    execution,
                    authorization,
                )
            ]
            if violation is not None
        ]

        results.append(
            failed(
                check_id,
                (
                    failure_prefix
                    + "; ".join(violations)
                ),
            )
            if violations
            else passed(
                check_id,
                success_message,
            )
        )

    scope_check(
        policy[
            "require_authorized_decision"
        ],
        "execution_authorization_decision_allows",
        (
            "Authorization decision check "
            "is disabled by policy."
        ),
        lambda execution, authorization: (
            f"{execution['execution_id']}"
            f"({authorization['decision']})"
            if (
                authorization["decision"]
                != "authorized"
            )
            else None
        ),
        (
            "Every Execution references "
            "an authorized decision."
        ),
        (
            "Execution used non-authorized "
            "decisions: "
        ),
    )

    scope_check(
        policy["require_action_match"],
        "execution_action_matches_scope",
        (
            "Action matching check "
            "is disabled by policy."
        ),
        lambda execution, authorization: (
            f"{execution['execution_id']}"
            f"(authorized="
            f"{authorization['authorized_scope']['action']}, "
            f"executed="
            f"{execution['observed_action']['action']})"
            if (
                execution[
                    "observed_action"
                ]["action"]
                != authorization[
                    "authorized_scope"
                ]["action"]
            )
            else None
        ),
        (
            "Every executed action matches "
            "its authorized action."
        ),
        "Action scope violations: ",
    )

    for (
        policy_key,
        check_id,
        observed_key,
        allowed_key,
        label,
    ) in (
        (
            "require_actor_scope",
            "execution_actor_within_scope",
            "actor",
            "actors",
            "execution actor",
        ),
        (
            "require_tool_scope",
            "execution_tool_within_scope",
            "tool",
            "tools",
            "execution tool",
        ),
        (
            "require_resource_scope",
            "execution_resource_within_scope",
            "resource",
            "resources",
            "execution resource",
        ),
    ):
        scope_check(
            policy[policy_key],
            check_id,
            (
                f"{label.title()} scope check "
                "is disabled by policy."
            ),
            lambda execution,
            authorization,
            observed_key=observed_key,
            allowed_key=allowed_key: (
                f"{execution['execution_id']}"
                f"({execution['observed_action'][observed_key]})"
                if (
                    execution[
                        "observed_action"
                    ][observed_key]
                    not in authorization[
                        "authorized_scope"
                    ][allowed_key]
                )
                else None
            ),
            (
                f"Every {label} is within "
                "the authorized set."
            ),
            f"Unauthorized {label}s: ",
        )

    scope_check(
        policy["require_cost_scope"],
        "execution_cost_within_scope",
        (
            "Cost scope check "
            "is disabled by policy."
        ),
        lambda execution, authorization: (
            f"{execution['execution_id']}"
            f"(observed="
            f"{execution['observed_action']['cost']['amount']} "
            f"{execution['observed_action']['cost']['currency']}, "
            f"limit="
            f"{authorization['authorized_scope']['cost_limit']['amount']} "
            f"{authorization['authorized_scope']['cost_limit']['currency']})"
            if (
                execution[
                    "observed_action"
                ]["cost"]["currency"]
                != authorization[
                    "authorized_scope"
                ]["cost_limit"]["currency"]
                or execution[
                    "observed_action"
                ]["cost"]["amount"]
                > authorization[
                    "authorized_scope"
                ]["cost_limit"]["amount"]
            )
            else None
        ),
        (
            "Every execution cost remains "
            "within its authorized limit."
        ),
        "Execution cost violations: ",
    )

    def time_violation(
        execution: dict[str, Any],
        authorization: dict[str, Any],
    ) -> str | None:
        scope = authorization[
            "authorized_scope"
        ]

        valid_from = parse_datetime(
            scope["valid_from"]
        )

        valid_until = parse_datetime(
            scope["valid_until"]
        )

        started_at = parse_datetime(
            execution["started_at"]
        )

        completed_at = parse_datetime(
            execution["completed_at"]
        )

        reasons: list[str] = []

        if valid_from > valid_until:
            reasons.append(
                "invalid-authorization-window"
            )

        if started_at > completed_at:
            reasons.append(
                "invalid-execution-chronology"
            )

        if started_at < valid_from:
            reasons.append(
                "started-before-validity"
            )

        if completed_at > valid_until:
            reasons.append(
                "completed-after-expiry"
            )

        return (
            f"{execution['execution_id']}"
            f"({','.join(reasons)})"
            if reasons
            else None
        )

    scope_check(
        policy["require_time_scope"],
        "execution_time_within_scope",
        (
            "Time scope check "
            "is disabled by policy."
        ),
        time_violation,
        (
            "Every execution begins and "
            "completes within its authorized "
            "time window."
        ),
        "Execution time violations: ",
    )

    return results


def check_execution_audit_royalty(
    case: dict[str, Any],
) -> list[dict[str, str]]:
    executions = case[
        "execution_records"
    ]
    audits = case["audit_records"]
    royalties = case["royalty_records"]
    policy = case["policy"]

    execution_index = {
        record["execution_id"]: record
        for record in executions
    }

    audit_index = {
        record["audit_id"]: record
        for record in audits
    }

    results = [
        unique_check(
            policy[
                "require_unique_execution_ids"
            ],
            [
                record["execution_id"]
                for record in executions
            ],
            "execution_id_unique",
            "Execution",
        ),
        unique_check(
            policy[
                "require_unique_audit_ids"
            ],
            [
                record["audit_id"]
                for record in audits
            ],
            "audit_id_unique",
            "Audit",
        ),
        unique_check(
            policy[
                "require_unique_royalty_ids"
            ],
            [
                record["royalty_id"]
                for record in royalties
            ],
            "royalty_id_unique",
            "Royalty",
        ),
    ]

    if policy[
        "require_registered_execution_for_audit"
    ]:
        unresolved: list[str] = []

        for audit in audits:
            for field_name in (
                "request_execution_ref",
                "report_execution_ref",
            ):
                execution_ref = audit[
                    field_name
                ]

                if (
                    execution_ref
                    not in execution_index
                ):
                    unresolved.append(
                        f"{audit['audit_id']}."
                        f"{field_name}="
                        f"{execution_ref}"
                    )

        results.append(
            failed(
                "audit_execution_reference_exists",
                (
                    "Unresolved Audit Execution "
                    "references: "
                    + "; ".join(
                        sorted(unresolved)
                    )
                ),
            )
            if unresolved
            else passed(
                "audit_execution_reference_exists",
                (
                    "Every Audit Execution reference "
                    "resolves to a supplied Execution."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "audit_execution_reference_exists",
                (
                    "Audit Execution resolution "
                    "check is disabled by policy."
                ),
            )
        )

    if policy[
        "require_preserved_execution_binding"
    ]:
        substitutions = [
            (
                f"{audit['audit_id']}"
                f"(request="
                f"{audit['request_execution_ref']}, "
                f"report="
                f"{audit['report_execution_ref']})"
            )
            for audit in audits
            if (
                audit[
                    "request_execution_ref"
                ]
                != audit[
                    "report_execution_ref"
                ]
            )
        ]

        results.append(
            failed(
                "audit_execution_binding_preserved",
                (
                    "Audit Execution substitutions "
                    "detected: "
                    + "; ".join(substitutions)
                ),
            )
            if substitutions
            else passed(
                "audit_execution_binding_preserved",
                (
                    "Every Audit report preserves "
                    "the submitted Execution binding."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "audit_execution_binding_preserved",
                (
                    "Audit Execution binding check "
                    "is disabled by policy."
                ),
            )
        )

    if policy[
        "require_audit_after_execution"
    ]:
        violations: list[str] = []

        for audit in audits:
            execution = execution_index.get(
                audit[
                    "report_execution_ref"
                ]
            )

            if execution is None:
                continue

            execution_completed = (
                parse_datetime(
                    execution["completed_at"]
                )
            )

            audit_started = parse_datetime(
                audit["started_at"]
            )

            audit_completed = parse_datetime(
                audit["completed_at"]
            )

            reasons: list[str] = []

            if (
                audit_started
                < execution_completed
            ):
                reasons.append(
                    "audit-started-before-"
                    "execution-completed"
                )

            if audit_started > audit_completed:
                reasons.append(
                    "invalid-audit-chronology"
                )

            if reasons:
                violations.append(
                    f"{audit['audit_id']}"
                    f"({','.join(reasons)})"
                )

        results.append(
            failed(
                "audit_occurs_after_execution",
                (
                    "Audit chronology violations: "
                    + "; ".join(violations)
                ),
            )
            if violations
            else passed(
                "audit_occurs_after_execution",
                (
                    "Every Audit begins after "
                    "Execution completion and has "
                    "valid chronology."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "audit_occurs_after_execution",
                (
                    "Audit chronology check "
                    "is disabled by policy."
                ),
            )
        )

    if policy[
        "require_registered_execution_for_royalty"
    ]:
        unresolved = [
            (
                f"{royalty['royalty_id']}"
                f"->{royalty['execution_ref']}"
            )
            for royalty in royalties
            if (
                royalty["execution_ref"]
                not in execution_index
            )
        ]

        results.append(
            failed(
                "royalty_execution_reference_exists",
                (
                    "Unresolved Royalty Execution "
                    "references: "
                    + "; ".join(unresolved)
                ),
            )
            if unresolved
            else passed(
                "royalty_execution_reference_exists",
                (
                    "Every Royalty Execution "
                    "reference resolves."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "royalty_execution_reference_exists",
                (
                    "Royalty Execution resolution "
                    "check is disabled by policy."
                ),
            )
        )

    if policy[
        "require_registered_audit_for_royalty"
    ]:
        unresolved = [
            (
                f"{royalty['royalty_id']}"
                f"->{royalty['audit_ref']}"
            )
            for royalty in royalties
            if (
                royalty["audit_ref"]
                not in audit_index
            )
        ]

        results.append(
            failed(
                "royalty_audit_reference_exists",
                (
                    "Unresolved Royalty Audit "
                    "references: "
                    + "; ".join(unresolved)
                ),
            )
            if unresolved
            else passed(
                "royalty_audit_reference_exists",
                (
                    "Every Royalty Audit reference "
                    "resolves."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "royalty_audit_reference_exists",
                (
                    "Royalty Audit resolution "
                    "check is disabled by policy."
                ),
            )
        )

    if policy[
        "require_royalty_execution_match"
    ]:
        mismatches: list[str] = []

        for royalty in royalties:
            audit = audit_index.get(
                royalty["audit_ref"]
            )

            if audit is None:
                continue

            if (
                royalty["execution_ref"]
                != audit[
                    "report_execution_ref"
                ]
            ):
                mismatches.append(
                    f"{royalty['royalty_id']}"
                    f"(royalty="
                    f"{royalty['execution_ref']}, "
                    f"audit="
                    f"{audit['report_execution_ref']})"
                )

        results.append(
            failed(
                "royalty_execution_matches_audit",
                (
                    "Royalty and Audit Execution "
                    "mismatches: "
                    + "; ".join(mismatches)
                ),
            )
            if mismatches
            else passed(
                "royalty_execution_matches_audit",
                (
                    "Every Royalty record references "
                    "the Execution evaluated by "
                    "its Audit."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "royalty_execution_matches_audit",
                (
                    "Royalty-to-Audit Execution "
                    "matching is disabled by policy."
                ),
            )
        )

    if policy[
        "require_passed_audit_before_royalty"
    ]:
        violations: list[str] = []

        for royalty in royalties:
            audit = audit_index.get(
                royalty["audit_ref"]
            )

            if (
                audit is None
                or royalty[
                    "royalty_status"
                ] == "blocked"
            ):
                continue

            if audit["verdict"] != "passed":
                violations.append(
                    f"{royalty['royalty_id']}"
                    f"({audit['verdict']})"
                )

        results.append(
            failed(
                "audit_verdict_allows_royalty",
                (
                    "Royalty proceeded without "
                    "a passed Audit: "
                    + "; ".join(violations)
                ),
            )
            if violations
            else passed(
                "audit_verdict_allows_royalty",
                (
                    "Every non-blocked Royalty "
                    "record is backed by a "
                    "passed Audit."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "audit_verdict_allows_royalty",
                (
                    "Passed-Audit gate check "
                    "is disabled by policy."
                ),
            )
        )

    if policy[
        "require_royalty_after_audit"
    ]:
        violations: list[str] = []

        for royalty in royalties:
            audit = audit_index.get(
                royalty["audit_ref"]
            )

            if (
                audit is None
                or royalty[
                    "royalty_status"
                ] == "blocked"
            ):
                continue

            if (
                parse_datetime(
                    royalty["initiated_at"]
                )
                < parse_datetime(
                    audit["completed_at"]
                )
            ):
                violations.append(
                    f"{royalty['royalty_id']}"
                    f"(initiated="
                    f"{royalty['initiated_at']}, "
                    f"audit_completed="
                    f"{audit['completed_at']})"
                )

        results.append(
            failed(
                "royalty_occurs_after_audit",
                (
                    "Royalty chronology violations: "
                    + "; ".join(violations)
                ),
            )
            if violations
            else passed(
                "royalty_occurs_after_audit",
                (
                    "Every non-blocked Royalty "
                    "record begins after "
                    "Audit completion."
                ),
            )
        )
    else:
        results.append(
            skipped(
                "royalty_occurs_after_audit",
                (
                    "Royalty chronology check "
                    "is disabled by policy."
                ),
            )
        )

    return results


CASE_CONFIGS: dict[
    str,
    dict[str, Any],
] = {
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
        "semantic_checker": (
            check_origin_trace
        ),
    },
    "trace_authorization_binding": {
        "schema_path": (
            SCHEMA_DIR
            / "trace-authorization-conformance-"
            "case.schema.json"
        ),
        "suite_id": (
            "kazene:conformance-suite:"
            "core-trace-authorization"
        ),
        "semantic_checker": (
            check_trace_authorization
        ),
    },
    "authorization_execution_scope": {
        "schema_path": (
            SCHEMA_DIR
            / "authorization-execution-"
            "conformance-case.schema.json"
        ),
        "suite_id": (
            "kazene:conformance-suite:"
            "core-authorization-execution"
        ),
        "semantic_checker": (
            check_authorization_execution
        ),
    },
    "execution_audit_royalty_gate": {
        "schema_path": (
            SCHEMA_DIR
            / "execution-audit-royalty-"
            "conformance-case.schema.json"
        ),
        "suite_id": (
            "kazene:conformance-suite:"
            "core-execution-audit-royalty"
        ),
        "semantic_checker": (
            check_execution_audit_royalty
        ),
    },
}


SUPPORTED_STAGE_PAIRS = {
    ("origin", "trace"),
    ("trace", "authorization"),
    ("authorization", "execution"),
    ("execution", "royalty"),
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
            manifest[
                "stage_pair"
            ]["source_stage"],
            manifest[
                "stage_pair"
            ]["target_stage"],
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

        if (
            pair == (
                "execution",
                "royalty",
            )
            and manifest.get(
                "gate_stage"
            ) != "audit"
        ):
            print(
                "[manifest-semantic-error] "
                "execution -> royalty suite "
                "requires gate_stage: audit"
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
    print("version : 0.4.0")
    print(
        "scope   : Origin -> Trace "
        "-> Authorization -> Execution "
        "-> Audit -> Royalty"
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
        EXAMPLES_DIR.glob(
            "pass/*.yaml"
        )
    ) + sorted(
        EXAMPLES_DIR.glob(
            "fail/*.yaml"
        )
    )

    if not example_paths:
        print("[fatal] no examples found")
        return 1

    results: list[
        dict[str, Any]
    ] = []

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

        case_type = case.get(
            "case_type"
        )

        if case_type not in CASE_CONFIGS:
            print(
                "[schema-selection-error] "
                "unsupported case_type: "
                f"{case_type!r}"
            )

            fatal_errors += 1
            print()
            continue

        config = CASE_CONFIGS[
            case_type
        ]

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

        case_result = evaluate_case(
            path,
            case,
            config,
        )

        results.append(
            case_result
        )

        for check in case_result[
            "check_results"
        ]:
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
            case_result[
                "expected_outcome"
            ]
            != folder_expected
        ):
            print(
                "[expectation-error] "
                "example folder and "
                "expected_outcome disagree: "
                f"folder={folder_expected}, "
                f"declared="
                f"{case_result['expected_outcome']}"
            )

            fatal_errors += 1

        if case_result[
            "matched_expectation"
        ]:
            print(
                "[expectation-ok] "
                f"{case_result['actual_outcome']}"
            )
        else:
            print(
                "[expectation-mismatch] "
                f"expected="
                f"{case_result['expected_outcome']}, "
                f"actual="
                f"{case_result['actual_outcome']}"
            )

            fatal_errors += 1

        print()

    generated_at = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )

    report = {
        "schema_version": "0.4.0",
        "suite_id": (
            "kazene:conformance-suite:core"
        ),
        "suite_version": "0.4.0",
        "generated_at": generated_at,
        "summary": {
            "total_cases": len(results),
            "conformant_cases": sum(
                item["actual_outcome"]
                == "conformant"
                for item in results
            ),
            "nonconformant_cases": sum(
                item["actual_outcome"]
                == "nonconformant"
                for item in results
            ),
            "matched_expectations": sum(
                item[
                    "matched_expectation"
                ]
                for item in results
            ),
            "mismatched_expectations": sum(
                not item[
                    "matched_expectation"
                ]
                for item in results
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
