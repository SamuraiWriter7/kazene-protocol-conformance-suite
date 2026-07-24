# Kazene Protocol Conformance Suite

Cross-protocol conformance tests for validating end-to-end integrity across the Kazene Civilization OS.

## Overview

A protocol record can be structurally valid while the complete protocol chain remains invalid.

For example:

* an Origin record may pass its own schema validator;
* a Trace record may also pass its own validator;
* but the Trace may reference an Origin that does not exist;
* an Authorization may reference a substituted Trace;
* an Execution may exceed its authorized scope;
* Royalty processing may begin before Audit completion;
* Settlement may complete while a Dispute remains unresolved.

Individual protocol validators verify records in isolation.

The Kazene Protocol Conformance Suite verifies the integrity of the connections between them.

```text
Origin
  ↓
Trace
  ↓
Authorization
  ↓
Execution
  ↓
Audit
  ↓
Royalty
  ↓
Dispute / Holdback
  ↓
Settlement
```

The suite acts as an executable verification layer for the Kazene Civilization OS.

## Current Version

```text
v0.5.0 — Dispute, Holdback, and Settlement Integrity
```

Version 0.5 completes the first end-to-end conformance path from Origin registration to final Settlement.

## Core Principle

Local validity does not guarantee global integrity.

```text
Schema-valid records
        ≠
Conformant protocol chain
```

This repository validates both:

1. the structure of each conformance fixture;
2. the semantic integrity of the cross-protocol relationships represented by that fixture.

## What the Suite Verifies

The current suite covers five major boundaries.

### 1. Origin → Trace

The suite verifies that:

* Origin IDs are unique;
* Trace IDs are unique;
* every Origin referenced by Trace exists;
* referenced Origins remain active when required.

```text
Trace.origin_refs ⊆ RegisteredOriginIDs
```

### 2. Trace → Authorization

The suite verifies that:

* Authorization IDs are unique;
* every Trace referenced by Authorization exists;
* the Trace attached to the request is preserved in the Authorization receipt;
* a different Trace cannot be substituted during authorization.

```text
request_trace_ref = receipt_trace_ref
```

### 3. Authorization → Execution

The suite verifies that Execution remains within the complete authorized scope.

The current scope dimensions are:

* action;
* actor;
* tool;
* resource;
* cost;
* validity period.

```text
ExecutedAction ⊆ AuthorizedScope
```

An Authorization receipt is not treated as a general-purpose permission token.

It authorizes only the action and boundaries explicitly recorded in its scope.

### 4. Execution → Audit → Royalty

The suite verifies that:

* Audit references a registered Execution;
* the Execution submitted for Audit is preserved in the Audit report;
* Audit begins after Execution completion;
* Royalty references a registered Audit;
* Royalty concerns the same Execution evaluated by that Audit;
* the Audit verdict is `passed`;
* Royalty begins only after Audit completion.

```text
Execution completed
  ↓
Audit completed
  ↓
Audit verdict = passed
  ↓
Royalty may proceed
```

Audit is therefore a required gate rather than optional metadata.

### 5. Royalty → Dispute / Holdback → Settlement

The suite verifies that:

* Disputes reference registered Royalty records;
* Holdbacks reference registered Disputes and the correct Royalty;
* Settlement discloses all related Disputes;
* unresolved Disputes block final Settlement;
* required Holdbacks exist and are sufficient;
* Settlement begins after Dispute resolution;
* gross, paid, and withheld values remain conserved;
* only allocated Royalty may reach final Settlement.

```text
Gross Amount = Paid Amount + Reserved Holdback Amount
```

A final Settlement must not retain an unresolved dispute or an active holdback.

## Primary Invariants

The complete v0.5 conformance path enforces the following high-level invariants.

```text
1. Every Trace Origin reference resolves.

2. Every Authorization preserves its request Trace.

3. Every Execution remains within Authorization scope.

4. Every non-blocked Royalty is backed by a passed Audit.

5. Every final Settlement is free from unresolved Disputes.

6. Settlement value is conserved.
```

## Repository Structure

```text
kazene-protocol-conformance-suite/
├── .github/
│   └── workflows/
│       └── validate.yml
├── examples/
│   ├── pass/
│   └── fail/
├── manifests/
│   ├── core-origin-trace-suite.yaml
│   ├── core-trace-authorization-suite.yaml
│   ├── core-authorization-execution-suite.yaml
│   ├── core-execution-audit-royalty-suite.yaml
│   └── core-royalty-dispute-settlement-suite.yaml
├── schemas/
│   ├── origin-trace-conformance-case.schema.json
│   ├── trace-authorization-conformance-case.schema.json
│   ├── authorization-execution-conformance-case.schema.json
│   ├── execution-audit-royalty-conformance-case.schema.json
│   ├── royalty-dispute-settlement-conformance-case.schema.json
│   ├── conformance-suite-manifest.schema.json
│   └── conformance-result.schema.json
├── scripts/
│   └── validate_examples.py
├── .gitignore
├── CHANGELOG.md
├── LICENSE
├── README.md
└── requirements.txt
```

## Conformance Case Types

The validator selects the appropriate schema and semantic checker through the `case_type` field.

### `origin_trace_linkage`

Validates:

```text
Origin → Trace
```

Schema version:

```text
0.1.0
```

### `trace_authorization_binding`

Validates:

```text
Trace → Authorization
```

Schema version:

```text
0.2.0
```

### `authorization_execution_scope`

Validates:

```text
Authorization → Execution
```

Schema version:

```text
0.3.0
```

### `execution_audit_royalty_gate`

Validates:

```text
Execution → Audit → Royalty
```

Schema version:

```text
0.4.0
```

### `royalty_dispute_settlement_integrity`

Validates:

```text
Royalty → Dispute / Holdback → Settlement
```

Schema version:

```text
0.5.0
```

## Pass and Fail Fixtures

Fixtures are divided into two directories.

```text
examples/pass/
examples/fail/
```

A pass fixture must declare:

```yaml
expected_outcome: conformant
```

A fail fixture must declare:

```yaml
expected_outcome: nonconformant
```

Fail fixtures are expected to remain structurally valid.

They represent protocol chains that pass JSON Schema validation but fail one or more semantic conformance checks.

```text
Schema failure
  = the fixture itself is malformed.

Conformance failure
  = the fixture is valid,
    but the represented protocol chain is invalid.
```

The validator also verifies that the declared outcome matches the fixture directory.

## Example: Origin–Trace Conformance

```yaml
schema_version: "0.1.0"
case_id: case:origin-trace:linked-basic
case_type: origin_trace_linkage
expected_outcome: conformant

origin_records:
  - origin_id: kazene:origin:human-question-001
    origin_type: human_input
    status: active
    source_ref: input://conversation/question-001
    registered_at: "2026-07-24T00:00:00Z"

trace_records:
  - trace_id: kazene:trace:derivation-001
    event_type: derivation
    origin_refs:
      - kazene:origin:human-question-001
    recorded_at: "2026-07-24T00:00:01Z"

policy:
  require_unique_origin_ids: true
  require_unique_trace_ids: true
  require_registered_origin: true
  require_active_origin: true
```

## Example: Authorization–Execution Conformance

```yaml
schema_version: "0.3.0"
case_id: case:authorization-execution:matched-basic
case_type: authorization_execution_scope
expected_outcome: conformant

authorization_records:
  - authorization_id: kazene:authorization:transfer-001
    decision: authorized
    trace_ref: kazene:trace:transfer-request-001
    decided_at: "2026-07-24T02:00:00Z"

    authorized_scope:
      action: action://payment/transfer

      actors:
        - agent://treasury/worker-001

      tools:
        - tool://banking/transfer-api

      resources:
        - account://operating/001

      cost_limit:
        amount: 2.50
        currency: USD

      valid_from: "2026-07-24T02:00:00Z"
      valid_until: "2026-07-24T02:05:00Z"

execution_records:
  - execution_id: kazene:execution:transfer-001
    authorization_ref: kazene:authorization:transfer-001
    execution_status: succeeded
    started_at: "2026-07-24T02:01:00Z"
    completed_at: "2026-07-24T02:01:05Z"

    observed_action:
      action: action://payment/transfer
      actor: agent://treasury/worker-001
      tool: tool://banking/transfer-api
      resource: account://operating/001

      cost:
        amount: 1.80
        currency: USD

policy:
  require_unique_authorization_ids: true
  require_unique_execution_ids: true
  require_registered_authorization: true
  require_authorized_decision: true
  require_action_match: true
  require_actor_scope: true
  require_tool_scope: true
  require_resource_scope: true
  require_cost_scope: true
  require_time_scope: true
```

## Suite Manifests

Each conformance boundary is described by a manifest in `manifests/`.

A manifest declares:

* suite ID;
* suite version;
* interoperability profile reference;
* source and target stages;
* required gate stage, when applicable;
* implemented checks;
* planned checks.

Example:

```yaml
schema_version: "0.5.0"
suite_id: kazene:conformance-suite:core-royalty-dispute-settlement
suite_name: Kazene Core Royalty–Dispute–Settlement Integrity Suite
suite_version: "0.5.0"
profile_ref: civilization-os-interoperability-profile@0.5.0

stage_pair:
  source_stage: royalty
  target_stage: settlement

gate_stage: dispute_resolution
```

The validator verifies that:

* `schema_version` matches `suite_version`;
* the stage pair is supported;
* required gate stages are present;
* unsupported gate declarations are rejected;
* check IDs are unique;
* suite IDs are unique.

## Supported Stage Pairs

```text
origin        → trace
trace         → authorization
authorization → execution
execution     → royalty
royalty       → settlement
```

The following mandatory gate stages apply:

```text
execution → royalty
  gate_stage: audit

royalty → settlement
  gate_stage: dispute_resolution
```

## Installation

Python 3.11 or later is recommended.

```bash
python -m pip install -r requirements.txt
```

Dependencies:

```text
jsonschema>=4.23,<5
PyYAML>=6.0,<7
```

## Running the Suite

Run the complete conformance suite with:

```bash
python scripts/validate_examples.py
```

The validator performs the following sequence:

```text
1. Load all schemas.
2. Validate all suite manifests.
3. Load every pass and fail fixture.
4. Select the case schema from case_type.
5. Run JSON Schema validation.
6. Run semantic conformance checks.
7. Compare actual and expected outcomes.
8. Validate the generated result report.
9. Write the machine-readable report.
```

## Generated Report

A successful run writes:

```text
build/conformance-results.json
```

The report contains:

* suite ID;
* suite version;
* generation timestamp;
* total case count;
* conformant and nonconformant case counts;
* matched and mismatched expectations;
* individual case results;
* check-level diagnostic messages.

Example:

```json
{
  "case_id": "case:royalty-settlement:unresolved-dispute",
  "case_type": "royalty_dispute_settlement_integrity",
  "suite_id": "kazene:conformance-suite:core-royalty-dispute-settlement",
  "expected_outcome": "nonconformant",
  "actual_outcome": "nonconformant",
  "matched_expectation": true,
  "check_results": [
    {
      "check_id": "unresolved_dispute_blocks_settlement",
      "status": "failed",
      "message": "Settlements completed with unresolved Disputes: ..."
    }
  ]
}
```

## Expected Command Output

```text
=== Kazene Protocol Conformance Suite Validation ===
version : 0.5.0
scope   : Origin -> Trace -> Authorization -> Execution -> Audit -> Royalty -> Dispute/Holdback -> Settlement

[validate-manifest] manifests/core-origin-trace-suite.yaml
[manifest-schema-ok]
[manifest-semantic-ok]

[validate] examples/pass/origin-trace-linked.example.yaml
[schema-ok]
[passed] origin_id_unique: All Origin IDs are unique.
[passed] trace_id_unique: All Trace IDs are unique.
[passed] origin_trace_reference_exists: Every Trace Origin reference resolves to a registered Origin.
[passed] origin_status_active: Every resolved Origin reference is active.
[expectation-ok] conformant

=== Summary ===
total_cases: ...
conformant_cases: ...
nonconformant_cases: ...
matched_expectations: ...
mismatched_expectations: 0
result: build/conformance-results.json

Validation passed.
```

## Continuous Integration

GitHub Actions runs the suite on:

* push;
* pull request;
* manual workflow dispatch.

The workflow:

1. checks out the repository;
2. installs Python;
3. installs dependencies;
4. runs `scripts/validate_examples.py`;
5. uploads the generated report.

The uploaded artifact is named:

```text
kazene-conformance-results
```

## Relationship to the Interoperability Profile

This repository is designed to work with:

```text
civilization-os-interoperability-profile
```

The interoperability profile defines:

* canonical identifiers;
* protocol ordering;
* compatibility rules;
* adapters;
* required stage transitions.

The conformance suite executes those relationships as testable assertions.

```text
Interoperability Profile
  = connection rules

Conformance Suite
  = executable proof that the rules were followed
```

## Relationship to Individual Validators

The suite does not replace protocol-specific validators.

```text
Individual validator
  → validates one protocol record

Conformance suite
  → validates relationships across protocols
```

Both layers are required.

A complete verification process is therefore:

```text
Record schema validation
  ↓
Protocol semantic validation
  ↓
Cross-protocol conformance validation
  ↓
End-to-end certification
```

## Security and Integrity Model

The suite is designed to detect failures such as:

* invented Origin references;
* revoked Origin reuse;
* duplicate canonical identifiers;
* Trace substitution;
* execution under denied authorization;
* action scope escalation;
* unauthorized actor or tool use;
* unauthorized resource access;
* cost-limit violations;
* expired authorization use;
* Audit substitution;
* Audit-before-completion;
* fabricated Audit references;
* Royalty after failed Audit;
* Royalty before Audit completion;
* undisclosed Disputes;
* missing Holdbacks;
* premature Settlement;
* Settlement amount mismatch.

The primary security principle is:

> No later-stage record may inherit legitimacy merely by referencing an earlier-stage identifier.

Every reference must resolve, bind to the correct record, preserve chronology, and satisfy the required gate conditions.

## Monetary Precision

Settlement calculations use Python `Decimal`.

This avoids binary floating-point errors in:

* gross amount comparison;
* paid and withheld amount addition;
* required Holdback comparison;
* reserved Holdback totals.

```text
Gross = Paid + Withheld
```

is checked as an exact decimal relationship.

## Current Limitations

Version 0.5 uses self-contained YAML fixtures.

It does not yet:

* clone or load records directly from external repositories;
* verify cryptographic signatures;
* verify remote canonical registries;
* execute protocol adapters;
* issue signed conformance certificates;
* certify production deployments.

These are possible post-v0.5 extensions.

## Post-v0.5 Direction

Potential future work includes:

### External Fixture Adapters

Load canonical examples from protocol repositories and normalize them into conformance cases.

### Registry Integration

Resolve identifiers through the canonical identifier registry rather than only through self-contained fixtures.

### Compatibility Enforcement

Consume protocol compatibility and adapter registries directly.

### Signed Reports

Sign conformance reports and bind them to:

* repository commit;
* suite version;
* fixture digest;
* validator digest;
* execution environment.

### Conformance Profiles

Support multiple strictness levels, such as:

```text
core
strict
enterprise
financial
public-sector
```

### Reference Implementations

Provide reusable adapters and verification libraries for protocol implementers.

### End-to-End Certification

Generate a machine-readable certificate proving that an implementation passed the complete Origin-to-Settlement path.

## Version History

```text
v0.1 — Origin–Trace Linkage Conformance
v0.2 — Trace–Authorization Binding Conformance
v0.3 — Authorization–Execution Scope Conformance
v0.4 — Audit Gate Before Royalty
v0.5 — Dispute, Holdback, and Settlement Integrity
```

## Design Philosophy

The suite is built on three principles.

### Provenance Before Action

An action must remain connected to its Origin and Trace.

### Authorization Before Execution

A valid request does not authorize unrestricted behavior.

### Audit Before Value Transfer

No economic value should move through Royalty or Settlement without completing the required verification and dispute-resolution gates.

The final objective is not merely to prove that individual files are valid.

It is to prove that an AI action and the value generated from it followed the complete required protocol path.

## License

MIT License.
