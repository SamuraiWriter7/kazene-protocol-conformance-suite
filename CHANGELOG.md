# Changelog

All notable changes to the Kazene Protocol Conformance Suite are documented in this file.

The project follows semantic versioning during its protocol-development lifecycle.

---

## [0.5.0] - 2026-07-24

### Added

* Royalty–Dispute–Settlement conformance case schema.
* Core Royalty–Dispute–Settlement suite manifest.
* Dispute record model.
* Holdback record model.
* Settlement record model.
* Exact decimal money comparison utilities.
* Royalty ID uniqueness validation.
* Dispute ID uniqueness validation.
* Holdback ID uniqueness validation.
* Settlement ID uniqueness validation.
* Dispute-to-Royalty reference validation.
* Holdback-to-Dispute reference validation.
* Holdback-to-Royalty binding validation.
* Settlement-to-Royalty reference validation.
* Complete Settlement Dispute disclosure validation.
* Unresolved Dispute blocking validation.
* Required Holdback validation.
* Settlement-after-resolution chronology validation.
* Settlement amount conservation validation.
* Royalty status eligibility validation.
* Two conformant Settlement examples.
* Five nonconformant Settlement examples.

### New Conformance Boundary

Version 0.5 adds:

```text
Royalty
  ↓
Dispute / Holdback
  ↓
Settlement
```

The required gate is:

```yaml
gate_stage: dispute_resolution
```

### New Core Invariants

```text
A final Settlement MUST NOT exist while a related
Dispute remains open or under review.
```

```text
Every Holdback-required Dispute MUST have a sufficient
and correctly bound Holdback.
```

```text
Gross Amount MUST equal Paid Amount plus Reserved
Holdback Amount.
```

```text
A final Settlement MUST reference an allocated Royalty.
```

### Added Pass Fixtures

* `settlement-without-dispute.example.yaml`
* `settlement-after-resolved-dispute.example.yaml`

### Added Fail Fixtures

* `unresolved-dispute-settlement.example.yaml`
* `undisclosed-dispute.example.yaml`
* `missing-required-holdback.example.yaml`
* `settlement-amount-mismatch.example.yaml`
* `settlement-before-dispute-resolution.example.yaml`

### Validator Improvements

* Added `Decimal`-based amount handling.
* Added exact money comparison.
* Added Holdback aggregation by Dispute.
* Added Dispute aggregation by Royalty.
* Added Settlement disclosure comparison.
* Added unknown and foreign Holdback reference detection.
* Added duplicate conformance case ID detection.
* Added complete Origin-to-Settlement result generation.
* Updated generated report version to `0.5.0`.

### Result

Version 0.5 completes the first executable end-to-end path:

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

---

## [0.4.0] - 2026-07-24

### Added

* Execution–Audit–Royalty conformance case schema.
* Core Execution–Audit–Royalty suite manifest.
* Audit record model.
* Royalty gate record model.
* Execution ID uniqueness validation for Audit fixtures.
* Audit ID uniqueness validation.
* Royalty ID uniqueness validation.
* Audit-to-Execution reference validation.
* Audit Execution binding preservation validation.
* Audit-after-Execution chronology validation.
* Royalty-to-Execution reference validation.
* Royalty-to-Audit reference validation.
* Royalty and Audit Execution matching validation.
* Passed-Audit gate validation.
* Royalty-after-Audit chronology validation.
* One conformant Execution–Audit–Royalty example.
* Six nonconformant Audit-gate examples.

### New Conformance Boundary

Version 0.4 adds:

```text
Execution
  ↓
Audit
  ↓
Royalty
```

The required gate is:

```yaml
gate_stage: audit
```

### New Core Invariants

```text
The Execution submitted for Audit MUST be the same
Execution recorded by the Audit report.
```

```text
Audit MUST begin after Execution completion.
```

```text
Royalty MUST reference the same Execution evaluated
by its Audit.
```

```text
Non-blocked Royalty MUST be backed by an Audit verdict
of passed.
```

```text
Royalty MUST begin after Audit completion.
```

### Added Pass Fixture

* `execution-audit-royalty-gated.example.yaml`

### Added Fail Fixtures

* `audit-before-execution-completion.example.yaml`
* `audit-execution-substitution.example.yaml`
* `missing-audit-reference.example.yaml`
* `royalty-after-failed-audit.example.yaml`
* `royalty-before-audit-completion.example.yaml`
* `royalty-execution-mismatch.example.yaml`

### Design Notes

* `royalty_status: blocked` is permitted after a failed or pending Audit.
* A blocked Royalty record is treated as evidence that processing stopped.
* `eligible` and `allocated` Royalty states require a passed Audit.
* Audit presence alone is insufficient; the Audit must concern the correct Execution.

---

## [0.3.0] - 2026-07-24

### Added

* Authorization–Execution conformance case schema.
* Core Authorization–Execution suite manifest.
* Authorized scope model.
* Observed Execution action model.
* Money and cost-limit model.
* Authorization ID uniqueness validation.
* Execution ID uniqueness validation.
* Execution-to-Authorization reference validation.
* Authorization decision validation.
* Action matching validation.
* Actor scope validation.
* Tool scope validation.
* Resource scope validation.
* Cost-limit validation.
* Authorization validity-window validation.
* One conformant Authorization–Execution example.
* Six nonconformant scope examples.

### New Conformance Boundary

Version 0.3 adds:

```text
Authorization
  ↓
Execution
```

### New Scope Dimensions

```text
Action
Actor
Tool
Resource
Cost
Time Window
```

### New Core Invariants

```text
Execution MUST reference an existing Authorization.
```

```text
Execution MUST NOT proceed under a denied or
human-review-required decision.
```

```text
Executed action MUST equal the authorized action.
```

```text
Execution actor, tool, and resource MUST belong to
their authorized sets.
```

```text
Execution cost MUST remain within the authorized
currency and amount limit.
```

```text
Execution MUST begin and complete within the
Authorization validity window.
```

### Added Pass Fixture

* `authorization-execution-matched.example.yaml`

### Added Fail Fixtures

* `execution-with-denied-authorization.example.yaml`
* `unauthorized-action.example.yaml`
* `actor-tool-scope-exceeded.example.yaml`
* `cost-resource-scope-exceeded.example.yaml`
* `execution-after-expiry.example.yaml`
* `duplicate-execution-id.example.yaml`

### Validator Improvements

* Added reusable scope-check execution.
* Added RFC 3339 datetime parsing.
* Added invalid Authorization-window detection.
* Added invalid Execution chronology detection.
* Added cost currency matching.
* Added multi-dimensional diagnostic messages.

### Design Notes

Version 0.3 changes the meaning of Authorization conformance.

Before v0.3, the suite verified that Authorization was connected to a Trace.

From v0.3 onward, the suite also verifies that Execution obeyed what was actually authorized.

---

## [0.2.0] - 2026-07-24

### Added

* Trace–Authorization conformance case schema.
* Core Trace–Authorization suite manifest.
* Authorization receipt fixture model.
* Authorization ID uniqueness validation.
* Trace reference resolution validation.
* Trace binding preservation validation.
* Trace substitution detection.
* One conformant Trace–Authorization example.
* Three nonconformant Trace–Authorization examples.
* Multi-case schema selection through `case_type`.
* Multiple suite manifest loading.
* Unified conformance result report.
* Manifest semantic validation.
* Required suite manifest detection.

### New Conformance Boundary

Version 0.2 adds:

```text
Trace
  ↓
Authorization
```

### New Core Invariants

```text
Every Trace referenced by Authorization MUST exist.
```

```text
The Trace attached to the Authorization request MUST
be preserved in the Authorization receipt.
```

```text
request_trace_ref MUST equal receipt_trace_ref.
```

### Added Pass Fixture

* `trace-authorization-linked.example.yaml`

### Added Fail Fixtures

* `missing-trace-reference.example.yaml`
* `trace-substitution.example.yaml`
* `duplicate-authorization-id.example.yaml`

### Validator Improvements

* Added `CASE_CONFIGS`.
* Added semantic checker dispatch by `case_type`.
* Added multiple manifest support.
* Added stage-pair validation.
* Added duplicate manifest suite ID detection.
* Added duplicate check ID detection.
* Added integrated v0.1 and v0.2 reporting.

### Design Notes

Version 0.2 distinguishes two types of failure:

```text
Missing Trace
  = the Authorization references a Trace that does not exist.

Trace substitution
  = both Traces exist, but the receipt refers to a
    different Trace from the request.
```

This prevents an Authorization receipt from legitimizing a different request after the decision process has begun.

---

## [0.1.0] - 2026-07-24

### Added

* Initial Kazene Protocol Conformance Suite repository structure.
* Origin–Trace conformance case schema.
* Conformance suite manifest schema.
* Machine-readable conformance result schema.
* Core Origin–Trace suite manifest.
* Origin ID uniqueness validation.
* Trace ID uniqueness validation.
* Origin reference resolution validation.
* Active Origin status validation.
* One conformant Origin–Trace example.
* Three nonconformant Origin–Trace examples.
* Python semantic conformance validator.
* Generated JSON conformance report.
* GitHub Actions validation workflow.
* Workflow artifact upload.
* Initial README.
* Initial CHANGELOG.
* MIT License.
* Python dependency definition.

### Initial Conformance Boundary

Version 0.1 establishes:

```text
Origin
  ↓
Trace
```

### Initial Core Invariants

```text
Every Origin ID referenced by Trace MUST resolve to
a registered Origin.
```

```text
Referenced Origins MUST have status active when the
strict active-Origin policy is enabled.
```

```text
Origin and Trace canonical identifiers MUST be unique
when uniqueness enforcement is enabled.
```

### Added Pass Fixture

* `origin-trace-linked.example.yaml`

### Added Fail Fixtures

* `missing-origin-reference.example.yaml`
* `revoked-origin-reference.example.yaml`
* `duplicate-trace-id.example.yaml`

### Initial Validator Features

* YAML fixture loading.
* JSON Schema validation.
* Semantic conformance checks.
* Pass and fail directory expectation checks.
* Machine-readable result generation.
* Summary statistics.
* Nonzero exit status on validation failure.

### Design Notes

Version 0.1 establishes the distinction between:

```text
Schema validity
```

and:

```text
Cross-protocol conformance
```

A fail fixture is expected to remain structurally valid while representing a nonconformant protocol relationship.

---

## Current Conformance Coverage

As of v0.5.0, the suite covers:

```text
Origin ID exists in Trace
Trace ID is preserved through Authorization
Authorization scope matches Execution
Audit gates Royalty
Dispute and Holdback state gates Settlement
```

## Future Directions

Possible post-v0.5 work includes:

* external repository fixture loading;
* canonical identifier registry integration;
* protocol compatibility registry enforcement;
* protocol adapter execution;
* signed conformance reports;
* fixture and validator digest binding;
* reference implementation adapters;
* configurable conformance profiles;
* production implementation certification;
* end-to-end signed conformance certificates.
