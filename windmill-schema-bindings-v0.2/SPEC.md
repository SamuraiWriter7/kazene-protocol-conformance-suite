# Windmill Schema Binding Adapter v0.2 (strict projection)

This is a **schema-field bridge prototype**, not an end-to-end four-repository integration proof.

## Verified source fields
- Kazene Windmill v1.0 policy example: `defaults`, `cases[].patch`, `cases[].expected`.
- Resilient AI Safety authority-envelope: `authority_envelope_id`, `trace_reference`.
- Resilient AI Safety recovery-receipt: `recovery_receipt_id`, `trace_reference`, `final_state`.
- Action Authorization Receipt: `authorization_id`, `decision`, `context_bindings.trace_reference`, `authorized_by.actor_id`.

The Windmill synthetic policy format does not carry a real trace identifier or an authorization ID. Neither is inferred or fabricated. They must be explicitly supplied in the integration event.

## Strict rules
1. All three trace references MUST match the event's explicitly provided Trace ID.
2. Receipt-level authorization ID MUST equal the explicit event authorization ID.
3. Authority-envelope ID MUST be explicitly bound to the event; it is not the same kind of ID as action authorization.
4. `decision` MUST be `authorized` or `conditionally_authorized` before active operation.
5. Recovery `final_state` MUST be `REAUTHORIZED` or `COMPLETED` for active D/R; no automatic mapping is assumed from the synthetic `approved` state.
6. Missing, mismatched, ambiguous, or non-string linkage values MUST fail closed.

## Demonstration
`python windmill-schema-bindings-v0.2/scripts/validate.py`

The fixtures are **real schema-field-shaped projections**, not full schema-valid source documents. Full JSON Schema verification of original records, cryptographic checks, adapters for live repository retrieval, and execution tests remain open.
