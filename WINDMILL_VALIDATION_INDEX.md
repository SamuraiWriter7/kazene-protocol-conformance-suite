# Windmill Validation Index (2026-10-26)

The Windmill extensions are **additive** to core Kazene Conformance Suite v0.5.0. Individual extension version numbers are not repository-wide tags.

| Milestone | Directory | Purpose |
| --- | --- | --- |
| Cross-protocol v0.6 | `windmill-v0.6/` | D/R/N/P synthetic conformance |
| Four-repository audit v0.1 | `windmill-integration-audit/` | Shared synthetic event checks |
| Schema-binding v0.2 | `windmill-schema-bindings-v0.2/` | Real schema field-name projection |
| Full-record gate v0.3 | `windmill-full-record-v0.3/` | Pinned official JSON Schema validation |
| Full-record integration v0.4 | `windmill-full-record-v0.4/` | Complete constructed records, Trace/authorization/recovery reconciliation |
| Upstream pin v0.5 | `windmill-upstream-pin-v0.5/` | Immutable upstream commits and blob checks |

Related specifications: [Kazene Windmill](https://github.com/SamuraiWriter7/kazene-os/tree/main/windmill), [Resilient Safety](https://github.com/SamuraiWriter7/resilient-ai-safety-principles/tree/main/windmill-safety-v0.6), [Authorization Receipt](https://github.com/SamuraiWriter7/agent-action-authorization-receipt-protocol/tree/main/windmill-authorization-v0.6).

## Commands

Install `requirements.txt`, then run:

```bash
python windmill-v0.6/scripts/validate_windmill.py
python windmill-integration-audit/scripts/validate.py
python windmill-schema-bindings-v0.2/scripts/validate.py
python windmill-full-record-v0.3/scripts/validate.py --self-test
python windmill-full-record-v0.4/scripts/validate.py
python windmill-upstream-pin-v0.5/scripts/verify.py
```

The upstream pin audit additionally supports external commit-specific checkouts; see its `SPEC.md`.

## Evidence boundaries

Validation succeeds for synthetic cases, constructed full schema-valid records, and pinned upstream schema bytes. No claim is made that live systems interoperate, GPTs autonomously collaborate, signatures are verified, or real attacks are contained. The Windmill replacement event still lacks a canonical schema.

## Release status

The last documented core repository release is v0.5.0. This index records merged extension work, not a new GitHub Release.
