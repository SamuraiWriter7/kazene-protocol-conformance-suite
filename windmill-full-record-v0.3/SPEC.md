# Windmill Full Record Validation v0.3 — Source-Schema Gate

**Status:** Draft schema-validation gate; NOT full four-repository interoperability certification.

This phase snapshots three actual JSON Schemas from existing repositories. The snapshots must be replaced by an explicitly reviewed update when upstream source files change. No pretense that source field-name projections are full records.

## Source manifest (retrieved on 2026-10-26)

| Local snapshot | Original upstream source | Upstream Git blob SHA |
|---|---|---|
| schemas/authority-envelope.schema.json | SamuraiWriter7/resilient-ai-safety-principles/schemas/authority-envelope.schema.json | a60ee4466f07eb29a66fb27f3ab68b6bd5375bb4 |
| schemas/recovery-receipt.schema.json | SamuraiWriter7/resilient-ai-safety-principles/schemas/recovery-receipt.schema.json | 92efd3dcb580a93154c1758b45a027613037de3a |
| schemas/action-authorization-receipt.schema.json | SamuraiWriter7/agent-action-authorization-receipt-protocol/schemas/action-authorization-receipt.schema.json | a6b03a40744bd42e6889e93f4248bb63b0fde51c |

## Gate behavior

- Validate source schemas against Draft 2020-12 meta-schema.
- Reject missing required fields, unknown fields and invalid types according to the complete underlying schemas.
- Accept any explicitly supplied full JSON record only if it passes the corresponding full JSON Schema.
- Reject unknown record types and missing source files, rather than bypassing the validation gate.
- After successful per-record validation, future revisions MAY project common Trace and Authorization links for cross-record comparison; this is **not yet implemented**.

## Usage

```bash
python -m pip install -r requirements.txt
python windmill-full-record-v0.3/scripts/validate.py --self-test
python windmill-full-record-v0.3/scripts/validate.py --type authority-envelope --input example.json
python windmill-full-record-v0.3/scripts/validate.py --type recovery-receipt --input example.json
python windmill-full-record-v0.3/scripts/validate.py --type action-authorization-receipt --input example.json
```

## Explicit gaps

- No verified full, positive cross-repository record fixture has yet been bound to a shared Windmill event.
- Windmill v1.0 currently uses a synthetic policy-case format instead of a canonical full blade-swap event schema.
- Snapshot validity and invalid-object rejection do not constitute an end-to-end PASS.
- Cryptographic integrity, remote registries and runtime isolation are not tested.
