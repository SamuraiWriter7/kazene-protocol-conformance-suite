# Windmill Full Record Integration v0.4

Experimental **schema-valid record fixture** suite. Reuses the three actual, pinned JSON Schema snapshots in `windmill-full-record-v0.3/schemas/`.

## Requirements
1. Each record MUST validate against its original Draft 2020-12 schema.
2. An event Trace ID MUST equal all three record Trace references.
3. The action authorization ID MUST equal the event authorization ID; the safety authority envelope ID MUST remain distinct and be explicitly linked through the recovery authority reference.
4. Active D/R MUST require an ACTIVE authority envelope, positive authorization, independent verified-safe recovery and REAUTHORIZED final state.
5. Subject identifiers MUST match the replacement blade.
6. Any source schema violation or cross-record mismatch MUST fail closed.

## Fixture boundary
Records are deliberately constructed complete documents with source schema shapes; not retrieved production records and not cryptographically verified.
The windmill event envelope is still a local test convention. An upstream canonical swap event schema and real inter-repository adapters are not yet available.

## Run
`python windmill-full-record-v0.4/scripts/validate.py`

Requires `jsonschema` from the root requirements file.
