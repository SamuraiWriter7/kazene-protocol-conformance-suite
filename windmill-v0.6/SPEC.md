# Kazene Protocol Conformance Suite v0.6 — Windmill Cross-Protocol Conformance

Status: **experimental additive profile**, not an implementation security certification.

## Purpose
Bind Kazene Windmill Network v1.0 control states to Origin, Trace, Authorization, Containment and Recovery checks without modifying the existing Origin → Trace → Authorization → Execution → Audit → Royalty → Settlement validators.

## Requirements
1. A Windmill event MUST retain a nonempty origin reference and unmodified linked Trace identity.
2. An external attack entity MUST NOT gain operational control or authorization to release itself.
3. D (forward capture) and R (offline reverse provenance) MUST defer to N/P safety precedence.
4. N MUST halt new untrusted ingress. P MUST halt observation workers; boundary protections remain separately active.
5. Reverse R MUST use saved Trace lineage and MUST NOT initiate contact with attack sources.
6. Replacement MUST require independently verified authorization, identity/signature, old-lease fencing, Trace integrity and post-swap health before resumed operation.
7. High pressure thresholds in synthetic cases (85/95) are illustrative only and MUST NOT be treated as production settings.
8. The validator MUST treat any safety violation as nonconformant regardless of whether individual record schemas would pass.

## Test boundary
The v0.6 fixtures are synthetic normalized projections of connected protocol records. They do not cryptographically verify signatures, resolve live registries, check real isolation, run GPTs, or measure detection quality.

## Execute
```bash
python3 windmill-v0.6/scripts/validate_windmill.py
```

This is a separate additive suite; existing v0.5 CI and fixtures remain authoritative for their original scope.

## Source compatibility
Kazene Windmill Network v1.0: `SamuraiWriter7/kazene-os/windmill/`.
Trace, Authorization and Recovery are referenced by roles; schemas are not copied or redefined.
