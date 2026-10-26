# Kazene Windmill Four-Repository Integration Audit v0.1

Status: **experimental synthetic correlation profile**.

## Source baseline (main branch, inspected 2026-10-26)
- `SamuraiWriter7/kazene-os/windmill/SPEC.md` — central state and blade model.
- `SamuraiWriter7/kazene-protocol-conformance-suite/windmill-v0.6/SPEC.md` — cross-protocol binding.
- `SamuraiWriter7/resilient-ai-safety-principles/windmill-safety-v0.6/SPEC.md` — containment and recovery.
- `SamuraiWriter7/agent-action-authorization-receipt-protocol/windmill-authorization-v0.6/SPEC.md` — swap authority.

## Integration requirements
Given one blade swap event, Origin, Trace ID, Authorization ID, mode, and Recovery state MUST agree across the projected records. Active D/R after replacement requires old lease fencing, authenticated replacement, independent review, verified recovery and post-swap health. Source attacker MUST NOT possess control authority. On disagreement, reject integration evidence and hold.

## Synthetic audit vs real integration
This suite tests a **shared normalized artificial record** with deliberate mismatches. It does not fetch, pin or parse live records across four repositories and does not prove the individual schemas are interoperable. No cryptographic, network isolation, or runtime safety claims are made.

## Reproduce
```bash
python3 windmill-integration-audit/scripts/validate.py
```

Next phases: pin dependency commit SHA values, define explicit adapters to each repository's schema, validate a real linked fixture, and require independent safety review before any operational use.
