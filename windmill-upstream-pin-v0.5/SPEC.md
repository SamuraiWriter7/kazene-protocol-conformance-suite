# Windmill Upstream Pin Audit v0.5

## Goal
Preserve the integrity of the v0.3 schema snapshots and the v0.4 integration tests by binding every imported upstream schema to an **immutable commit SHA and Git blob SHA**.

This is a provenance/integrity audit, **not a new AI defense capability**.

## Pinned dependencies
See `sources.json`; its full 40-digit commits were confirmed by fetching each exact source file at that commit.

## Validation levels
1. Offline comparison: calculate canonical Git blob SHA over the bytes of vendored schema snapshots; reject any unexpected edits.
2. CI comparison: check out both external source repositories at their pinned commits and compare the original source file bytes with the expected blob SHA.
3. Tamper-negative check: a modified digest must fail.
4. Existing v0.4 full-record tests remain in place and unchanged.

## Commands
```bash
python windmill-upstream-pin-v0.5/scripts/verify.py
python windmill-upstream-pin-v0.5/scripts/verify.py --upstream-root external
```

The second command requires external repositories already checked out into `external/resilient-ai-safety-principles` and `external/agent-action-authorization-receipt-protocol`, each at the listed commit.

## Scope and limitations
Git SHA-1 here identifies Git objects and catches accidental or unauthorized changes relative to a trusted manifest. It is **not a signature verification of publisher identity**. This audit does not assume upstream main always matches the pinned commit, and does not follow moving branches. Upstream updates require conscious manifest review. It does not load or process real events.
