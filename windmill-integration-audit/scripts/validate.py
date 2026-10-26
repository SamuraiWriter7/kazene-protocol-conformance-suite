"""Deterministic four-repository synthetic correlation audit."""
import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "examples/four-repo-cases.json"

def violations(x):
    issues = []
    for name in ("event_id", "origin_id", "trace_id", "authorization_id", "blade_id", "old_blade_id"):
        if not x[name]: issues.append("missing_" + name)
    if len({x["trace_id"],x["safety_trace_id"],x["conformance_trace_id"]}) != 1:
        issues.append("trace_disagreement")
    if len({x["authorization_id"],x["safety_authorization_id"],x["conformance_authorization_id"]}) != 1:
        issues.append("authorization_disagreement")
    if len({x["mode"],x["safety_mode"],x["authorization_mode"]}) != 1:
        issues.append("mode_disagreement")
    if len({x["recovery_state"],x["safety_recovery_state"],x["authorization_recovery_state"]}) != 1:
        issues.append("recovery_disagreement")
    if x["attack_source_authorized"]: issues.append("attacker_authority")
    if x["mode"] in ("D", "R"):
        if x["recovery_state"] != "approved": issues.append("active_without_recovery")
        for key in ("old_lease_fenced", "signature_ok", "independent_approval", "post_swap_health"):
            if not x[key]: issues.append("active_without_" + key)
    return issues

def main():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert len(data["cases"]) >= 16
    count = 0
    for case in data["cases"]:
        state = {**data["defaults"], **case["changes"]}
        errors = violations(state)
        actual = "FAIL" if errors else "PASS"
        valid = actual == case["expected"]
        print(f"{'MATCH' if valid else 'MISMATCH'} {case['id']} expected={case['expected']} actual={actual} {','.join(errors)}")
        count += valid
    print(f"Matched {count}/{len(data['cases'])}")
    return int(count != len(data["cases"]))

if __name__ == "__main__":
    raise SystemExit(main())
