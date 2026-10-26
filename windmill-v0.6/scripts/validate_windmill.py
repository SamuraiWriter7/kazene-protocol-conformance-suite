"""Kazene Conformance Suite v0.6 additive Windmill cross-protocol checks."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
FIXTURE = HERE / "examples/v0.6/windmill-cases.json"

def violations(x):
    errors = []
    if not x["origin_id"] or x["linked_trace_id"] != x["trace_id"]:
        errors.append("origin_trace_binding")
    if x["attack_control"] or x["blade_can_authorize_release"]:
        errors.append("authority_boundary")
    if not x["trace_integrity"]:
        errors.append("trace_integrity")
    if x["pressure"] >= 95 and x["mode"] != "P":
        errors.append("critical_pressure_parking")
    elif x["pressure"] >= 85 and x["mode"] not in ("N", "P"):
        errors.append("elevated_pressure_hold")
    if x["mode"] in ("N", "P") and x["ingress_active"]:
        errors.append("safe_disengagement")
    if x["mode"] == "P" and x["worker_active"]:
        errors.append("park_workers")
    if x["mode"] == "R" and (not x["trace_parent"] or x["source_contact"]):
        errors.append("reverse_offline_provenance")
    if x["replacement"] and not all(x[k] for k in (
        "signature_ok", "authorization_ok", "health_ok", "old_lease_fenced"
    )):
        errors.append("replacement_gate")
    return errors

def main():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert doc["version"] == "0.6.0"
    assert len(doc["cases"]) >= 20
    seen = set()
    mismatches = 0
    for case in doc["cases"]:
        assert case["id"] not in seen
        seen.add(case["id"])
        x = dict(doc["defaults"])
        x.update(case["patch"])
        violations_found = violations(x)
        actual = "FAIL" if violations_found else "PASS"
        good = actual == case["expected"]
        print(f"{'MATCH' if good else 'MISMATCH'} {case['id']} expected={case['expected']} actual={actual} rules={','.join(violations_found) or 'none'}")
        mismatches += not good
    print(f"Windmill v0.6: {len(doc['cases']) - mismatches}/{len(doc['cases'])} expectations matched")
    return 1 if mismatches else 0

if __name__ == "__main__":
    sys.exit(main())
