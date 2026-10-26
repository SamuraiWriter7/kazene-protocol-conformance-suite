"""Validate fully populated records against pinned original JSON Schemas, then cross-reference them."""
from __future__ import annotations
import copy
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[1]
SCHEMA_ROOT=ROOT.parent/"windmill-full-record-v0.3"/"schemas"
CASES=ROOT/"examples/cases.json"
KINDS=("authority-envelope","recovery-receipt","action-authorization-receipt")

def mutate(record, path, value):
    keys=path.split(".")
    dest=record
    for key in keys[:-1]: dest=dest[key]
    dest[keys[-1]]=value

def audit(data):
    failures=[]
    records=data["records"]
    for kind in KINDS:
        schema=json.loads((SCHEMA_ROOT/(kind+".schema.json")).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        issues=list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(records[kind]))
        if issues: failures.append("schema:"+kind)
    if failures: return failures
    e=data["event"]
    a=records["authority-envelope"]
    r=records["recovery-receipt"]
    p=records["action-authorization-receipt"]
    refs=(e["trace_id"],a["trace_reference"],r["trace_reference"],p["context_bindings"]["trace_reference"])
    if not all(isinstance(v,str) and v for v in refs) or len(set(refs))!=1: failures.append("trace_mismatch")
    if e["authorization_id"]!=p["authorization_id"]: failures.append("authorization_mismatch")
    if e["authority_envelope_id"]!=a["authority_envelope_id"]: failures.append("envelope_mismatch")
    if r["authority_outcome"].get("new_authority_reference")!=a["authority_envelope_id"]: failures.append("recovery_authority_mismatch")
    if r["subject"]["subject_id"]!=e["blade_id"] or a["subject"]["subject_id"]!=e["blade_id"]: failures.append("blade_mismatch")
    if e["mode"] in ("D","R"):
        if a["status"]!="ACTIVE": failures.append("inactive_envelope")
        if p["decision"] not in ("authorized","conditionally_authorized"): failures.append("denied_execution")
        if r["final_state"]!="REAUTHORIZED": failures.append("recovery_not_authorized")
        if r["verification"]["verification_result"]!="VERIFIED_SAFE" or not r["verification"]["independent"]: failures.append("verification_not_independent")
    elif e["mode"] not in ("N","P"): failures.append("invalid_mode")
    return failures

def main():
    fixture=json.loads(CASES.read_text(encoding="utf-8"))
    matches=0
    for c in fixture["cases"]:
        event=copy.deepcopy(fixture["defaults"])
        for key,value in c["changes"].items(): mutate(event,key,value)
        errors=audit(event)
        actual="FAIL" if errors else "PASS"
        is_match=actual==c["expected"]
        print(f"{'MATCH' if is_match else 'MISMATCH'} {c['id']} expected={c['expected']} actual={actual} rules={','.join(errors) or '-'}")
        matches+=is_match
    print(f"Matched {matches}/{len(fixture['cases'])}")
    return int(matches!=len(fixture["cases"]))
if __name__=="__main__":raise SystemExit(main())
