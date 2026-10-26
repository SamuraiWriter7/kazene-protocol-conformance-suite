"""Strict field-level adapter for Windmill cross-repository linkage. Not full schema verification."""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples/cases.json"

def put(target, dotted, value):
    keys=dotted.split(".")
    node=target
    for key in keys[:-1]:
        node=node[key]
    node[keys[-1]]=value

def check(doc):
    err=[]
    e=doc["event"]
    a=doc["safety_authority"]
    r=doc["safety_recovery"]
    x=doc["action_authorization"]
    def same(key, items):
        if not all(isinstance(v,str) and v for v in items) or len(set(items))!=1:
            err.append(key)
    same("trace_reference", [e["trace_id"], a["trace_reference"], r["trace_reference"], x["context_bindings"]["trace_reference"]])
    same("authorization_id", [e["authorization_id"],x["authorization_id"]])
    same("envelope_id", [e["authority_envelope_id"],a["authority_envelope_id"]])
    if not isinstance(x["authorized_by"]["actor_id"],str) or not x["authorized_by"]["actor_id"]:
        err.append("missing_actor")
    if e["mode"] in ("D","R"):
        if x["decision"] not in ("authorized","conditionally_authorized"):
            err.append("active_without_authorization")
        if r["final_state"] not in ("REAUTHORIZED","COMPLETED"):
            err.append("active_without_recovery")
    elif e["mode"] not in ("N","P"):
        err.append("unknown_mode")
    return err

def main():
    data=json.loads(SOURCE.read_text(encoding="utf-8"))
    passed=0
    for item in data["cases"]:
        doc=copy.deepcopy(data["defaults"])
        for field,value in item["patch"].items():
            put(doc,field,value)
        violations=check(doc)
        actual="FAIL" if violations else "PASS"
        matched=actual==item["expected"]
        print(f"{'MATCH' if matched else 'MISMATCH'} {item['id']} expected={item['expected']} actual={actual} {','.join(violations)}")
        passed+=matched
    print(f"Matched {passed}/{len(data['cases'])}")
    return int(passed!=len(data["cases"]))

if __name__=="__main__":
    raise SystemExit(main())
