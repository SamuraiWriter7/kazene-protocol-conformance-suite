"""Pinned upstream Git blob consistency verifier. No silent fallback."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=Path(__file__).resolve().parents[1]/"sources.json"

def blob_sha(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def verify(manifest, upstream=None):
    problems=[]
    for source in manifest["sources"]:
        local=ROOT/source["snapshot_path"]
        try:
            local_sha=blob_sha(local.read_bytes())
        except OSError:
            problems.append(source["name"]+":missing snapshot")
            continue
        if local_sha!=source["blob_sha"]:
            problems.append(source["name"]+":snapshot sha mismatch")
        if upstream is not None:
            path=upstream/source["repo"].split("/")[-1]/source["source_path"]
            try:
                upstream_sha=blob_sha(path.read_bytes())
            except OSError:
                problems.append(source["name"]+":missing pinned upstream checkout")
                continue
            if upstream_sha!=source["blob_sha"]:
                problems.append(source["name"]+":upstream sha mismatch")
        print(source["name"],local_sha)
    return problems

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--upstream-root",type=Path,help="Path containing source repositories checked out at manifest commits")
    args=parser.parse_args()
    manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
    if len(manifest["sources"])!=3 or len({s["name"] for s in manifest["sources"]})!=3:
        raise SystemExit("FAIL: invalid manifest")
    problems=verify(manifest,args.upstream_root)
    if not problems:
        # Negative test: mutation of SHA must always be detected.
        tampered=json.loads(json.dumps(manifest))
        tampered["sources"][0]["blob_sha"]="0"*40
        if not verify(tampered,args.upstream_root):
            raise SystemExit("FAIL: mutation was not detected")
        print("PASS: pinned schema blobs match; mutation rejected")
        return
    raise SystemExit("FAIL: "+"; ".join(problems))

if __name__=="__main__":
    main()
