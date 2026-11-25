"""Acquire only the authorized HTTPS snapshot and publish a read-only verified directory."""
import argparse
import ast
import hashlib
import json
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

here = Path(__file__).resolve().parent
project = here.parent
pin_path = here / "distilgpt2-pin.json"
pin = json.loads(pin_path.read_text())
tree = ast.parse((project / "pilot" / "neuron_probe.py").read_text())
pilot = {a.targets[0].id: ast.literal_eval(a.value) for a in tree.body if isinstance(a, ast.Assign)
         and isinstance(a.targets[0], ast.Name) and a.targets[0].id in ("PIN_REV", "PINS")}
if (pin["revision"] != pilot["PIN_REV"] or pin["repo_id"] != "distilbert/distilgpt2"
        or {k: v["sha256"] for k, v in pin["files"].items()} != pilot["PINS"]):
    raise ValueError("model pin disagreement")
ap = argparse.ArgumentParser()
ap.add_argument("--dest", type=Path, required=True)
ap.add_argument("--attempt", type=Path, required=True, help="fresh evidence directory")
args = ap.parse_args()
dest = args.dest.resolve()
args.attempt.mkdir(exist_ok=False)
if dest.exists():
    raise ValueError("refusing to replace a model input")
dest.parent.mkdir(exist_ok=True, parents=True)
stage = Path(tempfile.mkdtemp(prefix=".model-", dir=dest.parent))

def dump(p, obj):
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")

def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def fetch(name):
    want = pin["files"][name]
    path = stage / name
    url = f"https://huggingface.co/{pin['repo_id']}/resolve/{pin['revision']}/{name}"
    start = datetime.now(timezone.utc).isoformat()
    run = subprocess.run(["curl", "--disable", "--silent", "--show-error", "--fail", "--location",
                          "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "8",
                          "--connect-timeout", "25", "--max-time", "900",
                          "--max-filesize", str(want["bytes"]), "--output", str(path),
                          "--write-out", "%{http_code}\t%{num_redirects}\t%{ssl_verify_result}\t%{url_effective}",
                          url], capture_output=True, text=True)
    code, redirects, tls, location = run.stdout.split("\t")
    n = path.stat().st_size if path.exists() else None
    h = sha(path) if path.exists() else None
    ok = (run.returncode == 0 and code == "200" and tls == "0" and n == want["bytes"] and h == want["sha256"] and h == pilot["PINS"][name])
    record = {"started_utc": start, "completed_utc": datetime.now(timezone.utc).isoformat(), "source_url": url,
              "final_host": urlsplit(location).hostname, "curl_exit": run.returncode, "http": code,
              "redirects": int(redirects), "tls_verify_result": int(tls), "error": run.stderr, "bytes": n,
              "expected_bytes": want["bytes"], "sha256": h, "expected_sha256": want["sha256"],
              "passed_size_sha256_http_tls": ok}
    dump(args.attempt / (name + ".json"), record)
    return ok
with ThreadPoolExecutor(max_workers=4) as pool:
    checks = list(pool.map(fetch, pin["files"]))
if all(checks) and set(pin["files"]) == {p.name for p in stage.iterdir()}:
    for name in pin["files"]:
        if sha(stage / name) != pilot["PINS"][name]:
            raise ValueError("staged file changed before freezing")
        (stage / name).chmod(0o444)
    stage.chmod(0o555)
    if dest.exists():
        raise ValueError("destination created during transfer")
    os.rename(stage, dest)
    status = "VERIFIED"
else:
    status = "BLOCKED"
dump(args.attempt / "summary.json", {"status": status, "files_verified": sum(checks), "expected": len(checks),
     "revision": pin["revision"], "reference_pin_sha256": sha(pin_path),
     "pilot_source_sha256": sha(project / "pilot/neuron_probe.py"),
     "disposition": "read-only files 0444 and directory 0555" if status == "VERIFIED" else "partial files quarantined outside verified input"})
if status != "VERIFIED":
    raise SystemExit(1)
