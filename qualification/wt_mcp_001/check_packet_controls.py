"""Negative controls for packet.py. Run with the source checkout, retained packet and pin."""
import hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path

packet, selected_pin = sys.argv[1:]
checkout = Path(__file__).resolve().parents[2]
packet = Path(packet)
src = json.loads((packet/"source.json").read_bytes())
records = []
def run(path, name, expected, pin=selected_pin, commit=src["commit"], tree=src["tree"]):
    cmd = [sys.executable, "-B", str(Path(checkout)/"qualification/wt_mcp_001/packet.py"), "verify",
           str(path), "--manifest-pin",pin,"--commit",commit,"--tree",tree]
    res = subprocess.run(cmd, capture_output=True, timeout=15)
    records.append({"control":name,"exit":res.returncode,"expected":"accept" if expected else "reject"})
    if (res.returncode == 0) != expected:
        raise ValueError("unexpected verifier outcome for " + name)

def reseal(path):
    manifest = json.loads((path/"manifest.json").read_bytes())
    for n in manifest:
        content=(path/n).read_bytes()
        manifest[n]={"bytes":len(content),"sha256":hashlib.sha256(content).hexdigest()}
    raw=json.dumps(manifest,sort_keys=True).encode()
    (path/"manifest.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()

run(packet,"unaltered",True)
for name in ("missing","extra-file","symlink","hardlink","replaced","wrong-pin","wrong-commit","wrong-tree",
             "contradictory-journal","relabelled-run","substituted-effect","incomplete-cases","missing-os-witness"):
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/"packet";shutil.copytree(packet,path);member=path/"sdk-geotrace.json"
        pin=selected_pin;commit=src["commit"];tree=src["tree"]
        if name=="missing": member.unlink()
        elif name=="extra-file": (path/"unexpected").write_bytes(b"fictional")
        elif name in ("symlink","hardlink"):
            other=Path(tmp)/"member";member.rename(other)
            if name=="symlink":member.symlink_to(other)
            else:os.link(other,member)
        elif name=="replaced": member.write_bytes(b"changed")
        elif name=="wrong-pin": pin="0"*64
        elif name=="wrong-commit":commit="0"*40
        elif name=="wrong-tree":tree="0"*40
        elif name=="contradictory-journal":
            (path/"sdk.jsonl").write_text((path/"sdk.jsonl").read_text().replace('"committed"','"verified"'))
            pin=reseal(path)
        elif name=="relabelled-run":
            record=json.loads((path/"codex.json").read_text());record["source"]["commit"]="0"*40
            (path/"codex.json").write_text(json.dumps(record));pin=reseal(path)
        elif name=="substituted-effect":
            member.write_bytes(b"{}");pin=reseal(path)
        elif name=="incomplete-cases":
            record=json.loads((path/"safety-case.json").read_text());record["cases"].pop("changed-principal")
            (path/"safety-case.json").write_text(json.dumps(record));pin=reseal(path)
        elif name=="missing-os-witness":
            (path/"sdk.strace").write_text("omitted");pin=reseal(path)
        run(path,name,False,pin,commit,tree)
print(json.dumps(records,indent=2))
