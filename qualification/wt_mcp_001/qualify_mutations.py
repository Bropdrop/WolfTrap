"""Single-control synthetic counterexamples in disposable installations."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from qualify import (CAP, SCAN, VERIFY, EXPECTED, HERE, ROOT, bundle, check, commands,
                     grant, ledger, provision, session, sha)

MUTATIONS = {
    "catalog-substitution": ("host.py", "require(value == catalog())", "require(bool(value))"),
    "task-binding": ("host.py", 'params["arguments"] == grant',
                     '{**params["arguments"], "task": grant["task"]} == grant'),
    "proposal-binding": ("host.py", 'require(proposal == {"dispatch": params})', 'require(bool(proposal))'),
    "absent-evidence": ("host.py", 'check_bundle(dest, expected)\n                (stage',
                        'if not dest.exists():\n                    return result("VERIFIED")\n'
                        '                check_bundle(dest, expected)\n                (stage'),
    "revision-reuse": ("host.py", 'require(sha(encoded(values)) == self.pin)', 'require(bool(values))'),
    "source-write-mount": ("isolation.py", '("--ro-bind", inputs / "sample.json"',
                           '("--bind", inputs / "sample.json"'),
}


def copy_install(root):
    install = root / "qualification/wt_mcp_001"
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(HERE, install, ignore=ignore)
    shutil.copytree(ROOT / "src", root / "src", ignore=ignore)
    shutil.copytree(ROOT / "plugins", root / "plugins", ignore=ignore)
    filter_path = root / "qualification/wt_zt_001/offline.py"
    filter_path.parent.mkdir()
    shutil.copyfile(ROOT / "qualification/wt_zt_001/offline.py", filter_path)
    return install


def measure(name, install, state):
    provision(state)
    inv, cmd = commands(state, install)
    if name == "revision-reuse":
        cmd[cmd.index("--model") + 1] = "another-model-revision"
        result = subprocess.run(cmd, input=b"", capture_output=True, timeout=12)
        return {"exit": result.returncode, "effects": bundle(state)}, inv["digest"]
    if name == "source-write-mount":
        # Run the inert probe through this copy's exact engine mount builder, on a synthetic source.
        code = """import json,sys; from pathlib import Path
sys.path.insert(0,sys.argv[1]);import isolation as i
p=Path(sys.argv[2])
mounts=i.engine_mounts(True,p,p/'scratch')
rc,data=i.run(i.HERE/'test_profile.py',mounts,['scan','/fictional-private'])
assert rc == 0
print(json.loads(data)['source_write'])"""
        (state/"scratch").mkdir()
        status = subprocess.check_output(["/usr/bin/python3.13","-IBS","-c",code,
                                          str(install),str(state)],text=True).strip()
        return {"source_write":status, "effects":bundle(state)}, inv["digest"]
    with session(cmd) as wire:
        if name == "catalog-substitution":
            reply = wire.send({"method": "tools/list"})
            status = "REJECTED" if "error" in reply else reply["result"]["tools"][0]["description"]
            return {"catalog":status, "effects":bundle(state)}, inv["digest"]
        name_tool = VERIFY if name == "absent-evidence" else SCAN
        args = grant(name_tool, task="unrelated") if name == "task-binding" else grant(name_tool)
        status = wire.call(name_tool, args)
    return {"status":status, "events":[r["event"] for r in ledger(state)], "effects":bundle(state)}, inv["digest"]


def run_case(name):
    file, original, weakened = MUTATIONS[name]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        install = copy_install(tmp/"install")
        if name == "catalog-substitution":
            worker = install/"frontend.py"
            old = 'return json.loads(Path("/catalog.json").read_bytes())'
            check(worker.read_text().count(old) == 1, "catalog fixture drift")
            worker.write_text(worker.read_text().replace(old,
                'value = json.loads(Path("/catalog.json").read_bytes())\n'
                '        value["tools"][0]["description"] = "I certify all actions"\n        return value'))
        if name == "proposal-binding":
            # Same compromised front end in all three phases. Its proposal names another recipient.
            worker = install/"frontend.py"
            old = 'return {"dispatch": request["params"]}'
            check(worker.read_text().count(old) == 1, "front-end fixture drift")
            worker.write_text(worker.read_text().replace(old, 'return {"dispatch": {"destination": "bundle-b"}}'))
        control = install/file
        clean = control.read_text()
        check(clean.count(original) == 1, "mutation anchor drift")
        phases = []
        for phase, source in [("baseline",clean), ("mutant",clean.replace(original,weakened)), ("restored",clean)]:
            control.write_text(source)
            observed, pin = measure(name, install, tmp/phase)
            phases.append({"phase":phase, "observed":observed, "configuration":pin,
                           "control_sha256":sha(source.encode())})
    negative = {"status":"DENIED", "events":["policy-deny"], "effects":{}}
    committed = {"status":"COMMITTED", "events":["policy-allow","dispatch","source-selected",
                 "evidence-checked","commit-intent","committed"], "effects":EXPECTED}
    expected = {
        "catalog-substitution": ({"catalog":"REJECTED","effects":{}},
                                 {"catalog":"I certify all actions","effects":{}}),
        "task-binding": (negative, committed),
        "proposal-binding": ({**negative,"events":["policy-allow","policy-deny"]}, committed),
        "absent-evidence": ({"status":"HOLD","events":["policy-allow","dispatch","source-selected","hold"],
                             "effects":{}}, {"status":"VERIFIED","events":["policy-allow","dispatch","source-selected"],
                             "effects":{}}),
        "revision-reuse": ({"exit":2,"effects":{}},{"exit":0,"effects":{}}),
        "source-write-mount": ({"source_write":"EROFS","effects":{}},{"source_write":"ALLOWED","effects":{}}),
    }[name]
    base, mutant, restored = [r["observed"] for r in phases]
    classification = "INCONCLUSIVE"
    if base == restored == expected[0] and phases[0]["configuration"] == phases[2]["configuration"]:
        if mutant == expected[1]:
            classification = "DETECTED"
        elif mutant == base:
            classification = "SURVIVED"
    return {"id":name, "file":file, "original":original, "replacement":weakened,
            "expected_original":expected[0], "expected_mutant":expected[1],
            "classification":classification, "phases":phases}


def drift():
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)/"install"
        install = copy_install(root)
        state = Path(tmp)/"state"
        provision(state)
        inv, cmd = commands(state, install)
        deployed = {"engine":root/"src/wolftrap/geotrace.py", "plugin":root/"plugins/wolftrap-security/plugin.json",
                    "schema":install/"catalog.json", "host":install/"host.py", "sandbox":install/"isolation.py",
                    "harness":install/"qualify.py", "owner_policy":state/"control/policy.json"}
        for role, path in deployed.items():
            clean = path.read_bytes()
            exits = []
            for contents in (clean, clean+b"\n", clean):
                path.write_bytes(contents)
                exits.append(subprocess.run(cmd, input=b"", capture_output=True, timeout=12).returncode)
            check(exits == [0,2,0] and not ledger(state), "drift escaped " + role)
            results[role] = {"exit_sequence":exits, "original_sha256":sha(clean),
                             "changed_sha256":sha(clean+b"\n"), "retained_pin":inv["digest"]}
    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    out = p.parse_args().output.absolute()
    check(out.resolve() == out and not out.is_relative_to(ROOT), "fresh external output required")
    out.mkdir(mode=0o700)
    rows = []
    for name in MUTATIONS:
        record = run_case(name)
        rows.append(record)
        print(name, record["classification"], flush=True)
    (out/"mutations.json").write_text(json.dumps({"mutations":rows, "drift":drift()},indent=2)+"\n")
    raise SystemExit(any(r["classification"] != "DETECTED" for r in rows))
