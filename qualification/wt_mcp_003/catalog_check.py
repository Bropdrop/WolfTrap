"""Probe a reviewed local WolfTrap checkout with a fresh fictional grant, capture and slot."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path.cwd().resolve()

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    commit = git("rev-parse", "HEAD")
    origin = git("remote", "get-url", "origin").removesuffix(".git")
    if (commit != args.expected_commit or git("status", "--porcelain")
            or origin not in ("https://github.com/Bropdrop/WolfTrap", "git@github.com:Bropdrop/WolfTrap")):
        raise ValueError("use the clean, independently selected WolfTrap revision")
    output = args.output.absolute()
    if output != output.resolve() or output.is_relative_to(root):
        raise ValueError("external output required")
    output.mkdir(mode=0o700)
    q = root/"qualification/wt_mcp_002"
    sys.path.insert(0, str(q))
    from fixtures import REF, arguments, provision
    from profile import CAP, SCAN, VERIFY
    from reference_pin import expected_configuration
    from trials import command, observe, wire
    client = "wt-mcp-003-local-wire"
    record = {"schema":"wolftrap.catalog-diagnostic/v1", "commit":commit, "tree":git("rev-parse","HEAD^{tree}"),
              "kernel":platform.release(), "machine":platform.machine(), "uid":os.getuid(),
              "uid_map":Path("/proc/self/uid_map").read_text().strip(),
              "bubblewrap":subprocess.check_output(["/usr/bin/bwrap","--version"], text=True).strip(),
              "broker_python":subprocess.check_output(["/usr/bin/python3.13","--version"],text=True).strip(),
              "verdict":"BLOCKED", "initialize":"NOT_TESTED", "catalog":"NOT_TESTED", "outcomes":[]}
    with tempfile.TemporaryDirectory(dir=output) as temp:
        state = Path(temp)/"state"
        policy = provision(state)
        record["configuration"] = expected_configuration(q, client)
        cmd = command(state, policy, record["configuration"], client)
        trace = Path(temp)/"stderr-trace"
        try:
            with wire(["/usr/bin/strace","-f","-qq","-s","120","-o",str(trace),
                       "-e","trace=write",*cmd]) as w:
                record["initialize"] = "PASS"
                listing = w.send("tools/list")
                listed = {t["name"] for t in listing.get("result",{}).get("tools",[])} == {CAP,SCAN,VERIFY}
                record["catalog"] = "LISTED" if listed else "REJECTED"
                if listed:
                    scan = arguments(policy,SCAN,"alpha")
                    for tool, grant in [(SCAN, {**scan,"task":"unrelated"}), (SCAN,scan), (SCAN,scan),
                                        (VERIFY, arguments(policy,VERIFY,"alpha"))]:
                        record["outcomes"].append(w.call(tool,grant))
        except (OSError, ValueError, AssertionError, TypeError, KeyError, subprocess.SubprocessError) as exc:
            record["diagnostic_error"] = type(exc).__name__
        # Bubblewrap writes its prefix, diagnostic and strerror separately on this runtime.
        writes = {}
        if trace.is_file():
            for line in trace.read_text(errors="replace").splitlines():
                matched = re.match(r'(\d+)\s+write\(2, "([^"]*)"',line)
                if matched:
                    writes.setdefault(matched[1],[]).append(matched[2])
        record["uid_map_eperm"] = any("setting up uid map: Operation not permitted" in "".join(parts)
                                      for parts in writes.values())
        slot = observe(state,"alpha")
        record["slot"] = slot
        if (record["outcomes"] == ["DENIED","COMMITTED","ALREADY_COMMITTED","VERIFIED"]
                and [row[1] for row in slot["journal"]] == ["DISPATCH","COMMITTED","DISPATCH","VERIFIED"]
                and {k:v["sha256"] for k,v in slot["files"].items()} == REF["alpha"]["expected"]):
            record["verdict"] = "SYNTHETICALLY_VERIFIED"
    (output/"catalog.json").write_text(json.dumps(record, indent=2)+"\n")
    print(record["verdict"], record["catalog"], "uid_map_eperm", record["uid_map_eperm"])
    return 0 if record["verdict"] == "SYNTHETICALLY_VERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
