"""Offline Codex app-server client probe. Starts no model turns and uses a fresh home."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time

from qualify import trace_command, trace_observations
from qualify import CAP, SCAN, VERIFY, EXPECTED, bundle, check, commands, grant, ledger, provision


def run(out):
    out.mkdir(mode=0o700)
    state = out / "state"
    provision(state)
    binary = shutil.which("codex")
    if not binary:
        raise RuntimeError("Codex unavailable")
    with open(binary, "rb") as f:
        binary_sha = hashlib.file_digest(f, "sha256").hexdigest()
    inventory, cmd = commands(state, harness="codex-app-server-" + binary_sha)
    trace = out / "codex.strace"
    cmd = trace_command(cmd, trace)
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        config = home / "config.toml"
        config.write_text('[mcp_servers.wolftrap]\ncommand=' + json.dumps(cmd[0]) +
                          '\nargs=' + json.dumps(cmd[1:]) + '\nstartup_timeout_sec=30\n')
        environment = {"HOME": tmp, "CODEX_HOME": tmp, "PATH": os.defpath, "TMPDIR": tmp}
        command = [binary, "app-server"]
        with subprocess.Popen(command, env=environment, cwd=tmp, bufsize=0, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            seq = 0
            def rpc(method, params):
                nonlocal seq
                seq += 1
                frame = {"id": seq, "method": method, "params": params}
                proc.stdin.write(json.dumps(frame).encode() + b"\n")
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    check(select.select([proc.stdout], [], [], max(0, deadline-time.monotonic()))[0], method)
                    line = proc.stdout.readline()
                    check(bool(line), "Codex stream closed")
                    reply = json.loads(line)
                    if reply.get("id") == seq:
                        if "error" in reply:
                            raise RuntimeError(method + " returned " + str(reply["error"]["code"]) +
                                               " " + reply["error"].get("message", "")[:200])
                        return reply["result"]
                raise TimeoutError(method)
            try:
                rpc("initialize", {"clientInfo": {"name": "wt_qualification", "version": "1"},
                                    "capabilities": {"experimentalApi": True}})
                proc.stdin.write(b'{"method":"initialized"}\n')
                info = rpc("thread/start", {"cwd": tmp, "ephemeral": True, "approvalPolicy":"never"})
                thread = info["thread"]["id"]
                rows = []
                for name,args,expected,status in [(CAP,grant(CAP),{},"AVAILABLE"),
                        (SCAN,grant(SCAN,task="unrelated"),{},"DENIED"),
                        (SCAN,grant(SCAN),EXPECTED,"COMMITTED"),(VERIFY,grant(VERIFY),EXPECTED,"VERIFIED")]:
                    reply = rpc("mcpServer/tool/call", {"server": "wolftrap", "threadId": thread,
                                                        "tool": name, "arguments": args})
                    observed = {"reply":reply["structuredContent"]["status"], "bundle":bundle(state)}
                    rows.append(observed)
                    check(observed == {"reply":status, "bundle":expected}, "Codex external oracle")
            finally:
                proc.terminate()
                proc.wait(timeout=10)
    return {"configuration":inventory, "observations":rows, "witness":ledger(state),
            "os_witness":trace_observations(trace), "binary_sha256":binary_sha, "version":subprocess.check_output([binary, "--version"], text=True).strip()}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    out = p.parse_args().output.absolute()
    from qualify import ROOT
    check(out.resolve() == out and not out.is_relative_to(ROOT), "use fresh external output")
    try:
        report = {"classification": "SYNTHETICALLY_VERIFIED", **run(out)}
    except (OSError, ValueError, RuntimeError, AssertionError, KeyError, TypeError) as exc:
        report = {"classification": "BLOCKED", "reason": str(exc)}
    (out/"codex.json").write_text(json.dumps(report, indent=2)+"\n")
    print(report["classification"], report.get("reason", ""))
    raise SystemExit(report["classification"] == "BLOCKED")
