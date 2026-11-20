"""Qualify signed fictional advisories and independently check saved evidence at one revision."""

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from wolftrap.report import write_json_report
from wolftrap.revision import capture_source_revision, repository_root
from wolftrap.wolfnet_reference import EXPECT, FILE_EXPECT, REJECTIONS
from wolftrap.wolfprint_reference import architecture, frame, operation


AT = "2030-01-01T00:01:00Z"
PINS = {"trust": "813ac14f9e5a8c175bd8d67ea6dcc177f51f1fb19018d4362ae0e0325dabdc85",
        "checkpoint": "c12183112a311e64c1e56132c48052dda4f69b7ed4032b2526f97a3dd4ef7336",
        "incident-registry": "a43fa88277b919740524c2c457da419286c0a3fd42ef022bdbad4482aa457950",
        "policy": "0eaa86e478a3b2bce2c39497087ea4c6ad240f9fbece0e57205686b61b364bf2",
        "policy-opt-in": "cd62f573b569bee948f27942b1a84bae5ab1bae22076d4defcdc844904a7c149",
        "fixture-registry": "5d7517fd9b15ad2ed73820b23d7907518ed7ac296f69b9697643b71c39668430"}
MEMBERS = ("wolfnet.json", "wolfnet.md", "wolfnet.sarif", "wolfnet.manifest.json")
CHECKPOINT = "wolfnet-checkpoint.json"
BUNDLES = {"challenge": MEMBERS, "feed": (*MEMBERS, CHECKPOINT), "advisory": MEMBERS, "opt-in": MEMBERS,
           "withdrawn": (*MEMBERS, CHECKPOINT), "restored": MEMBERS}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def read(path):
    return json.loads(path.read_bytes())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def framed(label, value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return ("wolftrap.wolfnet/v1\0" + label + "\0" + encoded).encode("ascii")


def key_digest(label, value):
    return sha(framed(label, value))


def run(*args, expected=0):
    done = subprocess.run([sys.executable, "-m", *map(str, args)], check=False)
    need(done.returncode == expected, "unexpected qualification exit for " + str(args[0:2]))


def independently_check_signatures(example):
    """Check the checked-in feed and observation using only OpenSSL and stdlib serialization."""
    trust = read(example / "trust.json")
    keys = {(k["signer"], k["revision"]): k for k in trust["keys"]}
    active = read(example / "feed.json")["history"]
    log = read(example / "withdrawn-feed.json")["history"]
    need(len(active) == 1 and len(log) == 2 and log[:1] == active, "history prefix")
    checks = []
    previous = key_digest("genesis", trust["subscription"])
    for sequence, env in enumerate(log, 1):
        body = env["body"]
        need((body["previous"], body["sequence"]) == (previous, sequence), "independent log chain")
        previous = key_digest("frame", env)
        checks.append(("distributor", env["seal"], body))
        entry, = body["entries"]
        checks.append(("publisher", entry["author"], entry["record"]))
        checks.extend(("reviewer", seal, entry["record"]) for seal in entry["approvals"])
    receipt, = read(example / "witnesses.json")["witnesses"]
    checks.append(("observer", receipt["seal"], receipt["body"]))
    seen = set()
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        key, content, signature = (base / n for n in ("public.der", "content", "signature"))
        command = ["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(key),
                   "-rawin", "-in", str(content), "-sigfile", str(signature)]
        for role, seal, value in checks:
            public = keys[seal["signer"], seal["key_revision"]]
            need(public["role"] == role and seal["alg"] == "Ed25519", "key purpose")
            key.write_bytes(bytes.fromhex("302a300506032b6570032100" + public["public_key"]))
            raw = framed("signature/" + role, {**{k: seal[k] for k in ("signer", "key_revision", "alg")}, "body": value})
            signature.write_bytes(bytes.fromhex(seal["signature"]))
            for material, expected in ((raw, 0), (raw + b" ", 1)):
                content.write_bytes(material)
                result = subprocess.run(command, env={"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null"},
                                        capture_output=True, timeout=10, check=False)
                need(result.returncode == expected, "OpenSSL independent Ed25519 verification")
            seen.add(seal["signature"])
    need(len(seen) == len(checks) == 7, "distinct publication signatures")
    return len(checks)


def checked_checkpoint(out, example):
    """Independently reconstruct the extracted subscriber checkpoint before accepting its bytes."""
    file = out / "feed" / CHECKPOINT
    cp = read(example / "checkpoint.json")
    trust = read(example / "trust.json")
    head, = read(example / "feed.json")["history"]
    expected = {**cp, "accepted_at": AT, "sequence": 1, "head": key_digest("frame", head),
                "trust_sha256": key_digest("subscriber-trust", trust)}
    need(read(file) == expected, "first subscriber checkpoint")
    return file, sha(file.read_bytes())


def run_bundles(out, root, source, *, replay_only=False):
    ex = root / "examples/wolfnet"
    wp = root / "examples/wolfprint"
    common = ["--trust", ex / "trust.json", "--trust-sha256", PINS["trust"], "--at", AT,
              "--witnesses", ex / "witnesses.json", "--trace", ex / "incident-chain.json",
              "--witness-registry", ex / "incident-registry.json", "--witness-registry-sha256", PINS["incident-registry"]]
    for group in BUNDLES:
        target = out / group
        expected = 1 if group in ("advisory", "opt-in") else 0
        command, replay, opts = "challenge-wolfnet", "verify-wolfnet-challenge", []
        if group != "challenge":
            advanced = group in ("withdrawn", "restored")
            cp, pin = checked_checkpoint(out, ex) if advanced else (ex / "checkpoint.json", PINS["checkpoint"])
            feed = "withdrawn-feed" if advanced else "feed"
            opts = [*common, "--feed", ex / (feed + ".json"), "--checkpoint", cp, "--checkpoint-sha256", pin]
            command = replay = "verify-wolfnet-feed"
            if group in ("advisory", "opt-in", "restored"):
                policy = "policy" if group == "advisory" else "policy-opt-in"
                command = replay = "evaluate-wolfnet"
                opts += ["--verified-feed-dir", out / ("withdrawn" if advanced else "feed"), "--policy", ex / (policy + ".json"),
                         "--policy-sha256", PINS[policy], "--manifest", wp / "architecture.json", "--request", wp / "request.json",
                         "--registry", wp / "fixture-registry.json", "--registry-sha256", PINS["fixture-registry"]]
        opts += ["--expected-head", source.commit_sha]
        if not replay_only:
            run("wolftrap", command, *opts, "--output-dir", target, expected=expected)
        run("wolftrap", replay, *opts, "--evidence-dir", target, expected=expected)


def independent_check(out, root, source):
    """Inspect archived reports without importing the candidate verifier, analyzer or policy."""
    ex, wp = root / "examples/wolfnet", root / "examples/wolfprint"
    for name, pin in PINS.items():
        need(sha(((wp if name == "fixture-registry" else ex) / (name + ".json")).read_bytes()) == pin, "fixture pin " + name)
    sigs = independently_check_signatures(ex)
    for group, names in BUNDLES.items():
        path = out / group
        manifest = read(path / MEMBERS[-1])
        need(manifest["state"] == "COMPLETE" and set(manifest["files"]) == set(names) - {MEMBERS[-1]}
             and set(p.name for p in path.iterdir()) == set(names), "archived members")
        for name, meta in manifest["files"].items():
            data = (path / name).read_bytes()
            need(meta == {"bytes": len(data), "sha256": sha(data)}, "archived bytes")
        report = read(path / MEMBERS[0])
        rev = report["source_revision"]
        need(manifest["source_revision"] == rev and (rev["commit_sha"], rev["tree_sha"]) == (source.commit_sha, source.tree_sha)
             and report["fixture_only"] and report["runtime_incidents"] == report["host_permission_changes"] == 0, "source or scope")
    checked_checkpoint(out, ex)
    active = read(out / "feed/wolfnet.json")
    final = read(out / "withdrawn/wolfnet.json")
    row, = active["advisories"]
    record = row["record"]
    closed, = final["advisories"]
    withdrawn_head = read(ex / "withdrawn-feed.json")["history"][-1]
    raw_withdrawn, = withdrawn_head["body"]["entries"]
    raw_entry, = read(ex / "feed.json")["history"][0]["body"]["entries"]
    observation = read(ex / "witnesses.json")["witnesses"][0]["body"]
    need(record == raw_entry["record"] and record["evidence_sha256"] == key_digest("observation", observation)
         and record["advisory_id"] == "WN-" + key_digest("advisory-id", [record["subscription"], record["publisher"], record["serial"]])
         and row["state"] == "ACTIVE" and row["effective_level"] == 3 and row["classification"] == "SYNTHETICALLY VERIFIED"
         and set(row["approval_orgs"]) == {3, 4} and row["publisher_org"] == 2 and row["observer"]["org"] == 5, "publication evidence")
    need(final["checkpoint"]["sequence"] == 2 and final["checkpoint"]["head"] == key_digest("frame", withdrawn_head)
         and closed["record"] == raw_withdrawn["record"] and closed["record"]["withdraws"] == key_digest("advisory", record)
         and closed["state"] == "WITHDRAWN", "withdrawal continuity")
    envelope = read(ex / "incident-chain.json")
    registry = read(ex / "incident-registry.json")
    request = read(wp / "request.json")
    chain = envelope["chain"]
    claim = request["claim"]
    chain_hash = frame("cursorial-trace", chain)
    subject = frame("principal", {k: claim[k] for k in ("tenant", "issuer", "trust_domain", "principal")})
    instance = frame("instance", claim)
    host = {e["id"]: e for e in chain["sources"]["host"]["events"]}
    ledger, = chain["sources"]["ledger"]["events"]
    write, = ledger["records"]
    gate = host[ledger["commit"]]
    bind = host[gate["binding"]]
    proposal, = chain["sources"]["agent"]["events"]
    op = operation(proposal["operation"])
    need(observation["trace_sha256"] == chain_hash and observation["binding"] == bind["id"]
         and bind["proposal"] == proposal["id"] and write["operation"] == proposal["operation"] == request["operation"]
         and op == bind["digest"] == gate["digest"] == record["operation_sha256"], "host and ledger operation join")
    need(registry["grants"] == [] and not any(e["kind"] == "grant_observed" for e in host.values())
         and gate["phase"] == "commit" and gate["decision"] == "deny" and ledger["after_count"] - ledger["before_count"] == 1
         and ledger["after_hash"] == operation(ledger["records"]) and ledger["before_hash"] == operation([])
         and (write["tenant"], write["actor"], write["binding"]) == (claim["tenant"], claim["principal"], bind["id"])
         and row["observation"]["reference_commit"] == row["observation"]["host_commit"] == "deny"
         and row["observation"]["effects"] == 1, "observed fictional effect without current grant")
    arch = architecture(read(wp / "architecture.json"))
    need((record["subject"]["principal_id"], record["subject"]["instance_id"], record["subject"]["architecture_sha256"])
         == (subject, instance, arch) and observation["subject"] == record["subject"] and arch == claim["architecture_sha256"]
         and [s["statement"] for s in registry["sessions"]].count(claim) == 1, "pinned historical identity")
    for phase in ("prepare", "commit"):
        anchor, = [a for a in registry["bindings"] if a["phase"] == phase]
        witness, = [s for s in envelope["identity_witnesses"] if s["phase"] == phase]
        phase_gate, = [h for h in host.values() if h.get("phase") == phase]
        need(anchor["trace_sha256"] == chain_hash and anchor["operation_sha256"] == op
             and anchor["binding"] == witness["binding"] == bind["id"] and anchor["at"] == phase_gate["at"]
             and witness["claim"] == claim and anchor["statement_sha256"] == frame("statement", claim), "identity at both gates")
    for group, action, policy in (("advisory", "MONITOR", "policy"), ("opt-in", "DENY", "policy-opt-in"),
                                  ("restored", "ALLOW", "policy-opt-in")):
        d = read(out / group / "wolfnet.json")["decision"]
        need((d["principal_id"], d["instance_id"], d["operation_sha256"], d["resource_scope"])
             == (subject, instance, op, request["operation"]["resource"])
             and d["policy_sha256"] == key_digest("local-policy", read(ex / (policy + ".json")))
             and d["host_authority_sha256"] == frame("registry", read(wp / "fixture-registry.json"))
             and d["registry_proposal"] == d["proposed_action"] == action and d["host_proposal"] == "ALLOW"
             and d["at"] < d["valid_until"] and not d["enforced"] and d["current_scoped_grant"]
             and d["audit_sha256"] == key_digest("decision", {k: v for k, v in d.items() if k != "audit_sha256"}), "subscriber decision")
    challenge = read(out / "challenge/wolfnet.json")
    expected = {f"WN-{p}-{n}": v for p in range(1, 5) for n, v in {**{n: list(t) for n, t in EXPECT.items()}, **REJECTIONS}.items()}
    need(len(challenge["cases"]) == len(expected) and {r["id"]: r["observed"] for r in challenge["cases"]} == expected, "case oracle")
    need({r["id"]: r["observed"] for r in challenge["filesystem_controls"]} == {"IO-" + k: v for k, v in FILE_EXPECT.items()},
         "filesystem oracle")
    need(all(r["matched"] and r["expected"] == r["observed"] for r in challenge["input_controls"] + challenge["signature_controls"])
         and all(d["mismatches"] > 0 for d in challenge["defective_controls"]), "hostile inputs and defective controls")
    stats = challenge["summary"]
    need(stats["cases"] == 427 and stats["mismatches"] == 0 and stats["defects_caught"] == stats["defects"] == 11, "coverage")
    return {"summary": stats, "openssl_verified_signatures": sigs, "openssl_tampered_messages_rejected": sigs,
            "independently_scored_registry_policy_cases": len(expected), "selected_fictional_effects": 1,
            "selected_host_decision": gate["decision"], "subscriber_proposals": ["MONITOR", "DENY", "ALLOW"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-head", required=True)
    p.add_argument("--parent-netns")
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    root = repository_root()
    os.chdir(root)
    source = capture_source_revision(root)
    need(not source.dirty and source.commit_sha == args.expected_head, "clean exact source required")
    if args.parent_netns:
        need(os.readlink("/proc/self/ns/net") != args.parent_netns and {name for _, name in socket.if_nameindex()} == {"lo"},
             "loopback-only namespace required")
    out = args.output_dir.absolute()
    need(out == out.resolve() and not out.is_relative_to(root), "fresh external qualification directory required")
    out.mkdir(mode=0o700)
    run("wolftrap.public_guard", args.expected_head, "--workflow-dependencies")
    run("wolftrap.test_runner", "--pattern", "test_wolfnet*.py", "--output", out / "unit-tests.json")
    unit = read(out / "unit-tests.json")
    need(unit["successful"] and unit["tests_run"] >= 42 and not unit["skipped"] and not unit["expected_failures"]
         and unit["source_revision"] == source.to_dict(), "isolated WolfNet unit qualification")
    names = [group + "/" + name for group, members in BUNDLES.items() for name in members]
    with tempfile.TemporaryDirectory() as temp:
        for target in (out, Path(temp)):
            run_bundles(target, root, source)
        need(all((out / name).read_bytes() == (Path(temp) / name).read_bytes() for name in names), "evidence byte reproducibility")
    checks = independent_check(out, root, source)
    from wolftrap.wolfnet_crypto import sodium
    need(capture_source_revision(root) == source, "unstable qualification source")
    write_json_report({"schema": "wolftrap.wolfnet-qualification/v1", "status": "PASSED_BOUNDED",
                       "source_revision": source.to_dict(), "loopback_only_namespace_verified": bool(args.parent_netns),
                       "python": platform.python_version(), "libsodium": sodium().sodium_version_string().decode("ascii"),
                       "unit_tests": unit["tests_run"], "byte_identical_artifacts": len(names), **checks}, out / "qualification.json")
    run("wolftrap.public_guard", args.expected_head, "--report-root", out,
        *(v for name in ["unit-tests.json", "qualification.json", *names] for v in ("--report", name)))


if __name__ == "__main__":
    main()
