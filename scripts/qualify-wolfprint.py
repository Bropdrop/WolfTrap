"""Qualify and independently inspect saved fictional evidence at a clean source revision."""

from __future__ import annotations

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
from wolftrap.wolfprint_reference import EXPECT, architecture, frame, operation

REGISTRY_PIN = "5d7517fd9b15ad2ed73820b23d7907518ed7ac296f69b9697643b71c39668430"
WOLFPRINT = ("wolfprint.json", "wolfprint.md", "wolfprint.sarif", "wolfprint.manifest.json")
CURSORIAL = ("cursorial.json", "cursorial-chains.json", "cursorial.md", "cursorial.sarif", "cursorial.manifest.json")


def need(test, message):
    if not test:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_bytes())


def run(*args):
    subprocess.run([sys.executable, "-m", *map(str, args)], check=True)


def independent_check(out, root, source):
    """Read saved files. Do not call the candidate verifier, policy or trace analyzer."""
    example = root / "examples/wolfprint"
    manifest, request, registry, envelope = (read(example / n) for n in
        ("architecture.json", "request.json", "fixture-registry.json", "identity-chain.json"))
    need(hashlib.sha256((example / "fixture-registry.json").read_bytes()).hexdigest() == REGISTRY_PIN, "issuer pin")
    selected = read(out / "selected/wolfprint.json")
    s = request["claim"]
    principal = frame("principal", {k: s[k] for k in ("trust_domain", "issuer", "tenant", "principal")})
    instance = frame("instance", s)
    need(architecture(manifest) == s["architecture_sha256"] == selected["architecture_sha256"], "architecture mismatch")
    need([a["statement"] for a in registry["sessions"]].count(s) == 1 and s["issued"] <= 30 < s["expires"], "issuer record")
    need((principal, instance) == (selected["identity"]["principal_id"], selected["identity"]["instance_id"]), "subject binding")
    policy = selected["policy_proposal"]
    grant, = registry["grants"]
    need((grant["principal"], grant["scope"], grant["operation_sha256"], grant["delegation"], grant["epoch"]) ==
         (s["principal"], request["operation"]["resource"], operation(request["operation"]), s["delegation"], registry["epoch"])
         and grant["revoked_at"] is None and grant["since"] <= 30 < grant["expires"] and not registry["restrictions"]
         and grant["policy_revision"] == registry["policy_revision"] == s["policy_revision"]
         and policy["action"] == "ALLOW" and policy["write_eligible_in_model"] and not policy["enforced"], "scoped policy")
    need(frame("policy-audit", {k: v for k, v in policy.items() if k != "audit_sha256"}) == policy["audit_sha256"], "audit")
    chain = envelope["chain"]
    report = read(out / "cursorial/cursorial.json")["identity_profile"]
    need(report["trace_sha256"] == frame("cursorial-trace", chain), "independent trace binding")
    host = {e["id"]: e for e in chain["sources"]["host"]["events"]}
    ledger = {e["id"]: e for e in chain["sources"]["ledger"]["events"]}
    proposals = {e["id"]: e for e in chain["sources"]["agent"]["events"]}
    projection = []
    for attempt in report["attempts"]:
        bind = host[attempt["binding"]]
        op = proposals[bind["proposal"]]["operation"]
        need(attempt["initiator"] == {"at": proposals[bind["proposal"]]["at"], "principal_id": principal,
                                     "instance_id": instance}, "proposal initiator")
        receipt = ledger[attempt["effect_event"]]
        need(operation(op) == bind["digest"] == attempt["operation_sha256"], "operation binding")
        for phase in ("prepare", "commit"):
            row = attempt["phases"][phase]
            matches = [a for a in registry["bindings"] if a["phase"] == phase and a["binding"] == bind["id"]]
            anchor, = matches
            need(anchor["trace_sha256"] == report["trace_sha256"] and anchor["at"] == row["at"]
                 and anchor["statement_sha256"] == frame("statement", s) and anchor["operation_sha256"] == operation(op)
                 and anchor["proposal"] == bind["proposal"] and row["principal_id"] == principal
                 and row["instance_id"] == instance and row["host_delegation_event"] == bind["delegation"], "host identity join")
        gates = [row["decision"] for row in sorted(host.values(), key=lambda e: e["at"])
                 if row["kind"] == "gate_decision" and row["binding"] == bind["id"]]
        count = receipt["after_count"] - receipt["before_count"]
        need(len(receipt["records"]) == attempt["independently_observed_effects"] == count == 1
             and receipt["records"][0]["operation"] == op and host[receipt["commit"]]["binding"] == bind["id"], "ledger join")
        projection.append([op["verb"], *gates, count])
    tenant = frame("tenant", [registry[k] for k in ("trust_domain", "issuer", "tenant")])
    observed = frame("behavior", {"tenant": tenant, "observations": projection})
    need(bool(projection) and observed == report["behavioral_sha256"] == selected["behavioral_sha256"], "redacted behavior")
    challenge = read(out / "challenge/wolfprint.json")
    expected = {f"WP-{p}-{name}": result for p in range(1, 5) for name, result in EXPECT.items()}
    need(len(challenge["cases"]) == len(expected) and {c["id"] for c in challenge["cases"]} == expected.keys(), "case coverage")
    for c in challenge["cases"]:
        need((c["identity_status"], tuple(c["classification"]), c["action"], c["current_scoped_grant"]) == expected[c["id"]],
             "independent authored outcome")
    need(all(row["matched"] and row["expected"] == row["observed"] for row in challenge["traces"] + challenge["invalid_inputs"]),
         "boundary or hostile control mismatch")
    summary = challenge["summary"]
    need(summary["cases"] == 256 and summary["mismatches"] == 0 and summary["defects_caught"] == summary["defects"] == 11
         and all(d["mismatches"] > 0 for d in challenge["defective_controls"]), "mutation or coverage failure")
    for name, members in (("selected", WOLFPRINT), ("challenge", WOLFPRINT), ("cursorial", CURSORIAL)):
        data = read(out / name / members[-1])
        need(data["source_revision"]["commit_sha"] == source.commit_sha and data["source_revision"]["tree_sha"] == source.tree_sha,
             "archived source identity")
        need(set(data["files"]) == set(members[:-1]), "missing archived member")
        for member, meta in data["files"].items():
            raw = (out / name / member).read_bytes()
            need(len(raw) == meta["bytes"] and hashlib.sha256(raw).hexdigest() == meta["sha256"], "archived digest")
    return {"summary": summary, "independently_scored_identity_cases": len(expected), "selected_effect_windows": len(projection),
            "selected_effects": sum(row[-1] for row in projection), "selected_behavioral_sha256": observed}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-head", required=True)
    p.add_argument("--parent-netns")
    p.add_argument("--output-dir", required=True, type=Path)
    args = p.parse_args()
    root = repository_root()
    os.chdir(root)
    rev = capture_source_revision(root)
    need(not rev.dirty and rev.commit_sha == args.expected_head, "clean exact source required")
    if args.parent_netns:
        need(os.readlink("/proc/self/ns/net") != args.parent_netns and {n for _, n in socket.if_nameindex()} == {"lo"},
             "loopback-only namespace required")
    out = args.output_dir.absolute()
    need(out == out.resolve() and not out.is_relative_to(root), "fresh external qualification directory required")
    out.mkdir(mode=0o700)
    run("wolftrap.public_guard", args.expected_head)
    run("wolftrap.test_runner", "--pattern", "test_wolfprint*.py", "--output", out / "unit-tests.json")
    unit = read(out / "unit-tests.json")
    need(unit["successful"] and unit["tests_run"] >= 30 and not unit["skipped"] and not unit["expected_failures"]
         and unit["source_revision"] == rev.to_dict(), "isolated unit qualification")
    ex = Path("examples/wolfprint")
    issuer = ("--registry", ex / "fixture-registry.json", "--registry-sha256", REGISTRY_PIN)
    opts = ("--manifest", ex / "architecture.json", "--request", ex / "request.json", "--at", "30", *issuer,
            "--chain", ex / "identity-chain.json")
    groups = (("challenge", "challenge-wolfprint", "verify-wolfprint", (), WOLFPRINT),
              ("selected", "fingerprint-agent", "verify-agent-fingerprint", opts, WOLFPRINT),
              ("cursorial", "challenge-cursorial", "verify-cursorial",
               ("--chain", ex / "identity-chain.json", "--require-wolfprint", *issuer), CURSORIAL))
    names = []
    with tempfile.TemporaryDirectory() as temp:
        for group, create, verify, options, members in groups:
            for target in (out / group, Path(temp) / group):
                run("wolftrap", create, "--expected-head", args.expected_head, *options, "--output-dir", target)
                run("wolftrap", verify, "--expected-head", args.expected_head, *options, "--evidence-dir", target)
            for member in members:
                name = group + "/" + member
                need((out / name).read_bytes() == (Path(temp) / name).read_bytes(), "nonreproducible evidence")
                names.append(name)
    result = independent_check(out, root, rev)
    need(capture_source_revision(root) == rev, "qualification source changed")
    write_json_report({"schema": "wolftrap.wolfprint-qualification/v1", "status": "PASSED_BOUNDED",
                       "source_revision": rev.to_dict(), "loopback_only_namespace_verified": bool(args.parent_netns),
                       "python": platform.python_version(), "unit_tests": unit["tests_run"],
                       "byte_identical_artifacts": len(names), **result}, out / "qualification.json")
    run("wolftrap.public_guard", args.expected_head, "--report-root", out,
        *(s for name in ["qualification.json", "unit-tests.json", *names] for s in ("--report", name)))


if __name__ == "__main__":
    main()
