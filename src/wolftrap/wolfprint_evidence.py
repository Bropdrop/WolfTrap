"""Pinned local inputs, redacted WolfPrint evidence and independent byte replay."""

from __future__ import annotations

import re

from .agent_scan import _json, _sha
from .cursorial_evidence import _deliver, _input, _path, source_identity
from .cursorial_trace import Gap, decode_json, need
from .wolfprint import OPTIONAL, UNKNOWN
from .wolfprint_challenge import qualify
from .wolfprint_identity import ATTESTED, GAP, inspect
from .wolfprint_trace import inspect_chain

MEMBERS = ("wolfprint.json", "wolfprint.md", "wolfprint.sarif", "wolfprint.manifest.json")
REQUIRED = tuple("src/wolftrap/" + name for name in (
    "wolfprint.py", "wolfprint_identity.py", "wolfprint_trace.py", "wolfprint_challenge.py",
    "wolfprint_fixtures.py", "wolfprint_reference.py", "wolfprint_evidence.py", "schemas/wolfprint-v1.schema.json"))
LIMITATIONS = [
    "Identity agreement is conditional on an independently pinned fictional registry and a supplied logical time.",
    "Holder possession, publisher authenticity, live agents, model weights and production effects are unverified.",
    "Unknown or unobserved session reuse and authority changes outside the selected registry window are unresolved.",
    "The behavioral digest supports tenant-scoped investigation. It supplies no identity or policy authority.",
    "SHA-256 binds bytes. Public fixture aliases and low-entropy values can be guessed.",
]


def pinned(data: bytes, pin: str | None, kind: str):
    need(isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin) is not None and _sha(data) == pin,
         kind + "-pin-missing-or-mismatch")


def _selected(docs, at):
    row = inspect(docs["manifest"], docs.get("request"), docs.get("registry"), at, docs.get("baseline"))
    identity, policy = row["identity"], row["policy_proposal"]
    missing = any(v == UNKNOWN for k, v in row["coverage"].items() if k != OPTIONAL)
    if "request" not in docs:
        code = 2 if missing else int("CHANGED_ARCHITECTURE" in row["classification"])
    elif identity["status"] == GAP:
        code = 2
    else:
        code = int(identity["status"] != ATTESTED or policy["action"] != "ALLOW" or
                   bool(set(row["classification"]) & {"CHANGED_ARCHITECTURE", "SIMILAR_ARCHITECTURE_OTHER_PRINCIPAL"}))
    if "chain" in docs:
        need("request" in docs and "registry" in docs, "selected-trace-needs-request-and-registry")
        trace = inspect_chain(docs["chain"], docs["registry"])["identity_profile"]
        row["behavior_evidence"] = {"trace_sha256": trace["trace_sha256"], "status": trace["status"], "reason": trace["reason"]}
        phases = [phase for attempt in trace["attempts"] for phase in attempt["phases"].values()]
        same = bool(phases) and all(phase["instance_id"] == identity["instance_id"] and phase["at"] <= at for phase in phases)
        operation_present = any(a["operation_sha256"] == policy["operation_sha256"] for a in trace["attempts"])
        if trace["behavioral_sha256"] != UNKNOWN and same and operation_present:
            row["behavioral_sha256"] = trace["behavioral_sha256"]
        else:
            row["behavior_evidence"]["binding"] = "incomplete-or-different-request"
            code = 2
    status = ("FINGERPRINT_RECORDED" if policy is None else "FIXTURE_EVIDENCE_VERIFIED") if code == 0 else (
        "REVIEW_REQUIRED" if code == 1 else "INCONCLUSIVE")
    return {"schema": "wolftrap.wolfprint-evidence/v1", "mode": "selected", "status": status, "exit_code": code, **row}


def _render(report):
    status = report["status"]
    lines = ["# WolfPrint v1", "", "**" + status + "**", "",
             "Source commit `" + report["source_revision"]["commit_sha"] + "`", "",
             "Source tree `" + report["source_revision"]["tree_sha"] + "`", ""]
    signals = []
    if report["mode"] == "qualification":
        s = report["summary"]
        lines += [f"{s['cases']} synthetic cases, {s['mismatches']} expectation mismatches.",
                  f"{s['defects_caught']} of {s['defects']} deliberately defective controls caught.", "",
                  "| Defective control | Mismatches | First counterexample |", "| --- | ---: | --- |"]
        for row in report["defective_controls"]:
            lines.append(f"| {row['control']} | {row['mismatches']} | {row['first_counterexample'] or 'none'} |")
        if status != "PASSED_BOUNDED":
            signals.append(("WT-WP-CONTROL", "error", "A fictional expectation or mutation control failed."))
    else:
        identity, proposal = report["identity"], report["policy_proposal"]
        lines += ["Architecture `" + report["architecture_sha256"] + "`", "", "Issuer evidence " + identity["status"],
                  "", "Basis " + identity["reason"], "", "Classification " + ", ".join(report["classification"]),
                  "", "Behavioral digest `" + report["behavioral_sha256"] + "`", "",
                  "| Architecture component | Coverage |", "| --- | --- |"]
        lines += [f"| {k} | {v} |" for k, v in sorted(report["coverage"].items())]
        if proposal:
            lines += ["", "Simulated policy proposal **" + proposal["action"] + "**", "",
                      "Decision basis " + proposal["reason"], "", "Audit digest `" + proposal["audit_sha256"] + "`",
                      "", "Review route " + proposal["appeal"]["route"]]
        if report["exit_code"]:
            reason = report.get("behavior_evidence", {}).get("binding") or (proposal or identity)["reason"]
            signals.append(("WT-WP-GAP" if report["exit_code"] == 2 else "WT-WP-REVIEW", "note", reason))
    lines += ["", "## Limits", ""] + ["- " + limit for limit in LIMITATIONS] + [""]
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "WolfTrap WolfPrint", "rules": [
        {"id": rule} for rule in ("WT-WP-CONTROL", "WT-WP-GAP", "WT-WP-REVIEW")]}},
        "invocations": [{"executionSuccessful": report["exit_code"] != 2}],
        "results": [{"ruleId": rule, "level": level, "message": {"text": msg}} for rule, level, msg in signals],
        "properties": {"status": status, "mode": report["mode"], "synthetic_only": True}}]}
    files = {MEMBERS[0]: _json(report), MEMBERS[1]: "\n".join(lines).encode(), MEMBERS[2]: _json(sarif)}
    files[MEMBERS[-1]] = _json({"schema": "wolftrap.wolfprint-manifest/v1", "state": "COMPLETE",
                                "source_revision": report["source_revision"], "source_sha256": report["source_sha256"],
                                "files": {k: {"bytes": len(v), "sha256": _sha(v)} for k, v in files.items()}})
    return files


def run(directory, *, manifest=None, request=None, registry=None, registry_sha256=None, at=None,
        baseline=None, baseline_sha256=None, chain=None, expected_head=None, verify=False):
    out = _path(directory)
    revision = source_identity(expected_head, required_files=REQUIRED)
    inputs = {k: _path(v) for k, v in (("manifest", manifest), ("request", request), ("registry", registry),
                                          ("baseline", baseline), ("chain", chain)) if v is not None}
    need(len(set(inputs.values())) == len(inputs), "aliased-input-roles")
    for path in inputs.values():
        need(not out.is_relative_to(path.parent) and not path.parent.is_relative_to(out), "evidence-overlaps-input-directory")
    need((registry is None) == (registry_sha256 is None) == (at is None), "registry-pin-and-logical-time-required")
    need((baseline is None) == (baseline_sha256 is None), "baseline-pin-required")
    raw = {k: _input(p) for k, p in inputs.items()}
    if registry is not None:
        pinned(raw["registry"], registry_sha256, "registry")
    if baseline is not None:
        pinned(raw["baseline"], baseline_sha256, "baseline")
    if manifest is None:
        need(not inputs, "selected-manifest-missing")
        report = qualify()
        report["exit_code"] = int(report["status"] != "PASSED_BOUNDED")
    else:
        docs = {k: decode_json(v, canonical_numbers=True) for k, v in raw.items()}
        report = _selected(docs, at)
    report.update(source_revision=revision, source_sha256={k: _sha(v) for k, v in raw.items()},
                  logical_time=at, synthetic_identity_only=True, external_credential_verification=False,
                  production_effects=0, authorization_changes=0, limitations=LIMITATIONS)
    files = _render(report)
    need(source_identity(revision["commit_sha"], required_files=REQUIRED) == revision, "engine-changed-during-analysis")
    need(all(_input(p) == raw[k] for k, p in inputs.items()), "source-changed-during-analysis")
    _deliver(files, out, verify)
    if verify:
        need(all(_input(p) == raw[k] for k, p in inputs.items()), "source-changed-during-replay")
    return report


def command(args):
    verify = args.command.startswith("verify-")
    options = {k: getattr(args, k, None) for k in ("manifest", "request", "registry", "registry_sha256", "at",
                                                     "baseline", "baseline_sha256", "chain", "expected_head")}
    try:
        report = run(args.evidence_dir if verify else args.output_dir, verify=verify, **options)
        print(("VERIFIED_EVIDENCE " if verify else "") + report["status"])
        return report["exit_code"]
    except Gap as exc:
        print("INCONCLUSIVE " + str(exc))
    except (ValueError, OSError):
        print("INCONCLUSIVE unsafe or unavailable local evidence")
    return 2
