"""Source-bound WolfNet commands. All selected material is read as inert local data."""

from __future__ import annotations

from .agent_scan import _json, _sha
from .cursorial_evidence import _deliver, _input, _path, source_identity
from .cursorial_trace import Gap, decode_json, need
from .wolfprint_evidence import REQUIRED as WP_REQUIRED, pinned
from .wolfnet_challenge import qualify
from .wolfnet_format import GAP, LEVELS, time_value
from .wolfnet_policy import evaluate
from .wolfnet_witness import inspect_feed

REQUIRED = WP_REQUIRED + tuple("src/wolftrap/" + n for n in (
    "wolfnet_crypto.py", "wolfnet_format.py", "wolfnet_feed.py", "wolfnet_witness.py", "wolfnet_policy.py",
    "wolfnet_challenge.py", "wolfnet_fixtures.py", "wolfnet_corpus.py", "wolfnet_reference.py",
    "wolfnet_evidence.py", "schemas/wolfnet-v1.schema.json"))
MEMBERS = ("wolfnet.json", "wolfnet.md", "wolfnet.sarif", "wolfnet.manifest.json")
CHECKPOINT = "wolfnet-checkpoint.json"
LIMITS = ["Signatures authenticate bytes under subscriber-selected keys. Independent evidence determines support for a finding.",
          "All agent subjects and effects are fictional. Runtime attribution, holder possession and Level 4 are unqualified.",
          "CLEAR describes this operation in the selected feed, issuer and tenant at the supplied time.",
          "Subscriber storage supplies freshness. Offline inspection cannot discover withheld updates or undisclosed key compromise.",
          "Public fixture signing seeds are reproducible. The example trust bundle is suitable only for this fictional laboratory."]


def _bundle(mode, result, revision, sources, at, accepted=False):
    report = {**result, "schema": "wolftrap.wolfnet-report/v1", "mode": mode, "source_revision": revision,
              "source_sha256": sources, "as_of": at, "use_accepted": accepted, "signature_scheme": "Ed25519/libsodium-23",
              "fixture_only": True, "runtime_incidents": 0, "host_permission_changes": 0, "limitations": LIMITS}
    lines = ["# WolfNet v1", "", "**" + report["status"] + "**", "", "Source commit `" + revision["commit_sha"] + "`",
             "", "Source tree `" + revision["tree_sha"] + "`", ""]
    signals = []
    if "reason" in result:
        lines.append(result["reason"])
        signals.append(("WT-WN-GAP", result["reason"]))
    elif mode == "feed":
        lines += [f"Verified sequence {report['checkpoint']['sequence']}.", "",
                  "| Advisory | Lifecycle | Reported level | Supported level | Confidence | Subject assurance | Evidence |",
                  "| --- | --- | ---: | --- | --- | --- | --- |"]
        for row in report["advisories"]:
            r = row["record"]
            level = "UNKNOWN" if row["effective_level"] is None else LEVELS[row["effective_level"]]
            lines.append(f"| {r['advisory_id']} | {row['state']} | {r['severity']} | {level} | {r['confidence']} | "
                         f"{row['identity_assurance']} | {row['classification']} |")
            if row["state"] == "ACTIVE":
                signals.append(("WT-WN-GAP" if row["effective_level"] is None else "WT-WN-ADVISORY", row["basis"]))
    elif mode == "evaluate":
        d = report["decision"]
        lines += ["Registry proposal " + str(d["registry_proposal"]), "", "Local host proposal " + d["host_proposal"],
                  "", "Combined simulation " + d["proposed_action"], "", "Basis " + d["basis"],
                  "", "Severity " + d["severity_label"] + ", confidence " + str(d["confidence"]) +
                  ", subject assurance " + d["subject_assurance"], "", "Audit digest `" + d["audit_sha256"] + "`"]
        if d["registry_proposal"] != "ALLOW":
            signals.append(("WT-WN-GAP" if d["registry_proposal"] is None else "WT-WN-ADVISORY", d["basis"]))
    else:
        s = report["summary"]
        lines += [f"{s['cases']} controls, {s['mismatches']} expectation mismatches.",
                  f"{s['defects_caught']} of {s['defects']} deliberately defective controls detected.", "",
                  "| Control | Mismatches | First counterexample |", "| --- | ---: | --- |"]
        lines += [f"| {d['control']} | {d['mismatches']} | {d['first_counterexample']} |" for d in report["defective_controls"]]
        if report["exit_code"]:
            signals.append(("WT-WN-CONTROL", "A qualification control failed."))
    lines += ["", "## Limits", ""] + ["- " + limit for limit in LIMITS] + [""]
    rules = ("WT-WN-ADVISORY", "WT-WN-GAP", "WT-WN-CONTROL")
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "WolfTrap WolfNet", "rules": [{"id": v} for v in rules]}},
             "results": [{"ruleId": rule, "level": "note", "message": {"text": msg}} for rule, msg in signals],
             "invocations": [{"executionSuccessful": report["exit_code"] != 2}], "properties": {"status": report["status"]}}]}
    files = {MEMBERS[0]: _json(report), MEMBERS[1]: "\n".join(lines).encode(), MEMBERS[2]: _json(sarif)}
    if mode == "feed" and "checkpoint" in report:
        files[CHECKPOINT] = _json(report["checkpoint"])
    files[MEMBERS[-1]] = _json({"schema": "wolftrap.wolfnet-manifest/v1", "source_revision": revision, "state": "COMPLETE",
                                "mode": mode, "files": {k: {"sha256": _sha(v), "bytes": len(v)} for k, v in files.items()}})
    return report, files


def _read_options(args, out):
    names = ("feed", "trust", "checkpoint", "witnesses", "witness_registry", "manifest", "request", "registry", "policy")
    paths = {n: _path(getattr(args, n)) for n in names if getattr(args, n, None) is not None}
    traces = getattr(args, "trace", []) or []
    need(len(traces) <= 4, "too-many-selected-traces")
    paths.update({f"trace_{i}": _path(p) for i, p in enumerate(traces)})
    for path in paths.values():
        need(not out.is_relative_to(path.parent) and not path.parent.is_relative_to(out), "evidence-overlaps-input-directory")
    raw = {k: _input(p) for k, p in paths.items()}
    for name in ("trust", "checkpoint", "witness_registry", "registry", "policy"):
        pin = getattr(args, name + "_sha256", None)
        need((name in paths) == (pin is not None), name + "-independent-pin-required")
        if name in paths:
            pinned(raw[name], pin, name)
    return paths, raw


def _feed(docs, at, accepted):
    return inspect_feed(docs["feed"], docs["trust"], docs["checkpoint"],
                        docs.get("witnesses", {"schema": "wolftrap.wolfnet-witnesses/v1", "witnesses": []}),
                        [v for k, v in docs.items() if k.startswith("trace_")], docs.get("witness_registry"), at,
                        use_accepted=accepted)


def run(args):
    verify = bool(getattr(args, "evidence_dir", None))
    out = _path(args.evidence_dir if verify else args.output_dir)
    revision = source_identity(args.expected_head, required_files=REQUIRED)
    mode = {"verify-wolfnet-feed": "feed", "evaluate-wolfnet": "evaluate"}.get(args.command, "challenge")
    paths, raw = _read_options(args, out)
    hashes = {k: _sha(v) for k, v in raw.items()}
    feed_hashes = {k: v for k, v in hashes.items() if k not in ("registry", "manifest", "request", "policy")}
    at = getattr(args, "at", None)
    accepted = getattr(args, "use_accepted", False)
    replayed_feed = None
    if mode == "challenge":
        result = qualify()
    else:
        time_value(at)
        verified_dir = None
        if mode == "evaluate":
            verified_dir = _path(args.verified_feed_dir)
            need(not out.is_relative_to(verified_dir) and not verified_dir.is_relative_to(out), "evidence-directory-overlap")
        try:
            docs = {k: decode_json(v, canonical_numbers=True) for k, v in raw.items()}
            if mode == "evaluate":
                prior_time = args.verified_at or at
                time_value(prior_time)
                need(prior_time <= at, "evaluation-before-verified-feed")
                prior = _feed(docs, prior_time, accepted)
                expected = _bundle("feed", prior, revision, feed_hashes, prior_time, accepted)[1]
                _deliver(expected, verified_dir, True)
                replayed_feed = (expected, verified_dir)
                feed = prior if prior_time == at else _feed(docs, at, accepted)
                result = evaluate(feed, docs["trust"], docs["policy"], docs["manifest"], docs["request"], docs["registry"], at)
                result["verified_feed_manifest_sha256"] = _sha(expected[MEMBERS[-1]])
                result["verified_at"] = prior_time
            else:
                result = _feed(docs, at, accepted)
        except Gap as exc:
            result = {"status": "BLOCKED" if str(exc).startswith("BLOCKED-") else GAP,
                      "exit_code": 2, "reason": str(exc)}
    report, files = _bundle(mode, result, revision, hashes, at, accepted)
    need(source_identity(revision["commit_sha"], required_files=REQUIRED) == revision, "engine-changed-during-inspection")
    need(all(_input(p) == raw[k] for k, p in paths.items()), "source-changed-during-inspection")
    if replayed_feed:
        _deliver(*replayed_feed, True)
    _deliver(files, out, verify)
    if verify:
        need(all(_input(p) == raw[k] for k, p in paths.items()), "source-changed-during-replay")
    return report


def command(args):
    try:
        report = run(args)
        print(("VERIFIED_EVIDENCE " if getattr(args, "evidence_dir", None) else "") + report["status"])
        return report["exit_code"]
    except Gap as exc:
        print(("BLOCKED " if str(exc).startswith("BLOCKED-") else "INCONCLUSIVE ") + str(exc))
    except (OSError, ValueError):
        print("INCONCLUSIVE unsafe or unavailable local evidence")
    return 2
