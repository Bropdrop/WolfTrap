"""Exercise the public verifier and simulator against external authored fixture expectations."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from copy import deepcopy
from pathlib import Path

from .cursorial_evidence import _deliver, _input, _path
from .cursorial_trace import Gap, decode_json
from .wolfnet_corpus import case
from .wolfnet_crypto import sodium, verify
from .wolfnet_fixtures import public_key, sign, wire
from .wolfnet_format import GAP, SYNTHETIC, digest, validate
from .wolfnet_policy import evaluate
from .wolfnet_reference import EXPECT, FILE_EXPECT, REJECTIONS
from .wolfnet_witness import inspect_feed

POLICY_MUTANTS = ("always-allow", "always-deny", "severity-is-certainty", "shared-build-is-principal",
                  "ignore-local-consent", "ignore-withdrawal", "ignore-appeal", "ignore-high-water-mark")


def assess_case(x):
    feed = inspect_feed(x["feed"], x["trust"], x["checkpoint"], x["witnesses"], x["traces"], x["witness_registry"],
                        x["at"], use_accepted=x["accepted"])
    result = evaluate(feed, x["trust"], x["policy"], x["manifest"], x["request"], x["registry"], x["at"])
    return result["decision"]


def _alternative(name, data, actual):
    head = data["feed"]["history"][-1]["body"]
    entries = head["entries"]
    if name == "ignore-high-water-mark" and data["checkpoint"]["sequence"] >= head["sequence"]:
        altered = deepcopy(data)
        scope = data["trust"]["subscription"]
        altered["checkpoint"].update(sequence=0, head=digest("genesis", scope), accepted_at=data["trust"]["clock_origin"])
        altered["accepted"] = False
        try:
            d = assess_case(altered)
        except Gap as exc:
            return str(exc)
        return ["verified", d["effective_level"], d["registry_proposal"], d["classification"]]
    if not isinstance(actual, list):
        return actual
    overridden = list(actual)
    if name in ("always-allow", "always-deny"):
        overridden[2] = "ALLOW" if name == "always-allow" else "DENY"
    elif entries:
        r = entries[0]["record"]
        claim = data["request"]["claim"]
        if name == "severity-is-certainty" and r["severity"] >= 3:
            overridden[1:] = [r["severity"], "DENY", SYNTHETIC]
        elif name == "shared-build-is-principal" and claim and claim["architecture_sha256"] == r["subject"]["architecture_sha256"]:
            overridden[2] = r["recommendation"]
        elif name == "ignore-local-consent" and actual[1] == 3:
            overridden[2] = r["recommendation"]
        elif name == "ignore-withdrawal" and r["status"] == "WITHDRAWN":
            overridden[2] = r["recommendation"]
        elif name == "ignore-appeal" and r["advisory_id"] in data["policy"]["appeal_holds"]:
            overridden[2] = r["recommendation"]
    return overridden


def _signature_controls():
    results = []
    scores = {m: [] for m in ("signature-shape-only", "reject-all-signatures", "ignore-signed-content")}
    for signer in (1, 2, 3, 5):
        role = {1: "distributor", 2: "publisher", 3: "reviewer", 5: "observer"}[signer]
        body = {"fixture": signer}
        seal = sign(role, signer, body)
        pk = bytes.fromhex(public_key(signer)["public_key"])
        original = wire("signature/" + role, {"alg": "Ed25519", "signer": signer, "key_revision": 1, "body": body})
        sig = bytes.fromhex(seal["signature"])
        controls = (("valid", pk, original, sig, True), ("changed-bytes", pk, original + b" ", sig, False),
                    ("other-key", bytes.fromhex(public_key(7)["public_key"]), original, sig, False),
                    ("empty", pk, original, bytes(64), False), ("truncated", pk, original, sig[:-1], False))
        for kind, key, message, signature, expected in controls:
            code = f"SIG-{signer}-{kind}"
            actual = verify(key, message, signature)
            results.append({"id": code, "expected": expected, "observed": actual, "matched": actual == expected})
            variants = (len(signature) == 64, False, verify(key, original, signature))
            for label, alternative in zip(scores, variants, strict=True):
                if alternative != expected:
                    scores[label].append(code)
    return results, scores


def _input_controls():
    controls = (("duplicate", b'{"a":0,"\\u0061":1}', "duplicate-json-key"),
                ("integer", b'{"n":9999999}', "unsupported-number"), ("negative-zero", b'{"n":-0}', "noncanonical-negative-zero"),
                ("nan", b'{"n":NaN}', "unsupported-number"), ("fraction", b'{"n":2.5}', "unsupported-number"),
                ("oversize", b" " * 98305, "input-byte-limit"), ("depth", b"[" * 13, "json-depth-limit"),
                ("complexity", b"[" + b"0," * 4100 + b"0]", "json-complexity-limit"),
                ("utf8", b"\xff", "malformed-json"), ("truncated", b'{"a":', "malformed-json"),
                ("unicode-lookalike", b'{"schema":"wolftrap.wolfn\\u0435t-feed/v1","history":[]}', "invalid-feed-shape"),
                ("unknown-field", b'{"raw_prompt":"fictional-data"}', "invalid-feed-shape"))
    rows = []
    for name, raw, expected in controls:
        try:
            validate(decode_json(raw, canonical_numbers=True), "feed")
            reason = "accepted"
        except Gap as exc:
            reason = str(exc)
        rows.append({"id": "JSON-" + name, "observed": reason, "expected": expected, "matched": reason == expected})
    return rows


def _exercise_file(root, kind):
    source_dir = root / "input"
    source_dir.mkdir()
    source = source_dir / "fixture.json"
    raw = b'{"fixture":1}'
    source.write_bytes(raw)
    if kind in ("regular-input", "traversal", "linked-input", "linked-parent", "hardlinked-input", "fifo-input"):
        path = source
        if kind == "traversal":
            path = source_dir / ".." / "input" / source.name
        elif kind in ("linked-input", "hardlinked-input", "fifo-input"):
            path = root / "selected"
            if kind == "linked-input":
                path.symlink_to(source)
            elif kind == "hardlinked-input":
                path.hardlink_to(source)
            else:
                os.mkfifo(path)
        elif kind == "linked-parent":
            parent = root / "linked"
            parent.symlink_to(source_dir, target_is_directory=True)
            path = parent / source.name
        return _input(_path(path)) == raw
    directory = root / "evidence"

    def manifest(report):
        return json.dumps({"files": {"wolfnet.json": {"bytes": len(report), "sha256": hashlib.sha256(report).hexdigest()}}},
                          sort_keys=True).encode("ascii")

    files = {"wolfnet.json": raw, "wolfnet.manifest.json": manifest(raw)}
    _deliver(files, directory, False)
    if kind == "missing-member":
        (directory / "wolfnet.json").unlink()
    elif kind == "extra-member":
        (directory / "extra").write_bytes(b"{}")
    elif kind == "changed-manifest":
        (directory / "wolfnet.manifest.json").write_bytes(b"{}")
    elif kind == "rehashed-report":
        changed = b'{"fixture":2}'
        (directory / "wolfnet.json").write_bytes(changed)
        (directory / "wolfnet.manifest.json").write_bytes(manifest(changed))
    _deliver(files, directory, True)
    return True


def _filesystem_controls():
    rows = []
    for kind, expected in FILE_EXPECT.items():
        with tempfile.TemporaryDirectory() as temp:
            try:
                observed = _exercise_file(Path(temp), kind)
            except (OSError, Gap):
                observed = False
        rows.append({"id": "IO-" + kind, "expected": expected, "observed": observed, "matched": expected == observed})
    return rows


def qualify():
    sodium()
    rows = []
    scores = {k: [] for k in POLICY_MUTANTS}
    for profile in range(4):
        for family in (*EXPECT, *REJECTIONS):
            data = case(profile, family)
            code = f"WN-{profile + 1}-{family}"
            expected = list(EXPECT[family]) if family in EXPECT else REJECTIONS[family]
            audit, host, subject = None, None, None
            try:
                d = assess_case(data)
                actual = ["verified", d["effective_level"], d["registry_proposal"], d["classification"]]
                audit, host, subject = d["audit_sha256"], d["host_proposal"], d["principal_id"]
                integrity = not d["enforced"] and (d["proposed_action"] == "DENY" if host == "DENY" else True)
            except Gap as exc:
                actual, integrity = str(exc), True
            rows.append({"id": code, "expected": expected, "observed": actual, "matched": actual == expected and integrity,
                         "candidate_feed_sha256": digest("fixture-input", data["feed"]), "decision_sha256": audit,
                         "host_proposal": host, "principal_id": subject})
            for name in POLICY_MUTANTS:
                if _alternative(name, data, actual) != expected:
                    scores[name].append(code)
    signatures, sig_scores = _signature_controls()
    scores.update(sig_scores)
    parser = _input_controls()
    filesystem = _filesystem_controls()
    failures = sum(not r["matched"] for r in [*rows, *signatures, *parser, *filesystem])
    mutants = [{"control": name, "mismatches": len(ids), "first_counterexample": next(iter(ids), None)}
               for name, ids in scores.items()]
    caught = sum(bool(ids) for ids in scores.values())
    passed = not failures and caught == len(mutants)
    return {"status": "PASSED_BOUNDED" if passed else "CONTROL_GAP", "exit_code": 0 if passed else 1,
            "summary": {"cases": len(rows) + len(signatures) + len(parser) + len(filesystem), "registry_policy_cases": len(rows),
                        "signature_cases": len(signatures), "parser_cases": len(parser), "filesystem_cases": len(filesystem), "mismatches": failures,
                        "defects": len(mutants), "defects_caught": caught, "runtime_incidents": 0,
                        "decision_counts": dict(Counter(str(r["observed"][2]) for r in rows if isinstance(r["observed"], list)))},
            "cases": rows, "signature_controls": signatures, "input_controls": parser, "filesystem_controls": filesystem,
            "defective_controls": mutants}
