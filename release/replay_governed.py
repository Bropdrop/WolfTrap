"""Compare a pinned GitHub artifact with separately reproduced governed evaluation records."""

import argparse
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent / "verifier"))
from release_io import BUNDLE_LIMIT, DOC_LIMIT, Verdict, directory, file_bytes, parse, path, require, sha
from release_policy import hexval

COMMON = {"qualification.json", "unit-tests.json", "custody.json", "readiness.json"}
CHILDREN = COMMON - {"qualification.json"}
INSTALL = "governed/incident-install.json"
CAPSULE = "release-evidence/capsule/awooo-evaluation-00000001.zip"
OTHER = {
    INSTALL,
    CAPSULE,
    "release-evidence/trust/policy.json",
    "release-evidence/trust/root.pem",
    "release-evidence/trust/signer.pem",
    "release-evidence/qualification.json",
    "release-evidence/controls.json",
    "release-evidence/measurement.json",
    "release-evidence/receipt.json",
    "foundation/qualification.json",
}
HOSTED = {"governed/" + name for name in COMMON}
INVENTORY = HOSTED | OTHER
TRANSPORT_LIMIT = 10 * 1024 * 1024
WORKFLOW = ".github/workflows/governed-release-qualification.yml"

# Release-profile expectations are reviewed alongside this verifier. Recomputing
# them from reported "expected" fields would let a broken oracle pass a replay.
CUSTODY_ORACLE = {
    "governed-current-upgrade": "ADMITTED_EVALUATION_BYTES",
    "governed-reconciliation": "RECONCILED_EVALUATION_BYTES",
    "governed-policy-replay": "REJECTED/replayed-policy-generation",
    "governed-withdrawal-overrides-receipt": "REJECTED/manifest-withdrawn",
    "empty-pinned-archive": "VERIFIED_ARCHIVE_BYTES",
    "concurrent-admission": "INCONCLUSIVE/custody-busy-retry",
    "authorized-first-release": "ADMITTED_EVALUATION_BYTES",
    "independently-computed-checkpoint": "VERIFIED_ARCHIVE_BYTES",
    "stale-writer-sequence": "REJECTED/custody-head-sequence-mismatch",
    "self-selected-policy": "REJECTED/independent-policy-pin",
    "substituted-admission": "REJECTED/manifest-or-payload-mismatch",
    "withdrawn-build-admission": "REJECTED/release-withdrawn",
    "compromised-signer-admission": "REJECTED/authority-revoked",
    "authorized-version-upgrade": "ADMITTED_EVALUATION_BYTES",
    "lost-admission-reply": "RECONCILED_EVALUATION_BYTES",
    "mismatched-reconciliation-predecessor": "REJECTED/independent-custody-pin-mismatch",
    "independent-upgrade-checkpoint": "VERIFIED_ARCHIVE_BYTES",
    "expired-subscriber-policy": "REJECTED/policy-not-current",
    "source-replica-overlap": "REJECTED/custody-path-overlap",
    "interrupted-replication": "INCONCLUSIVE/storage-io",
    "interrupted-upload-invisible": "PENDING_REPORTED",
    "resume-replication": "REPLICATED_EVALUATION_BYTES",
    "repeat-replication": "REPLICATED_EVALUATION_BYTES",
    "replica-audits-independently": "VERIFIED_ARCHIVE_BYTES",
    "reject-missing-recovery-version": "REJECTED/unknown-recovery-sequence",
    "wrong-recovery-receipt": "REJECTED/independent-custody-pin-mismatch",
    "recover-primary-from-verified-replica": "RESTORED_BYTES",
    "historical-byte-oracle": "MATCH",
    "preserve-previous-recovery": "REJECTED/sequence-already-in-custody",
    "replica-refuses-equivocation": "REJECTED/independent-custody-pin-mismatch",
    "intact-replica": "ACCEPT",
    "corrupt-historical-bytes": "REFUSE",
    "missing-historical-version": "REFUSE",
    "symlink-storage-substitution": "REFUSE",
    "conflicting-local-history": "REFUSE",
    "stale-checkpoint": "REFUSE",
}
MUTANT_ORACLE = {
    "accept-all": {name for name, outcome in CUSTODY_ORACLE.items() if outcome == "REFUSE"},
    "reject-all": {"intact-replica"},
    "trust-local-pin": {"conflicting-local-history"},
    "head-only": {
        "corrupt-historical-bytes",
        "missing-historical-version",
        "symlink-storage-substitution",
        "stale-checkpoint",
    },
}
REQUIRED_GATES = {
    "reviewed_production_revision",
    "protected_production_branch",
    "independent_source_review",
    "authenticated_production_builder",
    "authorized_release_signer",
    "subscriber_trust_roots",
    "reproducible_tested_artifacts",
    "durable_verified_custody",
    "revocation_and_rollback",
    "qualified_platform_installation",
    "approved_release_documentation",
    "naming_clearance",
}
MODULE_FLOORS = {
    "test_governance_preflight.py": 22,
    "test_governed_custody.py": 7,
    "test_governed_readiness.py": 5,
    "test_governed_subscriber.py": 7,
    "test_governed_replay.py": 7,
}


def hosted_records(raw):
    # Bound the directory before ZipFile allocates one object per entry. This transport
    # profile covers ordinary single-disk GitHub artifacts with stored or deflated data.
    require(len(raw) >= 22, "invalid-zip")
    magic, disk, central, count, total, size, offset, comment = struct.unpack("<4s4H2IH", raw[-22:])
    require(
        magic == b"PK\x05\x06"
        and disk == central == comment == 0
        and 0 < count == total <= len(INVENTORY)
        and size <= count * 512
        and offset + size == len(raw) - 22,
        "zip-directory-bounds",
    )
    records = {}
    names = set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == count, "zip-entry-count")
        for item in entries:
            name = item.filename
            require(
                name == item.orig_filename
                and name in INVENTORY
                and name not in names
                and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                and not item.is_dir()
                and not (item.external_attr & 0x10)
                and item.flag_bits & ~(0x08 | 0x800) == 0
                and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and not item.extra
                and not item.comment,
                "unexpected-zip-entry",
            )
            names.add(name)
            limit = BUNDLE_LIMIT if name == CAPSULE else DOC_LIMIT
            require(0 < item.file_size <= limit and item.compress_size <= len(raw), "zip-entry-size")
            with archive.open(item) as stream:
                data = stream.read(limit + 1)
            require(len(data) == item.file_size, "zip-entry-length")
            if name in HOSTED:
                records[name.split("/")[1]] = data
    require(names == INVENTORY, "incomplete-hosted-artifact", "INCONCLUSIVE")
    return records, sorted(names - HOSTED)


def local_records(folder):
    fd = directory(folder)
    try:
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                require(
                    entry.name in COMMON | {"incident-install.json"} and entry.is_file(follow_symlinks=False),
                    "unexpected-local-entry",
                )
                names.add(entry.name)
        require(COMMON <= names, "missing-local-record", "INCONCLUSIVE")
        return {name: file_bytes(folder / name, DOC_LIMIT) for name in COMMON}
    finally:
        os.close(fd)


def count_matches(value, expected):
    return type(value) is int and value == expected


def validate(records, head, tree):
    docs = {name: parse(raw) for name, raw in records.items()}
    require(all(type(v) is dict for v in docs.values()), "record-schema")
    summary, custody, ready, unit = (
        docs[n]
        for n in (
            "qualification.json",
            "custody.json",
            "readiness.json",
            "unit-tests.json",
        )
    )
    schemas = (
        (
            summary,
            "schema status production commit tree namespace qualification_workflow qualification_workflow_sha256 "
            "legacy_capsule_fixture_workflow authenticated_production_builder governed_unit_tests workflow_policy_tests "
            "custody_cases defective_custody_controls_caught byte_identical_replays sha256",
        ),
        (custody, "schema status scope production_custody cases mutants"),
        (
            ready,
            "schema source status release_authorized production_signing_enabled github_observation conditions unmet evaluation_evidence",
        ),
        (
            unit,
            "run_by_research_engine framework tests_run tests_per_module skipped failures errors expected_failures "
            "unexpected_successes successful source_revision source_revision_end source_stable",
        ),
    )
    require(all(document.keys() == set(fields.split()) for document, fields in schemas), "record-schema")
    require(
        summary.get("schema") == "awooo.governed-qualification/v1"
        and summary["commit"] == head
        and summary["tree"] == tree
        and summary["status"] == "VERIFIED_DISPOSABLE_CONTROLS"
        and summary["production"] == "BLOCKED"
        and summary["authenticated_production_builder"] is False
        and summary["namespace"] == "loopback-only"
        and summary["qualification_workflow"] == WORKFLOW
        and summary["qualification_workflow_sha256"]
        == sha(file_bytes(Path(__file__).resolve().parents[1] / WORKFLOW, DOC_LIMIT))
        and summary["workflow_policy_tests"] == "separate full research discovery"
        and summary["legacy_capsule_fixture_workflow"] == ".github/workflows/release-trust-qualification.yml"
        and summary["byte_identical_replays"] == ["custody.json", "readiness.json"],
        "qualification-scope-or-source",
    )
    require(summary["sha256"] == {n: sha(records[n]) for n in CHILDREN}, "governed-manifest")
    per_module = unit["tests_per_module"]
    require(
        type(per_module) is dict
        and per_module.keys() == MODULE_FLOORS.keys()
        and all(type(per_module[k]) is int and per_module[k] >= floor for k, floor in MODULE_FLOORS.items())
        and count_matches(unit["tests_run"], sum(per_module.values())),
        "incomplete-test-inventory",
    )
    revision = {"commit_sha": head, "tree_sha": tree, "dirty": False, "diff_digest": "sha256:" + sha(b"")}
    require(
        unit.get("framework") == "unittest"
        and unit["run_by_research_engine"] is True
        and unit["successful"] is True
        and unit["source_stable"] is True
        and all(
            unit[k] == revision and unit[k]["dirty"] is False
            for k in ("source_revision", "source_revision_end")
        )
        and type(unit["tests_run"]) is int
        and unit["tests_run"] > 0
        and count_matches(summary["governed_unit_tests"], unit["tests_run"])
        and all(
            count_matches(unit[k], 0)
            for k in ("errors", "failures", "expected_failures", "unexpected_successes", "skipped")
        ),
        "unit-results-or-source",
    )
    require(
        ready.get("schema") == "awooo.production-readiness/v1"
        and ready["status"] == "BLOCKED"
        and ready["release_authorized"] is False
        and ready["production_signing_enabled"] is False
        and ready["source"] == {"commit": head, "tree": tree, "pull_request": None}
        and ready["github_observation"] == "OFFLINE"
        and type(ready["conditions"]) is dict
        and REQUIRED_GATES <= ready["conditions"].keys()
        and ready["unmet"] == sorted(ready["conditions"])
        and ready["evaluation_evidence"] == {"state": "NOT_PROVIDED"}
        and all(
            type(v) is dict
            and (
                (
                    v.keys() == {"state", "provenance", "control"}
                    and v["state"] == v["provenance"] == "UNKNOWN"
                )
                or (
                    v.keys() == {"state", "provenance", "basis"}
                    and v["state"] == "UNSATISFIED"
                    and v["provenance"] == "IMPLEMENTATION_LIMIT"
                )
            )
            for v in ready["conditions"].values()
        ),
        "readiness-outcome-or-source",
    )
    cases, mutants = custody["cases"], custody["mutants"]
    require(
        custody.get("schema") == "awooo.custody-exercise/v1"
        and custody["scope"] == "DISPOSABLE_LOCAL_FIXTURE"
        and custody["status"] == "VERIFIED_DISPOSABLE_EXERCISE"
        and custody["production_custody"] == "BLOCKED"
        and type(cases) is list
        and cases
        and count_matches(summary["custody_cases"], len(cases))
        and all(
            set(row) == {"name", "expected", "observed"}
            and row["name"] in CUSTODY_ORACLE
            and row["expected"] == row["observed"] == CUSTODY_ORACLE[row["name"]]
            for row in cases
        )
        and {r["name"] for r in cases} == CUSTODY_ORACLE.keys()
        and len(cases) == len(CUSTODY_ORACLE)
        and type(mutants) is dict
        and mutants.keys() == MUTANT_ORACLE.keys()
        and count_matches(summary["defective_custody_controls_caught"], len(mutants))
        and all(
            type(hits) is list and len(hits) == len(MUTANT_ORACLE[name]) and set(hits) == MUTANT_ORACLE[name]
            for name, hits in mutants.items()
        ),
        "custody-outcome",
    )


def replay(artifact, pin, local, head, tree):
    require(
        hexval(pin, 64) and hexval(head, 40) and hexval(tree, 40), "invalid-independent-pins", "INCONCLUSIVE"
    )
    raw = file_bytes(path(artifact), TRANSPORT_LIMIT)
    require(sha(raw) == pin, "artifact-digest-mismatch")
    hosted, other = hosted_records(raw)
    local_data = local_records(path(local))
    require(hosted == local_data, "hosted-local-records-differ")
    validate(local_data, head, tree)
    return {
        "status": "MATCHED_EVALUATION_REPLAY",
        "commit": head,
        "tree": tree,
        "artifact_sha256": pin,
        "records_sha256": {n: sha(raw) for n, raw in local_data.items()},
        "outside_replay": other,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("artifact", "artifact-sha256", "local-dir", "expected-head", "expected-tree"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    try:
        result = replay(
            args.artifact, args.artifact_sha256, args.local_dir, args.expected_head, args.expected_tree
        )
    except Verdict as exc:
        result = {
            "status": "INCONCLUSIVE" if exc.status == "INCONCLUSIVE" else "MISMATCH",
            "reason": exc.reason,
        }
    except (KeyError, TypeError, ValueError, zipfile.BadZipFile, zlib.error, EOFError):
        result = {"status": "MISMATCH", "reason": "malformed-evidence"}
    except OSError:
        result = {"status": "INCONCLUSIVE", "reason": "evidence-unavailable"}
    result.update(schema="awooo.governed-replay/v1", production="BLOCKED", release_authorized=False)
    print(json.dumps(result, sort_keys=True))
    return {"MATCHED_EVALUATION_REPLAY": 0, "MISMATCH": 1, "INCONCLUSIVE": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
