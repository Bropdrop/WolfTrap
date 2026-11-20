"""Replay governed release controls in a fresh loopback-only Linux namespace."""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release/verifier"))
from release_client import private_directory, publish_new
from release_io import DOC_LIMIT, directory, encode, file_bytes, path, sha

TEST_FILES = (
    "test_governance_preflight.py",
    "test_governed_custody.py",
    "test_governed_readiness.py",
    "test_governed_subscriber.py",
    "test_governed_replay.py",
)


def check(condition, reason):
    if not condition:
        raise ValueError(reason)


def invoke(*command, expected=0, source=False, cwd=ROOT):
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
    }
    if source:
        env["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, timeout=420)
    check(result.returncode == expected, "unexpected exit from " + Path(command[0]).name)
    return result.stdout


def clean_source(expected_head):
    check(re.fullmatch(r"[a-f0-9]{40}", expected_head), "supply an exact Git commit")
    head = invoke("git", "rev-parse", "HEAD").decode("ascii").strip()
    tree = invoke("git", "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    check(
        head == expected_head and not invoke("git", "status", "--porcelain=v1"),
        "clean exact checkout required",
    )
    return head, tree


def check_tests(report, head, tree):
    check(
        report["successful"] is True
        and report["source_stable"] is True
        and type(report["tests_run"]) is int
        and report["tests_run"] > 0,
        "governed tests did not complete",
    )
    check(
        all(
            report[k] == 0
            for k in ("skipped", "errors", "failures", "expected_failures", "unexpected_successes")
        ),
        "incomplete governed tests",
    )
    for key in ("source_revision", "source_revision_end"):
        source = report[key]
        check(
            (source["commit_sha"], source["tree_sha"], source["dirty"]) == (head, tree, False),
            "test results refer to another source",
        )


def isolated_source(args):
    head, tree = clean_source(args.expected_head)
    check(
        re.fullmatch(r"net:\[\d+\]", args.parent_netns)
        and os.readlink("/proc/self/ns/net") != args.parent_netns
        and {name for _, name in socket.if_nameindex()} == {"lo"},
        "dedicated loopback-only namespace required",
    )
    return head, tree


def qualify(args):
    head, tree = isolated_source(args)
    for name in TEST_FILES:
        check((ROOT / "tests" / name).is_file(), "required governed test module missing: " + name)
    output = path(args.output_dir)
    check(not output.is_relative_to(ROOT), "provide a fresh directory outside the checkout")
    parent_fd = directory(output.parent)
    try:
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    os.close(private_directory(output))

    # The two workflow-only test modules require the x86-only reviewed PyYAML
    # wheel. Full research discovery runs those separately. The subscriber
    # matrix and local replay use the same stdlib-only core test inventory.
    with tempfile.TemporaryDirectory(dir=output) as repeat:
        counts = {}
        for module in TEST_FILES:
            unit_file = Path(repeat) / (module + ".json")
            invoke(
                sys.executable,
                "-m",
                "wolftrap.test_runner",
                "--pattern",
                module,
                "--output",
                unit_file,
                source=True,
            )
            unit = json.loads(file_bytes(unit_file, DOC_LIMIT))
            check_tests(unit, head, tree)
            counts[module] = unit["tests_run"]
        unit.update(tests_run=sum(counts.values()), tests_per_module=counts)
        publish_new(output, "unit-tests.json", encode(unit))
        custody = None
        readiness = None
        for folder in (output, Path(repeat)):
            observed = invoke(
                sys.executable,
                "-I",
                ROOT / "release/custody",
                "exercise",
                "--output",
                folder / "custody.json",
            )
            stored = file_bytes(folder / "custody.json", DOC_LIMIT)
            check(json.loads(observed) == json.loads(stored), "exercise output does not match stored record")
            if custody is None:
                custody = stored
            check(stored == custody, "disaster recovery replay differs")

            assessment = json.loads(
                invoke(
                    sys.executable,
                    "-I",
                    ROOT / "release/governance/readiness.py",
                    "--offline",
                    "--expected-head",
                    head,
                    "--expected-tree",
                    tree,
                    expected=1,
                )
            )
            check(
                assessment["schema"] == "awooo.production-readiness/v1"
                and assessment["status"] == "BLOCKED"
                and assessment["source"] == {"commit": head, "tree": tree, "pull_request": None}
                and assessment["github_observation"] == "OFFLINE"
                and bool(assessment["unmet"])
                and assessment["release_authorized"] is False
                and assessment["production_signing_enabled"] is False,
                "offline production readiness must be blocked for this exact source",
            )
            encoded = encode(assessment)
            if readiness is None:
                readiness = encoded
            check(readiness == encoded, "offline readiness replay differs")
        publish_new(output, "readiness.json", readiness)

    recovery = json.loads(custody)
    check(
        recovery["schema"] == "awooo.custody-exercise/v1"
        and recovery["status"] == "VERIFIED_DISPOSABLE_EXERCISE"
        and recovery["production_custody"] == "BLOCKED",
        "custody exercise scope mismatch",
    )
    check(
        recovery["cases"] and all(row["observed"] == row["expected"] for row in recovery["cases"]),
        "disaster recovery control mismatch",
    )
    check(recovery["mutants"] and all(recovery["mutants"].values()), "undetected custody mutant")
    members = ("custody.json", "readiness.json", "unit-tests.json")
    check(clean_source(head) == (head, tree), "qualification changed source")
    summary = {
        "schema": "awooo.governed-qualification/v1",
        "status": "VERIFIED_DISPOSABLE_CONTROLS",
        "production": "BLOCKED",
        "commit": head,
        "tree": tree,
        "namespace": "loopback-only",
        "qualification_workflow": ".github/workflows/governed-release-qualification.yml",
        "qualification_workflow_sha256": sha(
            invoke("git", "show", head + ":.github/workflows/governed-release-qualification.yml")
        ),
        "legacy_capsule_fixture_workflow": ".github/workflows/release-trust-qualification.yml",
        "authenticated_production_builder": False,
        "governed_unit_tests": unit["tests_run"],
        "workflow_policy_tests": "separate full research discovery",
        "custody_cases": len(recovery["cases"]),
        "defective_custody_controls_caught": len(recovery["mutants"]),
        "byte_identical_replays": ["custody.json", "readiness.json"],
        "sha256": {name: sha(file_bytes(output / name, DOC_LIMIT)) for name in members},
    }
    publish_new(output, "qualification.json", encode(summary))
    invoke(
        sys.executable,
        "-m",
        "wolftrap.public_guard",
        head,
        "--report-root",
        output,
        *(arg for name in (*members, "qualification.json") for arg in ("--report", name)),
        source=True,
    )
    check(clean_source(head) == (head, tree), "source changed during screening")
    print("VERIFIED_DISPOSABLE_CONTROLS", head, tree, "production BLOCKED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--parent-netns", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    qualify(parser.parse_args())
