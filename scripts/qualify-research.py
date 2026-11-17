"""Replay the public research suites and write a source-bound evidence index."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path

from wolftrap.report import validate_report_pair, write_json_report
from wolftrap.revision import capture_source_revision, repository_root


def network_namespace_verified(parent: str | None) -> bool:
    if parent is None:
        return False
    if os.readlink("/proc/self/ns/net") == parent:
        raise ValueError("qualification process shares the parent network namespace")
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise ValueError("qualification network namespace contains a non-loopback interface")
    return True


def run_python(*arguments: str | Path, expected_code: int = 0) -> None:
    command = [sys.executable, "-m", *(str(argument) for argument in arguments)]
    result = subprocess.run(command, check=False)
    if result.returncode != expected_code:
        raise RuntimeError(f"{arguments[0]} {arguments[1]} returned {result.returncode}")


def file_index(root: Path) -> dict[str, dict[str, int | str]]:
    index = {}
    for member in sorted(root.rglob("*")):
        if member.is_symlink():
            raise ValueError("qualification output contains a symlink")
        if member.is_dir():
            continue
        if not member.is_file():
            raise ValueError("qualification output contains a non-regular file")
        content = member.read_bytes()
        index[member.relative_to(root).as_posix()] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }
    return index


def suite_summaries(root: Path, source: dict[str, object]) -> dict[str, object]:
    def read(name: str) -> dict:
        return json.loads((root / name).read_text(encoding="utf-8"))

    cloud = read("cloud-authority/cloud-authority-challenge.json")["summary"]
    funnel = read("authority-funnel/authority-funnel-challenge.json")["summary"]
    authority = read("authority-qualification/authority-qualification.json")["summary"]
    identity = read("identity-telemetry-challenge/identity-telemetry-challenge.json")["summary"]
    prompt = read("prompt-trust/prompt-trust-challenge.json")["summary"]
    vehicle_manifest = read("gt-vsa/gt-vsa.manifest.json")
    vehicle = vehicle_manifest["summary"]
    if (cloud["authority_checks"] < 1920 or cloud["mismatches"] or cloud["oracle_failures"]
            or funnel["proposals"] < 3019 or funnel["mismatches"]):
        raise ValueError("the cloud and authority challenge baselines did not qualify")
    if (authority["sentinels_total"] < 5
            or authority["sentinels_caught"] != authority["sentinels_total"]):
        raise ValueError("authority sentinel qualification regressed")
    if (vehicle_manifest["status"] != "PASS" or vehicle_manifest["source"] != source
            or vehicle["vehicles"] != 1024 or vehicle["failed_runs"]
            or vehicle["defects"] < 1 or vehicle["defects_detected"] != vehicle["defects"]):
        raise ValueError("the exact source vehicle fleet and defect controls did not qualify")
    return {
        "cloud_authority": cloud,
        "authority_funnel": funnel,
        "authority_qualification": authority,
        "identity_telemetry": identity,
        "prompt_trust": prompt,
        "gt_vsa": vehicle,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-head", help="require this exact Git commit")
    parser.add_argument("--parent-netns", help="parent Linux namespace from readlink /proc/self/ns/net")
    arguments = parser.parse_args()
    repo = repository_root()
    os.chdir(repo)
    source = capture_source_revision(repo)
    if source.dirty or source.commit_sha == "UNCOMMITTED":
        raise ValueError("qualification requires a clean Git checkout")
    if arguments.expected_head and source.commit_sha != arguments.expected_head:
        raise ValueError("checkout does not match the expected commit")
    offline = network_namespace_verified(arguments.parent_netns)
    output = arguments.output_dir.resolve()
    if output.is_relative_to(repo):
        raise ValueError("qualification output must be outside the source checkout")
    output.mkdir(mode=0o700)

    unit = output / "unit-tests.json"
    run_python("wolftrap.test_runner", "--output", unit)
    tests = json.loads(unit.read_text(encoding="utf-8"))
    if (tests["tests_run"] < 274 or tests["skipped"] or tests["expected_failures"]
            or tests["source_revision"] != source.to_dict()):
        raise ValueError("unit tests did not preserve the clean measured baseline")

    run_python("wolftrap", "run", "--unit-test-summary", unit, "--output-dir", output / "campaign")
    campaign = validate_report_pair(output / "campaign" / "wolftrap-report.json")
    if campaign["source_revision"] != source.to_dict() or campaign["qualification"]["status"] != "PASS":
        raise ValueError("the source-bound synthetic campaign did not qualify")
    for challenge in ("cloud-c2", "cloud-camouflage", "cloud-authority", "authority-funnel", "agent", "build"):
        target = output / challenge
        options: tuple[str, ...] = ()
        verifier = challenge
        if challenge == "agent":
            options = ("--seed", "20261115")
            verifier = "agent-challenge"
        if challenge == "build":
            options = ("--seed", "20261115", "--cases", "128")
            verifier = "challenge"
        run_python("wolftrap", f"challenge-{challenge}", *options, "--output-dir", target)
        run_python("wolftrap", f"verify-{verifier}", "--evidence-dir", target)

    run_python("wolftrap", "replay-agent-challenge", "--evidence-dir", output / "agent",
               "--output-dir", output / "agent-replay")
    run_python("wolftrap", "verify-agent-challenge", "--evidence-dir", output / "agent-replay")
    run_python("wolftrap", "scan-prompts", "--root", "tests/fixtures/prompt_docs",
               "--output-dir", output / "prompt-static", expected_code=1)
    run_python("wolftrap", "verify-prompts", "--evidence-dir", output / "prompt-static")

    for suite in ("identity_telemetry_challenge", "prompt_trust"):
        target = output / suite.replace("_", "-")
        run_python(f"wolftrap.{suite}", "run", "--output-dir", target)
        run_python(f"wolftrap.{suite}", "verify", "--evidence-dir", target)
    run_python("wolftrap.authority_qualification", "--output-dir", output / "authority-qualification")
    run_python("wolftrap.authority_qualification", "--evidence-dir", output / "authority-qualification")
    run_python("wolftrap", "challenge-gt-vsa", "--seed", "20261117", "--vehicles", "1024",
               "--output-dir", output / "gt-vsa")
    run_python("wolftrap", "verify-gt-vsa", "--evidence-dir", output / "gt-vsa")

    if capture_source_revision(repo) != source:
        raise ValueError("qualification source changed during replay")
    write_json_report({
        "schema": "wolftrap.public-qualification-index/v1",
        "state": "COMPLETE",
        "qualification": "SYNTHETICALLY VERIFIED",
        "source_revision": source.to_dict(),
        "environment": {
            "python": platform.python_version(),
            "os": platform.system(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "network_namespace_verified": offline,
        },
        "limits": [
            "Synthetic and static fixtures only. Live intrusion and private runtime conformance are NOT TESTED.",
            "Hashes bind local files and do not establish authenticity or production security.",
        ],
        "unit_tests": tests["tests_run"],
        "suites": suite_summaries(output, source.to_dict()),
        "files": file_index(output),
    }, output / "qualification.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
