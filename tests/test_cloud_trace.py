"""Hostile controls for bounded, sanitized GitHub cloud-event triage."""

from __future__ import annotations

import json
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from wolftrap.cli import main
from wolftrap.cloud_trace import (MANIFEST_NAME, MAX_EVENTS, REPORT_NAME, SCHEMA,
                                  inspect_trace, parse_trace, scan_cloud_trace,
                                  verify_cloud_trace)


SESSION = "session-opaque-a"
OTHER_SESSION = "session-opaque-b"
RESULTS = "repo-results"
COMMANDS = "repo-commands"
OTHER_COMMANDS = "repo-other-commands"
ISSUE = "issue-opaque-a"
OTHER_ISSUE = "issue-opaque-b"


def e(at: int, kind: str, *, session: str = SESSION, repo: str = RESULTS,
      issue: str | None = None) -> dict[str, object]:
    return {"at": at, "session": session, "repository": repo,
            "issue": issue, "kind": kind}


def attack_trace() -> list[dict[str, object]]:
    return [e(1, "issue_create", issue=ISSUE),
            e(2, "bug_label_add", issue=ISSUE),
            e(3, "repo_poll", repo=COMMANDS),
            e(4, "bug_label_remove", issue=ISSUE),
            e(5, "repo_poll", repo=COMMANDS),
            e(6, "source_map_put")]


def encode(events: list[dict[str, object]]) -> bytes:
    return json.dumps({"schema": SCHEMA, "events": events}, sort_keys=True).encode()


class CloudTraceHostileTests(unittest.TestCase):
    def fixture(self, events: list[dict[str, object]] | None = None):
        tmp = tempfile.TemporaryDirectory(prefix="wolftrap-cloud-trace-")
        root = Path(tmp.name) / "source"
        root.mkdir()
        (root / "input.json").write_bytes(encode(events if events is not None else attack_trace()))
        return tmp, root, Path(tmp.name) / "evidence"

    def test_correlated_two_repository_behavior_is_conditional(self) -> None:
        events = parse_trace(encode(attack_trace()))
        found = inspect_trace(events)
        self.assertEqual({f["rule_id"] for f in found},
                         {"WT-CLOUD-C2-003", "WT-CLOUD-C2-004"})
        self.assertTrue(all(f["classification"] == "REVIEW_REQUIRED" for f in found))
        self.assertNotIn(SESSION, json.dumps(found))
        self.assertNotIn(RESULTS, json.dumps(found))

    def test_different_sessions_cannot_be_spliced(self) -> None:
        events = [e(1, "issue_create", issue=ISSUE),
                  e(2, "bug_label_add", issue=ISSUE, session=OTHER_SESSION),
                  e(3, "repo_poll", repo=COMMANDS, session=OTHER_SESSION),
                  e(4, "bug_label_remove", issue=ISSUE, session=OTHER_SESSION),
                  e(5, "repo_poll", repo=COMMANDS, session=OTHER_SESSION),
                  e(6, "source_map_put", session=OTHER_SESSION)]
        self.assertEqual(inspect_trace(parse_trace(encode(events))), [])

    def test_different_issues_do_not_form_label_cycle(self) -> None:
        events = attack_trace()
        events[3] = e(4, "bug_label_remove", issue=OTHER_ISSUE)
        found = inspect_trace(parse_trace(encode(events)))
        self.assertEqual({f["rule_id"] for f in found}, {"WT-CLOUD-C2-004"})

    def test_unrelated_command_repositories_cannot_complete_cycle(self) -> None:
        events = attack_trace()
        events[4] = e(5, "repo_poll", repo=OTHER_COMMANDS)
        found = inspect_trace(parse_trace(encode(events)))
        self.assertEqual({f["rule_id"] for f in found}, {"WT-CLOUD-C2-004"})

    def test_same_repository_poll_and_wrong_result_sink_do_not_match(self) -> None:
        events = [e(1, "issue_create", issue=ISSUE),
                  e(2, "bug_label_add", issue=ISSUE),
                  e(3, "repo_poll"),
                  e(4, "bug_label_remove", issue=ISSUE),
                  e(5, "repo_poll"),
                  e(6, "source_map_put")]
        self.assertEqual(inspect_trace(parse_trace(encode(events))), [])
        events = attack_trace()
        events[5] = e(6, "source_map_put", repo=OTHER_COMMANDS)
        found = inspect_trace(parse_trace(encode(events)))
        self.assertEqual({f["rule_id"] for f in found}, {"WT-CLOUD-C2-003"})

    def test_unordered_and_expired_sequences_are_not_joined(self) -> None:
        events = [e(1, "issue_create", issue=ISSUE),
                  e(2, "source_map_put"),
                  e(3, "bug_label_add", issue=ISSUE),
                  e(4, "bug_label_remove", issue=ISSUE),
                  e(5, "repo_poll", repo=COMMANDS)]
        found = inspect_trace(parse_trace(encode(events)))
        self.assertEqual({f["rule_id"] for f in found}, set())
        events = attack_trace()
        events[1] = e(202, "bug_label_add", issue=ISSUE)
        events[2] = e(203, "repo_poll", repo=COMMANDS)
        events[3] = e(204, "bug_label_remove", issue=ISSUE)
        events[4] = e(205, "repo_poll", repo=COMMANDS)
        events[5] = e(206, "source_map_put")
        self.assertEqual(inspect_trace(parse_trace(encode(events))), [])

    def test_untrusted_fields_duplicates_and_oversized_inputs_fail(self) -> None:
        invalid: list[bytes] = [
            encode([dict(attack_trace()[0], token="top-secret")]),
            encode([dict(attack_trace()[0], repository="https://api.github.com")]),
            encode([dict(attack_trace()[0], issue=None)]),
            encode([dict(attack_trace()[2], issue=ISSUE)]),
            encode([dict(attack_trace()[0], at=True)]),
            encode([e(2, "other"), e(1, "other")]),
            encode([e(n, "other") for n in range(MAX_EVENTS + 1)]),
            b'{"schema":"wolftrap.normalized-cloud-trace/v1","schema":"override","events":[]}',
            b'{"schema":"wolftrap.normalized-cloud-trace/v1","events":[{"at":1,"at":2}]}',
            b'{"schema":"wolftrap.normalized-cloud-trace/v1","events":[{"at":NaN}]}',
            b"\x00not-json",
        ]
        for raw in invalid:
            with self.subTest(raw=raw[:50]), self.assertRaises((ValueError, UnicodeDecodeError)):
                parse_trace(raw)

    def test_source_redaction_manifest_and_cli_replay(self) -> None:
        temporary, root, evidence = self.fixture()
        with temporary:
            with patch.object(socket, "socket", side_effect=AssertionError("network attempted")):
                with redirect_stdout(StringIO()):
                    code = main(["scan-cloud-trace", "--root", str(root),
                                 "--file", "input.json", "--output-dir", str(evidence)])
                self.assertEqual(code, 1)
                self.assertEqual(verify_cloud_trace(root, "input.json", evidence)
                                 ["summary"]["findings"], 2)
            report = json.loads((evidence / REPORT_NAME).read_text())
            self.assertFalse(report["qualification"]["source_identity_verified"])
            self.assertEqual(report["qualification"]["confirmed_vulnerabilities"], 0)
            self.assertFalse(report["network_contacted"])
            for private in (SESSION, RESULTS, COMMANDS, ISSUE):
                self.assertNotIn(private, (evidence / REPORT_NAME).read_text())
            self.assertEqual(json.loads((evidence / MANIFEST_NAME).read_text())
                             ["state"], "COMPLETE")
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["verify-cloud-trace", "--root", str(root),
                                       "--file", "input.json", "--evidence-dir", str(evidence)]), 0)

    def test_modified_source_or_artifact_fails_verification(self) -> None:
        temporary, root, evidence = self.fixture()
        with temporary:
            scan_cloud_trace(root, "input.json", evidence)
            original = (root / "input.json").read_bytes()
            (root / "input.json").write_bytes(encode([e(1, "other")]))
            with self.assertRaises(ValueError):
                verify_cloud_trace(root, "input.json", evidence)
            (root / "input.json").write_bytes(original)
            (evidence / REPORT_NAME).write_text("altered\n")
            with self.assertRaises(ValueError):
                verify_cloud_trace(root, "input.json", evidence)

    def test_symlink_unsafe_selection_and_source_overlap_fail_closed(self) -> None:
        temporary, root, evidence = self.fixture()
        with temporary:
            (root / "link.json").symlink_to(root / "input.json")
            result, code = scan_cloud_trace(root, "link.json", evidence)
            self.assertEqual(code, 2)
            self.assertEqual(result["qualification"]["status"], "INCONCLUSIVE")
            self.assertEqual(verify_cloud_trace(root, "link.json", evidence), result)
            for file in ("../input.json", "subdir/input.json", ".hidden.json"):
                with self.subTest(file=file), self.assertRaises(ValueError):
                    scan_cloud_trace(root, file, Path(temporary.name) / "bad-output")
            with self.assertRaises(ValueError):
                scan_cloud_trace(root, "input.json", root / "reports")

    def test_malformed_source_is_inconclusive_not_a_clean_pass(self) -> None:
        temporary, root, evidence = self.fixture()
        with temporary:
            (root / "input.json").write_text('{"schema": "unexpected"}')
            result, code = scan_cloud_trace(root, "input.json", evidence)
            self.assertEqual(code, 2)
            self.assertEqual(result["qualification"]["status"], "INCONCLUSIVE")
            self.assertEqual(result["summary"]["errors"], 1)
            self.assertEqual(verify_cloud_trace(root, "input.json", evidence), result)


if __name__ == "__main__":
    unittest.main()
