from __future__ import annotations

import copy
import math
import unittest

from wolftrap.scenario import ScenarioValidationError, parse_scenario


ADVISORY_SHA = "3dd86a94d33b29c65f56b4307919b74358e63cfde33a600b61adce5794d169e2"


def valid_scenario() -> dict:
    return {
        "schema_version": "1.0",
        "scenario_id": "validation-fixture",
        "scenario_version": "1.0.0",
        "title": "Validation fixture",
        "summary": "A contained synthetic fixture.",
        "category": "test",
        "threat": {
            "source": {
                "source_id": "FBI-FLASH-20261113-001",
                "title": "Threat Overview of ARTEX Autonomous Penetration Testing Framework",
                "publication_date": "2026-11-13",
                "url": "https://www.ic3.gov/CSA/2026/261113.pdf",
                "sha256": ADVISORY_SHA,
                "pages": [3],
                "observed_behavior": "Valid-account abuse.",
                "mapping_note": "Synthetic defensive mapping.",
            },
            "attack": [
                {
                    "technique_id": "T1078",
                    "name": "Valid Accounts",
                    "url": "https://attack.mitre.org/techniques/T1078/",
                    "relationship": "DIRECT",
                }
            ],
        },
        "fixtures": {
            "current_epoch": 1,
            "security_state_known": True,
            "principals": [{"principal_id": "alice", "roles": ["writer"]}],
            "authorizations": [
                {
                    "authorization_id": "auth-1",
                    "subject": "alice",
                    "scopes": ["write:synthetic://vault/item"],
                    "epoch": 1,
                    "origin_binding": "synthetic-origin://employee",
                    "operation_digest": "@operation:op-1",
                    "issued_at": 0,
                    "expires_at": 100,
                    "signature_valid": True,
                    "nonce": "nonce-1",
                }
            ],
            "operations": [
                {
                    "operation_id": "op-1",
                    "action": "write",
                    "resource": "synthetic://vault/item",
                    "arguments": {"value": "safe"},
                    "protected": True,
                }
            ],
        },
        "requests": [
            {
                "request_id": "request-1",
                "principal_id": "alice",
                "authorization_id": "auth-1",
                "operation_id": "op-1",
                "origin": "synthetic-origin://employee",
                "credential_overrides": {},
            }
        ],
        "actions": [
            {"kind": "SUBMIT", "at": 10, "task_id": "task-1", "request_id": "request-1"},
            {"kind": "ADVANCE", "at": 10, "task_id": "task-1", "repeat": 7},
        ],
        "expectation": {
            "control": "POSITIVE",
            "description": "One legitimate effect succeeds.",
            "invariants": ["POSITIVE_CONTROL_MUST_EXECUTE"],
        },
        "mutation_axes": ["principal_identity"],
    }


class ScenarioValidationTests(unittest.TestCase):
    def test_valid_strict_scenario_parses_and_resolves_digest(self) -> None:
        scenario = parse_scenario(valid_scenario())
        self.assertEqual(scenario.schema_version, "1.0")
        self.assertEqual(len(scenario.commands), 8)
        self.assertEqual(scenario.authorizations[0].operation_digest, scenario.operations[0].digest)

    def test_unknown_top_level_key_fails_closed(self) -> None:
        raw = valid_scenario()
        raw["surprise"] = True
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_unknown_schema_version_fails_closed(self) -> None:
        raw = valid_scenario()
        raw["schema_version"] = "2.0"
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_non_synthetic_resource_is_rejected(self) -> None:
        raw = valid_scenario()
        raw["fixtures"]["operations"][0]["resource"] = "https://example.invalid/target"
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_unknown_action_is_rejected(self) -> None:
        raw = valid_scenario()
        raw["fixtures"]["operations"][0]["action"] = "execute_shell"
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_non_finite_argument_is_rejected(self) -> None:
        raw = valid_scenario()
        raw["fixtures"]["operations"][0]["arguments"]["value"] = math.nan
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_duplicate_principals_are_rejected(self) -> None:
        raw = valid_scenario()
        raw["fixtures"]["principals"].append(copy.deepcopy(raw["fixtures"]["principals"][0]))
        with self.assertRaises(ValueError):
            parse_scenario(raw)

    def test_bad_advisory_digest_is_rejected(self) -> None:
        raw = valid_scenario()
        raw["threat"]["source"]["sha256"] = "0" * 64
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_non_monotonic_logical_time_is_rejected(self) -> None:
        raw = valid_scenario()
        raw["actions"][1]["at"] = 9
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_unknown_mutation_axis_is_rejected(self) -> None:
        raw = valid_scenario()
        raw["mutation_axes"] = ["external_target"]
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)


if __name__ == "__main__":
    unittest.main()
