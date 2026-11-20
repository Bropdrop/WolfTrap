"""Pinned subscriber-policy v2 controls. All certificates and capsules are ephemeral fixtures."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.object(
    sys, "path", [str(ROOT / "release/verifier"), str(ROOT / "release/qualification"), *sys.path]
):
    import release_client as client
    import release_core as core
    import release_policy
    from release_cases import Corpus
    from release_io import Verdict, encode, pack, sha


class GovernedSubscriberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.work.cleanup)
        cls.lab = Corpus(Path(cls.work.name))

    def setUp(self):
        self.clock = self.lab.now
        self.policy = deepcopy(self.lab.base)
        self.policy.update(
            schema="awooo.subscriber-policy/v2",
            generation=7,
            incidents={
                "observed_at": self.clock,
                "next_update": self.clock + 3600,
                "suspended": False,
                "publisher_status": "ACTIVE",
                "signer_status": "ACTIVE",
                "withdrawn_manifests": [],
            },
        )

    def check(self, policy=None, *, generation=7, clock=None, sequence=2, mode="current", floor=2):
        policy = policy if policy is not None else self.policy
        raw_policy = encode(policy)
        capsule = self.lab.new if sequence == 2 else self.lab.old
        return core.verify(
            pack(capsule),
            dict(self.lab.trust, **{"policy.json": raw_policy}),
            sha(raw_policy),
            floor,
            sequence,
            mode,
            self.clock if clock is None else clock,
            generation,
        )[0]

    def test_independent_outcomes_for_current_authority(self):
        # Fixed expected decisions come from the operator policy. The oracle never calls a verifier.
        cases = [
            ({"suspended": False}, "VERIFIED", None),
            ({"suspended": True}, "REJECTED", "emergency-release-suspension"),
            ({"publisher_status": "REVOKED"}, "REJECTED", "publisher-authority-unavailable"),
            ({"signer_status": "REVOKED"}, "REJECTED", "signer-authority-unavailable"),
            ({"signer_status": "LOST"}, "REJECTED", "signer-authority-unavailable"),
            ({"publisher_status": "LOST"}, "REJECTED", "publisher-authority-unavailable"),
            ({"publisher_status": "UNKNOWN"}, "INCONCLUSIVE", "unknown-publisher-status"),
            ({"signer_status": None}, "INCONCLUSIVE", "unknown-signer-status"),
            ({"observed_at": self.clock + 1}, "INCONCLUSIVE", "incident-bulletin-not-yet-current"),
            ({"next_update": self.clock + 86401}, "REJECTED", "invalid-incident-window"),
            ({"withdrawn_manifests": [self.lab.r2["manifest_sha256"]]}, "REJECTED", "manifest-withdrawn"),
            ({"withdrawn_manifests": [self.lab.r1["manifest_sha256"]]}, "VERIFIED", None),
        ]
        for update, expected, reason in cases:
            with self.subTest(update=update):
                p = deepcopy(self.policy)
                p["incidents"].update(update)
                if expected == "VERIFIED":
                    result = self.check(p)
                    self.assertEqual((result["status"], result["policy_generation"]), (expected, 7))
                    self.assertEqual(result["incident_status_valid_until"], self.clock + 3600)
                else:
                    with self.assertRaises(Verdict) as cm:
                        self.check(p)
                    self.assertEqual((cm.exception.status, cm.exception.reason), (expected, reason))

    def test_independent_generation_prevents_policy_replay_and_profile_downgrade(self):
        for p, floor, reason in [
            (self.policy, 8, "replayed-policy-generation"),
            (self.policy, None, "missing-policy-generation-floor"),
            (self.lab.base, 7, "incident-policy-downgrade"),
        ]:
            with self.subTest(floor=floor), self.assertRaisesRegex(Verdict, reason):
                self.check(p, generation=floor)
        self.assertEqual(self.check(generation=6)["scope"], "EVALUATION_ONLY")

    def test_stale_or_missing_evidence_is_explicitly_inconclusive(self):
        missing_bulletin = deepcopy(self.policy)
        del missing_bulletin["incidents"]
        missing_key = deepcopy(self.policy)
        del missing_key["incidents"]["signer_status"]
        for p, when, reason in [
            (missing_bulletin, self.clock, "missing-incident-policy"),
            (missing_key, self.clock, "incomplete-incident-bulletin"),
            (self.policy, self.clock + 3600, "stale-incident-bulletin"),
            (self.policy, self.policy["valid_until"], "stale-subscriber-policy"),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(Verdict, reason) as cm:
                self.check(p, clock=when)
            self.assertEqual(cm.exception.status, "INCONCLUSIVE")

    def test_withdrawal_survives_original_signature_and_rollback_authorization(self):
        self.policy["rollback"] = self.lab.permit
        self.assertEqual(self.check(sequence=1, mode="rollback")["status"], "VERIFIED")
        self.assertEqual(self.check(sequence=1, mode="historical")["status"], "VERIFIED")
        with self.assertRaisesRegex(Verdict, "rollback-origin-unconfirmed"):
            self.check(sequence=1, mode="rollback", floor=1)
        with self.assertRaisesRegex(Verdict, "rollback-or-replay"):
            self.check(sequence=1)
        self.policy["incidents"]["withdrawn_manifests"] = [self.lab.r1["manifest_sha256"]]
        for mode in ("historical", "rollback", "current"):
            with self.subTest(mode=mode), self.assertRaisesRegex(Verdict, "manifest-withdrawn"):
                self.check(sequence=1, mode=mode)
        self.assertEqual(self.check()["version"], self.lab.r2["version"])

    def test_counterfeit_and_malformed_incident_policy(self):
        trust = dict(self.lab.trust, **{"policy.json": encode(self.policy)})
        pin = sha(trust["policy.json"])
        self.policy["generation"] = 8
        trust["policy.json"] = encode(self.policy)
        with self.assertRaisesRegex(Verdict, "independent-policy-pin"):
            core.verify(pack(self.lab.new), trust, pin, 2, 2, "current", self.clock, 7)
        for value in ("absent", ["."], ["0" * 64] * 2, ["0" * 64] * 257):
            self.policy["incidents"]["withdrawn_manifests"] = value
            with (
                self.subTest(value=type(value)),
                self.assertRaisesRegex(Verdict, "invalid-withdrawal-register"),
            ):
                self.check()

    def test_policy_that_expires_during_venv_setup_stops_before_package_install(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            trust_dir = root / "trust"
            trust_dir.mkdir()
            for name, data in self.lab.trust.items():
                (trust_dir / name).write_bytes(encode(self.policy) if name == "policy.json" else data)
            bundle = root / "capsule.zip"
            bundle.write_bytes(pack(self.lab.new))
            args = [
                "install",
                "--evaluation",
                "--trust-dir",
                str(trust_dir),
                "--bundle",
                str(bundle),
                "--policy-sha256",
                sha(encode(self.policy)),
                "--minimum-sequence",
                "2",
                "--sequence",
                "2",
                "--minimum-policy-generation",
                "7",
                "--venv",
                str(root / "new"),
            ]
            # Let the real openssl commands run, intercept only the subprocess that creates the venv.
            run = subprocess.run
            wall = [self.clock]
            calls = []

            def setup(cmd, **options):
                if cmd[0] == sys.executable:
                    self.assertIn("venv", cmd)
                    wall[0] = self.policy["incidents"]["next_update"]
                    calls.append("venv")
                    return
                self.assertNotIn("pip", cmd)
                return run(cmd, **options)

            with (
                patch.object(client, "host_profile", return_value=release_policy.PLATFORMS[0]),
                patch.object(client.time, "time", side_effect=lambda: wall[0]),
                patch.object(client.subprocess, "run", side_effect=setup),
                patch("sys.stdout") as output,
            ):
                self.assertEqual(client.main(args), 2)
            self.assertEqual(calls, ["venv"])
            self.assertEqual(
                json.loads(output.write.call_args_list[0].args[0])["reason"], "stale-incident-bulletin"
            )

    def test_defective_verifiers_disagree_with_independent_incident_decisions(self):
        def decisions():
            outcomes = []
            for suspended in (False, True):
                self.policy["incidents"]["suspended"] = suspended
                try:
                    outcomes.append(self.check()["status"])
                except Verdict as error:
                    outcomes.append(error.status)
            return outcomes

        expected = ["VERIFIED", "REJECTED"]
        self.assertEqual(decisions(), expected)
        defects = (
            ("always-approve", patch.object(core, "verify", return_value=({"status": "VERIFIED"}, b""))),
            ("always-reject", patch.object(core, "verify", side_effect=Verdict("REJECTED", "blanket"))),
            ("ignore-incidents", patch.object(release_policy, "check_incidents")),
        )
        for name, defect in defects:
            with self.subTest(name=name), defect:
                self.assertNotEqual(decisions(), expected)
