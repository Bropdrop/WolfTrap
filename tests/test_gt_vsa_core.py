"""Exercise security state and actual effect mutations on synthetic vehicles."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from threading import Barrier, Event, Thread
import unittest

from wolftrap.gt_vsa import (
    AUTHORIZED,
    CANCELLED,
    COMMITTED,
    DENIED,
    MAX_EFFECTS,
    MAX_IDENTITIES,
    MAX_PENDING,
    MAX_REVOCATIONS,
    EvidenceOverflow,
    Effect,
    Firmware,
    Identity,
    Ingress,
    Request,
    SyntheticVehicle,
    request_digest,
    sign_firmware,
    sign_grant,
    sign_request,
)


def fixture_key(label: str) -> bytes:
    return sha256(f"gt-vsa-core-test:{label}".encode()).digest()


AUTHORITY_KEY = fixture_key("authority")
FIRMWARE_KEY = fixture_key("firmware")
DISPLAY = Identity("operator", "ui", "display", fixture_key("display"), Ingress())
DIAGNOSTICS = Identity("service", "diagnostic-port", "diagnostics", fixture_key("diagnostics"), Ingress())
PRIVACY = Identity("privacy", "app", "privacy", fixture_key("privacy"), Ingress())
UPDATER = Identity("release-service", "release-origin", "updater", fixture_key("updater"), Ingress())
AI = Identity("assistant", "telemetry", "untrusted", fixture_key("untrusted"), Ingress())
IDENTITIES = (DISPLAY, DIAGNOSTICS, PRIVACY, UPDATER, AI)
IMAGE_DIGEST = sha256(b"synthetic firmware manifest hash").hexdigest()


class VehicleShieldTests(unittest.TestCase):
    def setUp(self):
        self.vehicle = SyntheticVehicle("vehicle-a", IDENTITIES, AUTHORITY_KEY, FIRMWARE_KEY)
        self.shield = self.vehicle.shield

    def request(self, identity=DISPLAY, operation="display", scope="infotainment", **changes):
        return replace(Request("request-a", identity.principal, identity.origin, "vehicle-a", operation,
                               scope, "simulated-message"), **changes)

    def signed(self, request, identity=DISPLAY, **changes):
        grant = sign_grant(request, f"nonce-{request.request_id}", 95, 115, 1, AUTHORITY_KEY)
        return sign_request(request, identity.key), replace(grant, **changes)

    def attempt(self, request, identity=DISPLAY, **grant_changes):
        proof, grant = self.signed(request, identity, **grant_changes)
        decision = self.shield.prepare(request, proof, grant, identity.ingress)
        return self.shield.commit(request.request_id, proof, identity.ingress) if decision == AUTHORIZED else decision

    def firmware_request(self, version=2, **changes):
        manifest = sign_firmware("vehicle-a", version, IMAGE_DIGEST, FIRMWARE_KEY)
        request = self.request(UPDATER, "firmware_update", "noncritical-infotainment",
                               payload=IMAGE_DIGEST, firmware=manifest)
        return replace(request, **changes)

    def test_verified_authorized_committed_are_separate_states(self):
        request = self.request()
        proof, grant = self.signed(request)
        self.assertTrue(self.shield.authenticate(request, proof, DISPLAY.ingress))
        self.assertEqual(self.shield.prepare(request, proof, None, DISPLAY.ingress), DENIED)
        self.assertEqual(self.shield.commit(request.request_id, proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.vehicle.snapshot(), ())
        self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), AUTHORIZED)
        self.assertEqual(self.vehicle.snapshot(), ())
        self.assertEqual(self.shield.commit(request.request_id, proof, DISPLAY.ingress), COMMITTED)
        effect = Effect("vehicle-a", "external", "display", "infotainment", DISPLAY.principal,
                        DISPLAY.origin, "request-a", "nonce-request-a",
                        sha256(request.payload.encode()).hexdigest(), None)
        self.assertEqual(self.vehicle.snapshot(), (effect,))
        with self.assertRaises(FrozenInstanceError):
            self.vehicle.snapshot()[0].domain = "safety"
        self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), DENIED)
        self.assertEqual(self.shield.commit(request.request_id, proof, DISPLAY.ingress), DENIED)

    def test_only_proven_origin_can_commit_or_cancel_pending_request(self):
        request = self.request()
        proof, grant = self.signed(request)
        invalid_proof = sign_request(request, AI.key)
        self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), AUTHORIZED)
        self.assertEqual(self.shield.commit(request.request_id, invalid_proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.shield.cancel(request.request_id, invalid_proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.shield.cancel(request.request_id, proof, DISPLAY.ingress), CANCELLED)
        self.assertEqual(self.shield.cancel(request.request_id, proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.shield.commit(request.request_id, proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.vehicle.snapshot(), ())

    def test_copied_proof_and_grant_fail_on_a_different_or_unenrolled_ingress(self):
        request = self.request()
        proof, grant = self.signed(request)
        for ingress in (AI.ingress, Ingress(), None):
            self.assertFalse(self.shield.authenticate(request, proof, ingress))
            self.assertEqual(self.shield.prepare(request, proof, grant, ingress), DENIED)
        self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), AUTHORIZED)
        self.assertEqual(self.shield.commit(request.request_id, proof, AI.ingress), DENIED)
        self.assertEqual(self.shield.cancel(request.request_id, proof, AI.ingress), DENIED)
        self.assertEqual(self.vehicle.snapshot(), ())
        self.assertEqual(self.shield.commit(request.request_id, proof, DISPLAY.ingress), COMMITTED)
        self.assertEqual(len(self.vehicle.snapshot()), 1)

    def test_origin_and_grant_bind_each_request_field(self):
        request = self.request()
        proof, grant = self.signed(request)
        for field, value in (
            ("request_id", "request-b"), ("principal", DIAGNOSTICS.principal),
            ("origin", "ui-copy"), ("vehicle", "vehicle-b"),
            ("operation", "data_export"), ("scope", "location"), ("payload", "substituted"),
        ):
            with self.subTest(field=field):
                altered = replace(request, **{field: value})
                self.assertNotEqual(request_digest(request), request_digest(altered))
                self.assertFalse(self.shield.authenticate(altered, proof, DISPLAY.ingress))
                self.assertEqual(self.shield.prepare(altered, sign_request(altered, DISPLAY.key), grant, DISPLAY.ingress), DENIED)
        self.assertFalse(self.shield.authenticate(request, sign_request(request, AI.key), DISPLAY.ingress))
        self.assertEqual(self.vehicle.snapshot(), ())

    def test_cross_vehicle_deny_even_with_target_origin_proof(self):
        target = SyntheticVehicle("vehicle-b", IDENTITIES, AUTHORITY_KEY, FIRMWARE_KEY)
        source_request = self.request()
        _, grant = self.signed(source_request)
        target_request = replace(source_request, vehicle="vehicle-b")
        proof = sign_request(target_request, DISPLAY.key)
        self.assertTrue(target.shield.authenticate(target_request, proof, DISPLAY.ingress))
        self.assertEqual(target.shield.prepare(target_request, proof, grant, DISPLAY.ingress), DENIED)
        self.assertEqual(target.snapshot(), ())

    def test_untrusted_input_types_and_sizes_deny_without_raising(self):
        request = self.request()
        proof, grant = self.signed(request)
        for candidate in (None, {}, replace(request, request_id=[]), replace(request, payload=b"bad"),
                          replace(request, payload="x" * 257), replace(request, payload="🌲" * 65),
                          replace(request, payload="\ud800"), replace(request, firmware={}),
                          replace(request, firmware=Firmware(True, IMAGE_DIGEST, "0" * 64))):
            with self.subTest(candidate=repr(candidate)):
                self.assertEqual(self.shield.prepare(candidate, proof, grant, DISPLAY.ingress), DENIED)
        for candidate in (None, "💡" * 64, "x" * 65, 0, [], {}):
            with self.subTest(proof=candidate):
                self.assertEqual(self.shield.prepare(request, candidate, grant, DISPLAY.ingress), DENIED)
        for candidate in (None, {}, replace(grant, nonce=[]), replace(grant, signature="é" * 64),
                          replace(grant, request_digest=0), replace(grant, issued_at=True),
                          replace(grant, expires_at=2**64), replace(grant, epoch=-1)):
            with self.subTest(grant=repr(candidate)):
                self.assertEqual(self.shield.prepare(request, proof, candidate, DISPLAY.ingress), DENIED)
        self.assertEqual(self.shield.commit([], proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.shield.cancel([], proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.vehicle.snapshot(), ())
        with self.assertRaises(ValueError):
            request_digest(replace(request, payload="\ud800"))

    def test_full_grant_authentication_and_short_lifetime(self):
        request = self.request()
        proof, grant = self.signed(request)
        incorrect = (
            replace(grant, signature="0" * 64), replace(grant, nonce="changed"),
            replace(grant, issued_at=96), replace(grant, expires_at=114),
            replace(grant, epoch=2), sign_grant(request, "a", 80, 111, 1, AUTHORITY_KEY),
            sign_grant(request, "a", 80, 100, 1, AUTHORITY_KEY),
            sign_grant(request, "a", 101, 111, 1, AUTHORITY_KEY),
            sign_grant(request, "a", 95, 115, 2, AUTHORITY_KEY),
            sign_grant(request, "a", 95, 115, 1, DISPLAY.key),
        )
        for candidate in incorrect:
            with self.subTest(grant=candidate):
                self.assertEqual(self.shield.prepare(request, proof, candidate, DISPLAY.ingress), DENIED)
        boundary = sign_grant(request, "a", 100, 130, 1, AUTHORITY_KEY)
        self.assertEqual(self.shield.prepare(request, proof, boundary, DISPLAY.ingress), AUTHORIZED)
        self.assertEqual(self.vehicle.snapshot(), ())

    def test_settlement_revalidates_each_live_authority_source(self):
        for change in (
            lambda shield, grant: shield.set_connectivity(False, True),
            lambda shield, grant: shield.set_connectivity(True, False),
            lambda shield, grant: shield.set_connectivity(True, None),
            lambda shield, grant: shield.set_connectivity(None, True),
            lambda shield, grant: shield.set_connectivity(1, True),
            lambda shield, grant: shield.set_time(grant.expires_at),
            lambda shield, grant: shield.set_time(None),
            lambda shield, grant: shield.set_epoch(2),
            lambda shield, grant: shield.set_epoch(None),
            lambda shield, grant: shield.revoke(grant.nonce),
            lambda shield, grant: shield.set_revocation_known(None),
            lambda shield, grant: shield.set_revocation_known(False),
        ):
            with self.subTest(change=change):
                vehicle = SyntheticVehicle("vehicle-a", IDENTITIES, AUTHORITY_KEY, FIRMWARE_KEY)
                request = self.request()
                proof, grant = self.signed(request)
                self.assertEqual(vehicle.shield.prepare(request, proof, grant, DISPLAY.ingress), AUTHORIZED)
                change(vehicle.shield, grant)
                self.assertEqual(vehicle.shield.commit(request.request_id, proof, DISPLAY.ingress), DENIED)
                self.assertEqual(vehicle.shield.prepare(request, proof, grant, DISPLAY.ingress), DENIED)
                self.assertEqual(vehicle.snapshot(), ())

    def test_clock_and_epoch_cannot_rollback_from_unknown(self):
        self.shield.set_time(105)
        self.shield.set_time(None)
        for value in (False, 104, 2**64):
            with self.subTest(time=value), self.assertRaises(ValueError):
                self.shield.set_time(value)
        self.shield.set_time(105)
        self.shield.set_epoch(2)
        self.shield.set_epoch(None)
        for value in (False, 1, -1):
            with self.subTest(epoch=value), self.assertRaises(ValueError):
                self.shield.set_epoch(value)
        self.shield.set_epoch(2)
        request = self.request()
        proof = sign_request(request, DISPLAY.key)
        grant = sign_grant(request, "current", 104, 118, 2, AUTHORITY_KEY)
        self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), AUTHORIZED)
        self.assertEqual(self.shield.commit(request.request_id, proof, DISPLAY.ingress), COMMITTED)

    def test_revocation_bound_never_silently_forgets(self):
        request = self.request()
        proof, grant = self.signed(request)
        self.shield.revoke(grant.nonce)
        self.shield.revoke(grant.nonce)
        self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), DENIED)
        request = replace(request, request_id="originally-valid")
        proof, grant = self.signed(request)
        for number in range(MAX_REVOCATIONS - 1):
            self.shield.revoke(f"revoked-{number}")
        self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), AUTHORIZED)
        self.shield.revoke("revoked-overflow")
        self.assertEqual(self.shield.commit(request.request_id, proof, DISPLAY.ingress), DENIED)
        self.assertEqual(self.vehicle.snapshot(), ())
        with self.assertRaises(ValueError):
            self.shield.revoke("not a valid nonce")

    def test_replay_race_and_reissued_grant_cannot_duplicate_effect(self):
        workers = 8
        barrier = Barrier(workers)
        request = self.request()
        proof, grant = self.signed(request)

        def contender(_):
            barrier.wait(timeout=10)
            decision = self.shield.prepare(request, proof, grant, DISPLAY.ingress)
            return self.shield.commit(request.request_id, proof, DISPLAY.ingress) if decision == AUTHORIZED else decision

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(contender, range(workers)))
        self.assertEqual(sorted(results), [COMMITTED] + [DENIED] * (workers - 1))
        self.assertEqual(len(self.vehicle.snapshot()), 1)
        fresh_nonce = sign_grant(request, "fresh-nonce", 95, 115, 1, AUTHORITY_KEY)
        self.assertEqual(self.shield.prepare(request, proof, fresh_nonce, DISPLAY.ingress), DENIED)
        another_request = replace(request, request_id="different-request")
        reused_nonce = sign_grant(another_request, grant.nonce, 95, 115, 1, AUTHORITY_KEY)
        self.assertEqual(self.shield.prepare(another_request, sign_request(another_request, DISPLAY.key),
                                             reused_nonce, DISPLAY.ingress), DENIED)
        self.assertEqual(len(self.vehicle.snapshot()), 1)

    def test_pending_and_committed_capacity_do_not_starve_safety(self):
        for number in range(MAX_PENDING):
            request = self.request(request_id=f"pending-{number}")
            proof, grant = self.signed(request)
            self.assertEqual(self.shield.prepare(request, proof, grant, DISPLAY.ingress), AUTHORIZED)
        self.assertEqual(self.attempt(self.request()), DENIED)
        first = self.request(request_id="pending-0")
        self.assertEqual(self.shield.cancel(first.request_id, sign_request(first, DISPLAY.key), DISPLAY.ingress), CANCELLED)
        for number in range(MAX_EFFECTS):
            self.assertEqual(self.attempt(self.request(request_id=f"write-{number}")), COMMITTED)
        self.assertEqual(self.attempt(self.request()), DENIED)
        self.assertEqual(self.vehicle.local.observe_hazard("still-available", True), COMMITTED)
        self.assertEqual(len(self.vehicle.snapshot()), MAX_EFFECTS + 1)
        self.assertEqual(self.vehicle.snapshot()[-1].domain, "safety")

    def test_ledger_rejection_does_not_consume_grant_or_install_firmware(self):
        self.shield.set_conditions(True, True)
        request = self.firmware_request()
        proof, grant = self.signed(request, UPDATER)
        record_external = self.shield._record_external
        self.shield._record_external = lambda _: False
        self.assertEqual(self.shield.prepare(request, proof, grant, UPDATER.ingress), AUTHORIZED)
        self.assertEqual(self.shield.commit(request.request_id, proof, UPDATER.ingress), DENIED)
        self.assertEqual(self.vehicle.firmware_version, 1)
        self.assertEqual(self.vehicle.snapshot(), ())
        self.shield._record_external = record_external
        self.assertEqual(self.shield.prepare(request, proof, grant, UPDATER.ingress), AUTHORIZED)
        self.assertEqual(self.shield.commit(request.request_id, proof, UPDATER.ingress), COMMITTED)
        self.assertEqual(self.vehicle.firmware_version, 2)

    def test_destination_writer_cannot_write_or_exhaust_safety_journal(self):
        writer = self.shield._record_external
        effect = Effect("vehicle-a", "safety", "emergency_braking", "local", "local-safety-controller",
                        "local-sensor", "trial", None, sha256(b"").hexdigest(), None)
        self.assertFalse(writer(effect))
        self.assertFalse(writer(replace(effect, domain="external")))
        self.assertFalse(writer.__self__.record(effect))
        with self.assertRaises(ValueError):
            self.vehicle._ledger.record(replace(effect, domain="unknown"))
        external = replace(effect, domain="external", operation="display")
        for number in range(MAX_EFFECTS):
            self.assertTrue(self.vehicle._ledger.record(replace(external, request_id=f"sink-{number}")))
        self.assertFalse(writer(external))
        self.assertEqual(self.vehicle.local.observe_hazard("reserved-sink", True), COMMITTED)
        self.assertEqual(self.vehicle.snapshot()[-1].domain, "safety")

    def test_only_consent_bound_coarse_export_and_health_diagnostics(self):
        diagnostics = self.request(DIAGNOSTICS, "diagnostic_read", "health-summary")
        self.assertEqual(self.attempt(diagnostics, DIAGNOSTICS), COMMITTED)
        export = self.request(PRIVACY, "data_export", "trip-summary", payload="coarse-region")
        self.assertEqual(self.attempt(export, PRIVACY), DENIED)
        self.shield.set_privacy_consent(True)
        for scope in ("location", "camera", "microphone"):
            self.assertEqual(self.attempt(replace(export, scope=scope), PRIVACY), DENIED)
        self.assertEqual(self.attempt(replace(export, payload="precise-location"), PRIVACY), DENIED)
        self.assertEqual(self.attempt(replace(export, firmware=self.firmware_request().firmware),
                                      PRIVACY), DENIED)
        proof, grant = self.signed(export, PRIVACY)
        self.assertEqual(self.shield.prepare(export, proof, grant, PRIVACY.ingress), DENIED)  # nonce already consumed
        export = replace(export, request_id="independent-export")
        proof, grant = self.signed(export, PRIVACY)
        self.assertEqual(self.shield.prepare(export, proof, grant, PRIVACY.ingress), AUTHORIZED)
        self.shield.set_privacy_consent(False)
        self.assertEqual(self.shield.commit(export.request_id, proof, PRIVACY.ingress), DENIED)
        self.shield.set_privacy_consent(True)
        self.assertEqual(self.attempt(export, PRIVACY), COMMITTED)
        self.assertEqual([row.operation for row in self.vehicle.snapshot()], ["diagnostic_read", "data_export"])

    def test_firmware_provenance_conditions_payload_and_version_rechecked(self):
        request = self.firmware_request()
        proof, grant = self.signed(request, UPDATER)
        self.assertEqual(self.shield.prepare(request, proof, grant, UPDATER.ingress), DENIED)
        self.shield.set_conditions(True, False)
        self.assertEqual(self.shield.prepare(request, proof, grant, UPDATER.ingress), DENIED)
        self.shield.set_conditions(False, True)
        self.assertEqual(self.shield.prepare(request, proof, grant, UPDATER.ingress), DENIED)
        self.shield.set_conditions(True, True)
        for candidate in (
            replace(request, firmware=None), replace(request, payload="f" * 64), self.firmware_request(1),
            replace(request, firmware=sign_firmware("vehicle-b", 2, IMAGE_DIGEST, FIRMWARE_KEY)),
            replace(request, firmware=sign_firmware("vehicle-a", 2, IMAGE_DIGEST, AUTHORITY_KEY)),
        ):
            self.assertEqual(self.attempt(candidate, UPDATER), DENIED)
        self.assertEqual(self.shield.prepare(request, proof, grant, UPDATER.ingress), AUTHORIZED)
        self.shield.set_conditions(None, True)
        self.assertEqual(self.shield.commit(request.request_id, proof, UPDATER.ingress), DENIED)
        self.assertEqual(self.vehicle.firmware_version, 1)
        self.shield.set_conditions(True, True)
        self.assertEqual(self.shield.prepare(request, proof, grant, UPDATER.ingress), AUTHORIZED)
        newer = replace(self.firmware_request(3), request_id="newer-update")
        self.assertEqual(self.attempt(newer, UPDATER), COMMITTED)
        self.assertEqual(self.shield.commit(request.request_id, proof, UPDATER.ingress), DENIED)
        self.assertEqual(self.vehicle.firmware_version, 3)
        self.assertEqual([row.firmware_version for row in self.vehicle.snapshot()], [3])

    def test_authenticated_external_safety_and_inert_input_denied_even_with_valid_grant(self):
        for identity in (AI, DISPLAY, DIAGNOSTICS, UPDATER):
            for operation in ("emergency_braking", "steering", "acceleration", "battery_management",
                              "adas_override", "execute_telemetry", "diagnostic_write"):
                with self.subTest(identity=identity.role, operation=operation):
                    request = self.request(identity, operation, "local", payload="pretend-local-instruction")
                    self.assertTrue(self.shield.authenticate(request, sign_request(request, identity.key), identity.ingress))
                    self.assertEqual(self.attempt(request, identity), DENIED)
                    self.assertEqual(self.vehicle.snapshot(), ())
        self.assertEqual(self.attempt(self.request(AI), AI), DENIED)
        self.assertEqual(self.attempt(self.request(firmware=self.firmware_request().firmware)), DENIED)

    def test_local_hazard_requires_true_input_and_survives_authority_lock(self):
        self.assertEqual(self.vehicle.local.observe_hazard("missing-sensor", None), DENIED)
        self.assertEqual(self.vehicle.local.driver_brake("not-pressed", False), DENIED)
        self.assertEqual(self.vehicle.local.observe_hazard("wrong-type", 1), DENIED)
        self.assertEqual(self.vehicle.local.observe_hazard([], True), DENIED)
        self.assertEqual(self.vehicle.snapshot(), ())
        self.shield.set_connectivity(False, False)
        finished = Event()

        def local_sensors():
            self.vehicle.local.observe_hazard("trusted-obstacle", True)
            self.vehicle.local.driver_brake("trusted-pedal", True)
            finished.set()

        with self.shield._lock, self.vehicle._ledger.external._lock:
            worker = Thread(target=local_sensors, daemon=True)
            worker.start()
            completed = finished.wait(timeout=3)
        worker.join(timeout=3)
        self.assertTrue(completed)
        self.assertEqual([row.origin for row in self.vehicle.snapshot()], ["local-sensor", "local-driver"])
        self.assertEqual([row.operation for row in self.vehicle.snapshot()], [
            "emergency_braking", "driver_braking",
        ])

    def test_evidence_overflow_does_not_disable_local_braking(self):
        for number in range(MAX_EFFECTS + 2):
            self.assertEqual(self.vehicle.local.driver_brake(f"local-{number}", True), COMMITTED)
        with self.assertRaises(EvidenceOverflow):
            self.vehicle.snapshot()
        self.assertEqual(self.vehicle.local.observe_hazard("latest", True), COMMITTED)

    def test_misconfigured_trust_anchors_fail_at_construction(self):
        for identities in (
            (*IDENTITIES, DISPLAY), (replace(DISPLAY, key=AUTHORITY_KEY),),
            (AI, replace(DISPLAY, ingress=AI.ingress)), (replace(DISPLAY, ingress=object()),),
            (replace(DISPLAY, origin="local-driver"),), (replace(DISPLAY, origin="local-sensor"),),
            (replace(DISPLAY, principal="local-safety-controller"),), (replace(DISPLAY, key=b"weak"),),
            ({},), tuple(Identity(f"principal-{i}", "ui", "display", fixture_key(str(i)), Ingress())
                         for i in range(MAX_IDENTITIES + 1)),
        ):
            with self.subTest(identities=len(identities)), self.assertRaises(ValueError):
                SyntheticVehicle("vehicle-a", identities, AUTHORITY_KEY, FIRMWARE_KEY)
        with self.assertRaises(ValueError):
            SyntheticVehicle("vehicle-a", IDENTITIES, AUTHORITY_KEY, AUTHORITY_KEY)


if __name__ == "__main__":
    unittest.main()
