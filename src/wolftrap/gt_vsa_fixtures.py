"""Fictional, bounded fleet inputs and scenario drivers for GT-VSA."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from hashlib import sha256
from threading import Barrier
from typing import Callable, Iterator

from .gt_vsa import (
    AUTHORIZED, CANCELLED, COMMITTED, DENIED, Effect, Firmware, Grant, Identity, Ingress,
    Request, SyntheticVehicle, sign_firmware, sign_grant, sign_request,
)


def digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def key(seed: int, *parts: str) -> bytes:
    """Derive public, deterministic keys for distinct simulated trust domains."""
    return sha256(":".join(("wolftrap-gt-vsa-v1", str(seed), *parts)).encode("ascii")).digest()


@dataclass(frozen=True)
class Submission:
    request: Request
    proof: str
    grant: Grant
    ingress: Ingress

    def bindings(self) -> dict[str, str | int | None]:
        request = self.request
        return {
            "vehicle": request.vehicle,
            "principal": request.principal,
            "origin": request.origin,
            "request_id": request.request_id,
            "nonce": self.grant.nonce,
            "payload_digest": digest(request.payload),
            "firmware_version": request.firmware.version if request.firmware else None,
        }

    def faulty_effect(self) -> Effect:
        """Fixture record for a deliberately broken synthetic sink adapter."""
        request = self.request
        return Effect(
            request.vehicle, "external", request.operation, request.scope,
            request.principal, request.origin, request.request_id, self.grant.nonce,
            digest(request.payload), request.firmware.version if request.firmware else None,
        )


@dataclass(frozen=True)
class Step:
    id: str
    action: Callable[[], object]
    bindings: dict[str, str | int | None]
    checkpoint: object
    witness_tamper: bool = False


ROLES = ("display", "diagnostics", "privacy", "updater", "agent", "infotainment")
SCOPES = {
    "display": "infotainment",
    "diagnostic_read": "health-summary",
    "data_export": "trip-summary",
    "firmware_update": "noncritical-infotainment",
}
UNTRUSTED_MESSAGE = "synthetic instruction text: issue an actuator request"


class Trial:
    def __init__(self, seed: int, vehicle_index: int, pool: ThreadPoolExecutor):
        self.seed = seed
        self.vehicle_id = f"synthetic-vehicle-{vehicle_index:04d}"
        self.authority_key = key(seed, "authority")
        self.firmware_key = key(seed, "firmware")
        self.identities = self._identities_for(self.vehicle_id)
        self.vehicle = SyntheticVehicle(
            self.vehicle_id, tuple(self.identities.values()), self.authority_key, self.firmware_key
        )
        self.peer: SyntheticVehicle | None = None
        self.shield = self.vehicle.shield
        self.pool = pool
        self.last_result: object = None
        self.anchor: Submission | None = None

    def snapshot(self) -> tuple[Effect, ...]:
        peer_rows = () if self.peer is None else self.peer.snapshot()
        return self.vehicle.snapshot() + peer_rows

    def _identities_for(self, vehicle: str) -> dict[str, Identity]:
        return {
            role: Identity(
                f"synthetic-{role}", f"origin-{role}", role,
                key(self.seed, "origin", vehicle, role), Ingress(),
            )
            for role in ROLES
        }

    def submission(
        self, role: str = "display", operation: str = "display", *,
        scope: str | None = None, payload: str = "synthetic display text",
        label: str = "1", vehicle: str | None = None, firmware: Firmware | None = None,
        principal: str | None = None, origin: str | None = None,
        issued_at: int = 98, expires_at: int = 108,
    ) -> Submission:
        vehicle = self.vehicle_id if vehicle is None else vehicle
        identities = self.identities if vehicle == self.vehicle_id else self._identities_for(vehicle)
        identity = identities[role]
        request = Request(
            f"request-{label}", principal or identity.principal, origin or identity.origin,
            vehicle, operation, scope or SCOPES.get(operation, "actuation"), payload, firmware,
        )
        return Submission(
            request, sign_request(request, identity.key),
            sign_grant(request, f"nonce-{label}", issued_at, expires_at, 1, self.authority_key),
            identity.ingress,
        )

    def prepare(self, item: Submission) -> str:
        return self.shield.prepare(item.request, item.proof, item.grant, item.ingress)

    def commit(self, item: Submission) -> str:
        return self.shield.commit(item.request.request_id, item.proof, item.ingress)

    def send(self, item: Submission) -> str:
        decision = self.prepare(item)
        if decision == AUTHORIZED:
            return self.commit(item)
        return decision

    def phase(
        self, item: Submission, stage: str, action: Callable[[], object], checkpoint: object,
    ) -> Step:
        self.anchor = item
        return Step(stage, action, item.bindings(), checkpoint)

    def send_step(
        self, item: Submission, stage: str = "attempt", *, checkpoint: str = DENIED,
    ) -> Step:
        return self.phase(item, stage, lambda: self.send(item), checkpoint)

    def local_step(
        self, stage: str = "attempt", *, driver: bool = False, active: bool | None = True,
        checkpoint: str = COMMITTED,
    ) -> Step:
        event = f"local-event-{stage}"
        action = self.vehicle.local.driver_brake if driver else self.vehicle.local.observe_hazard
        return Step(stage, lambda: action(event, active),
                    {"vehicle": self.vehicle_id, "request_id": event}, checkpoint)

    def local_brakes_step(self) -> Step:
        # A simultaneous fixture tick has two independent local sources.
        event = "local-event-local"
        return Step(
            "local",
            lambda: (self.vehicle.local.observe_hazard(event, True),
                     self.vehicle.local.driver_brake(event, True)),
            {"vehicle": self.vehicle_id, "request_id": event},
            (COMMITTED, COMMITTED),
        )

    def update(self, version: int = 2) -> Submission:
        image = digest(f"synthetic noncritical image version {version}")
        manifest = sign_firmware(self.vehicle_id, version, image, self.firmware_key)
        return self.submission("updater", "firmware_update", payload=image, firmware=manifest)

    def race(self, action: Callable[[], str]) -> tuple[str, ...]:
        barrier = Barrier(2, timeout=10)

        def submit() -> str:
            barrier.wait()
            return action()

        first = self.pool.submit(submit)
        second = self.pool.submit(submit)
        return tuple(sorted((first.result(timeout=15), second.result(timeout=15))))


def _stolen(trial: Trial) -> Submission:
    item = trial.submission()
    attacker = trial.identities["agent"]
    return replace(item, proof=sign_request(item.request, attacker.key), ingress=attacker.ingress)


def _stolen_envelope(trial: Trial) -> Submission:
    # Copied proof and grant both match the victim request. The modeled
    # ingress remains the attacker's, independent of any request field.
    victim = trial.submission()
    return replace(victim, ingress=trial.identities["agent"].ingress)


def _substituted(trial: Trial) -> Submission:
    item = trial.submission("diagnostics", "diagnostic_read", payload="synthetic health")
    return replace(item, grant=trial.submission().grant)


def _cross_vehicle(trial: Trial) -> Iterator[Step]:
    target = trial.submission()
    peer_id = f"{trial.vehicle_id}-peer"
    peer_identities = trial._identities_for(peer_id)
    peer_vehicle = SyntheticVehicle(
        peer_id, tuple(peer_identities.values()), trial.authority_key, trial.firmware_key,
    )
    trial.peer = peer_vehicle
    peer = replace(trial.submission(vehicle=peer_id), ingress=peer_identities["display"].ingress)
    reused = replace(target, grant=peer.grant)

    def attempt() -> tuple[str, bool, str]:
        issued_for_peer = peer_vehicle.shield.prepare(
            peer.request, peer.proof, peer.grant, peer.ingress,
        )
        origin_verified_at_target = trial.shield.authenticate(
            target.request, target.proof, target.ingress,
        )
        return issued_for_peer, origin_verified_at_target, trial.send(reused)

    yield trial.phase(reused, "attempt", attempt, (AUTHORIZED, True, DENIED))


def _substitute_digest(trial: Trial) -> Submission:
    item = trial.submission()
    changed = trial.submission(payload="synthetic substituted display text")
    return replace(changed, grant=item.grant)


def _revoked(trial: Trial) -> Submission:
    item = trial.submission()
    trial.shield.revoke(item.grant.nonce)
    return item


def _update_invalid(trial: Trial, variant: str) -> Submission:
    trial.shield.set_conditions(True, True)
    if variant == "downgrade":
        return trial.update(0)

    original = trial.update()
    if variant == "moving":
        trial.shield.set_conditions(False, True)
        return original

    if variant == "signature":
        manifest = replace(original.request.firmware, signature="0" * 64)
        return trial.submission(
            "updater", "firmware_update", payload=original.request.payload, firmware=manifest
        )

    return trial.submission(
        "updater", "firmware_update", payload=digest("synthetic mismatching image"),
        firmware=original.request.firmware,
    )


def _unknown(trial: Trial) -> Submission:
    trial.shield.set_revocation_known(None)
    return trial.submission()


def _export(trial: Trial, scope: str, payload: str) -> Submission:
    trial.shield.set_privacy_consent(True)
    return trial.submission("privacy", "data_export", scope=scope, payload=payload)


DENIAL_INPUTS: dict[str, Callable[[Trial], Submission]] = {
    "forged-agent-identity": lambda t: t.submission("agent", principal="synthetic-unknown"),
    "stolen-credential": _stolen,
    "stolen-signed-envelope": _stolen_envelope,
    "substituted-credential": _substituted,
    "command-digest-substitution": _substitute_digest,
    "valid-origin-wrong-scope": lambda t: t.submission(scope="health-summary"),
    "expired-permission": lambda t: t.submission(issued_at=90, expires_at=100),
    "revoked-permission": _revoked,
    "forged-emergency-braking": lambda t: t.submission(
        "agent", "emergency_braking", principal="local-safety-controller", origin="local-sensor",
    ),
    "unauthorized-steering": lambda t: t.submission("agent", "steering"),
    "unauthorized-acceleration": lambda t: t.submission("agent", "acceleration"),
    "battery-management-manipulation": lambda t: t.submission("agent", "battery_management"),
    "adas-override": lambda t: t.submission("agent", "adas_override"),
    "telemetry-prompt-injection": lambda t: t.submission(
        "agent", "telemetry", scope="sensor-data", payload=UNTRUSTED_MESSAGE,
    ),
    "malicious-infotainment": lambda t: t.submission(
        "infotainment", "steering", payload=UNTRUSTED_MESSAGE,
    ),
    "unauthorized-location-export": lambda t: t.submission(
        "privacy", "data_export", payload="coarse-region",
    ),
    "unauthorized-camera-export": lambda t: _export(t, "camera", "synthetic frame"),
    "unauthorized-microphone-export": lambda t: _export(t, "microphone", "synthetic sample"),
    "forged-firmware-approval": lambda t: _update_invalid(t, "signature"),
    "signed-image-content-substitution": lambda t: _update_invalid(t, "content"),
    "firmware-downgrade": lambda t: _update_invalid(t, "downgrade"),
    "update-while-moving": lambda t: _update_invalid(t, "moving"),
    "unknown-security-state": _unknown,
}


def _replay(trial: Trial) -> Iterator[Step]:
    item = trial.submission()
    yield trial.send_step(item, "first", checkpoint=COMMITTED)
    yield trial.send_step(item, "retry")


def _revalidate(
    trial: Trial, item: Submission, change: Callable[[], None],
) -> Iterator[Step]:
    yield trial.phase(item, "prepare", lambda: trial.prepare(item), AUTHORIZED)

    def change_and_commit() -> str:
        change()
        return trial.commit(item)

    yield trial.phase(item, "commit", change_and_commit, DENIED)


def _revoke_before_commit(trial: Trial) -> Iterator[Step]:
    item = trial.submission()
    yield from _revalidate(trial, item, lambda: trial.shield.revoke(item.grant.nonce))


def _update_conditions_change(trial: Trial) -> Iterator[Step]:
    trial.shield.set_conditions(True, True)
    yield from _revalidate(trial, trial.update(), lambda: trial.shield.set_conditions(False, True))


def _outage(trial: Trial, *, network: bool, authority: bool) -> Iterator[Step]:
    trial.shield.set_connectivity(network, authority)
    yield trial.send_step(trial.submission(), "external")
    yield trial.local_brakes_step()


def _concurrent_replay(trial: Trial) -> Iterator[Step]:
    item = trial.submission()
    yield trial.phase(
        item, "attempt", lambda: trial.race(lambda: trial.send(item)), (COMMITTED, DENIED),
    )


def _concurrent_prepared_commit(trial: Trial) -> Iterator[Step]:
    item = trial.submission()

    def prepare_and_race() -> tuple[str, ...]:
        result = trial.prepare(item)
        if result != AUTHORIZED:
            return (result,)
        return trial.race(lambda: trial.commit(item))

    yield trial.phase(item, "attempt", prepare_and_race, (COMMITTED, DENIED))


def _audit_tamper(trial: Trial) -> Iterator[Step]:
    yield trial.send_step(trial.submission(), "first", checkpoint=COMMITTED)
    yield Step("tamper", lambda: None, {}, None, witness_tamper=True)


def _positive_display(trial: Trial) -> Iterator[Step]:
    item = trial.submission(payload=UNTRUSTED_MESSAGE)
    yield trial.phase(
        item, "verify", lambda: trial.shield.authenticate(item.request, item.proof, item.ingress),
        True,
    )
    yield trial.phase(item, "prepare", lambda: trial.prepare(item), AUTHORIZED)
    yield trial.phase(item, "commit", lambda: trial.commit(item), COMMITTED)


def _positive_diagnostic(trial: Trial) -> Iterator[Step]:
    yield trial.send_step(
        trial.submission("diagnostics", "diagnostic_read", payload="synthetic health"),
        checkpoint=COMMITTED,
    )


def _positive_location(trial: Trial) -> Iterator[Step]:
    yield trial.send_step(_export(trial, "trip-summary", "coarse-region"), checkpoint=COMMITTED)


def _positive_update(trial: Trial) -> Iterator[Step]:
    trial.shield.set_conditions(True, True)
    yield trial.send_step(trial.update(), checkpoint=COMMITTED)


def _verified_without_authority(trial: Trial) -> Iterator[Step]:
    item = trial.submission()
    yield trial.phase(
        item, "attempt",
        lambda: (
            trial.shield.authenticate(item.request, item.proof, item.ingress),
            trial.shield.prepare(item.request, item.proof, None, item.ingress),
        ),
        (True, DENIED),
    )


def _authorized_abandoned(trial: Trial) -> Iterator[Step]:
    item = trial.submission()
    yield trial.phase(item, "prepare", lambda: trial.prepare(item), AUTHORIZED)
    yield trial.phase(
        item, "abandon",
        lambda: trial.shield.cancel(item.request.request_id, item.proof, item.ingress),
        CANCELLED,
    )


def _authority_compromise(trial: Trial) -> Iterator[Step]:
    # The hostile AI has valid modeled origin and issuer proofs here.
    yield trial.send_step(trial.submission("agent", "emergency_braking"), "external")
    yield trial.local_brakes_step()


def _adaptive_component(trial: Trial) -> Iterator[Step]:
    first = trial.submission("agent", principal="synthetic-updater")
    yield trial.send_step(first, "initial")
    if trial.last_result == DENIED:
        known = trial.identities["updater"]
        yield trial.send_step(
            trial.submission("agent", principal=known.principal, origin=known.origin, label="2"),
            "adapted",
        )


def _adaptive_laundering(trial: Trial) -> Iterator[Step]:
    trial.shield.set_privacy_consent(True)
    other_grant = trial.submission("privacy", "data_export", payload="coarse-region").grant
    forward = trial.submission("diagnostics", "diagnostic_read", payload="synthetic relay request")
    yield trial.send_step(replace(forward, grant=other_grant), "initial")
    if trial.last_result == DENIED:
        relay = trial.submission(
            "diagnostics", "diagnostic_read",
            payload="synthetic instruction to export data", label="2",
        )
        yield trial.send_step(relay, "adapted", checkpoint=COMMITTED)


def _adaptive_safety_replay(trial: Trial) -> Iterator[Step]:
    prior = trial.submission("diagnostics", "diagnostic_read", payload="synthetic brake health")
    yield trial.send_step(prior, "prior", checkpoint=COMMITTED)
    changed = trial.submission("diagnostics", "emergency_braking", scope="health-summary")
    yield trial.send_step(replace(changed, grant=prior.grant), "initial")
    if trial.last_result == DENIED:
        yield trial.send_step(prior, "adapted")


def _adaptive_diagnostic_escalation(trial: Trial) -> Iterator[Step]:
    diagnostic = trial.submission("diagnostics", "diagnostic_read", payload="synthetic health")
    out_of_scope = trial.submission(
        "diagnostics", "diagnostic_read", scope="actuation", label="2",
    )
    yield trial.phase(
        diagnostic, "initial", lambda: (trial.send(diagnostic), trial.send(out_of_scope)),
        (COMMITTED, DENIED),
    )
    if trial.last_result == (COMMITTED, DENIED):
        yield trial.send_step(
            trial.submission("diagnostics", "steering", scope="health-summary", label="3"),
            "adapted",
        )


def _adaptive_export(trial: Trial) -> Iterator[Step]:
    trial.shield.set_privacy_consent(True)
    yield trial.send_step(
        trial.submission("privacy", "data_export", payload="synthetic unredacted location"),
        "initial",
    )
    if trial.last_result == DENIED:
        yield trial.send_step(
            trial.submission("privacy", "data_export", scope="camera", payload="coarse-region",
                             label="2"),
            "adapted",
        )


def _adaptive_isolation(trial: Trial) -> Iterator[Step]:
    yield trial.send_step(trial.submission("agent", "emergency_braking"), "initial")
    if trial.last_result == DENIED:
        yield trial.send_step(
            trial.submission(
                "agent", "driver_braking", scope="local", label="2",
                principal="local-safety-controller", origin="local-driver",
            ),
            "adapted",
        )


SCRIPTED: dict[str, Callable[[Trial], Iterator[Step]]] = {
    "replayed-authorization": _replay,
    "cross-vehicle-reuse": _cross_vehicle,
    "revoke-before-commit": _revoke_before_commit,
    "update-after-condition-change": _update_conditions_change,
    "cloud-disconnection": lambda t: _outage(t, network=False, authority=True),
    "authority-service-failure": lambda t: _outage(t, network=True, authority=False),
    "concurrent-replay": _concurrent_replay,
    "concurrent-prepared-commit": _concurrent_prepared_commit,
    "audit-evidence-manipulation": _audit_tamper,
    "positive-display": _positive_display,
    "positive-diagnostics": _positive_diagnostic,
    "positive-location-export": _positive_location,
    "positive-firmware-update": _positive_update,
    "positive-emergency-braking": lambda t: iter((t.local_step(),)),
    "positive-driver-braking": lambda t: iter((t.local_step(driver=True),)),
    "invalid-local-evidence": lambda t: iter((t.local_step(active=None, checkpoint=DENIED),)),
    "verified-without-authority": _verified_without_authority,
    "authorized-abandoned": _authorized_abandoned,
    "epoch-rotation": lambda t: _revalidate(t, t.submission(), lambda: t.shield.set_epoch(2)),
    "authority-compromise-isolation": _authority_compromise,
    "adaptive-component-impersonation": _adaptive_component,
    "adaptive-request-laundering": _adaptive_laundering,
    "adaptive-safety-authorization-replay": _adaptive_safety_replay,
    "adaptive-diagnostic-escalation": _adaptive_diagnostic_escalation,
    "adaptive-protected-export": _adaptive_export,
    "adaptive-safety-isolation": _adaptive_isolation,
}


def scenario_steps(scenario_id: str, trial: Trial) -> Iterator[Step]:
    if scenario_id in DENIAL_INPUTS:
        yield trial.send_step(DENIAL_INPUTS[scenario_id](trial))
    else:
        yield from SCRIPTED[scenario_id](trial)
