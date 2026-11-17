"""GT-VSA security boundaries for synthetic, in-memory effects only."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from threading import Lock

from .canonical import canonical_json, sha256_json

MAX_GRANT_TTL = 30
MAX_PAYLOAD_BYTES = 256
MAX_PENDING = 32
MAX_EFFECTS = 128
MAX_REVOCATIONS = 128
MAX_IDENTITIES = 32
_MAX_COUNTER = (1 << 63) - 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()

AUTHORIZED = "AUTHORIZED"
DENIED = "DENIED"
COMMITTED = "COMMITTED"
CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class Firmware:
    version: int
    image_digest: str
    signature: str


@dataclass(frozen=True, slots=True)
class Request:
    request_id: str
    principal: str
    origin: str
    vehicle: str
    operation: str
    scope: str
    payload: str = ""
    firmware: Firmware | None = None


@dataclass(frozen=True, slots=True)
class Grant:
    nonce: str
    request_digest: str
    issued_at: int
    expires_at: int
    epoch: int
    signature: str


class Ingress:
    """Opaque identity of a trusted, fixture-wired transport endpoint."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class Identity:
    principal: str
    origin: str
    role: str
    key: bytes
    ingress: Ingress


@dataclass(frozen=True, slots=True)
class Effect:
    vehicle: str
    domain: str
    operation: str
    scope: str
    principal: str
    origin: str
    request_id: str
    nonce: str | None
    payload_digest: str
    firmware_version: int | None


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _counter(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_COUNTER


def _key(value: object) -> bool:
    return type(value) is bytes and 16 <= len(value) <= 64


def _valid_request(request: Request) -> bool:
    if type(request) is not Request or not all(
        _identifier(value) for value in (
            request.request_id, request.principal, request.origin, request.vehicle,
            request.operation, request.scope,
        )
    ):
        return False
    if type(request.payload) is not str or len(request.payload) > MAX_PAYLOAD_BYTES:
        return False
    try:
        if len(request.payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            return False
    except UnicodeEncodeError:
        return False
    firmware = request.firmware
    return firmware is None or (
        type(firmware) is Firmware and _counter(firmware.version)
        and _digest(firmware.image_digest) and _digest(firmware.signature)
    )


def request_digest(request: Request) -> str:
    """Digest the versioned request including the manifest, when present."""
    if not _valid_request(request):
        raise ValueError("invalid synthetic request")
    firmware = request.firmware
    manifest = None if firmware is None else (
        firmware.version, firmware.image_digest, firmware.signature,
    )
    return sha256_json((
        "gt-vsa-request/v1", request.request_id, request.principal, request.origin,
        request.vehicle, request.operation, request.scope, request.payload, manifest,
    ))


def _mac(key: bytes, domain: str, fields: tuple) -> str:
    return hmac.digest(key, canonical_json((domain, fields)).encode("utf-8"), "sha256").hex()


def sign_request(request: Request, key: bytes) -> str:
    """Create a test principal's proof of possession over the exact request."""
    return _mac(key, "gt-vsa-origin/v1", (request_digest(request),))


def sign_grant(
    request: Request, nonce: str, issued_at: int, expires_at: int, epoch: int, key: bytes,
) -> Grant:
    """Create a fixture issuer's grant; the shield independently rechecks it."""
    digest = request_digest(request)
    fields = nonce, digest, issued_at, expires_at, epoch
    return Grant(*fields, _mac(key, "gt-vsa-grant/v1", fields))


def sign_firmware(vehicle: str, version: int, image_digest: str, key: bytes) -> Firmware:
    """Create a fictional release manifest for the exact synthetic recipient."""
    fields = vehicle, version, image_digest
    return Firmware(version, image_digest, _mac(key, "gt-vsa-firmware/v1", fields))


class EvidenceOverflow(RuntimeError):
    """The safety observer exceeded its fixed retention window."""


class _EffectJournal:
    def __init__(self, domain: str, sequence: Callable[[], int]) -> None:
        self._domain = domain
        self._sequence = sequence
        self._rows: deque[tuple[int, Effect]] = deque(maxlen=MAX_EFFECTS)
        self._overflow = False
        self._lock = Lock()

    def record(self, effect: Effect) -> bool:
        if effect.domain != self._domain:
            return False
        with self._lock:
            if len(self._rows) == MAX_EFFECTS:
                if self._domain == "external":
                    return False
                self._overflow = True
            self._rows.append((self._sequence(), effect))
            return True

    def record_external(self, effect: Effect) -> bool:
        return effect.domain == "external" and effect.operation in (
            "display", "diagnostic_read", "data_export", "firmware_update",
        ) and self.record(effect)


class _Ledger:
    """The observer sees both journals while each writer only holds its own journal."""

    def __init__(self) -> None:
        sequence_lock = Lock()
        sequence = 0

        def next_sequence() -> int:
            nonlocal sequence
            with sequence_lock:
                value = sequence
                # Beyond this bound the observer has already lost safety history.
                sequence = min(sequence + 1, 2 * MAX_EFFECTS)
                return value

        self.external = _EffectJournal("external", next_sequence)
        self.safety = _EffectJournal("safety", next_sequence)

    def record(self, effect: Effect) -> bool:
        """Record direct synthetic sink mutations for independent test fixtures."""
        if effect.domain == "external":
            return self.external.record(effect)
        if effect.domain == "safety":
            return self.safety.record(effect)
        raise ValueError("unknown synthetic effect domain")

    def snapshot(self) -> tuple[Effect, ...]:
        with self.external._lock, self.safety._lock:
            if self.safety._overflow:
                raise EvidenceOverflow("synthetic safety history incomplete")
            return tuple(effect for _, effect in sorted((*self.external._rows, *self.safety._rows)))


@dataclass(slots=True)
class _AuthorityState:
    now: int | None
    epoch: int | None
    network: bool | None = True
    available: bool | None = True
    revocations_known: bool | None = True
    revocation_overflow: bool = False


@dataclass(slots=True)
class _PolicyState:
    firmware_version: int
    parked: bool | None = None
    powered: bool | None = None
    privacy_consent: bool | None = None


def _permitted(request: Request, role: str, state: _PolicyState, firmware_key: bytes) -> bool:
    action = request.operation, request.scope, role
    if action == ("firmware_update", "noncritical-infotainment", "updater"):
        firmware = request.firmware
        if (
            firmware is None or request.payload != firmware.image_digest
            or firmware.version <= state.firmware_version
            or state.parked is not True or state.powered is not True
        ):
            return False
        expected = sign_firmware(request.vehicle, firmware.version, firmware.image_digest, firmware_key)
        return hmac.compare_digest(firmware.signature, expected.signature)

    if request.firmware is not None:
        return False
    if action == ("data_export", "trip-summary", "privacy"):
        return state.privacy_consent is True and request.payload == "coarse-region"
    return action in (
        ("display", "infotainment", "display"),
        ("diagnostic_read", "health-summary", "diagnostics"),
    )


@dataclass(frozen=True, slots=True)
class _Pending:
    request: Request
    grant: Grant


class Shield:
    """Independent identity/authority checks followed by deterministic policy."""

    def __init__(
        self, vehicle: str, identities: Iterable[Identity], authority_key: bytes,
        firmware_key: bytes, record_external: Callable[[Effect], bool], *,
        now: int | None, epoch: int | None, firmware_version: int,
    ) -> None:
        if (
            not _identifier(vehicle) or not _key(authority_key) or not _key(firmware_key)
            or authority_key == firmware_key or not _counter(firmware_version)
            or (now is not None and not _counter(now))
            or (epoch is not None and not _counter(epoch))
        ):
            raise ValueError("invalid synthetic trust configuration")
        self._vehicle = vehicle
        self._authority_key = authority_key
        self._firmware_key = firmware_key
        self._identities: dict[tuple[str, str], Identity] = {}
        keys = {authority_key, firmware_key}
        ingress_channels: set[Ingress] = set()
        for identity in identities:
            if (
                type(identity) is not Identity or len(self._identities) == MAX_IDENTITIES
                or not all(_identifier(value) for value in (identity.principal, identity.origin, identity.role))
                or identity.origin in ("local-driver", "local-sensor")
                or identity.principal == "local-safety-controller"
                or not _key(identity.key) or identity.key in keys
                or type(identity.ingress) is not Ingress or identity.ingress in ingress_channels
                or (identity.principal, identity.origin) in self._identities
            ):
                raise ValueError("invalid synthetic identity configuration")
            self._identities[identity.principal, identity.origin] = identity
            keys.add(identity.key)
            ingress_channels.add(identity.ingress)
        self._record_external = record_external
        self._authority = _AuthorityState(now, epoch)
        self._policy = _PolicyState(firmware_version)
        self._time_floor = 0 if now is None else now
        self._epoch_floor = 0 if epoch is None else epoch
        self._pending: dict[str, _Pending] = {}
        self._revoked: set[str] = set()
        self._consumed: set[str] = set()
        self._settled: set[tuple[str, str]] = set()
        self._lock = Lock()

    @property
    def firmware_version(self) -> int:
        with self._lock:
            return self._policy.firmware_version

    def set_time(self, now: int | None) -> None:
        with self._lock:
            if now is not None:
                if not _counter(now) or now < self._time_floor:
                    raise ValueError("invalid or decreasing synthetic time")
                self._time_floor = now
            self._authority.now = now

    def set_epoch(self, epoch: int | None) -> None:
        with self._lock:
            if epoch is not None:
                if not _counter(epoch) or epoch < self._epoch_floor:
                    raise ValueError("invalid or decreasing authority epoch")
                self._epoch_floor = epoch
            self._authority.epoch = epoch

    def set_connectivity(self, network: bool | None, authority_available: bool | None) -> None:
        with self._lock:
            self._authority.network = network
            self._authority.available = authority_available

    def set_revocation_known(self, known: bool | None) -> None:
        with self._lock:
            self._authority.revocations_known = known

    def set_conditions(self, parked: bool | None, powered: bool | None) -> None:
        with self._lock:
            self._policy.parked = parked
            self._policy.powered = powered

    def set_privacy_consent(self, consent: bool | None) -> None:
        with self._lock:
            self._policy.privacy_consent = consent

    def revoke(self, nonce: str) -> None:
        if not _identifier(nonce):
            raise ValueError("invalid synthetic grant nonce")
        with self._lock:
            if nonce in self._revoked:
                return
            if len(self._revoked) == MAX_REVOCATIONS:
                self._authority.revocation_overflow = True
                return
            self._revoked.add(nonce)

    def _authenticated(self, request: Request, proof: str, ingress: Ingress) -> Identity | None:
        if not _valid_request(request) or request.vehicle != self._vehicle or not _digest(proof):
            return None
        identity = self._identities.get((request.principal, request.origin))
        if (
            identity is not None and ingress is identity.ingress
            and hmac.compare_digest(proof, sign_request(request, identity.key))
        ):
            return identity
        return None

    def authenticate(self, request: Request, proof: str, ingress: Ingress) -> bool:
        """Verify an origin without granting permission or committing an effect."""
        return self._authenticated(request, proof, ingress) is not None

    def _current_grant(self, request: Request, grant: Grant | None) -> bool:
        state = self._authority
        if (
            state.network is not True or state.available is not True
            or state.revocations_known is not True or state.revocation_overflow
            or state.now is None or state.epoch is None
            or type(grant) is not Grant or not _identifier(grant.nonce)
            or not _digest(grant.signature) or not _digest(grant.request_digest)
            or not all(_counter(value) for value in (grant.issued_at, grant.expires_at, grant.epoch))
        ):
            return False
        if (
            grant.epoch != state.epoch or not grant.issued_at <= state.now < grant.expires_at
            or grant.expires_at - grant.issued_at > MAX_GRANT_TTL
            or grant.nonce in self._revoked or grant.nonce in self._consumed
            or (request.principal, request.request_id) in self._settled
            or len(self._consumed) == MAX_EFFECTS
            or grant.request_digest != request_digest(request)
        ):
            return False
        expected = _mac(self._authority_key, "gt-vsa-grant/v1", (
            grant.nonce, grant.request_digest, grant.issued_at, grant.expires_at, grant.epoch,
        ))
        return hmac.compare_digest(grant.signature, expected)

    def prepare(self, request: Request, proof: str, grant: Grant | None, ingress: Ingress) -> str:
        with self._lock:
            identity = self._authenticated(request, proof, ingress)
            if (
                identity is None or not self._current_grant(request, grant)
                or not _permitted(request, identity.role, self._policy, self._firmware_key)
                or request.request_id in self._pending or len(self._pending) == MAX_PENDING
            ):
                return DENIED
            self._pending[request.request_id] = _Pending(request, grant)
            return AUTHORIZED

    def commit(self, request_id: str, proof: str, ingress: Ingress) -> str:
        with self._lock:
            pending = self._pending.get(request_id) if _identifier(request_id) else None
            if pending is None:
                return DENIED
            request, grant = pending.request, pending.grant
            identity = self._authenticated(request, proof, ingress)
            if identity is None:
                return DENIED
            del self._pending[request_id]
            if (
                not self._current_grant(request, grant)
                or not _permitted(request, identity.role, self._policy, self._firmware_key)
            ):
                return DENIED
            manifest = request.firmware
            effect = Effect(
                request.vehicle, "external", request.operation, request.scope, request.principal,
                request.origin, request.request_id, grant.nonce,
                hashlib.sha256(request.payload.encode("utf-8")).hexdigest(),
                None if manifest is None else manifest.version,
            )
            if not self._record_external(effect):
                return DENIED
            self._consumed.add(grant.nonce)
            self._settled.add((request.principal, request.request_id))
            if manifest is not None:
                self._policy.firmware_version = manifest.version
            return COMMITTED

    def cancel(self, request_id: str, proof: str, ingress: Ingress) -> str:
        with self._lock:
            pending = self._pending.get(request_id) if _identifier(request_id) else None
            if pending is None or self._authenticated(pending.request, proof, ingress) is None:
                return DENIED
            del self._pending[request_id]
            return CANCELLED


class LocalSafety:
    """An isolated local input path with no external identity or grant interface."""

    def __init__(self, vehicle: str, record_safety: Callable[[Effect], bool]) -> None:
        self._vehicle = vehicle
        self._record_safety = record_safety

    def _brake(self, event_id: str, active: bool | None, operation: str, source: str) -> str:
        if active is not True or not _identifier(event_id):
            return DENIED
        self._record_safety(Effect(
            self._vehicle, "safety", operation, "local", "local-safety-controller", source,
            event_id, None, _EMPTY_DIGEST, None,
        ))
        return COMMITTED

    def observe_hazard(self, event_id: str, obstacle: bool | None) -> str:
        return self._brake(event_id, obstacle, "emergency_braking", "local-sensor")

    def driver_brake(self, event_id: str, pressed: bool | None) -> str:
        return self._brake(event_id, pressed, "driver_braking", "local-driver")


class SyntheticVehicle:
    """Wire separate external and local capabilities to an observer, with no I/O."""

    def __init__(
        self, vehicle: str, identities: Iterable[Identity], authority_key: bytes,
        firmware_key: bytes, *, now: int | None = 100, epoch: int | None = 1,
        firmware_version: int = 1,
    ) -> None:
        self._ledger = _Ledger()
        self.shield = Shield(
            vehicle, identities, authority_key, firmware_key, self._ledger.external.record_external,
            now=now, epoch=epoch, firmware_version=firmware_version,
        )
        self.local = LocalSafety(vehicle, self._ledger.safety.record)

    def snapshot(self) -> tuple[Effect, ...]:
        return self._ledger.snapshot()

    @property
    def firmware_version(self) -> int:
        return self.shield.firmware_version
