"""WolfNet's closed JSON vocabulary, canonical signing inputs and calendar bounds."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from .agent_scan import _open_directory, _read_file
from .canonical import canonical_json
from .cursorial_trace import Gap, need
from .wolfprint import matches_schema

STATIC = "STATIC REVIEW SIGNAL"
SYNTHETIC = "SYNTHETICALLY VERIFIED"
RUNTIME = "AUTHORIZED RUNTIME VERIFIED"
GAP = "INCONCLUSIVE"
LEVELS = ("CLEAR", "ADVISORY", "MODERATE", "HIGH", "CRITICAL")
CONFIDENCE = ("LOW", "MEDIUM", "HIGH")
ACTIONS = ("ALLOW", "MONITOR", "READ_ONLY", "REQUIRE_HUMAN_APPROVAL", "REAUTHENTICATE", "QUARANTINE", "DENY")


@lru_cache(maxsize=1)
def definitions():
    fd = _open_directory(Path(__file__).parent / "schemas")
    try:
        return json.loads(_read_file(fd, "wolfnet-v1.schema.json", 65536))["$defs"]
    finally:
        os.close(fd)


def validate(doc, name):
    defs = definitions()
    need(matches_schema(doc, defs[name], defs), "invalid-" + name + "-shape")


def time_value(value):
    validate(value, "time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Gap("invalid-utc-timestamp") from None


def advance(origin, ticks):
    try:
        return (time_value(origin) + timedelta(seconds=ticks)).isoformat(timespec="seconds").replace("+00:00", "Z")
    except OverflowError:
        raise Gap("timestamp-out-of-range") from None


def logical_time(trust, stamp):
    ticks = int((time_value(stamp) - time_value(trust["clock_origin"])).total_seconds())
    need(0 <= ticks <= 999999, "outside-fixture-clock-window")
    return ticks


def interval(start, end, maximum_days=None):
    delta = time_value(end) - time_value(start)
    need(delta > timedelta(0) and (maximum_days is None or delta <= timedelta(days=maximum_days)), "invalid-validity-window")


def canonical(domain, document):
    return b"wolftrap.wolfnet/v1\x00" + domain.encode("ascii") + b"\x00" + canonical_json(document).encode("ascii")


def digest(domain, document):
    return hashlib.sha256(canonical(domain, document)).hexdigest()


def signing_bytes(role, signer, revision, body):
    return canonical("signature/" + role, {"alg": "Ed25519", "signer": signer, "key_revision": revision, "body": body})


def advisory_id(subscription, publisher, serial):
    return "WN-" + digest("advisory-id", [subscription, publisher, serial])


def genesis(subscription):
    return digest("genesis", subscription)
