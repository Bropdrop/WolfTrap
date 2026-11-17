"""Assess observed GT-VSA ledger writes against an independently authored corpus."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Iterable, Mapping


INVARIANTS = {
    "current-authority": "NO CURRENT AUTHORITY → NO PROTECTED EFFECT",
    "origin-binding": "NO VALID ORIGIN BINDING → NO PROTECTED EFFECT",
    "local-safety-approval": "NO SAFETY APPROVAL → NO SIMULATED SAFETY EFFECT",
    "isolated-safety": "NO EXTERNAL AGENT → DIRECT SAFETY-CONTROL AUTHORITY",
    "revoked-authority": "REVOKED AUTHORITY → NO NEW PROTECTED EFFECT",
    "replay": "REPLAYED AUTHORIZATION → NO DUPLICATE EFFECT",
    "local-availability": "NETWORK FAILURE → ESSENTIAL LOCAL SAFETY REMAINS AVAILABLE",
    "verified-only": "VERIFIED ≠ AUTHORIZED",
    "authorized-only": "AUTHORIZED ≠ EXECUTED",
    "data-export": "PROTECTED DATA EXPORT REQUIRES MATCHING PURPOSE AND CONSENT",
    "firmware-provenance": "SOFTWARE UPDATE REQUIRES AUTHENTIC IMAGE PROVENANCE",
    "firmware-version": "SOFTWARE UPDATE MAY ONLY ADVANCE THE INSTALLED VERSION",
    "update-conditions": "SOFTWARE UPDATE REQUIRES CURRENT SAFE OPERATING CONDITIONS",
    "inert-input": "UNTRUSTED DATA CANNOT EXECUTE A COMMAND",
    "audit-integrity": "CLAIMED EVIDENCE MUST MATCH THE INDEPENDENT LEDGER WITNESS",
    "positive-control": "A COMMITTED POSITIVE CONTROL MUST HAVE THE EXACT EXPECTED EFFECT",
}
FIELDS = (
    "vehicle", "domain", "operation", "scope", "principal", "origin",
    "request_id", "nonce", "payload_digest", "firmware_version",
)
MAX_LEDGER_ROWS = 256
MAX_TEXT = 256
MAX_CORPUS_BYTES = 64 * 1024
CORPUS_NAME = "gt-vsa-v1.json"
CORPUS_SCHEMA = "wolftrap.gt-vsa-corpus/v1"

Scalar = str | int | None
Row = tuple[Scalar, ...]


@dataclass(frozen=True)
class Stage:
    id: str
    invariants: tuple[str, ...]
    expected: tuple[Row, ...]


@dataclass(frozen=True)
class Scenario:
    id: str
    kind: str
    stages: tuple[Stage, ...]


@dataclass(frozen=True)
class Corpus:
    scenarios: tuple[Scenario, ...]
    sha256: str


@dataclass(frozen=True)
class Snapshot:
    checkpoint: str
    rows: tuple[Row, ...]
    mac: str

    @property
    def ledger_sha256(self) -> str:
        return hashlib.sha256(_encode(self.rows)).hexdigest()


@dataclass(frozen=True)
class Assessment:
    violations: tuple[str, ...]
    expected: tuple[dict[str, Scalar], ...]
    observed: tuple[dict[str, Scalar], ...]

    @property
    def passed(self) -> bool:
        return not self.violations


def _encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _is_digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _text(value: object) -> bool:
    return type(value) is str and 1 <= len(value) <= MAX_TEXT


def _row_values(row: Row) -> bool:
    if type(row) is not tuple or len(row) != len(FIELDS):
        return False
    *required_text, nonce, payload_digest, version = row
    return (
        all(_text(value) for value in required_text)
        and (nonce is None or _text(nonce))
        and _is_digest(payload_digest)
        and (version is None or (type(version) is int and 0 <= version < 2**63))
    )


def _shaped_row(row: Mapping[str, Scalar]) -> Row:
    if len(row) != len(FIELDS) or any(field not in row for field in FIELDS):
        raise ValueError("ledger row has unknown or missing fields")
    return tuple(row[field] for field in FIELDS)


class LedgerWitness:
    """Hold synthetic fixture key material outside the system under test."""

    def __init__(self, key: bytes, context: str) -> None:
        if type(key) is not bytes or len(key) != 32 or not _text(context):
            raise ValueError("invalid ledger witness configuration")
        self._key = key
        self._context = context

    def _mac(self, checkpoint: str, rows: tuple[Row, ...]) -> str:
        message = _encode(("wolftrap.gt-vsa-ledger-witness/v1", self._context, checkpoint, rows))
        return hmac.digest(self._key, message, "sha256").hex()

    def capture(self, rows: Iterable[Mapping[str, Scalar]], checkpoint: str) -> Snapshot:
        if not _text(checkpoint):
            raise ValueError("invalid ledger checkpoint")
        normalized = []
        for row in rows:
            if len(normalized) == MAX_LEDGER_ROWS:
                raise ValueError("ledger witness row limit exceeded")
            values = _shaped_row(row)
            if not _row_values(values):
                raise ValueError("ledger row has unsupported values")
            normalized.append(values)
        frozen = tuple(normalized)
        return Snapshot(checkpoint, frozen, self._mac(checkpoint, frozen))

    def verify(self, snapshot: Snapshot, checkpoint: str) -> bool:
        if (
            type(snapshot) is not Snapshot or not _text(checkpoint) or snapshot.checkpoint != checkpoint
            or type(snapshot.rows) is not tuple or len(snapshot.rows) > MAX_LEDGER_ROWS
            or not all(_row_values(row) for row in snapshot.rows)
            or not _is_digest(snapshot.mac)
        ):
            return False
        return hmac.compare_digest(snapshot.mac, self._mac(checkpoint, snapshot.rows))


def _render(template: Row, bindings: Mapping[str, Scalar]) -> Row:
    try:
        row = tuple(
            bindings[value[1:]] if isinstance(value, str) and value.startswith("$") else value
            for value in template
        )
    except KeyError as error:
        raise ValueError(f"missing expected ledger binding {error.args[0]}") from error
    if not _row_values(row):
        raise ValueError("invalid expected ledger binding")
    return row


def _rows(rows: tuple[Row, ...]) -> tuple[dict[str, Scalar], ...]:
    return tuple(dict(zip(FIELDS, values, strict=True)) for values in rows)


def assess(
    before: Snapshot,
    after: Snapshot,
    stage: Stage,
    bindings: Mapping[str, Scalar],
    witness: LedgerWitness,
) -> Assessment:
    """Compare exact ordered mutations, including fields and negative effects."""
    expected = tuple(_render(template, bindings) for template in stage.expected)
    if not witness.verify(before, f"{stage.id}:before"):
        return Assessment(("invalid-before-witness",), _rows(expected), ())
    if not witness.verify(after, f"{stage.id}:after"):
        return Assessment(("invalid-after-witness",), _rows(expected), ())
    if after.rows[:len(before.rows)] != before.rows:
        return Assessment(("ledger-prefix-changed",), _rows(expected), _rows(after.rows))
    observed = after.rows[len(before.rows):]
    violations = ()
    if observed != expected:
        if len(observed) < len(expected):
            violations = ("missing-expected-effects",)
        elif len(observed) > len(expected):
            violations = ("unexpected-extra-effects",)
        else:
            violations = ("effect-value-or-order-mismatch",)
    return Assessment(violations, _rows(expected), _rows(observed))


def _identifier(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value) is not None


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate corpus field")
    return fields


def _corpus_templates(definitions: object) -> dict[str, Row]:
    if type(definitions) is not dict or not 1 <= len(definitions) <= 16:
        raise ValueError("invalid expected ledger templates")
    examples = {
        "vehicle": "synthetic-vehicle",
        "principal": "synthetic-principal",
        "origin": "synthetic-origin",
        "request_id": "synthetic-request",
        "nonce": "synthetic-nonce",
        "payload_digest": "0" * 64,
        "firmware_version": 2,
    }
    result = {}
    for name, definition in definitions.items():
        if not _identifier(name) or type(definition) is not dict:
            raise ValueError("invalid expected ledger template")
        template = _shaped_row(definition)
        for field, value in zip(FIELDS, template, strict=True):
            if isinstance(value, str) and value.startswith("$") and value != f"${field}":
                raise ValueError("unexpected expected ledger placeholder")
        _render(template, examples)
        result[name] = template
    return result


def _stages(entries: object, templates: Mapping[str, Row]) -> tuple[Stage, ...]:
    if type(entries) is not list or not 1 <= len(entries) <= 6:
        raise ValueError("invalid corpus stage count")
    stages = []
    seen = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"id", "invariants", "expect"}:
            raise ValueError("invalid corpus stage")
        name, invariants, expected = entry["id"], entry["invariants"], entry["expect"]
        if not _identifier(name) or name in seen:
            raise ValueError("invalid or duplicate corpus stage identifier")
        if (
            type(invariants) is not list or not invariants
            or any(type(value) is not str or value not in INVARIANTS for value in invariants)
            or len(set(invariants)) != len(invariants)
        ):
            raise ValueError("invalid corpus invariant")
        if (
            type(expected) is not list or len(expected) > 4
            or any(type(value) is not str or value not in templates for value in expected)
        ):
            raise ValueError("invalid corpus expected effects")
        seen.add(name)
        stages.append(Stage(name, tuple(invariants), tuple(templates[value] for value in expected)))
    return tuple(stages)


def load_corpus() -> Corpus:
    with files("wolftrap").joinpath("data", CORPUS_NAME).open("rb") as source:
        raw = source.read(MAX_CORPUS_BYTES + 1)
    if len(raw) > MAX_CORPUS_BYTES:
        raise ValueError("GT-VSA corpus limit exceeded")
    document = json.loads(raw, object_pairs_hook=_unique_fields)
    if (
        type(document) is not dict or set(document) != {"schema", "effects", "scenarios"}
        or document["schema"] != CORPUS_SCHEMA
    ):
        raise ValueError("unsupported GT-VSA corpus")
    templates = _corpus_templates(document["effects"])
    entries = document["scenarios"]
    if type(entries) is not list or not 1 <= len(entries) <= 64:
        raise ValueError("invalid corpus case count")
    scenarios = []
    seen = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"id", "kind", "stages"}:
            raise ValueError("invalid corpus scenario")
        name, kind = entry["id"], entry["kind"]
        if not _identifier(name) or name in seen or kind not in ("hostile", "positive", "adaptive"):
            raise ValueError("invalid or duplicate corpus scenario identifier or kind")
        seen.add(name)
        scenarios.append(Scenario(name, kind, _stages(entry["stages"], templates)))
    return Corpus(tuple(scenarios), hashlib.sha256(raw).hexdigest())
