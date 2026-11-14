"""Append-only, in-memory protected-effect ledger.

This component deliberately does not enforce authorization.  The system under test
decides when to append; the independent oracle judges every resulting transition.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .canonical import sha256_json


class UnsafeSyntheticEffect(ValueError):
    pass


@dataclass(frozen=True)
class EffectRecord:
    effect_id: str
    sequence: int
    logical_time: int
    task_id: str
    request_id: str
    principal_id: str
    authorization_id: str
    credential_nonce: str
    origin: str
    operation_id: str
    operation_digest: str
    action: str
    resource: str
    argument_digest: str
    payload_digest: str
    replay_key: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SyntheticEffectLedger:
    """A permissive mock executor confined to synthetic URI namespaces."""

    def __init__(self) -> None:
        self._records: list[EffectRecord] = []

    def append(
        self,
        *,
        logical_time: int,
        task_id: str,
        request_id: str,
        principal_id: str,
        authorization_id: str,
        credential_nonce: str,
        origin: str,
        operation_id: str,
        operation_digest: str,
        action: str,
        resource: str,
        arguments: Mapping[str, Any],
        replay_key: str,
    ) -> EffectRecord:
        if not resource.startswith("synthetic://"):
            raise UnsafeSyntheticEffect("protected effects require synthetic:// resources")
        if not origin.startswith("synthetic-origin://"):
            raise UnsafeSyntheticEffect("effects require synthetic-origin:// origins")
        destination = arguments.get("destination")
        if destination is not None and (
            not isinstance(destination, str)
            or not destination.startswith("synthetic-sink://")
        ):
            raise UnsafeSyntheticEffect(
                "transfer destinations require synthetic-sink:// confinement"
            )
        sequence = len(self._records) + 1
        argument_digest = "sha256:" + sha256_json(dict(arguments))
        payload_digest = "sha256:" + sha256_json(
            {
                "action": action,
                "arguments": dict(arguments),
                "resource": resource,
            }
        )
        effect_id = "WT-E-" + sha256_json(
            {
                "authorization_id": authorization_id,
                "credential_nonce": credential_nonce,
                "operation_digest": operation_digest,
                "sequence": sequence,
            }
        )[:16].upper()
        record = EffectRecord(
            effect_id=effect_id,
            sequence=sequence,
            logical_time=logical_time,
            task_id=task_id,
            request_id=request_id,
            principal_id=principal_id,
            authorization_id=authorization_id,
            credential_nonce=credential_nonce,
            origin=origin,
            operation_id=operation_id,
            operation_digest=operation_digest,
            action=action,
            resource=resource,
            argument_digest=argument_digest,
            payload_digest=payload_digest,
            replay_key=replay_key,
        )
        self._records.append(record)
        return record

    def snapshot(self) -> tuple[EffectRecord, ...]:
        return tuple(self._records)

    @property
    def state_hash(self) -> str:
        return "sha256:" + sha256_json([record.to_dict() for record in self._records])


def effect_delta(
    before: tuple[EffectRecord, ...], after: tuple[EffectRecord, ...]
) -> tuple[EffectRecord, ...]:
    if len(after) < len(before) or after[: len(before)] != before:
        raise ValueError("effect ledger is not append-only")
    return after[len(before) :]
