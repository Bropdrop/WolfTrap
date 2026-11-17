"""Independent, dictionary-only reference for the synthetic authority funnel.

Keep this independent of authority_funnel's validator, digest helper and gate.
It models the same published contract so the challenge can compare observed
decisions and synthetic effect records, not just self-reported allow/deny flags.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


def _fingerprint(attempt: Mapping[str, Any]) -> str:
    operation = {
        "resource": attempt["resource"],
        "protected": True,
        "arguments": attempt["arguments"],
        "action": attempt["action"],
    }
    blob = json.dumps(operation, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def reference_funnel(
    grants: Sequence[dict[str, Any]],
    proposals: Sequence[dict[str, Any]],
    *,
    current_epoch: int,
    security_state_known: bool,
) -> dict[str, Any]:
    """Replay a clean in-memory fixture through an independent decision model.

    Inputs are validated by the challenge before calling this reference. This
    is not production authorization and does not perform crypto verification.
    """
    index = {grant["grant_id"]: grant for grant in grants}
    seen_nonces: set[str] = set()
    committed_slots: set[str] = set()
    effects: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    for item in proposals:
        grant = index.get(item["grant_id"])
        denial = None
        if security_state_known is False:
            denial = "UNKNOWN_SECURITY_STATE"
        elif grant is None:
            denial = "UNKNOWN_GRANT"
        elif grant["seal_valid"] is not True:
            denial = "UNVERIFIED_GRANT"
        elif current_epoch != grant["epoch"]:
            denial = "STALE_EPOCH"
        elif grant["revoked_at"] is not None and grant["revoked_at"] <= item["at"]:
            denial = "REVOKED"
        elif not grant["issued_at"] <= item["at"] < grant["expires_at"]:
            denial = "EXPIRED_OR_NOT_YET_VALID"
        else:
            bindings = (
                ("principal_id", "SUBJECT_MISMATCH"),
                ("agent_id", "DELEGATE_MISMATCH"),
                ("tenant", "TENANT_MISMATCH"),
                ("origin", "ORIGIN_MISMATCH"),
                ("slot", "SLOT_MISMATCH"),
            )
            for attempted, label in bindings:
                bound = "delegate_id" if attempted == "agent_id" else attempted
                if item[attempted] != grant[bound]:
                    denial = label
                    break
            if denial is None:
                if f"{item['action']}:{item['resource']}" != grant["scope"]:
                    denial = "SCOPE_MISMATCH"
                elif _fingerprint(item) != grant["operation_digest"]:
                    denial = "OPERATION_MISMATCH"
                elif grant["nonce"] in seen_nonces:
                    denial = "REPLAY"
                elif item["slot"] in committed_slots:
                    denial = "SLOT_EXHAUSTED"
        if denial is None:
            seen_nonces.add(grant["nonce"])
            committed_slots.add(item["slot"])
            effects.append({
                "at": item["at"],
                "agent_id": item["agent_id"],
                "grant_id": grant["grant_id"],
                "slot": item["slot"],
                "operation_digest": _fingerprint(item),
            })
        decisions.append({
            "agent_id": item["agent_id"],
            "reason": denial if denial is not None else "ACCEPTED",
        })
    return {"effects": effects, "decisions": decisions}
