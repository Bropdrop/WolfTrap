"""Independent oracle for the inert multi-step ARTEX-inspired challenge.

Deliberately does not import the challenge's gates, digest routine or state
machine. Every possible effect is only a fictional in-memory record.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _operation_hash(request: dict[str, Any]) -> str:
    canonical = {
        "arguments": request["arguments"],
        "resource": request["resource"],
        "action": request["step"],
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def reference_chain(case: dict[str, Any]) -> dict[str, Any]:
    """Replay a separately coded host-owned authorization reference."""
    registry = {row["grant_id"]: row for row in case["grants"]}
    host = case["host"]
    order = ("RECON", "ACCESS", "PRIVILEGE", "COMMIT")
    consumed: set[str] = set()
    approvals: list[dict[str, Any]] = []
    effects: list[dict[str, Any]] = []
    next_action = 0
    stopped = False
    pinned_identity: tuple[str, str, str] | None = None

    for request in case["intents"]:
        reason: str | None = None
        if stopped:
            reason = "CHAIN_HALTED"
        elif next_action == len(order) or request["step"] != order[next_action]:
            reason = "CHAIN_ORDER_DENIED"
        else:
            environment = host["envelopes"].get(request["environment_id"])
            if environment is None or environment["agent_id"] != request["agent_id"]:
                reason = "UNKNOWN_SANDBOX"
            elif environment["isolation_enforced"] is not True:
                reason = "UNKNOWN_ISOLATION"
            elif request["file_request"] != "SCOPED":
                reason = "FILESYSTEM_DENIED"
            elif request["network_request"] != "NONE":
                reason = "NETWORK_DENIED"
            else:
                trusted = registry.get(request["grant_id"])
                if host["security_state_known"] is not True:
                    reason = "UNKNOWN_AUTHORITY_STATE"
                elif trusted is None:
                    reason = "UNKNOWN_GRANT"
                elif trusted["seal_valid"] is not True:
                    reason = "UNVERIFIED_GRANT"
                elif host["current_epoch"] != trusted["epoch"]:
                    reason = "STALE_EPOCH"
                elif (trusted["revoked_at"] is not None
                      and trusted["revoked_at"] <= request["at"]):
                    reason = "REVOKED"
                elif not trusted["issued_at"] <= request["at"] < trusted["expires_at"]:
                    reason = "EXPIRED"
                elif trusted["chain_id"] != request["chain_id"]:
                    reason = "CHAIN_MISMATCH"
                elif trusted["delegate_id"] != request["agent_id"]:
                    reason = "DELEGATE_MISMATCH"
                elif trusted["tenant"] != request["tenant"]:
                    reason = "TENANT_MISMATCH"
                elif (trusted["scope"] != request["step"] + ":" + request["resource"]):
                    reason = "SCOPE_MISMATCH"
                elif trusted["operation_digest"] != _operation_hash(request):
                    reason = "OPERATION_MISMATCH"
                elif trusted["approved"] is not True:
                    reason = "APPROVAL_REQUIRED"
                elif trusted["nonce"] in consumed:
                    reason = "REPLAY"

            if reason is None and pinned_identity is not None and (
                request["chain_id"], request["agent_id"], request["tenant"]
            ) != pinned_identity:
                reason = "CHAIN_IDENTITY_MISMATCH"

        if reason is not None:
            stopped = True
        else:
            reason = "ACCEPTED"
            trusted = registry[request["grant_id"]]
            consumed.add(trusted["nonce"])
            if pinned_identity is None:
                pinned_identity = (request["chain_id"], request["agent_id"], request["tenant"])
            next_action += 1
            if next_action == 4:
                effects.append({
                    "chain_id": request["chain_id"],
                    "agent_id": request["agent_id"],
                    "at": request["at"],
                    "resource": request["resource"],
                    "grant_id": request["grant_id"],
                    "operation_digest": _operation_hash(request),
                })
        approvals.append({
            "step": request["step"], "at": request["at"],
            "agent_id": request["agent_id"], "reason": reason,
        })
    return {"decisions": approvals, "effects": effects}
