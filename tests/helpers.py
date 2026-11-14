from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from wolftrap.model import (
    AttackReference,
    Authorization,
    Command,
    CommandKind,
    ExperimentCase,
    Operation,
    Principal,
    RequestSpec,
    ThreatSource,
)


SOURCE = ThreatSource(
    source_id="FBI-FLASH-20261113-001",
    title="Threat Overview of ARTEX Autonomous Penetration Testing Framework",
    publication_date="2026-11-13",
    url="https://www.ic3.gov/CSA/2026/261113.pdf",
    sha256="3dd86a94d33b29c65f56b4307919b74358e63cfde33a600b61adce5794d169e2",
    pages=(3,),
    observed_behavior="Synthetic valid-account authorization exercise.",
    mapping_note="Underlying operation mapping; the fixture is synthetic.",
)

ATTACK = AttackReference(
    technique_id="T1078",
    name="Valid Accounts",
    url="https://attack.mitre.org/techniques/T1078/",
    relationship="UNDERLYING_OPERATION",
)

ALL_INVARIANTS = (
    "NO_CURRENT_AUTHORITY_NO_PROTECTED_EFFECT",
    "NO_VALID_ORIGIN_BINDING_NO_PROTECTED_EFFECT",
    "REVOKED_AUTHORITY_NO_NEW_PROTECTED_EFFECT",
    "REPLAYED_AUTHORIZATION_NO_DUPLICATE_EFFECT",
    "VERIFIED_DOES_NOT_MEAN_AUTHORIZED",
    "AUTHORIZED_DOES_NOT_MEAN_EXECUTED",
    "UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
    "POSITIVE_CONTROL_MUST_EXECUTE",
)


def advance(task_id: str, count: int, *, at: int = 10) -> list[Command]:
    return [Command(CommandKind.ADVANCE, at=at, task_id=task_id) for _ in range(count)]


def base_case(
    *,
    commands: Iterable[Command] | None = None,
    request: RequestSpec | None = None,
    authorization_changes: dict[str, Any] | None = None,
    operation: Operation | None = None,
    current_epoch: int = 1,
    security_state_known: bool = True,
    control: str = "POSITIVE",
    extra_requests: tuple[RequestSpec, ...] = (),
) -> ExperimentCase:
    operation = operation or Operation(
        operation_id="op-write",
        action="write",
        resource="synthetic://vault/records",
        arguments={"value": "safe"},
        protected=True,
    )
    authorization = Authorization(
        authorization_id="auth-alice",
        subject="alice",
        scopes=(f"write:{operation.resource}",),
        epoch=1,
        origin_binding="synthetic-origin://employee",
        operation_digest=operation.digest,
        issued_at=0,
        expires_at=100,
        signature_valid=True,
        nonce="nonce-alice-1",
    )
    if authorization_changes:
        authorization = replace(authorization, **authorization_changes)
    request = request or RequestSpec(
        request_id="request-1",
        principal_id="alice",
        authorization_id="auth-alice",
        operation_id=operation.operation_id,
        origin="synthetic-origin://employee",
        credential_overrides={},
    )
    if commands is None:
        commands = (
            Command(CommandKind.SUBMIT, at=10, task_id="task-1", request_id=request.request_id),
            *advance("task-1", 7),
        )
    case = ExperimentCase(
        case_id="pending",
        case_seed=7,
        generator_version="stateful-v1",
        scenario_ids=("unit-fixture",),
        scenario_versions=("1.0.0",),
        title="Unit synthetic authorization fixture",
        category="unit",
        sources=(SOURCE,),
        attack_references=(ATTACK,),
        current_epoch=current_epoch,
        security_state_known=security_state_known,
        principals=(Principal("alice"), Principal("mallory")),
        authorizations=(authorization,),
        operations=(operation,),
        requests=(request, *extra_requests),
        commands=tuple(commands),
        control=control,
        invariants=ALL_INVARIANTS,
        mutation_labels=("unit",),
        interaction_depth=1,
    )
    return case.with_identity()
