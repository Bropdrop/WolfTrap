"""Deterministic stateful property and schedule exploration.

The explorer is deliberately self-contained and dependency-free.  It generates
complete executable cases; a seed is recorded for provenance, but reproduction
uses the saved case and explicit command schedule rather than assuming that a
future generator version will make the same choices.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, replace
from itertools import combinations
from typing import Any, Iterable, Sequence

from .canonical import canonical_json
from .model import (
    AttackReference,
    Authorization,
    Command,
    CommandKind,
    ExperimentCase,
    Operation,
    Principal,
    RequestSpec,
    Scenario,
    ThreatSource,
    scenario_to_case,
)


GENERATOR_VERSION = "stateful-v1"

MUTATION_AXES = (
    "principal_identity",
    "permission_scope",
    "authorization_epoch",
    "operation_digest",
    "tool_arguments",
    "execution_ordering",
    "concurrent_requests",
    "revocation_timing",
    "simulated_crash",
    "retry_recovery",
)

DATA_AXES = (
    "principal_identity",
    "permission_scope",
    "authorization_epoch",
    "operation_digest",
    "tool_arguments",
)

SCHEDULE_AXES = (
    "execution_ordering",
    "concurrent_requests",
    "revocation_timing",
    "simulated_crash",
    "retry_recovery",
)


class ExplorationError(ValueError):
    """The requested bounded exploration cannot be generated safely."""


@dataclass(frozen=True)
class ExplorationBounds:
    max_cases: int = 64
    max_commands_per_case: int = 128
    max_mutation_depth: int = 3
    max_interactions: int = 8
    max_schedules: int = 16
    max_actors: int = 8
    max_retries: int = 4
    max_seeded_cases: int = 20

    def validate(self) -> None:
        limits = {
            "max_cases": (self.max_cases, 1, 1000),
            "max_commands_per_case": (self.max_commands_per_case, 4, 1000),
            "max_mutation_depth": (self.max_mutation_depth, 1, 5),
            "max_interactions": (self.max_interactions, 0, 100),
            "max_schedules": (self.max_schedules, 5, 200),
            "max_actors": (self.max_actors, 2, 64),
            "max_retries": (self.max_retries, 1, 16),
            "max_seeded_cases": (self.max_seeded_cases, 0, 500),
        }
        for name, (value, lower, upper) in limits.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ExplorationError(f"{name} must be an integer")
            if value < lower or value > upper:
                raise ExplorationError(
                    f"{name} must be between {lower} and {upper}, got {value}"
                )


@dataclass(frozen=True)
class ExplorationResult:
    cases: tuple[ExperimentCase, ...]
    coverage: dict[str, Any]


class _HashStream:
    """Stable counter-mode choices independent of Python's RNG implementation."""

    def __init__(self, seed: int, label: str) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ExplorationError("seed must be a non-negative integer")
        self._key = f"wolftrap|{GENERATOR_VERSION}|{seed}|{label}".encode("utf-8")
        self._counter = 0

    def uint(self) -> int:
        block = hashlib.sha256(
            self._key + b"|" + self._counter.to_bytes(16, "big")
        ).digest()
        self._counter += 1
        return int.from_bytes(block, "big")

    def choice(self, values: Sequence[Any]) -> Any:
        if not values:
            raise ExplorationError("cannot choose from an empty domain")
        return values[self.uint() % len(values)]

    def sample(self, values: Sequence[Any], count: int) -> tuple[Any, ...]:
        if count < 0 or count > len(values):
            raise ExplorationError("sample count is outside the finite domain")
        pool = list(values)
        chosen: list[Any] = []
        while len(chosen) < count:
            chosen.append(pool.pop(self.uint() % len(pool)))
        return tuple(chosen)


def _derived_seed(seed: int, *parts: object) -> int:
    material = "|".join([GENERATOR_VERSION, str(seed), *(str(part) for part in parts)])
    return int.from_bytes(hashlib.sha256(material.encode("utf-8")).digest()[:8], "big")


def _unique(items: Iterable[Any], key: Any) -> tuple[Any, ...]:
    seen: set[Any] = set()
    output: list[Any] = []
    for item in items:
        marker = key(item)
        if marker not in seen:
            output.append(item)
            seen.add(marker)
    return tuple(output)


def _eligible_request(
    scenario: Scenario, *, minimum_window: int = 2
) -> tuple[RequestSpec, Authorization, Operation, int] | None:
    grants = {item.authorization_id: item for item in scenario.authorizations}
    operations = {item.operation_id: item for item in scenario.operations}
    principals = {item.principal_id for item in scenario.principals}
    for request in sorted(scenario.requests, key=lambda item: item.request_id):
        grant = grants.get(request.authorization_id)
        operation = operations.get(request.operation_id)
        if grant is None or operation is None or request.credential_overrides:
            continue
        at = max(0, grant.issued_at)
        exact_scope = f"{operation.action}:{operation.resource}"
        wildcard_scope = f"{operation.action}:*"
        if (
            grant.signature_valid is True
            and grant.subject == request.principal_id
            and grant.subject in principals
            and grant.origin_binding == request.origin
            and grant.epoch == scenario.current_epoch
            and grant.operation_digest == operation.digest
            and (exact_scope in grant.scopes or wildcard_scope in grant.scopes)
            and at + minimum_window < grant.expires_at
        ):
            return request, grant, operation, at
    return None


def _scenario_for_axis(scenarios: Sequence[Scenario], axis: str) -> Scenario:
    declared = [item for item in scenarios if axis in item.mutation_axes]
    candidates = declared + [item for item in scenarios if item not in declared]
    minimum_window = 3 if axis in SCHEDULE_AXES else 2
    for scenario in candidates:
        if _eligible_request(scenario, minimum_window=minimum_window) is not None:
            return scenario
    raise ExplorationError(
        f"no legitimate fixture exists from which to generate {axis!r}; "
        "the positive-control corpus is incomplete"
    )


def _replace_request(
    requests: tuple[RequestSpec, ...], replacement: RequestSpec
) -> tuple[RequestSpec, ...]:
    return tuple(
        replacement if item.request_id == replacement.request_id else item
        for item in requests
    )


def _replace_authorization(
    authorizations: tuple[Authorization, ...], replacement: Authorization
) -> tuple[Authorization, ...]:
    return tuple(
        replacement if item.authorization_id == replacement.authorization_id else item
        for item in authorizations
    )


def _replace_operation(
    operations: tuple[Operation, ...], replacement: Operation
) -> tuple[Operation, ...]:
    return tuple(
        replacement if item.operation_id == replacement.operation_id else item
        for item in operations
    )


def _submission(task: str, request: str, at: int) -> Command:
    return Command(
        kind=CommandKind.SUBMIT,
        at=at,
        task_id=task,
        request_id=request,
    )


def _advances(task: str, at: int, count: int) -> list[Command]:
    return [Command(kind=CommandKind.ADVANCE, at=at, task_id=task) for _ in range(count)]


def _minimal_denial_commands(request_id: str, at: int, label: str) -> tuple[Command, ...]:
    task = f"mx-{label}"
    return tuple([_submission(task, request_id, at), *_advances(task, at, 2)])


def _concurrent_commands(
    request_id: str, at: int, *, winner: str, commit_before_loser: bool = False
) -> tuple[Command, ...]:
    first = "mx-agent-a"
    second = "mx-agent-b"
    winner_task, loser_task = (first, second) if winner == "a" else (second, first)
    commands: list[Command] = [
        _submission(first, request_id, at),
        _submission(second, request_id, at),
    ]
    # Both actors verify and take an authorization snapshot before the replay race.
    for _ in range(2):
        commands.extend(
            [
                Command(CommandKind.ADVANCE, at, task_id=first),
                Command(CommandKind.ADVANCE, at, task_id=second),
            ]
        )
    commands.append(Command(CommandKind.ADVANCE, at, task_id=winner_task))
    if commit_before_loser:
        commands.extend(_advances(winner_task, at, 2))  # prepare, atomic effect
        commands.append(Command(CommandKind.ADVANCE, at, task_id=loser_task))
        commands.extend(_advances(winner_task, at, 2))  # commit, response
    else:
        commands.append(Command(CommandKind.ADVANCE, at, task_id=loser_task))
        commands.extend(_advances(winner_task, at, 4))
    return tuple(commands)


def _concurrent_revocation_commands(
    request_id: str, authorization_id: str, at: int, *, reverse: bool
) -> tuple[Command, ...]:
    tasks = ("mx-agent-b", "mx-agent-a") if reverse else ("mx-agent-a", "mx-agent-b")
    commands: list[Command] = [
        _submission("mx-agent-a", request_id, at),
        _submission("mx-agent-b", request_id, at),
    ]
    for _ in range(2):
        for task in tasks:
            commands.append(Command(CommandKind.ADVANCE, at, task_id=task))
    commands.append(
        Command(
            CommandKind.REVOKE,
            at + 1,
            authorization_id=authorization_id,
        )
    )
    # Each actor reaches a terminal revoked denial; no later terminal advance occurs.
    for task in tasks:
        commands.append(Command(CommandKind.ADVANCE, at + 1, task_id=task))
    return tuple(commands)


def _revocation_commands(
    request_id: str, authorization_id: str, at: int, *, advances_before_revoke: int
) -> tuple[Command, ...]:
    task = "mx-revocation"
    commands: list[Command] = [
        _submission(task, request_id, at),
        *_advances(task, at, advances_before_revoke),
        Command(CommandKind.REVOKE, at + 1, authorization_id=authorization_id),
    ]
    # At EFFECTED or later, revocation must not erase the already committed effect.
    if advances_before_revoke < 5:
        commands.append(Command(CommandKind.ADVANCE, at + 1, task_id=task))
    return tuple(commands)


def _crash_commands(
    request_id: str,
    at: int,
    *,
    crash_after_advances: int,
    recover: bool,
    revoke_authorization: str | None = None,
    unknown_recovery: bool = False,
) -> tuple[Command, ...]:
    original = "mx-crash-original"
    recovered = "mx-crash-recovered"
    commands: list[Command] = [
        _submission(original, request_id, at),
        *_advances(original, at, crash_after_advances),
        Command(CommandKind.CRASH, at, task_id=original),
    ]
    if not recover:
        return tuple(commands)
    next_time = at + 1
    if revoke_authorization is not None:
        commands.append(
            Command(
                CommandKind.REVOKE,
                next_time,
                authorization_id=revoke_authorization,
            )
        )
    if unknown_recovery:
        commands.append(
            Command(CommandKind.SET_SECURITY_STATE, next_time, value=False)
        )
    commands.append(
        Command(
            CommandKind.RECOVER,
            next_time,
            task_id=original,
            new_task_id=recovered,
        )
    )
    if unknown_recovery or crash_after_advances >= 5:
        return tuple(commands)
    if revoke_authorization is not None:
        # Reservation transfer is followed by a final current-authority rejection.
        if crash_after_advances >= 3:
            commands.append(Command(CommandKind.ADVANCE, next_time, task_id=recovered))
        else:
            commands.extend(_advances(recovered, next_time, 2))
        return tuple(commands)
    remaining = 4 if crash_after_advances >= 3 else 7
    commands.extend(_advances(recovered, next_time, remaining))
    return tuple(commands)


def _finish(
    base: ExperimentCase,
    *,
    seed: int,
    axes: Sequence[str],
    title_suffix: str,
    commands: tuple[Command, ...],
    control: str,
    extra_labels: Sequence[str] = (),
) -> ExperimentCase:
    labels = tuple(["stateful_property", *axes, *extra_labels])
    return replace(
        base,
        case_id="pending",
        case_seed=seed,
        generator_version=GENERATOR_VERSION,
        title=f"{base.title} — {title_suffix}",
        commands=commands,
        control=control,
        mutation_labels=labels,
    ).with_identity()


def _mutated_case(
    scenario: Scenario,
    axes: Sequence[str],
    *,
    seed: int,
    crash_site: int = 4,
    concurrency_winner: str = "a",
    commit_before_loser: bool = False,
    unknown_recovery: bool = False,
) -> ExperimentCase:
    if not axes:
        raise ExplorationError("a mutation case requires at least one axis")
    selected = _eligible_request(scenario, minimum_window=3)
    if selected is None:
        raise ExplorationError(f"scenario {scenario.scenario_id} lacks a valid seed request")
    request, grant, operation, at = selected
    base = scenario_to_case(scenario, seed=seed)
    principals = base.principals
    authorizations = base.authorizations
    operations = base.operations
    requests = base.requests
    current_epoch = base.current_epoch

    if "principal_identity" in axes:
        adversary_id = "synthetic-mutant-principal"
        if adversary_id not in {item.principal_id for item in principals}:
            principals = (*principals, Principal(adversary_id, ("synthetic-adversary",)))
        request = replace(request, principal_id=adversary_id)
        requests = _replace_request(requests, request)
    if "permission_scope" in axes:
        grant = replace(grant, scopes=())
        authorizations = _replace_authorization(authorizations, grant)
    if "authorization_epoch" in axes:
        current_epoch = grant.epoch + 1
    if "operation_digest" in axes:
        grant = replace(grant, operation_digest="sha256:" + ("0" * 64))
        authorizations = _replace_authorization(authorizations, grant)
    if "tool_arguments" in axes:
        changed_arguments = dict(operation.arguments)
        changed_arguments["wolftrap_mutation"] = "argument-boundary-v1"
        operation = replace(operation, arguments=changed_arguments)
        operations = _replace_operation(operations, operation)

    base = replace(
        base,
        principals=principals,
        authorizations=authorizations,
        operations=operations,
        requests=requests,
        current_epoch=current_epoch,
    )

    schedule_axes = set(axes) & set(SCHEDULE_AXES)
    if "concurrent_requests" in schedule_axes or "execution_ordering" in schedule_axes:
        if "revocation_timing" in schedule_axes:
            commands = _concurrent_revocation_commands(
                request.request_id,
                grant.authorization_id,
                at,
                reverse=concurrency_winner == "b",
            )
            control = "NEGATIVE"
        else:
            commands = _concurrent_commands(
                request.request_id,
                at,
                winner=concurrency_winner,
                commit_before_loser=commit_before_loser,
            )
            control = "MIXED"
    elif "retry_recovery" in schedule_axes:
        commands = _crash_commands(
            request.request_id,
            at,
            crash_after_advances=crash_site,
            recover=True,
            revoke_authorization=(
                grant.authorization_id if "revocation_timing" in schedule_axes else None
            ),
            unknown_recovery=unknown_recovery,
        )
        # A crash after five advances occurs *after* the synthetic effect has
        # committed.  Revoking or losing authority during subsequent recovery
        # cannot retroactively erase that legitimate effect.  Mark only
        # pre-commit revocation/unknown-recovery schedules as strict negatives.
        control = (
            "NEGATIVE"
            if crash_site < 5 and ("revocation_timing" in schedule_axes or unknown_recovery)
            else "MIXED"
        )
    elif "simulated_crash" in schedule_axes:
        commands = _crash_commands(
            request.request_id,
            at,
            crash_after_advances=crash_site,
            recover=False,
        )
        control = "NEGATIVE" if crash_site < 5 else "MIXED"
    elif "revocation_timing" in schedule_axes:
        commands = _revocation_commands(
            request.request_id,
            grant.authorization_id,
            at,
            advances_before_revoke=crash_site,
        )
        control = "NEGATIVE" if crash_site < 5 else "MIXED"
    else:
        commands = _minimal_denial_commands(
            request.request_id, at, "-".join(sorted(axes))
        )
        control = "NEGATIVE"

    return _finish(
        base,
        seed=seed,
        axes=axes,
        title_suffix=" + ".join(axes),
        commands=commands,
        control=control,
        extra_labels=(f"crash_site:{crash_site}",)
        if schedule_axes & {"simulated_crash", "retry_recovery"}
        else (),
    )


def _prefixed_case(case: ExperimentCase, prefix: str, *, time_shift: int) -> dict[str, Any]:
    principal_ids = {item.principal_id: f"{prefix}{item.principal_id}" for item in case.principals}
    authorization_ids = {
        item.authorization_id: f"{prefix}{item.authorization_id}"
        for item in case.authorizations
    }
    operation_ids = {item.operation_id: f"{prefix}{item.operation_id}" for item in case.operations}
    request_ids = {item.request_id: f"{prefix}{item.request_id}" for item in case.requests}

    principals = tuple(
        replace(item, principal_id=principal_ids[item.principal_id])
        for item in case.principals
    )
    authorizations = tuple(
        replace(
            item,
            authorization_id=authorization_ids[item.authorization_id],
            subject=principal_ids[item.subject],
            issued_at=item.issued_at + time_shift,
            expires_at=item.expires_at + time_shift,
            nonce=f"{prefix}{item.nonce}",
        )
        for item in case.authorizations
    )
    operations = tuple(
        replace(item, operation_id=operation_ids[item.operation_id])
        for item in case.operations
    )
    requests: list[RequestSpec] = []
    for item in case.requests:
        overrides = dict(item.credential_overrides)
        if overrides.get("authorization_id") in authorization_ids:
            overrides["authorization_id"] = authorization_ids[overrides["authorization_id"]]
        if overrides.get("subject") in principal_ids:
            overrides["subject"] = principal_ids[overrides["subject"]]
        if "issued_at" in overrides:
            overrides["issued_at"] = int(overrides["issued_at"]) + time_shift
        if "expires_at" in overrides:
            overrides["expires_at"] = int(overrides["expires_at"]) + time_shift
        if "nonce" in overrides:
            overrides["nonce"] = f"{prefix}{overrides['nonce']}"
        requests.append(
            replace(
                item,
                request_id=request_ids[item.request_id],
                principal_id=principal_ids[item.principal_id],
                authorization_id=authorization_ids[item.authorization_id],
                operation_id=operation_ids[item.operation_id],
                credential_overrides=overrides,
            )
        )
    commands: list[Command] = []
    for item in case.commands:
        commands.append(
            replace(
                item,
                at=item.at + time_shift,
                task_id=f"{prefix}{item.task_id}" if item.task_id else None,
                new_task_id=f"{prefix}{item.new_task_id}" if item.new_task_id else None,
                request_id=request_ids.get(item.request_id, item.request_id),
                authorization_id=authorization_ids.get(
                    item.authorization_id, item.authorization_id
                ),
            )
        )
    return {
        "principals": principals,
        "authorizations": authorizations,
        "operations": operations,
        "requests": tuple(requests),
        "commands": tuple(commands),
    }


def _compose(first: Scenario, second: Scenario, *, seed: int) -> ExperimentCase:
    first_case = scenario_to_case(first, seed=_derived_seed(seed, first.scenario_id, "stage-a"))
    second_case = scenario_to_case(second, seed=_derived_seed(seed, second.scenario_id, "stage-b"))
    a = _prefixed_case(first_case, "stage-a::", time_shift=0)
    b = _prefixed_case(second_case, "stage-b::", time_shift=0)
    # Compositions use a normalized, long-lived epoch so the experiment isolates
    # stage interactions rather than accidentally inheriting an unrelated expiry
    # or epoch transition from either authored baseline.
    a_authorizations = tuple(
        replace(item, epoch=1, issued_at=0, expires_at=1000)
        for item in a["authorizations"]
    )
    b_authorizations = tuple(
        replace(item, epoch=1, issued_at=0, expires_at=1000)
        for item in b["authorizations"]
    )
    if not a_authorizations or not b_authorizations or not a["operations"] or not b["operations"]:
        raise ExplorationError("composition requires authority and operation fixtures")
    # Each stage gets a normalized legitimate control request constructed from its
    # own fixtures.  This is intentionally distinct from the authored adversarial
    # request, which might have no valid form (for example an escalation-only
    # operation).  The cross-stage request below is the adversarial composition.
    a_operation = a["operations"][0]
    b_operation = b["operations"][0]
    a_grant = replace(
        a_authorizations[0],
        scopes=(f"{a_operation.action}:{a_operation.resource}",),
        operation_digest=a_operation.digest,
        signature_valid=True,
    )
    b_grant = replace(
        b_authorizations[0],
        scopes=(f"{b_operation.action}:{b_operation.resource}",),
        operation_digest=b_operation.digest,
        signature_valid=True,
    )
    a_authorizations = (a_grant, *a_authorizations[1:])
    b_authorizations = (b_grant, *b_authorizations[1:])
    first_request_id = "stage-a::composition-valid-request"
    second_request_id = "stage-b::composition-valid-request"
    first_control_request = RequestSpec(
        request_id=first_request_id,
        principal_id=a_grant.subject,
        authorization_id=a_grant.authorization_id,
        operation_id=a_operation.operation_id,
        origin=a_grant.origin_binding,
        credential_overrides={},
    )
    second_control_request = RequestSpec(
        request_id=second_request_id,
        principal_id=b_grant.subject,
        authorization_id=b_grant.authorization_id,
        operation_id=b_operation.operation_id,
        origin=b_grant.origin_binding,
        credential_overrides={},
    )
    stage_time = 10
    commands: list[Command] = [
        _submission("stage-a::actor", first_request_id, stage_time),
        *_advances("stage-a::actor", stage_time, 4),  # prepared, not yet effected
        _submission("stage-b::actor", second_request_id, stage_time),
        *_advances("stage-b::actor", stage_time, 2),  # authorized snapshot
    ]
    requests = [
        *a["requests"],
        *b["requests"],
        first_control_request,
        second_control_request,
    ]

    # Add a final cross-stage substitution: stage-A identity/authority attempts the
    # stage-B protected operation.  It is advanced only through authorization, so
    # an expected denial remains a valid terminal schedule.
    a_requests = [first_control_request]
    b_operations = [b_operation]
    if a_requests and b_operations:
        source_request = a_requests[0]
        target_operation = b_operations[0]
        cross_request = RequestSpec(
            request_id="composition::cross-stage-request",
            principal_id=source_request.principal_id,
            authorization_id=source_request.authorization_id,
            operation_id=target_operation.operation_id,
            origin=source_request.origin,
            credential_overrides=dict(source_request.credential_overrides),
        )
        requests.append(cross_request)
        cross_time = stage_time
        cross_task = "composition::cross-stage-task"
        commands.extend(
            [
                _submission(cross_task, cross_request.request_id, cross_time),
                *_advances(cross_task, cross_time, 2),
            ]
        )
    # Complete the two independently authorized stages after probing the cross-
    # stage substitution.  This also supplies positive controls inside the
    # composed experiment, preventing a deny-all implementation from passing it.
    commands.extend(_advances("stage-a::actor", stage_time, 3))
    commands.extend(_advances("stage-b::actor", stage_time, 5))

    attacks = _unique(
        (*first.attack_references, *second.attack_references),
        key=lambda item: (item.technique_id, item.name, item.relationship),
    )
    invariants = tuple(
        sorted(set(first.expectation.invariants) | set(second.expectation.invariants))
    )
    result = ExperimentCase(
        case_id="pending",
        case_seed=seed,
        generator_version=GENERATOR_VERSION,
        scenario_ids=(first.scenario_id, second.scenario_id),
        scenario_versions=(first.scenario_version, second.scenario_version),
        title=f"Composed stages: {first.title} → {second.title}",
        category="multi-stage-composition",
        sources=(first.source, second.source),
        attack_references=attacks,
        current_epoch=1,
        security_state_known=first.security_state_known and second.security_state_known,
        principals=(*a["principals"], *b["principals"]),
        authorizations=(*a_authorizations, *b_authorizations),
        operations=(*a["operations"], *b["operations"]),
        requests=tuple(requests),
        commands=tuple(commands),
        control="MIXED",
        invariants=invariants,
        mutation_labels=(
            "stateful_property",
            "scenario_composition",
            "cross_stage_substitution",
        ),
        interaction_depth=2,
    )
    return result.with_identity()


def _actors(case: ExperimentCase) -> int:
    identities = {
        command.task_id
        for command in case.commands
        if command.kind is CommandKind.SUBMIT and command.task_id
    }
    identities.update(
        command.new_task_id
        for command in case.commands
        if command.kind is CommandKind.RECOVER and command.new_task_id
    )
    return len(identities)


class StatefulExplorer:
    """Generate bounded cases and explicit race schedules from a scenario corpus."""

    def __init__(
        self, *, seed: int = 20261113, bounds: ExplorationBounds | None = None
    ) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ExplorationError("seed must be a non-negative integer")
        self.seed = seed
        self.bounds = bounds or ExplorationBounds()
        self.bounds.validate()

    def generate(self, scenarios: Sequence[Scenario]) -> ExplorationResult:
        ordered = tuple(sorted(scenarios, key=lambda item: (item.scenario_id, item.scenario_version)))
        if not ordered:
            raise ExplorationError("cannot explore an empty scenario corpus")
        identifiers = [(item.scenario_id, item.scenario_version) for item in ordered]
        if len(set(identifiers)) != len(identifiers):
            raise ExplorationError("scenario/version pairs must be unique")
        mandatory_count = len(ordered) + len(MUTATION_AXES)
        if self.bounds.max_cases < mandatory_count:
            raise ExplorationError(
                f"max_cases={self.bounds.max_cases} cannot hold {mandatory_count} "
                "mandatory baseline and one-axis cases"
            )

        cases: list[ExperimentCase] = []
        seen_digests: set[str] = set()
        truncation_reasons: list[str] = []
        generated_axes: set[str] = set()
        crash_sites: set[int] = set()
        schedule_candidates = 0
        schedule_generated = 0
        schedule_pruned = 0

        def add(case: ExperimentCase, *, mandatory: bool = False, schedule: bool = False) -> bool:
            nonlocal schedule_generated, schedule_pruned
            if schedule and not mandatory and schedule_generated >= self.bounds.max_schedules:
                truncation_reasons.append("max_schedules")
                return False
            if len(case.commands) > self.bounds.max_commands_per_case:
                if mandatory:
                    raise ExplorationError(
                        f"mandatory case {case.case_id} exceeds max_commands_per_case"
                    )
                truncation_reasons.append("max_commands_per_case")
                return False
            if _actors(case) > self.bounds.max_actors:
                if mandatory:
                    raise ExplorationError(
                        f"mandatory case {case.case_id} exceeds max_actors"
                    )
                truncation_reasons.append("max_actors")
                return False
            retries = sum(
                command.kind is CommandKind.RECOVER for command in case.commands
            )
            if retries > self.bounds.max_retries:
                if mandatory:
                    raise ExplorationError(
                        f"mandatory case {case.case_id} exceeds max_retries"
                    )
                truncation_reasons.append("max_retries")
                return False
            if len(cases) >= self.bounds.max_cases:
                truncation_reasons.append("max_cases")
                return False
            if case.digest in seen_digests:
                if schedule:
                    schedule_pruned += 1
                return False
            cases.append(case)
            seen_digests.add(case.digest)
            if schedule:
                schedule_generated += 1
            return True

        # Every authored baseline is mandatory, including the deny-all guard's
        # legitimate positive control.
        for ordinal, scenario in enumerate(ordered):
            baseline = scenario_to_case(
                scenario,
                seed=_derived_seed(self.seed, "baseline", ordinal, scenario.scenario_id),
            )
            add(baseline, mandatory=True)

        # One explicit case per required dimension prevents random sampling from
        # silently omitting a security boundary.
        for ordinal, axis in enumerate(MUTATION_AXES):
            scenario = _scenario_for_axis(ordered, axis)
            kwargs: dict[str, Any] = {}
            if axis == "execution_ordering":
                kwargs["concurrency_winner"] = "b"
            if axis == "simulated_crash":
                kwargs["crash_site"] = 4
                crash_sites.add(4)
            case = _mutated_case(
                scenario,
                (axis,),
                seed=_derived_seed(self.seed, "one-axis", ordinal, axis),
                **kwargs,
            )
            schedule_case = axis in SCHEDULE_AXES
            schedule_candidates += int(schedule_case)
            if add(case, mandatory=True, schedule=schedule_case):
                generated_axes.add(axis)

        # Enumerate bounded, security-relevant schedule variants rather than rely
        # on OS thread timing.  These cover both replay winners, commit-before-
        # loser orderings, revocation windows, and crash/recovery sites.
        concurrency_scenario = _scenario_for_axis(ordered, "concurrent_requests")
        schedule_specs: list[tuple[tuple[str, ...], dict[str, Any], str]] = [
            (("concurrent_requests",), {"concurrency_winner": "a", "commit_before_loser": True}, "a-commit-first"),
            (("concurrent_requests",), {"concurrency_winner": "b", "commit_before_loser": True}, "b-commit-first"),
        ]
        revocation_scenario = _scenario_for_axis(ordered, "revocation_timing")
        for window in (2, 3, 4, 5):
            schedule_specs.append(
                (("revocation_timing",), {"crash_site": window}, f"revoke-window-{window}")
            )
        recovery_scenario = _scenario_for_axis(ordered, "retry_recovery")
        for crash_site in range(0, 7):
            schedule_specs.append(
                (
                    ("simulated_crash", "retry_recovery"),
                    {"crash_site": crash_site},
                    f"recover-crash-site-{crash_site}",
                )
            )
        schedule_specs.append(
            (
                ("simulated_crash", "retry_recovery"),
                {"crash_site": 4, "unknown_recovery": True},
                "unknown-recovery",
            )
        )
        remaining_schedule_budget = self.bounds.max_schedules - schedule_generated
        for ordinal, (axes, kwargs, label) in enumerate(schedule_specs):
            schedule_candidates += 1
            if remaining_schedule_budget <= 0:
                truncation_reasons.append("max_schedules")
                continue
            scenario = (
                concurrency_scenario
                if "concurrent_requests" in axes
                else revocation_scenario
                if axes == ("revocation_timing",)
                else recovery_scenario
            )
            case = _mutated_case(
                scenario,
                axes,
                seed=_derived_seed(self.seed, "schedule", ordinal, label),
                **kwargs,
            )
            case = replace(case, mutation_labels=(*case.mutation_labels, f"schedule:{label}"))
            case = replace(case, case_id="pending").with_identity()
            if add(case, schedule=True):
                remaining_schedule_budget -= 1
                generated_axes.update(axes)
                if "crash_site" in kwargs:
                    crash_sites.add(int(kwargs["crash_site"]))

        # Deterministically rank all scenario pairs before applying the interaction
        # and global case bounds.  Each case preserves both scenario lineages.
        pairs = list(combinations(ordered, 2))
        pair_stream = _HashStream(self.seed, "composition-order")
        ranked_pairs = sorted(
            pairs,
            key=lambda pair: hashlib.sha256(
                f"{pair_stream._key.decode()}|{pair[0].scenario_id}|{pair[1].scenario_id}".encode()
            ).hexdigest(),
        )
        interaction_candidates = len(ranked_pairs)
        interactions_generated = 0
        for ordinal, (first, second) in enumerate(ranked_pairs[: self.bounds.max_interactions]):
            case = _compose(
                first,
                second,
                seed=_derived_seed(
                    self.seed, "interaction", ordinal, first.scenario_id, second.scenario_id
                ),
            )
            if add(case):
                interactions_generated += 1
        if interaction_candidates > self.bounds.max_interactions:
            truncation_reasons.append("max_interactions")

        # Seeded higher-order properties are drawn from type-compatible domains so
        # generated schedules remain enabled after an expected early denial.
        stream = _HashStream(self.seed, "higher-order")
        data_combinations = [
            combo
            for depth in range(2, self.bounds.max_mutation_depth + 1)
            for combo in combinations(DATA_AXES, depth)
        ]
        schedule_combinations: list[tuple[str, ...]] = [
            ("simulated_crash", "retry_recovery"),
            ("revocation_timing", "retry_recovery"),
            ("concurrent_requests", "execution_ordering"),
            ("concurrent_requests", "revocation_timing"),
        ]
        domains = [*data_combinations, *schedule_combinations]
        seeded_generated = 0
        for ordinal in range(self.bounds.max_seeded_cases):
            if not domains or len(cases) >= self.bounds.max_cases:
                if len(cases) >= self.bounds.max_cases:
                    truncation_reasons.append("max_cases")
                break
            axes = tuple(stream.choice(domains))
            scenario = _scenario_for_axis(ordered, axes[0])
            kwargs = {
                "crash_site": stream.choice((2, 3, 4, 5)),
                "concurrency_winner": stream.choice(("a", "b")),
                "commit_before_loser": bool(stream.uint() & 1),
            }
            case = _mutated_case(
                scenario,
                axes,
                seed=_derived_seed(self.seed, "higher-order", ordinal, *axes),
                **kwargs,
            )
            is_schedule = bool(set(axes) & set(SCHEDULE_AXES))
            schedule_candidates += int(is_schedule)
            if add(case, schedule=is_schedule):
                seeded_generated += 1
                generated_axes.update(axes)

        command_kinds = sorted(
            {
                command.kind.value
                for case in cases
                for command in case.commands
            }
        )
        declared_axes = sorted(
            {axis for scenario in ordered for axis in scenario.mutation_axes}
        )
        threat_mappings = sorted(
            {
                (
                    scenario.scenario_id,
                    attack.technique_id,
                    attack.name,
                    attack.relationship,
                )
                for scenario in ordered
                for attack in scenario.attack_references
            }
        )
        unique_truncation = sorted(set(truncation_reasons))
        coverage = {
            "generator_version": GENERATOR_VERSION,
            "engine": "deterministic_model_based_stateful_properties",
            "seed": self.seed,
            "bounds": asdict(self.bounds),
            "bounded_not_exhaustive": True,
            "cases_generated": len(cases),
            "baseline_cases": len(ordered),
            "one_axis_cases": len(MUTATION_AXES),
            "seeded_higher_order_cases": seeded_generated,
            "scenario_ids": [item.scenario_id for item in ordered],
            "declared_mutation_axes": declared_axes,
            "required_mutation_axes": list(MUTATION_AXES),
            "generated_mutation_axes": sorted(generated_axes),
            "missing_mutation_axes": sorted(set(MUTATION_AXES) - generated_axes),
            "command_kinds_generated": command_kinds,
            "mutation_depths_reached": sorted(
                {
                    len(set(case.mutation_labels) & set(MUTATION_AXES))
                    for case in cases
                    if set(case.mutation_labels) & set(MUTATION_AXES)
                }
            ),
            "control_cases": {
                control: sum(case.control == control for case in cases)
                for control in ("POSITIVE", "NEGATIVE", "MIXED")
            },
            "case_digests": [case.digest for case in cases],
            "schedules": {
                "candidate_security_schedules": schedule_candidates,
                "generated": schedule_generated,
                "duplicate_pruned": schedule_pruned,
                "pending_or_bound_excluded": max(
                    0, schedule_candidates - schedule_generated - schedule_pruned
                ),
                "truncated": schedule_generated < schedule_candidates,
                "crash_sites_reached": sorted(crash_sites),
                "race_windows_reached": sorted(
                    {
                        label.removeprefix("schedule:")
                        for case in cases
                        for label in case.mutation_labels
                        if label.startswith("schedule:")
                    }
                ),
                "uses_os_thread_scheduling": False,
            },
            "interactions": {
                "candidate_pairs": interaction_candidates,
                "generated": interactions_generated,
                "generated_pairs": [
                    list(case.scenario_ids)
                    for case in cases
                    if case.interaction_depth > 1
                ],
                "max_depth": max((case.interaction_depth for case in cases), default=0),
                "truncated": interactions_generated < interaction_candidates,
            },
            "threat_mappings": [
                {
                    "scenario_id": scenario_id,
                    "technique_id": technique_id,
                    "name": name,
                    "relationship": relationship,
                }
                for scenario_id, technique_id, name, relationship in threat_mappings
            ],
            "truncated": bool(unique_truncation),
            "truncation_reasons": unique_truncation,
        }
        if coverage["missing_mutation_axes"]:
            raise ExplorationError(
                "generator failed its mandatory mutation coverage gate: "
                + ", ".join(coverage["missing_mutation_axes"])
            )
        return ExplorationResult(tuple(cases), coverage)


def generate_cases(
    scenarios: Sequence[Scenario],
    *,
    seed: int = 20261113,
    bounds: ExplorationBounds | None = None,
) -> ExplorationResult:
    """Convenience entry point used by the runner and tests."""

    return StatefulExplorer(seed=seed, bounds=bounds).generate(scenarios)


def explore(
    scenarios: Sequence[Scenario],
    seed: int = 20261113,
    bounds: ExplorationBounds | None = None,
) -> ExplorationResult:
    """Compatibility-oriented public API for bounded exploration.

    Baseline cases are included first, followed by mandatory one-axis properties,
    explicit schedule variants, compositions, and seeded higher-order cases.
    """

    return generate_cases(scenarios, seed=seed, bounds=bounds)


def result_manifest(result: ExplorationResult) -> str:
    """Stable JSON manifest useful for deterministic-generation assertions."""

    return canonical_json(
        {
            "cases": [case.to_dict() for case in result.cases],
            "coverage": result.coverage,
        }
    )
