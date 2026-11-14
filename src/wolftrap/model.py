"""Data contracts for scenarios, experiment cases, and evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any, Mapping, Sequence

from .canonical import operation_digest, sha256_json


JSONValue = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]


class CommandKind(str, Enum):
    SUBMIT = "SUBMIT"
    ADVANCE = "ADVANCE"
    REVOKE = "REVOKE"
    ADVANCE_EPOCH = "ADVANCE_EPOCH"
    SET_SECURITY_STATE = "SET_SECURITY_STATE"
    CRASH = "CRASH"
    RECOVER = "RECOVER"


class TaskPhase(str, Enum):
    RECEIVED = "RECEIVED"
    VERIFIED = "VERIFIED"
    AUTHORIZED = "AUTHORIZED"
    RESERVED = "RESERVED"
    PREPARED = "PREPARED"
    EFFECTED = "EFFECTED"
    COMMITTED = "COMMITTED"
    RESPONDED = "RESPONDED"
    DENIED = "DENIED"
    CRASHED = "CRASHED"


class DenialReason(str, Enum):
    NONE = "NONE"
    UNKNOWN_SECURITY_STATE = "UNKNOWN_SECURITY_STATE"
    UNVERIFIED_CREDENTIAL = "UNVERIFIED_CREDENTIAL"
    UNKNOWN_AUTHORIZATION = "UNKNOWN_AUTHORIZATION"
    CREDENTIAL_SUBSTITUTION = "CREDENTIAL_SUBSTITUTION"
    UNKNOWN_PRINCIPAL = "UNKNOWN_PRINCIPAL"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    STALE_EPOCH = "STALE_EPOCH"
    ORIGIN_MISMATCH = "ORIGIN_MISMATCH"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    OPERATION_DIGEST_MISMATCH = "OPERATION_DIGEST_MISMATCH"
    REPLAY = "REPLAY"
    UNSAFE_RESOURCE = "UNSAFE_RESOURCE"
    INVALID_RECOVERY = "INVALID_RECOVERY"


class FindingClassification(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNVERIFIED = "UNVERIFIED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    DUPLICATE = "DUPLICATE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class ThreatSource:
    source_id: str
    title: str
    publication_date: str
    url: str
    sha256: str
    pages: tuple[int, ...]
    observed_behavior: str
    mapping_note: str


@dataclass(frozen=True)
class AttackReference:
    technique_id: str
    name: str
    url: str
    relationship: str = "DIRECT"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class Authorization:
    authorization_id: str
    subject: str
    scopes: tuple[str, ...]
    epoch: int
    origin_binding: str
    operation_digest: str
    issued_at: int
    expires_at: int
    signature_valid: bool | None
    nonce: str

    def with_overrides(self, overrides: Mapping[str, Any]) -> "Authorization":
        values = {
            "authorization_id": self.authorization_id,
            "subject": self.subject,
            "scopes": self.scopes,
            "epoch": self.epoch,
            "origin_binding": self.origin_binding,
            "operation_digest": self.operation_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature_valid": self.signature_valid,
            "nonce": self.nonce,
        }
        values.update(overrides)
        if isinstance(values["scopes"], list):
            values["scopes"] = tuple(values["scopes"])
        return Authorization(**values)


@dataclass(frozen=True)
class Operation:
    operation_id: str
    action: str
    resource: str
    arguments: Mapping[str, Any]
    protected: bool = True

    @property
    def digest(self) -> str:
        return operation_digest(
            action=self.action,
            resource=self.resource,
            arguments=self.arguments,
            protected=self.protected,
        )


@dataclass(frozen=True)
class RequestSpec:
    request_id: str
    principal_id: str
    authorization_id: str
    operation_id: str
    origin: str
    credential_overrides: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Command:
    kind: CommandKind
    at: int
    task_id: str | None = None
    request_id: str | None = None
    authorization_id: str | None = None
    value: int | bool | str | None = None
    new_task_id: str | None = None


@dataclass(frozen=True)
class ScenarioExpectation:
    control: str
    description: str
    invariants: tuple[str, ...]


@dataclass(frozen=True)
class Scenario:
    schema_version: str
    scenario_id: str
    scenario_version: str
    title: str
    summary: str
    category: str
    source: ThreatSource
    attack_references: tuple[AttackReference, ...]
    current_epoch: int
    security_state_known: bool
    principals: tuple[Principal, ...]
    authorizations: tuple[Authorization, ...]
    operations: tuple[Operation, ...]
    requests: tuple[RequestSpec, ...]
    commands: tuple[Command, ...]
    expectation: ScenarioExpectation
    mutation_axes: tuple[str, ...]
    definition_digest: str


@dataclass(frozen=True)
class ExperimentCase:
    case_id: str
    case_seed: int
    generator_version: str
    scenario_ids: tuple[str, ...]
    scenario_versions: tuple[str, ...]
    title: str
    category: str
    sources: tuple[ThreatSource, ...]
    attack_references: tuple[AttackReference, ...]
    current_epoch: int
    security_state_known: bool
    principals: tuple[Principal, ...]
    authorizations: tuple[Authorization, ...]
    operations: tuple[Operation, ...]
    requests: tuple[RequestSpec, ...]
    commands: tuple[Command, ...]
    control: str
    invariants: tuple[str, ...]
    mutation_labels: tuple[str, ...] = ()
    interaction_depth: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_seed": self.case_seed,
            "generator_version": self.generator_version,
            "scenario_ids": list(self.scenario_ids),
            "scenario_versions": list(self.scenario_versions),
            "title": self.title,
            "category": self.category,
            "sources": [asdict(item) for item in self.sources],
            "attack_references": [asdict(item) for item in self.attack_references],
            "current_epoch": self.current_epoch,
            "security_state_known": self.security_state_known,
            "principals": [asdict(item) for item in self.principals],
            "authorizations": [
                {**asdict(item), "scopes": list(item.scopes)}
                for item in self.authorizations
            ],
            "operations": [
                {**asdict(item), "arguments": dict(item.arguments)}
                for item in self.operations
            ],
            "requests": [
                {**asdict(item), "credential_overrides": dict(item.credential_overrides)}
                for item in self.requests
            ],
            "commands": [
                {**asdict(item), "kind": item.kind.value} for item in self.commands
            ],
            "control": self.control,
            "invariants": list(self.invariants),
            "mutation_labels": list(self.mutation_labels),
            "interaction_depth": self.interaction_depth,
        }

    @property
    def digest(self) -> str:
        value = self.to_dict()
        value.pop("case_id", None)
        return sha256_json(value)

    def with_identity(self) -> "ExperimentCase":
        return replace(self, case_id="WT-C-" + self.digest[:16].upper())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExperimentCase":
        if not isinstance(value, dict):
            raise ValueError("saved case must be an object")
        required = {
            "case_id", "case_seed", "generator_version", "scenario_ids",
            "scenario_versions", "title", "category", "sources",
            "attack_references", "current_epoch", "security_state_known",
            "principals", "authorizations", "operations", "requests", "commands",
            "control", "invariants", "mutation_labels", "interaction_depth",
        }
        if set(value) != required:
            raise ValueError("saved case has missing or unknown fields")
        string_fields = ("case_id", "generator_version", "title", "category", "control")
        if any(not isinstance(value[field], str) or not value[field] for field in string_fields):
            raise ValueError("saved case string field is invalid")
        if type(value["case_seed"]) is not int or type(value["current_epoch"]) is not int:
            raise ValueError("saved case numeric field is invalid")
        if type(value["security_state_known"]) is not bool:
            raise ValueError("saved case security state must be boolean")
        if type(value["interaction_depth"]) is not int:
            raise ValueError("saved case interaction depth must be integer")
        for field in (
            "scenario_ids", "scenario_versions", "sources", "attack_references",
            "principals", "authorizations", "operations", "requests", "commands",
            "invariants", "mutation_labels",
        ):
            if not isinstance(value[field], list):
                raise ValueError(f"saved case {field} must be an array")
        sources = tuple(
            ThreatSource(
                **{
                    **item,
                    "pages": tuple(item["pages"]),
                }
            )
            for item in value["sources"]
        )
        attacks = tuple(AttackReference(**item) for item in value["attack_references"])
        principals = tuple(
            Principal(item["principal_id"], tuple(item.get("roles", ())))
            for item in value["principals"]
        )
        authorizations = tuple(
            Authorization(
                **{
                    **item,
                    "scopes": tuple(item["scopes"]),
                }
            )
            for item in value["authorizations"]
        )
        operations = tuple(Operation(**item) for item in value["operations"])
        requests = tuple(RequestSpec(**item) for item in value["requests"])
        commands = tuple(
            Command(**{**item, "kind": CommandKind(item["kind"])})
            for item in value["commands"]
        )
        return cls(
            case_id=value["case_id"],
            case_seed=value["case_seed"],
            generator_version=value["generator_version"],
            scenario_ids=tuple(value["scenario_ids"]),
            scenario_versions=tuple(value["scenario_versions"]),
            title=value["title"],
            category=value["category"],
            sources=sources,
            attack_references=attacks,
            current_epoch=value["current_epoch"],
            security_state_known=value["security_state_known"],
            principals=principals,
            authorizations=authorizations,
            operations=operations,
            requests=requests,
            commands=commands,
            control=value["control"],
            invariants=tuple(value["invariants"]),
            mutation_labels=tuple(value.get("mutation_labels", ())),
            interaction_depth=value["interaction_depth"],
        )


def scenario_to_case(scenario: Scenario, *, seed: int) -> ExperimentCase:
    case = ExperimentCase(
        case_id="pending",
        case_seed=seed,
        generator_version="stateful-v1",
        scenario_ids=(scenario.scenario_id,),
        scenario_versions=(scenario.scenario_version,),
        title=scenario.title,
        category=scenario.category,
        sources=(scenario.source,),
        attack_references=scenario.attack_references,
        current_epoch=scenario.current_epoch,
        security_state_known=scenario.security_state_known,
        principals=scenario.principals,
        authorizations=scenario.authorizations,
        operations=scenario.operations,
        requests=scenario.requests,
        commands=scenario.commands,
        control=scenario.expectation.control,
        invariants=scenario.expectation.invariants,
        mutation_labels=("baseline",),
        interaction_depth=1,
    )
    return case.with_identity()


def unique_by_id(items: Sequence[Any], attr: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in items:
        identifier = getattr(item, attr)
        if identifier in result:
            raise ValueError(f"duplicate {attr}: {identifier}")
        result[identifier] = item
    return result
