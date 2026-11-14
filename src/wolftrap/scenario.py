"""Strict, fail-closed loading for versioned scenario definitions."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import sha256_json
from .model import (
    AttackReference,
    Authorization,
    Command,
    CommandKind,
    Operation,
    Principal,
    RequestSpec,
    Scenario,
    ScenarioExpectation,
    ThreatSource,
    unique_by_id,
)


class ScenarioValidationError(ValueError):
    """A scenario cannot be interpreted safely."""


SUPPORTED_SCHEMA_VERSION = "1.0"
ALLOWED_CONTROLS = {"POSITIVE", "NEGATIVE", "MIXED"}
ALLOWED_INVARIANTS = {
    "NO_CURRENT_AUTHORITY_NO_PROTECTED_EFFECT",
    "NO_VALID_ORIGIN_BINDING_NO_PROTECTED_EFFECT",
    "REVOKED_AUTHORITY_NO_NEW_PROTECTED_EFFECT",
    "REPLAYED_AUTHORIZATION_NO_DUPLICATE_EFFECT",
    "VERIFIED_DOES_NOT_MEAN_AUTHORIZED",
    "AUTHORIZED_DOES_NOT_MEAN_EXECUTED",
    "UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
    "POSITIVE_CONTROL_MUST_EXECUTE",
}
ALLOWED_MUTATION_AXES = {
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
    "scenario_composition",
}
ALLOWED_ACTIONS = {
    "read",
    "write",
    "transfer",
    "assign_role",
    "add_credential",
    "publish",
}
OVERRIDE_FIELDS = {
    "authorization_id",
    "subject",
    "scopes",
    "epoch",
    "origin_binding",
    "operation_digest",
    "issued_at",
    "expires_at",
    "signature_valid",
    "nonce",
}


def _reject_constant(value: str) -> None:
    raise ScenarioValidationError(f"non-finite JSON number is forbidden: {value}")


def _object(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioValidationError(f"{where} must be an object")
    return value


def _list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ScenarioValidationError(f"{where} must be an array")
    return value


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioValidationError(f"{where} must be a non-empty string")
    return value


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScenarioValidationError(f"{where} must be an integer")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ScenarioValidationError(f"{where} must be a boolean")
    return value


def _keys(
    value: Mapping[str, Any],
    where: str,
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = required_set - set(value)
    unknown = set(value) - allowed
    if missing:
        raise ScenarioValidationError(f"{where} missing keys: {sorted(missing)}")
    if unknown:
        raise ScenarioValidationError(f"{where} has unknown keys: {sorted(unknown)}")


def _strict_strings(value: Any, where: str) -> tuple[str, ...]:
    items = _list(value, where)
    result = tuple(_str(item, f"{where}[]") for item in items)
    if len(set(result)) != len(result):
        raise ScenarioValidationError(f"{where} contains duplicates")
    return result


def _safe_json_value(value: Any, where: str) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ScenarioValidationError(f"{where} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _safe_json_value(item, f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _str(key, f"{where} key")
            _safe_json_value(item, f"{where}.{key}")
        return
    raise ScenarioValidationError(f"{where} contains unsupported JSON data")


def default_scenario_directory() -> Path:
    return Path(str(files("wolftrap").joinpath("scenarios", "v1")))


def load_corpus(directory: str | Path | None = None) -> list[Scenario]:
    root = Path(directory) if directory is not None else default_scenario_directory()
    paths = sorted(root.glob("*.json"))
    if not paths:
        raise ScenarioValidationError(f"no scenario definitions found in {root}")
    scenarios = [load_scenario(path) for path in paths]
    seen: set[tuple[str, str]] = set()
    for scenario in scenarios:
        key = (scenario.scenario_id, scenario.scenario_version)
        if key in seen:
            raise ScenarioValidationError(f"duplicate scenario/version: {key}")
        seen.add(key)
    return scenarios


def load_scenario(path: str | Path) -> Scenario:
    source_path = Path(path)
    try:
        raw = json.loads(
            source_path.read_text(encoding="utf-8"),
            parse_constant=_reject_constant,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ScenarioValidationError(f"cannot load {source_path}: {exc}") from exc
    return parse_scenario(raw, origin=str(source_path))


def parse_scenario(raw: Any, *, origin: str = "<memory>") -> Scenario:
    root = _object(raw, origin)
    _keys(
        root,
        origin,
        required=(
            "schema_version",
            "scenario_id",
            "scenario_version",
            "title",
            "summary",
            "category",
            "threat",
            "fixtures",
            "requests",
            "actions",
            "expectation",
            "mutation_axes",
        ),
    )
    schema_version = _str(root["schema_version"], f"{origin}.schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise ScenarioValidationError(
            f"unsupported schema_version {schema_version!r} in {origin}"
        )

    threat = _object(root["threat"], f"{origin}.threat")
    _keys(threat, f"{origin}.threat", required=("source", "attack"))
    source_raw = _object(threat["source"], f"{origin}.threat.source")
    _keys(
        source_raw,
        f"{origin}.threat.source",
        required=(
            "source_id",
            "title",
            "publication_date",
            "url",
            "sha256",
            "pages",
            "observed_behavior",
            "mapping_note",
        ),
    )
    pages = tuple(_int(item, f"{origin}.threat.source.pages[]") for item in _list(source_raw["pages"], f"{origin}.threat.source.pages"))
    if not pages or any(page < 1 for page in pages):
        raise ScenarioValidationError(f"{origin}: threat pages must be positive")
    source = ThreatSource(
        source_id=_str(source_raw["source_id"], "source_id"),
        title=_str(source_raw["title"], "source title"),
        publication_date=_str(source_raw["publication_date"], "publication_date"),
        url=_str(source_raw["url"], "source url"),
        sha256=_str(source_raw["sha256"], "source sha256"),
        pages=pages,
        observed_behavior=_str(source_raw["observed_behavior"], "observed_behavior"),
        mapping_note=_str(source_raw["mapping_note"], "mapping_note"),
    )
    if source.source_id != "FBI-FLASH-20261113-001":
        raise ScenarioValidationError(f"{origin}: unexpected authoritative source id")
    if source.publication_date != "2026-11-13":
        raise ScenarioValidationError(f"{origin}: unexpected advisory publication date")
    if source.url != "https://www.ic3.gov/CSA/2026/261113.pdf":
        raise ScenarioValidationError(f"{origin}: unexpected advisory URL")
    if source.sha256 != "3dd86a94d33b29c65f56b4307919b74358e63cfde33a600b61adce5794d169e2":
        raise ScenarioValidationError(f"{origin}: advisory digest does not match corpus pin")

    attacks: list[AttackReference] = []
    for index, item in enumerate(_list(threat["attack"], f"{origin}.threat.attack")):
        attack = _object(item, f"attack[{index}]")
        _keys(
            attack,
            f"attack[{index}]",
            required=("technique_id", "name", "url", "relationship"),
        )
        relationship = _str(attack["relationship"], "relationship")
        if relationship not in {"DIRECT", "UNDERLYING_OPERATION", "DEFENSIVE_STRESSOR"}:
            raise ScenarioValidationError(f"invalid ATT&CK relationship: {relationship}")
        attacks.append(
            AttackReference(
                technique_id=_str(attack["technique_id"], "technique_id"),
                name=_str(attack["name"], "attack name"),
                url=_str(attack["url"], "attack url"),
                relationship=relationship,
            )
        )
        expected_attack_url = (
            "https://attack.mitre.org/techniques/"
            + attack["technique_id"].replace(".", "/")
            + "/"
        )
        if attack["url"] != expected_attack_url:
            raise ScenarioValidationError(
                f"ATT&CK URL does not match {attack['technique_id']}: {attack['url']}"
            )
    if not attacks:
        raise ScenarioValidationError(f"{origin}: at least one ATT&CK reference is required")

    fixtures = _object(root["fixtures"], f"{origin}.fixtures")
    _keys(
        fixtures,
        f"{origin}.fixtures",
        required=(
            "current_epoch",
            "security_state_known",
            "principals",
            "authorizations",
            "operations",
        ),
    )
    principals: list[Principal] = []
    for index, item in enumerate(_list(fixtures["principals"], "principals")):
        value = _object(item, f"principal[{index}]")
        _keys(value, f"principal[{index}]", required=("principal_id", "roles"))
        principals.append(
            Principal(
                principal_id=_str(value["principal_id"], "principal_id"),
                roles=_strict_strings(value["roles"], "roles"),
            )
        )
    principal_map = unique_by_id(principals, "principal_id")

    operations: list[Operation] = []
    for index, item in enumerate(_list(fixtures["operations"], "operations")):
        value = _object(item, f"operation[{index}]")
        _keys(
            value,
            f"operation[{index}]",
            required=("operation_id", "action", "resource", "arguments", "protected"),
        )
        action = _str(value["action"], "operation.action")
        if action not in ALLOWED_ACTIONS:
            raise ScenarioValidationError(f"operation action is not allowed: {action}")
        resource = _str(value["resource"], "operation.resource")
        if not resource.startswith("synthetic://"):
            raise ScenarioValidationError("all operation resources must use synthetic://")
        arguments = _object(value["arguments"], "operation.arguments")
        _safe_json_value(arguments, "operation.arguments")
        destination = arguments.get("destination")
        if action == "transfer" and destination is None:
            raise ScenarioValidationError("transfer operations require a synthetic destination")
        if destination is not None and (
            not isinstance(destination, str)
            or not destination.startswith("synthetic-sink://")
        ):
            raise ScenarioValidationError(
                "operation destinations must use synthetic-sink://"
            )
        operations.append(
            Operation(
                operation_id=_str(value["operation_id"], "operation_id"),
                action=action,
                resource=resource,
                arguments=dict(arguments),
                protected=_bool(value["protected"], "operation.protected"),
            )
        )
    operation_map = unique_by_id(operations, "operation_id")

    authorizations: list[Authorization] = []
    for index, item in enumerate(_list(fixtures["authorizations"], "authorizations")):
        value = _object(item, f"authorization[{index}]")
        _keys(
            value,
            f"authorization[{index}]",
            required=(
                "authorization_id",
                "subject",
                "scopes",
                "epoch",
                "origin_binding",
                "operation_digest",
                "issued_at",
                "expires_at",
                "signature_valid",
                "nonce",
            ),
        )
        subject = _str(value["subject"], "authorization.subject")
        if subject not in principal_map:
            raise ScenarioValidationError(f"unknown authorization subject: {subject}")
        origin_binding = _str(value["origin_binding"], "origin_binding")
        if not origin_binding.startswith("synthetic-origin://"):
            raise ScenarioValidationError("origin bindings must use synthetic-origin://")
        digest = _str(value["operation_digest"], "operation_digest")
        if digest.startswith("@operation:"):
            operation_id = digest.removeprefix("@operation:")
            if operation_id not in operation_map:
                raise ScenarioValidationError(f"unknown digest operation: {operation_id}")
            digest = operation_map[operation_id].digest
        scopes = _strict_strings(value["scopes"], "authorization.scopes")
        authorizations.append(
            Authorization(
                authorization_id=_str(value["authorization_id"], "authorization_id"),
                subject=subject,
                scopes=scopes,
                epoch=_int(value["epoch"], "authorization.epoch"),
                origin_binding=origin_binding,
                operation_digest=digest,
                issued_at=_int(value["issued_at"], "authorization.issued_at"),
                expires_at=_int(value["expires_at"], "authorization.expires_at"),
                signature_valid=(
                    value["signature_valid"]
                    if value["signature_valid"] is None
                    else _bool(value["signature_valid"], "signature_valid")
                ),
                nonce=_str(value["nonce"], "authorization.nonce"),
            )
        )
    authorization_map = unique_by_id(authorizations, "authorization_id")

    requests: list[RequestSpec] = []
    for index, item in enumerate(_list(root["requests"], "requests")):
        value = _object(item, f"request[{index}]")
        _keys(
            value,
            f"request[{index}]",
            required=(
                "request_id",
                "principal_id",
                "authorization_id",
                "operation_id",
                "origin",
                "credential_overrides",
            ),
        )
        principal_id = _str(value["principal_id"], "request.principal_id")
        authorization_id = _str(value["authorization_id"], "request.authorization_id")
        operation_id = _str(value["operation_id"], "request.operation_id")
        if principal_id not in principal_map:
            raise ScenarioValidationError(f"unknown request principal: {principal_id}")
        if authorization_id not in authorization_map:
            raise ScenarioValidationError(f"unknown request authorization: {authorization_id}")
        if operation_id not in operation_map:
            raise ScenarioValidationError(f"unknown request operation: {operation_id}")
        origin_value = _str(value["origin"], "request.origin")
        if not origin_value.startswith("synthetic-origin://"):
            raise ScenarioValidationError("request origins must use synthetic-origin://")
        overrides = _object(value["credential_overrides"], "credential_overrides")
        unknown_overrides = set(overrides) - OVERRIDE_FIELDS
        if unknown_overrides:
            raise ScenarioValidationError(
                f"unknown credential overrides: {sorted(unknown_overrides)}"
            )
        resolved_overrides = dict(overrides)
        for override_name, override_value in list(resolved_overrides.items()):
            override_where = f"credential_overrides.{override_name}"
            if override_name in {
                "authorization_id",
                "subject",
                "origin_binding",
                "operation_digest",
                "nonce",
            }:
                resolved_overrides[override_name] = _str(
                    override_value, override_where
                )
            elif override_name == "scopes":
                resolved_overrides[override_name] = list(
                    _strict_strings(override_value, override_where)
                )
            elif override_name in {"epoch", "issued_at", "expires_at"}:
                resolved_overrides[override_name] = _int(
                    override_value, override_where
                )
            elif override_name == "signature_valid" and override_value is not None:
                resolved_overrides[override_name] = _bool(
                    override_value, override_where
                )
        override_origin = resolved_overrides.get("origin_binding")
        if override_origin is not None and not override_origin.startswith(
            "synthetic-origin://"
        ):
            raise ScenarioValidationError(
                "credential origin overrides must use synthetic-origin://"
            )
        override_digest = resolved_overrides.get("operation_digest")
        if isinstance(override_digest, str) and override_digest.startswith("@operation:"):
            override_operation = override_digest.removeprefix("@operation:")
            if override_operation not in operation_map:
                raise ScenarioValidationError(f"unknown override operation: {override_operation}")
            resolved_overrides["operation_digest"] = operation_map[override_operation].digest
        requests.append(
            RequestSpec(
                request_id=_str(value["request_id"], "request_id"),
                principal_id=principal_id,
                authorization_id=authorization_id,
                operation_id=operation_id,
                origin=origin_value,
                credential_overrides=resolved_overrides,
            )
        )
    request_map = unique_by_id(requests, "request_id")

    commands: list[Command] = []
    last_time = -1
    known_tasks: set[str] = set()
    for index, item in enumerate(_list(root["actions"], "actions")):
        value = _object(item, f"action[{index}]")
        kind_text = _str(value.get("kind"), f"action[{index}].kind")
        try:
            kind = CommandKind(kind_text)
        except ValueError as exc:
            raise ScenarioValidationError(f"unknown action kind: {kind_text}") from exc
        common = {"kind", "at"}
        optional: set[str] = set()
        required: set[str] = set(common)
        if kind is CommandKind.SUBMIT:
            required |= {"task_id", "request_id"}
        elif kind is CommandKind.ADVANCE:
            required |= {"task_id"}
            optional |= {"repeat"}
        elif kind is CommandKind.REVOKE:
            required |= {"authorization_id"}
        elif kind is CommandKind.ADVANCE_EPOCH:
            required |= {"value"}
        elif kind is CommandKind.SET_SECURITY_STATE:
            required |= {"value"}
        elif kind is CommandKind.CRASH:
            required |= {"task_id"}
        elif kind is CommandKind.RECOVER:
            required |= {"task_id", "new_task_id"}
        _keys(value, f"action[{index}]", required=required, optional=optional)
        at = _int(value["at"], f"action[{index}].at")
        if at < last_time:
            raise ScenarioValidationError("action times must be monotonic")
        last_time = at
        task_id = value.get("task_id")
        request_id = value.get("request_id")
        authorization_id = value.get("authorization_id")
        new_task_id = value.get("new_task_id")
        if task_id is not None:
            task_id = _str(task_id, "action.task_id")
        if request_id is not None:
            request_id = _str(request_id, "action.request_id")
        if authorization_id is not None:
            authorization_id = _str(authorization_id, "action.authorization_id")
        if new_task_id is not None:
            new_task_id = _str(new_task_id, "action.new_task_id")
        if kind is CommandKind.SUBMIT:
            if request_id not in request_map:
                raise ScenarioValidationError(f"unknown submitted request: {request_id}")
            if task_id in known_tasks:
                raise ScenarioValidationError(f"duplicate task id: {task_id}")
            known_tasks.add(str(task_id))
        elif kind in {CommandKind.ADVANCE, CommandKind.CRASH, CommandKind.RECOVER}:
            if task_id not in known_tasks:
                raise ScenarioValidationError(f"action references unknown task: {task_id}")
        if kind is CommandKind.RECOVER:
            if new_task_id in known_tasks:
                raise ScenarioValidationError(f"duplicate recovered task id: {new_task_id}")
            known_tasks.add(str(new_task_id))
        if kind is CommandKind.REVOKE and authorization_id not in authorization_map:
            raise ScenarioValidationError(f"cannot revoke unknown authorization: {authorization_id}")
        action_value = value.get("value")
        if kind is CommandKind.ADVANCE_EPOCH:
            action_value = _int(action_value, "ADVANCE_EPOCH.value")
        elif kind is CommandKind.SET_SECURITY_STATE:
            action_value = _bool(action_value, "SET_SECURITY_STATE.value")
        repeat = value.get("repeat", 1)
        if kind is CommandKind.ADVANCE:
            repeat = _int(repeat, "ADVANCE.repeat")
            if repeat < 1 or repeat > 16:
                raise ScenarioValidationError("ADVANCE.repeat must be between 1 and 16")
        else:
            repeat = 1
        for _ in range(repeat):
            commands.append(
                Command(
                    kind=kind,
                    at=at,
                    task_id=task_id,
                    request_id=request_id,
                    authorization_id=authorization_id,
                    value=action_value,
                    new_task_id=new_task_id,
                )
            )

    expectation_raw = _object(root["expectation"], "expectation")
    _keys(
        expectation_raw,
        "expectation",
        required=("control", "description", "invariants"),
    )
    control = _str(expectation_raw["control"], "expectation.control")
    if control not in ALLOWED_CONTROLS:
        raise ScenarioValidationError(f"unknown control type: {control}")
    invariants = _strict_strings(expectation_raw["invariants"], "expectation.invariants")
    unknown_invariants = set(invariants) - ALLOWED_INVARIANTS
    if unknown_invariants:
        raise ScenarioValidationError(f"unknown invariants: {sorted(unknown_invariants)}")
    mutation_axes = _strict_strings(root["mutation_axes"], "mutation_axes")
    unknown_axes = set(mutation_axes) - ALLOWED_MUTATION_AXES
    if unknown_axes:
        raise ScenarioValidationError(f"unknown mutation axes: {sorted(unknown_axes)}")

    return Scenario(
        schema_version=schema_version,
        scenario_id=_str(root["scenario_id"], "scenario_id"),
        scenario_version=_str(root["scenario_version"], "scenario_version"),
        title=_str(root["title"], "title"),
        summary=_str(root["summary"], "summary"),
        category=_str(root["category"], "category"),
        source=source,
        attack_references=tuple(attacks),
        current_epoch=_int(fixtures["current_epoch"], "fixtures.current_epoch"),
        security_state_known=_bool(fixtures["security_state_known"], "fixtures.security_state_known"),
        principals=tuple(principals),
        authorizations=tuple(authorizations),
        operations=tuple(operations),
        requests=tuple(requests),
        commands=tuple(commands),
        expectation=ScenarioExpectation(
            control=control,
            description=_str(expectation_raw["description"], "expectation.description"),
            invariants=invariants,
        ),
        mutation_axes=mutation_axes,
        definition_digest=sha256_json(root),
    )
