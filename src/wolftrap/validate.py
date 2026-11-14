"""Fail-closed validation for generated and saved executable cases."""

from __future__ import annotations

from typing import Any

from .model import CommandKind, ExperimentCase, unique_by_id


class CaseValidationError(ValueError):
    pass


def _plain_json(value: Any, where: str) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CaseValidationError(f"{where} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _plain_json(item, f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise CaseValidationError(f"{where} has an invalid key")
            _plain_json(item, f"{where}.{key}")
        return
    raise CaseValidationError(f"{where} contains a non-JSON value")


def validate_experiment_case(
    case: ExperimentCase,
    *,
    max_commands: int = 512,
    max_fixtures: int = 512,
) -> None:
    if type(case.case_seed) is not int or case.case_seed < 0:
        raise CaseValidationError("case_seed must be a non-negative integer")
    if case.control not in {"POSITIVE", "NEGATIVE", "MIXED"}:
        raise CaseValidationError("case control is invalid")
    if not 1 <= case.interaction_depth <= 3:
        raise CaseValidationError("interaction depth is outside the v0.1 bound")
    if not 1 <= len(case.commands) <= max_commands:
        raise CaseValidationError("command count is outside the execution bound")
    fixture_groups = (
        case.principals,
        case.authorizations,
        case.operations,
        case.requests,
    )
    if any(not 1 <= len(group) <= max_fixtures for group in fixture_groups):
        raise CaseValidationError("fixture count is outside the execution bound")
    if type(case.current_epoch) is not int or type(case.security_state_known) is not bool:
        raise CaseValidationError("initial security state has invalid types")

    principals = unique_by_id(case.principals, "principal_id")
    authorizations = unique_by_id(case.authorizations, "authorization_id")
    operations = unique_by_id(case.operations, "operation_id")
    requests = unique_by_id(case.requests, "request_id")
    for authorization in case.authorizations:
        if authorization.subject not in principals:
            raise CaseValidationError("authorization subject is unknown")
        if type(authorization.epoch) is not int:
            raise CaseValidationError("authorization epoch must be an integer")
        if type(authorization.issued_at) is not int or type(authorization.expires_at) is not int:
            raise CaseValidationError("authorization times must be integers")
        if authorization.signature_valid is not None and type(authorization.signature_valid) is not bool:
            raise CaseValidationError("signature state must be true, false, or unknown")
        if not all(isinstance(scope, str) and scope for scope in authorization.scopes):
            raise CaseValidationError("authorization scopes must be non-empty strings")
        if not authorization.origin_binding.startswith("synthetic-origin://"):
            raise CaseValidationError("authorization origin is outside the synthetic namespace")
    for operation in case.operations:
        if operation.action not in {
            "read", "write", "transfer", "assign_role", "add_credential", "publish"
        }:
            raise CaseValidationError("operation action is outside the v0.1 allowlist")
        if type(operation.protected) is not bool:
            raise CaseValidationError("operation protected flag must be boolean")
        if not operation.resource.startswith("synthetic://"):
            raise CaseValidationError("operation resource is outside the synthetic namespace")
        _plain_json(dict(operation.arguments), "operation.arguments")
        destination = operation.arguments.get("destination")
        if operation.action == "transfer" and destination is None:
            raise CaseValidationError("transfer operation has no destination")
        if destination is not None and (
            not isinstance(destination, str)
            or not destination.startswith("synthetic-sink://")
        ):
            raise CaseValidationError("operation destination is outside the synthetic namespace")
    for request in case.requests:
        if request.principal_id not in principals:
            raise CaseValidationError("request principal is unknown")
        if request.authorization_id not in authorizations:
            raise CaseValidationError("request authorization fixture is unknown")
        if request.operation_id not in operations:
            raise CaseValidationError("request operation is unknown")
        if not request.origin.startswith("synthetic-origin://"):
            raise CaseValidationError("request origin is outside the synthetic namespace")
        _plain_json(dict(request.credential_overrides), "credential_overrides")
        allowed_overrides = {
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
        if set(request.credential_overrides) - allowed_overrides:
            raise CaseValidationError("request contains unknown credential overrides")
        for name, value in request.credential_overrides.items():
            if name in {
                "authorization_id", "subject", "origin_binding", "operation_digest", "nonce"
            } and (not isinstance(value, str) or not value):
                raise CaseValidationError(f"credential override {name} must be a string")
            if name == "scopes" and (
                not isinstance(value, (list, tuple))
                or not all(isinstance(scope, str) and scope for scope in value)
            ):
                raise CaseValidationError("credential scope override is invalid")
            if name in {"epoch", "issued_at", "expires_at"} and type(value) is not int:
                raise CaseValidationError(f"credential override {name} must be an integer")
            if name == "signature_valid" and value is not None and type(value) is not bool:
                raise CaseValidationError("credential signature override is invalid")
        override_origin = request.credential_overrides.get("origin_binding")
        if override_origin is not None and not override_origin.startswith("synthetic-origin://"):
            raise CaseValidationError("credential override origin is outside synthetic namespace")

    last_time = -1
    known_tasks: set[str] = set()
    for command in case.commands:
        if type(command.at) is not int or command.at < last_time:
            raise CaseValidationError("command time must be a monotonic integer")
        last_time = command.at
        if command.kind is CommandKind.SUBMIT:
            if not command.task_id or command.task_id in known_tasks:
                raise CaseValidationError("SUBMIT task id is missing or duplicate")
            if command.request_id not in requests:
                raise CaseValidationError("SUBMIT request is unknown")
            known_tasks.add(command.task_id)
        elif command.kind in {
            CommandKind.ADVANCE,
            CommandKind.CRASH,
            CommandKind.RECOVER,
        }:
            if command.task_id not in known_tasks:
                raise CaseValidationError("command task is unknown")
        if command.kind is CommandKind.RECOVER:
            if not command.new_task_id or command.new_task_id in known_tasks:
                raise CaseValidationError("RECOVER target is missing or duplicate")
            known_tasks.add(command.new_task_id)
        elif command.kind is CommandKind.REVOKE:
            if command.authorization_id not in authorizations:
                raise CaseValidationError("REVOKE authorization is unknown")
        elif command.kind is CommandKind.ADVANCE_EPOCH:
            if type(command.value) is not int:
                raise CaseValidationError("ADVANCE_EPOCH value must be an integer")
        elif command.kind is CommandKind.SET_SECURITY_STATE:
            if type(command.value) is not bool:
                raise CaseValidationError("SET_SECURITY_STATE value must be boolean")
