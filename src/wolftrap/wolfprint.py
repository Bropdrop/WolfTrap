"""Domain-separated identities over a closed, bounded manifest language."""

from __future__ import annotations

import hashlib
import json
import os
import re
from functools import lru_cache
from pathlib import Path

from .agent_scan import _open_directory, _read_file
from .canonical import canonical_json
from .cursorial_trace import Gap, need, validate as validate_cursorial

UNKNOWN = "UNKNOWN"
TRACE = "wolftrap.cursorial-identity-chain/v2"
OPTIONAL = "protected_config_sha256"


@lru_cache(maxsize=1)
def definitions() -> dict:
    fd = _open_directory(Path(__file__).parent / "schemas")
    try:
        return json.loads(_read_file(fd, "wolfprint-v1.schema.json", 65536))["$defs"]
    finally:
        os.close(fd)


def _matches(value, spec: dict) -> bool:
    if "$ref" in spec:
        if spec["$ref"] == "cursorial-chain-v1.schema.json":
            try:
                validate_cursorial(value, "chain")
            except Gap:
                return False
            return True
        return _matches(value, definitions()[spec["$ref"].removeprefix("#/$defs/")])
    if "anyOf" in spec:
        return any(_matches(value, alternative) for alternative in spec["anyOf"])
    if "const" in spec:
        return value == spec["const"]
    if "enum" in spec:
        return value in spec["enum"]
    kind = spec["type"]
    if kind == "null":
        return value is None
    if kind == "integer":
        return type(value) is int and spec["minimum"] <= value <= spec["maximum"]
    if kind == "string":
        return (isinstance(value, str) and spec["minLength"] <= len(value) <= spec["maxLength"]
                and re.fullmatch(spec["pattern"], value) is not None)
    if kind == "array":
        return (isinstance(value, list) and spec["minItems"] <= len(value) <= spec["maxItems"]
                and all(_matches(item, spec["items"]) for item in value))
    if kind == "object":
        return (isinstance(value, dict) and set(spec["required"]) <= value.keys() <= spec["properties"].keys()
                and all(_matches(v, spec["properties"][k]) for k, v in value.items()))
    raise Gap("unsupported-local-schema-keyword")


def validate(value, kind: str) -> None:
    need(_matches(value, definitions()[kind]), "invalid-" + kind + "-shape")


def domain_digest(domain: str, value) -> str:
    """Length-unambiguous framing. Domain names are fixed by the calling protocol."""
    encoded = canonical_json(value).encode("ascii")
    prefix = ("wolftrap.wolfprint/v1\0" + domain + "\0").encode("ascii")
    return hashlib.sha256(prefix + encoded).hexdigest()


def fingerprint(manifest: dict) -> dict:
    validate(manifest, "architecture")
    canonical = {**manifest, OPTIONAL: manifest.get(OPTIONAL, UNKNOWN)}
    if canonical["mcp_tools"] != UNKNOWN:
        tools = sorted(canonical["mcp_tools"], key=lambda x: (x["server_sha256"], x["tool_sha256"]))
        need(len({(v["server_sha256"], v["tool_sha256"]) for v in tools}) == len(tools),
             "ambiguous-namespaced-tool")
        canonical["mcp_tools"] = tools
    if canonical["capabilities"] != UNKNOWN:
        caps = canonical["capabilities"]
        need(len(set(caps)) == len(caps), "duplicate-capability")
        canonical["capabilities"] = sorted(caps)
    components = {k: UNKNOWN if v == UNKNOWN else "DECLARED" for k, v in sorted(canonical.items()) if k != "schema"}
    return {"architecture_sha256": domain_digest("architecture", canonical), "components": components,
            "required_unknown": [k for k, v in components.items() if v == UNKNOWN and k != OPTIONAL]}


def subject(statement: dict) -> str:
    return domain_digest("principal", {k: statement[k] for k in ("trust_domain", "issuer", "tenant", "principal")})


def session_id(statement: dict) -> str:
    return domain_digest("instance", statement)


def tenant_id(registry: dict) -> str:
    return domain_digest("tenant", [registry[k] for k in ("trust_domain", "issuer", "tenant")])


def behavior(trace: dict, assessment: dict, registry: dict) -> str:
    """Opt-in, tenant-scoped projection of independently witnessed outcomes."""
    from .cursorial import VERIFIED

    if assessment["classification"] != VERIFIED or not assessment["witnesses"]:
        return UNKNOWN
    host = {e["id"]: e for e in trace["sources"]["host"]["events"]}
    proposals = {e["id"]: e for e in trace["sources"]["agent"]["events"]}
    observations = []
    for witness in assessment["witnesses"]:
        proposal = proposals[host[witness["binding"]]["proposal"]]
        gates = witness["host_witness"]
        observations.append([proposal["operation"]["verb"], gates["prepare"], gates["commit"],
                             len(witness["ledger_witness"]["records"])])
    return domain_digest("behavior", {"tenant": tenant_id(registry), "observations": observations})
