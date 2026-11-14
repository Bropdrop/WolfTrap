"""Canonical encodings used by the system under test.

The reference oracle intentionally does not import this module.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


def canonical_json(value: Any) -> str:
    """Return a stable, strict JSON encoding."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def operation_digest(
    *, action: str, resource: str, arguments: Mapping[str, Any], protected: bool
) -> str:
    payload = {
        "action": action,
        "arguments": dict(arguments),
        "protected": protected,
        "resource": resource,
    }
    return "sha256:" + sha256_json(payload)
