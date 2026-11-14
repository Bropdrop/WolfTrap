"""Disabled, optional future model-hypothesis boundary.

Model proposals are never findings and cannot bypass deterministic verification.
No keys are read and no network client is imported in v0.1.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class HypothesisStatus(str, Enum):
    PROPOSED = "PROPOSED"
    REJECTED = "REJECTED"
    TRANSLATED = "TRANSLATED"


class HypothesisProviderDisabled(RuntimeError):
    pass


@dataclass(frozen=True)
class DefensiveHypothesis:
    provider_requested: str
    provider_available: bool
    model_variant: str
    prompt_digest: str | None
    proposal: str | None
    status: HypothesisStatus


@dataclass(frozen=True)
class HypothesisProviderStatus:
    requested_provider: str
    requested_model: str
    requested_mode: str
    available: bool
    enabled: bool
    used: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class DisabledHypothesisProvider:
    status = HypothesisProviderStatus(
        requested_provider="OpenAI",
        requested_model="GPT-5.6 Sol",
        requested_mode="Daybreak Blue",
        available=False,
        enabled=False,
        used=False,
        reason=(
            "The requested model/mode is not available in this environment; "
            "v0.1 performs no model or API calls."
        ),
    )

    def propose(self, _: str) -> tuple[DefensiveHypothesis, ...]:
        raise HypothesisProviderDisabled(
            "model hypothesis generation is unavailable and disabled in WolfTrap v0.1"
        )
