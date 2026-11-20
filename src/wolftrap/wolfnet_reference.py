"""Independent authored outcomes. No imports from verifier, classifier, fixtures or policy."""

# Entries encode feed acceptance, effective level, registry-only proposal and public classification.
CLEAR = ("verified", 0, "ALLOW", "NO_ACTIVE_ADVERSE_IN_SCOPE")
UNCERTAIN = ("verified", None, None, "INCONCLUSIVE")
NOTICE = ("verified", 1, "MONITOR", "STATIC REVIEW SIGNAL")


def bounded(level, action):
    return "verified", level, action, "SYNTHETICALLY VERIFIED"


EXPECT = {
    "advisory-default": bounded(3, "MONITOR"), "explicit-deny": bounded(3, "DENY"),
    "no-deny-consent": bounded(3, "MONITOR"), "quarantine": bounded(3, "QUARANTINE"),
    "policy-reauth": bounded(3, "REAUTHENTICATE"), "human-review": bounded(3, "REQUIRE_HUMAN_APPROVAL"),
    "read-only": bounded(2, "READ_ONLY"), "extra-reviewer-required": bounded(3, "MONITOR"),
    "low-confidence": bounded(3, "MONITOR"), "higher-local-threshold": bounded(3, "MONITOR"),
    "static-lookalike": NOTICE, "healthy-accused": UNCERTAIN, "missing-evidence": UNCERTAIN,
    "missing-trace": UNCERTAIN, "contradictory-host-binding": UNCERTAIN, "unsigned-custody": UNCERTAIN,
    "unrelated-behavior": CLEAR, "same-build-other-principal": CLEAR, "benign-upgrade": CLEAR,
    "different-instance": CLEAR, "principal-scope-restart": bounded(3, "MONITOR"),
    "wrong-operation": CLEAR, "wrong-resource": CLEAR, "foreign-presentation": UNCERTAIN,
    "missing-presentation": UNCERTAIN, "publisher-not-selected": CLEAR, "no-published-records": CLEAR,
    "withdrawn": CLEAR, "contested": UNCERTAIN, "local-appeal": UNCERTAIN,
    "pending-review": UNCERTAIN, "corrected-and-reviewed": bounded(3, "DENY"), "expired-record": CLEAR,
    "expired-observation": UNCERTAIN, "policy-revision-change": bounded(3, "REAUTHENTICATE"),
    "unauthorized-host-operation": bounded(3, "MONITOR"), "rotation": bounded(3, "DENY"),
    "recovered-publisher": bounded(3, "DENY"), "pinned-reassessment": bounded(3, "MONITOR"),
    "superseded-downgrade": bounded(2, "MONITOR"), "conflicting-publishers": UNCERTAIN,
    "withdrawal-disagreement": UNCERTAIN, "runtime-claim": UNCERTAIN, "critical-on-simulation": UNCERTAIN,
    "copied-presentation": UNCERTAIN, "session-assurance-unknown": UNCERTAIN,
    "immutable-legal-hold": UNCERTAIN, "wrong-digest": UNCERTAIN, "unlinked-provenance": UNCERTAIN,
    "independent-observer-required": UNCERTAIN,
}

REJECTIONS = {
    "trust-equivocation": "changed-trust-without-new-revision",
    "forged-feed": "invalid-ed25519-signature", "changed-advisory": "invalid-ed25519-signature",
    "forged-approval": "invalid-ed25519-signature", "forged-witness": "invalid-ed25519-signature",
    "fake-publisher": "untrusted-signer-or-role", "foreign-author": "unauthorized-publisher",
    "wrong-role": "untrusted-signer-or-role", "old-signature-on-update": "invalid-ed25519-signature",
    "unknown-schema": "invalid-feed-shape", "algorithm-substitution": "invalid-feed-shape",
    "compromised-publisher": "revoked-signing-key", "compromised-distributor": "revoked-signing-key",
    "compromised-reviewer": "revoked-signing-key", "retired-distributor": "current-signer-unavailable",
    "duplicate-key-material": "ambiguous-or-invalid-trust-key", "small-order-key": "ambiguous-or-invalid-trust-key",
    "unlinked-rotation": "invalid-key-lineage", "stale-trust": "stale-publisher-trust",
    "replayed-head": "replayed-update-or-wrong-accepted-head", "rollback": "rolled-back-snapshot",
    "checkpoint-fork": "checkpoint-fork", "missing-frame": "broken-feed-scope-sequence-or-predecessor",
    "future-snapshot": "future-or-unordered-feed", "expired-feed": "expired-feed",
    "trust-downgrade": "checkpoint-or-trust-scope-mismatch", "wrong-stream": "broken-feed-scope-sequence-or-predecessor",
    "wrong-tenant": "publication-outside-subscriber-scope", "wrong-issuer": "publication-outside-subscriber-scope",
    "wrong-domain": "publication-outside-subscriber-scope", "publication-without-consent": "unapproved-publication",
    "only-one-reviewer": "independent-publication-approval-missing", "same-review-org": "review-independence-failed",
    "publisher-reviews-itself": "review-independence-failed", "duplicate-signoff": "ambiguous-approval-order",
    "revive-withdrawn": "replayed-or-terminal-advisory", "tombstone-reissue": "duplicate-or-reissued-incident",
    "change-subject": "supersession-subject-or-incident-substitution", "broken-correction": "broken-advisory-supersession",
    "attacker-free-text": "invalid-feed-shape", "duplicated-id": "duplicate-advisory-in-frame",
    "stale-policy": "stale-or-foreign-local-policy", "invalid-subscriber-scope": "stale-or-foreign-local-policy",
    "replayed-witness": "ambiguous-observation", "advisory-id-clash": "advisory-id-namespace-mismatch",
}
