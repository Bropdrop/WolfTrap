"""Subscriber-owned policy and the closed in-toto/SLSA evaluation profile."""
import re

from release_io import require

REPO = "https://github.com/GovernableIntelligence/WolfTrap"
REPO_ID = "1436465132"
WORKFLOW = ".github/workflows/release-trust-qualification.yml"
BUILDER = REPO + "/evaluators/ephemeral-cms-v1"
BUILD_TYPE = REPO + "/build-types/offline-wheel/v1"
PROFILE = "EVALUATION_ONLY"
PLATFORMS = ["ubuntu-24.04-aarch64-cpython-3.12.14", "ubuntu-24.04-x86_64-cpython-3.12.14"]
BUILDER_WHEEL = "setuptools-84.2.1-py3-none-any.whl"
DOCUMENTS = {"LICENSE", "SECURITY.md", "VERIFY.md", "RELEASE-NOTES.md", "platforms.json", "core.cdx.json"}


def shape(value, names, reason):
    require(type(value) is dict and set(value) == set(names.split()), reason)


def integer(value):
    return type(value) is int and 0 <= value < 2**53


def hexval(value, size):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None


def wheel_name(version):
    require(type(version) is str and re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:\.dev[0-9]{1,4})?", version), "bad-version")
    return "wolftrap-" + version + "-py3-none-any.whl"


def policy_record(p, sequence, mode, floor, now):
    shape(p, "schema profile repository repository_id workflow builder authority valid_from valid_until current_sequence releases rollback", "policy-schema")
    require(p["schema"] == "awooo.subscriber-policy/v1" and p["profile"] == PROFILE, "unsupported-policy", "INCONCLUSIVE")
    require((p["repository"], p["repository_id"], p["workflow"], p["builder"]) == (REPO, REPO_ID, WORKFLOW, BUILDER), "wrong-trust-domain")
    require(all(integer(v) for v in (now, floor, sequence, p["valid_from"], p["valid_until"], p["current_sequence"]))
            and floor >= 1 and p["current_sequence"] >= floor and sequence >= 1, "stale-policy-or-invalid-sequence")
    require(p["valid_from"] <= now < p["valid_until"] <= p["valid_from"] + 31 * 86400, "policy-not-current")
    a = p["authority"]
    shape(a, "issuer signer root_sha256 signer_sha256 revoked", "authority-schema")
    require((a["issuer"], a["signer"]) == ("urn:awooo:test:ca", "urn:awooo:test:builder") and
            all(hexval(a[k], 64) for k in ("root_sha256", "signer_sha256")) and type(a["revoked"]) is bool, "wrong-authority")
    require(not a["revoked"], "authority-revoked")
    require(type(p["releases"]) is list and 1 <= len(p["releases"]) <= 32, "policy-catalog")
    catalog = {}
    for r in p["releases"]:
        shape(r, "sequence version commit tree workflow_sha256 builder_sha256 lock_sha256 dependency_sha256 manifest_sha256 archived_signature_sha256 observed_at withdrawn", "approval-schema")
        wheel_name(r["version"])
        require(integer(r["sequence"]) and 1 <= r["sequence"] <= p["current_sequence"] and r["sequence"] not in catalog
                and type(r["withdrawn"]) is bool and integer(r["observed_at"]) and r["observed_at"] <= now
                and all(hexval(r[k], 40) for k in ("commit", "tree"))
                and all(hexval(r[k], 64) for k in ("workflow_sha256", "builder_sha256", "lock_sha256", "dependency_sha256",
                                                  "manifest_sha256", "archived_signature_sha256")), "invalid-approval")
        catalog[r["sequence"]] = r
    require(p["current_sequence"] in catalog and sequence in catalog, "unapproved-release")
    selected = catalog[sequence]
    require(not selected["withdrawn"], "release-withdrawn")
    require(mode in ("current", "historical", "rollback"), "invalid-purpose")
    rollback = p["rollback"]
    if rollback is not None:
        shape(rollback, "from_sequence to_sequence manifest_sha256 expires", "rollback-schema")
        require(all(integer(rollback[k]) for k in ("from_sequence", "to_sequence", "expires"))
                and hexval(rollback["manifest_sha256"], 64), "invalid-rollback")
    if mode == "current":
        require(sequence == p["current_sequence"] and sequence >= floor, "rollback-or-replay")
    if mode == "rollback":
        require(rollback is not None and rollback["from_sequence"] == p["current_sequence"]
                and rollback["to_sequence"] == sequence < p["current_sequence"] and now < rollback["expires"] <= p["valid_until"]
                and rollback["manifest_sha256"] == selected["manifest_sha256"], "rollback-unapproved")
    return selected


def statement(release, subjects):
    commit = release["commit"]
    def dependency(name, key, value):
        return {"uri": name, "digest": {key: value}}
    deps = [dependency("git+" + REPO + "@" + commit, "gitTree", release["tree"]),
            dependency(REPO + "/blob/" + commit + "/" + WORKFLOW, "sha256", release["workflow_sha256"]),
            dependency(REPO + "/blob/" + commit + "/scripts/build-product.py", "sha256", release["builder_sha256"]),
            dependency(REPO + "/blob/" + commit + "/.github/product-builder.lock", "sha256", release["lock_sha256"]),
            dependency("pkg:pypi/setuptools@84.2.1", "sha256", release["dependency_sha256"])]
    params = {"repository": REPO, "repositoryId": REPO_ID, "sourceCommit": commit, "sourceTree": release["tree"],
              "workflow": WORKFLOW, "workflowRevision": commit, "version": release["version"],
              "sequence": release["sequence"], "declaredPlatforms": PLATFORMS, "profile": PROFILE,
              "issuer": "urn:awooo:test:ca", "signer": "urn:awooo:test:builder"}
    return {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": n, "digest": {"sha256": d}} for n, d in sorted(subjects.items())],
            "predicate": {"buildDefinition": {"buildType": BUILD_TYPE, "externalParameters": params,
                          "internalParameters": {"sourceDateEpoch": 315532800, "network": "loopback-only"},
                          "resolvedDependencies": deps}, "runDetails": {"builder": {"id": BUILDER}}}}
