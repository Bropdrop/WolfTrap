"""Authored expectations and finite variations of inert CMS release documents."""
from copy import deepcopy
import io
import json
import time
from unittest.mock import patch
import zipfile

import release_core
import release_policy
from release_io import Verdict, encode, pack, parse, sha
from release_fixtures import TestIssuer, toy

# These are expected policy outcomes, independent of verifier output.
EXPECTED = {
    "current": "VERIFIED", "version-upgrade": "VERIFIED", "historical-audit": "VERIFIED",
    "explicit-rollback": "VERIFIED", "idempotent-recheck": "VERIFIED", "old-under-new-policy": "REJECTED",
    "stale-subscriber-floor": "REJECTED", "no-rollback-permission": "REJECTED", "expired-rollback": "REJECTED",
    "rollback-wrong-digest": "REJECTED", "withdrawn-release": "REJECTED", "expired-authority": "REJECTED",
    "revoked-authority": "REJECTED", "expired-policy": "REJECTED", "future-policy": "REJECTED",
    "missing-signature": "INCONCLUSIVE", "empty-signature": "REJECTED", "wrong-signature": "REJECTED",
    "wrong-repository": "REJECTED", "wrong-source": "REJECTED", "wrong-tree": "REJECTED",
    "wrong-workflow": "REJECTED", "wrong-workflow-revision": "REJECTED", "wrong-builder": "REJECTED",
    "wrong-signer-identity": "REJECTED", "changed-build-input": "REJECTED", "changed-dependency": "REJECTED",
    "changed-build-parameter": "REJECTED", "wrong-subject": "REJECTED", "fake-trust-domain": "REJECTED",
    "self-selected-root": "REJECTED", "self-declared-signer": "REJECTED", "alternate-publisher": "REJECTED",
    "substituted-policy": "REJECTED", "changed-wheel": "REJECTED", "swapped-sbom": "REJECTED",
    "changed-manifest": "REJECTED", "changed-notes": "REJECTED", "unsigned-bundle": "INCONCLUSIVE",
    "wrong-predicate": "REJECTED", "duplicate-statement-key": "REJECTED", "malformed-signature": "REJECTED",
    "trailing-signature-bytes": "REJECTED", "trailing-archive-bytes": "REJECTED", "missing-provenance": "INCONCLUSIVE",
    "unknown-policy-version": "INCONCLUSIVE", "duplicate-approval-sequence": "REJECTED", "unlisted-sequence": "REJECTED",
    "unsafe-member": "REJECTED", "absolute-member": "REJECTED", "zip-symlink": "REJECTED", "compressed-member": "REJECTED",
    "oversize-archive": "REJECTED", "ambiguous-json": "REJECTED", "extra-root-in-bundle": "REJECTED",
    "bad-inner-wheel-path": "REJECTED", "inconsistent-sbom": "REJECTED", "unavailable-crypto": "INCONCLUSIVE",
}


def set_field(obj, path, val):
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = val


class Corpus:
    def __init__(self, work):
        self.issuer = TestIssuer(work / "signing")
        self.foreign = TestIssuer(work / "foreign")
        self.now = int(time.time())
        self.old, self.r1 = toy(self.issuer, "0.5.4.dev1", 1, self.now)
        self.new, self.r2 = toy(self.issuer, "0.5.4.dev2", 2, self.now)
        self.trust = self.issuer.trust([self.r1, self.r2], self.now)
        self.base = parse(self.trust["policy.json"])
        self.permit = {"from_sequence": 2, "to_sequence": 1, "manifest_sha256": self.r1["manifest_sha256"],
                       "expires": self.now + 3600}

    def variation(self, name):
        data, trust, policy = self.new.copy(), self.trust.copy(), deepcopy(self.base)
        seq, floor, mode, clock = 2, 2, "current", self.now
        encoded, pin = None, None
        foreign = self.foreign
        if name in ("historical-audit", "explicit-rollback", "old-under-new-policy", "no-rollback-permission",
                    "expired-rollback", "rollback-wrong-digest"):
            data, seq = self.old.copy(), 1
            if name == "historical-audit":
                mode = "historical"
            elif name != "old-under-new-policy":
                mode = "rollback"
                if name != "no-rollback-permission":
                    policy["rollback"] = self.permit.copy()
                if name == "expired-rollback":
                    policy["rollback"]["expires"] = clock
                if name == "rollback-wrong-digest":
                    policy["rollback"]["manifest_sha256"] = "0" * 64
        if name == "current":
            data, seq, floor = self.old.copy(), 1, 1
            policy["current_sequence"], policy["releases"] = 1, [self.r1]
        if name == "stale-subscriber-floor":
            floor = 3
        if name == "withdrawn-release":
            policy["releases"][1]["withdrawn"] = True
        if name == "revoked-authority":
            policy["authority"]["revoked"] = True
        if name in ("expired-authority", "expired-policy", "future-policy"):
            clock += {"expired-authority": 8 * 86400, "expired-policy": 16 * 86400, "future-policy": -1}[name]
        if name in ("missing-signature", "unsigned-bundle"):
            del data["provenance.p7s"]
        if name == "missing-provenance":
            del data["provenance.json"]
        if name == "empty-signature":
            data["provenance.p7s"] = b""
        if name == "wrong-signature":
            data["provenance.p7s"] = self.old["provenance.p7s"]
        if name == "malformed-signature":
            data["provenance.p7s"] = b"A" * 100
        if name == "trailing-signature-bytes":
            data["provenance.p7s"] += b"extra"
        ext = ["predicate", "buildDefinition", "externalParameters"]
        dep = ["predicate", "buildDefinition", "resolvedDependencies"]
        variations = {"wrong-repository": ext + ["repository"], "wrong-source": ext + ["sourceCommit"], "wrong-tree": ext + ["sourceTree"],
                      "wrong-workflow": ext + ["workflow"], "wrong-workflow-revision": ext + ["workflowRevision"],
                      "wrong-builder": ["predicate","runDetails","builder","id"], "wrong-signer-identity": ext+["signer"],
                      "changed-build-input": dep+[2,"digest","sha256"], "changed-dependency": dep+[4,"digest","sha256"],
                      "changed-build-parameter": ["predicate","buildDefinition","internalParameters","network"],
                      "wrong-subject": ["subject",0,"digest","sha256"], "wrong-predicate": ["predicateType"]}
        if name in variations:
            statement = parse(data["provenance.json"])
            set_field(statement, variations[name], "foreign")
            data["provenance.json"] = encode(statement)
            data["provenance.p7s"] = self.issuer.sign(data["provenance.json"])
        if name in ("alternate-publisher","self-selected-root","self-declared-signer"):
            data["provenance.p7s"] = foreign.sign(data["provenance.json"])
            if name == "self-selected-root":
                trust["root.pem"] = foreign.root
            if name == "self-declared-signer":
                # Trust data selected by the distribution is deliberately excluded.
                trust["signer.pem"] = foreign.signer
        if name == "fake-trust-domain":
            policy["repository_id"] = "12345"
        if name == "substituted-policy":
            policy["valid_until"] += 1
            pin = sha(self.trust["policy.json"])
        wheel = release_policy.wheel_name(self.r2["version"])
        changed = {"changed-wheel": wheel,"changed-manifest":"release.json","changed-notes":"RELEASE-NOTES.md"}
        if name in changed:
            data[changed[name]] += b"modified"
        if name == "swapped-sbom":
            data["core.cdx.json"] = self.old["core.cdx.json"]
        if name == "duplicate-statement-key":
            data["provenance.json"] = data["provenance.json"].replace(b'{', b'{"_type":null,', 1)
        if name == "unknown-policy-version":
            policy["schema"] = "awooo.subscriber-policy/v99"
        if name == "duplicate-approval-sequence":
            policy["releases"].append(self.r2)
        if name == "unlisted-sequence":
            seq = 3
        if name in ("unsafe-member","absolute-member","extra-root-in-bundle"):
            data[{"unsafe-member":"../escape","absolute-member":"/escape","extra-root-in-bundle":"root.pem"}[name]]=b"fictional"
        if name in ("zip-symlink", "compressed-member"):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                info = zipfile.ZipInfo("entry")
                info.external_attr = (0o120777 if name == "zip-symlink" else 0o100644) << 16
                archive.writestr(info, b"entry", compress_type=zipfile.ZIP_DEFLATED if name == "compressed-member" else zipfile.ZIP_STORED)
            encoded = stream.getvalue()
        if name == "oversize-archive":
            encoded = b"a" * (6 * 1024 * 1024 + 1)
        if name == "trailing-archive-bytes":
            encoded = pack(data) + b"extra"
        if name in ("bad-inner-wheel-path", "inconsistent-sbom"):
            # Even a validly signed, explicitly pinned artifact must be safe to parse.
            if name == "bad-inner-wheel-path":
                data[wheel] = pack({"../outside": b"fictional"})
            bom = parse(data["core.cdx.json"])
            bom["metadata"]["component"]["hashes"][0]["content"] = sha(data[wheel]) if name == "bad-inner-wheel-path" else "0"*64
            data["core.cdx.json"] = encode(bom)
            m = parse(data["release.json"])
            for n in (wheel, "core.cdx.json"):
                m["files"][n] = {"bytes":len(data[n]),"sha256":sha(data[n])}
            data["release.json"] = encode(m)
            r = policy["releases"][1]
            r["manifest_sha256"] = sha(data["release.json"])
            data["provenance.json"] = encode(release_policy.statement(r, {n:sha(data[n]) for n in (wheel,"core.cdx.json","release.json")}))
            data["provenance.p7s"] = self.issuer.sign(data["provenance.json"])
        trust["policy.json"] = encode(policy)
        if name == "ambiguous-json":
            trust["policy.json"] = trust["policy.json"].replace(b"{", b'{"profile":null,',1)
        return (encoded if encoded is not None else pack(data), trust, pin or sha(trust["policy.json"]), floor, seq, mode, clock)

    def score(self):
        variations = {name:self.variation(name) for name in EXPECTED}
        def outcome(name, args):
            try:
                if name == "unavailable-crypto":
                    with patch.object(release_core, "OPENSSL", "/nonexistent/fictional-provider"):
                        release_core.verify(*args)
                else:
                    release_core.verify(*args)
                return "VERIFIED"
            except Verdict as e:
                return e.status
        results = {n:outcome(n,args) for n,args in variations.items()}
        def skip_reason(orig, reason):
            def weakened(condition, code, *rest):
                return orig(condition or code == reason, code, *rest)
            return weakened
        # Each defective implementation executes against a named independent
        # expectation. The exact mutation and its counterexample are retained.
        def defective(mutant, name):
            args = list(variations[name])
            if mutant == "accept-any-signature":
                with patch.object(release_core, "verify_cms", return_value=None):
                    return outcome(name,args)
            if mutant == "trust-self-selected-signer":
                args[1] = self.foreign.trust([self.r1,self.r2],self.now)
                args[2] = sha(args[1]["policy.json"])
            elif mutant == "ignore-artifact-bytes":
                args[0] = pack(self.new)
            elif mutant == "ignore-source-revision":
                # Overwrite the expected source from the unauthenticated claim.
                original = release_core.statement
                def self_reported(*params):
                    val = original(*params)
                    val["predicate"]["buildDefinition"]["externalParameters"]["sourceCommit"] = "foreign"
                    return val
                with patch.object(release_core,"statement",self_reported):
                    return outcome(name,args)
            elif mutant in ("ignore-revocation","ignore-rollback"):
                reason = "authority-revoked" if mutant == "ignore-revocation" else "rollback-or-replay"
                with patch.object(release_policy,"require",skip_reason(release_policy.require,reason)):
                    return outcome(name,args)
            elif mutant == "missing-is-success":
                result = outcome(name,args)
                return "VERIFIED" if result == "INCONCLUSIVE" else result
            elif mutant in ("always-reject","always-allow"):
                return "REJECTED" if mutant == "always-reject" else "VERIFIED"
            return outcome(name,args)
        pairs = {"accept-any-signature":"wrong-signature","trust-self-selected-signer":"alternate-publisher",
                 "ignore-artifact-bytes":"changed-wheel","ignore-source-revision":"wrong-source","ignore-revocation":"revoked-authority",
                 "ignore-rollback":"old-under-new-policy","missing-is-success":"missing-signature",
                 "always-reject":"version-upgrade","always-allow":"changed-manifest"}
        mutants = {m:{"case":n,"observed":defective(m,n),"expected":EXPECTED[n]} for m,n in pairs.items()}
        if results != EXPECTED or any(v["observed"] == v["expected"] for v in mutants.values()):
            raise ValueError("qualification mismatch: " + str([n for n in EXPECTED if results[n]!=EXPECTED[n]])
                             + str([n for n,v in mutants.items() if v["observed"]==v["expected"]]))
        return {"schema":"awooo.release-controls/v1","cases":[{"id":n,"expected":EXPECTED[n],"observed":v} for n,v in results.items()],
                "defective_verifiers":mutants,"mismatches":0}
