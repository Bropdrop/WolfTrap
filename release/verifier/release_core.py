"""Pre-install verification using OS OpenSSL and independently pinned subscriber policy."""

import base64
import csv
import io
import os
from pathlib import Path
import re
import subprocess
import tempfile
from email.parser import BytesParser

from release_io import Verdict, encode, parse, require, sha, unzip
from release_policy import (
    DOCUMENTS,
    PLATFORMS,
    PROFILE,
    REPO,
    hexval,
    policy_record,
    shape,
    statement,
    wheel_name,
)

OPENSSL = "/usr/bin/openssl"


def crypto(arguments, cwd):
    try:
        result = subprocess.run(
            [OPENSSL, *arguments],
            cwd=cwd,
            env={"PATH": os.defpath, "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Verdict("INCONCLUSIVE", "crypto-provider-unavailable") from None
    return result


def verify_cms(payload, signature, root, signer, instant):
    require(64 <= len(signature) <= 32768, "invalid-signature")
    pem = rb"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END CERTIFICATE-----\n"
    require(
        all(len(v) <= 16384 and re.fullmatch(pem, v) for v in (root, signer)), "malformed-trust-certificate"
    )
    with tempfile.TemporaryDirectory() as work:
        temp = Path(work)
        for name, raw in (("root", root), ("leaf", signer), ("sig", signature), ("statement", payload)):
            (temp / name).write_bytes(raw)
        require(
            crypto(["version"], temp).stdout.startswith(b"OpenSSL 3."),
            "unsupported-crypto-provider",
            "INCONCLUSIVE",
        )
        normalized = crypto(
            ["cms", "-cmsout", "-binary", "-inform", "DER", "-in", "sig", "-outform", "DER"], temp
        )
        require(normalized.returncode == 0 and normalized.stdout == signature, "malformed-cms")
        # OpenSSL decodes the ASN.1. This profile only accepts detached SHA-256
        # SignedData with one signer and no embedded certificate or CRL sources.
        decoded = crypto(["cms", "-cmsout", "-print", "-inform", "DER", "-in", "sig"], temp)
        names = re.findall(rb"(?m)^\s*algorithm: ([^\r\n]+)", decoded.stdout)
        require(
            decoded.returncode == 0
            and names == [b"sha256 (2.16.840.1.101.3.4.2.1)"] * 2 + [b"rsaEncryption (1.2.840.113549.1.1.1)"]
            and all(
                re.search(pattern, decoded.stdout)
                for pattern in (
                    rb"(?m)^\s*eContent: <ABSENT>$",
                    rb"certificates:\s+<ABSENT>",
                    rb"crls:\s+<ABSENT>",
                    rb"unsignedAttrs:\s+<ABSENT>",
                )
            ),
            "unsupported-cms-profile",
        )
        pinned = [
            "-CAfile",
            "root",
            "-no-CApath",
            "-no-CAstore",
            "-x509_strict",
            "-auth_level",
            "2",
            "-verify_depth",
            "0",
            "-attime",
            str(instant),
            "-purpose",
            "smimesign",
        ]
        chain = crypto(["verify", *pinned, "leaf"], temp)
        require(chain.returncode == 0, "signer-chain-or-validity")
        checked = crypto(
            [
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                "sig",
                "-content",
                "statement",
                "-nointern",
                "-certfile",
                "leaf",
                "-signer",
                "verified-signer",
                "-cades",
                "-verify_retcode",
                *pinned,
            ],
            temp,
        )
        require(
            checked.returncode == 0
            and checked.stdout == payload
            and (temp / "verified-signer").read_bytes() == signer,
            "signature-or-signer",
        )


def verify_wheel(raw, release, license_bytes):
    files = unzip(raw, wheel=True)
    dist = "wolftrap-" + release["version"] + ".dist-info/"
    meta = {"METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt", "licenses/LICENSE"}
    core = "wolftrap/data/product-build-v1.json"
    require(core in files and all(dist + n in files for n in meta), "wheel-metadata")
    build = parse(files[core])
    shape(build, "schema version commit tree members", "wheel-build-record")
    require(
        build["schema"] == "wolftrap.product-build/v1"
        and all(build[k] == release[k] for k in ("commit", "tree", "version"))
        and type(build["members"]) is dict
        and 1 <= len(build["members"]) <= 256,
        "wheel-source-binding",
    )
    actual = {
        n.removeprefix("wolftrap/"): sha(v)
        for n, v in files.items()
        if n.startswith("wolftrap/") and n != core
    }
    require(
        actual == build["members"]
        and all(n.endswith((".py", ".json", ".js", ".md")) for n in actual)
        and set(files) == {core} | {"wolftrap/" + n for n in actual} | {dist + n for n in meta},
        "wheel-inventory",
    )
    require(
        files[dist + "entry_points.txt"].strip() == b"[console_scripts]\nwolftrap = wolftrap.cli:main"
        and files[dist + "licenses/LICENSE"] == license_bytes,
        "wheel-entrypoint-or-license",
    )
    metadata = BytesParser().parsebytes(files[dist + "METADATA"])
    tags = BytesParser().parsebytes(files[dist + "WHEEL"])
    require(
        tags.get_all("Wheel-Version") == ["1.0"]
        and tags.get_all("Root-Is-Purelib") == ["true"]
        and tags.get_all("Tag") == ["py3-none-any"],
        "wheel-platform-tags",
    )
    require(
        metadata.get_all("Name") == ["wolftrap"] and metadata.get_all("Version") == [release["version"]],
        "wheel-identity",
    )
    try:
        rows = list(csv.reader(io.StringIO(files[dist + "RECORD"].decode("utf-8")), strict=True))
        require(
            len(rows) == len(files)
            and all(len(row) == 3 for row in rows)
            and {row[0] for row in rows} == set(files),
            "wheel-record",
        )
        for name, hash_field, size in rows:
            if name == dist + "RECORD":
                require((hash_field, size) == ("", ""), "wheel-record")
            else:
                digest = base64.urlsafe_b64encode(bytes.fromhex(sha(files[name]))).rstrip(b"=").decode()
                require((hash_field, size) == ("sha256=" + digest, str(len(files[name]))), "wheel-record")
    except (ValueError, csv.Error, UnicodeError):
        raise Verdict("REJECTED", "wheel-record") from None


def verify(raw_bundle, trust, policy_pin, floor, sequence, mode, now):
    require(hexval(policy_pin, 64) and sha(trust["policy.json"]) == policy_pin, "independent-policy-pin")
    policy = parse(trust["policy.json"])
    approval = policy_record(policy, sequence, mode, floor, now)
    authority = policy["authority"]
    root, signer = trust["root.pem"], trust["signer.pem"]
    require(
        sha(root) == authority["root_sha256"]
        and sha(signer) == authority["signer_sha256"]
        and root != signer,
        "untrusted-root-or-signer",
    )
    files = unzip(raw_bundle)
    wheel = wheel_name(approval["version"])
    payloads = DOCUMENTS | {wheel}
    needed = payloads | {"release.json", "provenance.json", "provenance.p7s"}
    require(not set(files) - needed, "unexpected-bundle-member")
    require(needed <= set(files), "missing-release-evidence", "INCONCLUSIVE")
    mraw = files["release.json"]
    require(sha(mraw) == approval["manifest_sha256"], "unapproved-manifest")
    manifest = parse(mraw)
    inventory = {n: {"bytes": len(files[n]), "sha256": sha(files[n])} for n in sorted(payloads)}
    expected = {
        "schema": "awooo.release/v1",
        "profile": PROFILE,
        "repository": REPO,
        **{k: approval[k] for k in ("version", "sequence", "commit", "tree")},
        "files": inventory,
    }
    require(mraw == encode(expected), "manifest-or-payload-mismatch")
    subjects = {n: sha(files[n]) for n in (wheel, "release.json", "core.cdx.json")}
    payload = files["provenance.json"]
    parse(payload)
    require(payload == encode(statement(approval, subjects)), "provenance-policy-mismatch")
    # Historical observation is supplied by the pinned subscriber record. Only
    # audit uses it. Revocation and withdrawal still apply at verification time.
    if mode in ("historical", "rollback"):
        require(
            sha(files["provenance.p7s"]) == approval["archived_signature_sha256"],
            "different-archived-signature",
        )
    verify_cms(
        payload,
        files["provenance.p7s"],
        root,
        signer,
        approval["observed_at"] if mode == "historical" else now,
    )
    require(files["platforms.json"] == encode(PLATFORMS), "platform-matrix")
    bom = parse(files["core.cdx.json"])
    component = (
        bom.get("metadata", {}).get("component", {})
        if type(bom) is dict and type(bom.get("metadata")) is dict
        else {}
    )
    require(
        type(component) is dict
        and bom.get("bomFormat") == "CycloneDX"
        and bom.get("specVersion") == "1.6"
        and component.get("name") == "wolftrap"
        and component.get("version") == approval["version"]
        and component.get("hashes") == [{"alg": "SHA-256", "content": subjects[wheel]}]
        and type(component.get("properties")) is list
        and all(
            {"name": "wolftrap:source:" + k, "value": approval[k]} in component["properties"]
            for k in ("commit", "tree")
        ),
        "sbom-binding",
    )
    verify_wheel(files[wheel], approval, files["LICENSE"])
    return {
        "status": "VERIFIED",
        "scope": PROFILE,
        "purpose": mode,
        "commit": approval["commit"],
        "tree": approval["tree"],
        "version": approval["version"],
        "sequence": sequence,
        "policy_sha256": policy_pin,
        "manifest_sha256": sha(mraw),
        "wheel_sha256": subjects[wheel],
        "sbom_sha256": subjects["core.cdx.json"],
        "archive_sha256": sha(raw_bundle),
    }, files[wheel]
