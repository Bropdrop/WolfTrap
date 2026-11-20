"""Evaluation-only issuer and builders. All signing secrets are disposable and kept outside outputs."""

import base64
import csv
import io
import os
from pathlib import Path
import subprocess

from release_io import encode, pack, sha
from release_policy import PLATFORMS, PROFILE, REPO, REPO_ID, WORKFLOW, BUILDER, statement, wheel_name

ROOT = Path(__file__).resolve().parents[2]


class TestIssuer:
    def __init__(self, work):
        self.work = work
        work.mkdir(mode=0o700)
        self.openssl(
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-noenc",
            "-sha256",
            "-days",
            "14",
            "-subj",
            "/CN=awooo evaluation CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            "root.key",
            "-out",
            "root.pem",
        )
        self.openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-noenc",
            "-sha256",
            "-subj",
            "/CN=awooo evaluation builder",
            "-keyout",
            "leaf.key",
            "-out",
            "request",
        )
        (work / "extensions").write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=emailProtection,codeSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
            "subjectAltName=URI:urn:awooo:test:builder\n"
        )
        self.openssl(
            "x509",
            "-req",
            "-in",
            "request",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "2",
            "-days",
            "7",
            "-sha256",
            "-extfile",
            "extensions",
            "-out",
            "signer.pem",
        )
        self.root = (work / "root.pem").read_bytes()
        self.signer = (work / "signer.pem").read_bytes()

    def openssl(self, *args, data=None):
        return subprocess.run(
            ["/usr/bin/openssl", *args],
            cwd=self.work,
            input=data,
            capture_output=True,
            check=True,
            env={"PATH": os.defpath, "LC_ALL": "C", "OPENSSL_CONF": "/etc/ssl/openssl.cnf"},
            timeout=20,
        ).stdout

    def sign(self, raw):
        return self.openssl(
            "cms",
            "-sign",
            "-binary",
            "-md",
            "sha256",
            "-cades",
            "-nosmimecap",
            "-nocerts",
            "-signer",
            "signer.pem",
            "-inkey",
            "leaf.key",
            "-outform",
            "DER",
            data=raw,
        )

    def trust(self, releases, now):
        p = {
            "schema": "awooo.subscriber-policy/v1",
            "profile": PROFILE,
            "repository": REPO,
            "repository_id": REPO_ID,
            "workflow": WORKFLOW,
            "builder": BUILDER,
            "valid_from": now,
            "valid_until": now + 14 * 86400,
            "authority": {
                "issuer": "urn:awooo:test:ca",
                "signer": "urn:awooo:test:builder",
                "root_sha256": sha(self.root),
                "signer_sha256": sha(self.signer),
                "revoked": False,
            },
            "current_sequence": max(r["sequence"] for r in releases),
            "releases": releases,
            "rollback": None,
        }
        return {"policy.json": encode(p), "root.pem": self.root, "signer.pem": self.signer}


def source_file(head, name):
    return subprocess.check_output(
        ["git", "show", head + ":" + name],
        cwd=ROOT,
        env={
            "PATH": os.defpath,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "",
        },
    )


def inputs(head, tree):
    import re

    lock = source_file(head, ".github/product-builder.lock")
    (dep,) = re.findall(rb"^setuptools==84\.2\.1 --hash=sha256:([0-9a-f]{64})$", lock, re.M)
    return {
        "commit": head,
        "tree": tree,
        "workflow_sha256": sha(source_file(head, WORKFLOW)),
        "builder_sha256": sha(source_file(head, "scripts/build-product.py")),
        "lock_sha256": sha(lock),
        "dependency_sha256": dep.decode(),
    }


def seal(
    issuer, wheel, sbom, version, sequence, material, now, *, license_text, security, instructions, notes
):
    name = wheel_name(version)
    body = {
        name: wheel,
        "core.cdx.json": sbom,
        "LICENSE": license_text,
        "SECURITY.md": security,
        "platforms.json": encode(PLATFORMS),
        "VERIFY.md": instructions,
        "RELEASE-NOTES.md": notes,
    }
    manifest = {
        "schema": "awooo.release/v1",
        "profile": PROFILE,
        "repository": REPO,
        "version": version,
        "sequence": sequence,
        "commit": material["commit"],
        "tree": material["tree"],
        "files": {n: {"bytes": len(v), "sha256": sha(v)} for n, v in body.items()},
    }
    body["release.json"] = encode(manifest)
    record = {
        **material,
        "sequence": sequence,
        "version": version,
        "manifest_sha256": sha(body["release.json"]),
        "observed_at": now,
        "withdrawn": False,
    }
    body["provenance.json"] = encode(
        statement(record, {n: sha(body[n]) for n in (name, "core.cdx.json", "release.json")})
    )
    body["provenance.p7s"] = issuer.sign(body["provenance.json"])
    record["archived_signature_sha256"] = sha(body["provenance.p7s"])
    return body, record


def toy(issuer, version, seq, now):
    # Small inert wheel for structural qualification. It is never installed.
    material = dict(
        commit=str(seq) * 40,
        tree="a" * 40,
        workflow_sha256="b" * 64,
        builder_sha256="c" * 64,
        lock_sha256="d" * 64,
        dependency_sha256="e" * 64,
    )
    dist = "wolftrap-" + version + ".dist-info/"
    module = b'"""Inert evaluation fixture."""\n'
    build = {
        "schema": "wolftrap.product-build/v1",
        "version": version,
        "commit": material["commit"],
        "tree": material["tree"],
        "members": {"cli.py": sha(module)},
    }
    files = {
        "wolftrap/cli.py": module,
        "wolftrap/data/product-build-v1.json": encode(build),
        dist + "METADATA": ("Metadata-Version: 2.4\nName: wolftrap\nVersion: " + version + "\n").encode(),
        dist + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        dist + "top_level.txt": b"wolftrap\n",
        dist + "entry_points.txt": b"[console_scripts]\nwolftrap = wolftrap.cli:main\n",
        dist + "licenses/LICENSE": b"Apache-2.0\n",
    }
    rows = io.StringIO()
    writer = csv.writer(rows, lineterminator="\n")
    for n, raw in sorted(files.items()):
        writer.writerow(
            [n, "sha256=" + base64.urlsafe_b64encode(bytes.fromhex(sha(raw))).rstrip(b"=").decode(), len(raw)]
        )
    writer.writerow([dist + "RECORD", "", ""])
    files[dist + "RECORD"] = rows.getvalue().encode()
    wheel = pack(files)
    component = {
        "name": "wolftrap",
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": sha(wheel)}],
        "properties": [{"name": "wolftrap:source:" + k, "value": material[k]} for k in ("commit", "tree")],
    }
    sbom = encode({"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": component}})
    return seal(
        issuer,
        wheel,
        sbom,
        version,
        seq,
        material,
        now,
        license_text=b"Apache-2.0\n",
        security=b"Evaluation\n",
        instructions=b"Verify before use.\n",
        notes=b"Fictional evaluation release.\n",
    )
