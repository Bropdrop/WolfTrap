"""Separate qualification witness using GnuPG/libksba and stdlib subject checks."""
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import zipfile


def check(value, message):
    if not value:
        raise ValueError(message)


def independent_witness(capsule, trust, independently_selected_pin, source, tree, work):
    from hashlib import sha256
    check(sha256(trust["policy.json"]).hexdigest() == independently_selected_pin, "reference policy pin")
    policy = json.loads(trust["policy.json"])
    auth = policy["authority"]
    check(not auth["revoked"] and all(sha256(trust[name]).hexdigest() == auth[key] for name,key in
          (("root.pem","root_sha256"),("signer.pem","signer_sha256"))), "reference certificate pins")
    with zipfile.ZipFile(io.BytesIO(capsule)) as archive:
        signed = archive.read("provenance.json")
        sig = archive.read("provenance.p7s")
        st = json.loads(signed); m = json.loads(archive.read("release.json"))
        check(st["_type"] == "https://in-toto.io/Statement/v1" and st["predicateType"] == "https://slsa.dev/provenance/v1", "reference format")
        params=st["predicate"]["buildDefinition"]["externalParameters"]
        check(params["repositoryId"]=="1436465132" and params["sourceCommit"]==source and params["sourceTree"]==tree
              and params["workflowRevision"]==source and (m["commit"],m["tree"])==(source,tree), "reference source")
        subjects={s["name"]:s["digest"]["sha256"] for s in st["subject"]}
        wheel="wolftrap-"+m["version"]+"-py3-none-any.whl"
        check(set(subjects)=={wheel,"core.cdx.json","release.json"} and len(st["subject"])==3, "reference subjects")
        check(all(sha256(archive.read(n)).hexdigest()==v for n,v in subjects.items()), "reference digests")
        check(all(v=={"bytes":len(archive.read(n)),"sha256":sha256(archive.read(n)).hexdigest()} for n,v in m["files"].items()), "reference inventory")
    home=work/"keyring"; home.mkdir(mode=0o700)
    def selector(pem):
        # GnuPG's local selector. The full SHA-256 certificate pins were checked above.
        return hashlib.sha1(ssl.PEM_cert_to_DER_cert(pem.decode("ascii")), usedforsecurity=False).hexdigest().upper()
    (home/"trustlist.txt").write_text(selector(trust["root.pem"])+" S\n")
    for name,raw in trust.items():
        if name.endswith(".pem"):
            (work/name).write_bytes(raw)
    (work/"statement").write_bytes(signed)
    (work/"signature").write_bytes(sig)
    ctl=["/usr/bin/gpgsm","--no-options","--homedir",str(home),"--batch","--disable-dirmngr","--disable-crl-checks"]
    env={"PATH":os.defpath,"LC_ALL":"C","GNUPGHOME":str(home)}
    def command(args):
        return subprocess.run(ctl+args,cwd=work,env=env,capture_output=True,timeout=20)
    try:
        check(command(["--import","root.pem","signer.pem"]).returncode==0,"reference import")
        def signature():
            return command(["--status-fd","1","--verify","signature","statement"])
        good=signature()
        check(good.returncode==0 and ("VALIDSIG "+selector(trust["signer.pem"])).encode() in good.stdout
              and b"TRUST_FULLY" in good.stdout, "reference signing identity or signature")
        (work/"statement").write_bytes(signed+b"modified")
        check(signature().returncode!=0,"reference accepted changed content")
        return {"implementation":"GnuPG gpgsm / libksba","signature":"VALID","altered_payload":"REJECTED","subjects":len(subjects)}
    finally:
        subprocess.run(["/usr/bin/gpgconf","--homedir",str(home),"--kill","all"],env=env,capture_output=True,timeout=10)
