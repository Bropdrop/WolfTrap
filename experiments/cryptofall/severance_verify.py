"""Offline decision verifier. Supply the independently retained provisioning pins."""
from pathlib import Path
import json
import sys
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey


def checked(condition):
    if not condition:
        raise ValueError("qualification mismatch")


def signed(pin,role,cert):
    body=cert["body"]
    raw=json.dumps(["WT-CRYPTO-005/v1",role,body],sort_keys=True,separators=(",",":")).encode()
    MLDSA65PublicKey.from_public_bytes(bytes.fromhex(pin)).verify(bytes.fromhex(cert["signature"]),raw)
    return body


def verify(pins_file,certs_file,matrix_file):
    trust=json.loads(Path(pins_file).read_bytes())
    realm,pins=trust["realm"],trust["pins"]
    checked(len(set(pins.values()))==len(pins))
    packet=json.loads(Path(certs_file).read_bytes())
    retained=signed(pins["retainer"],"retainer",packet["retained"])
    statuses=[]
    def votes(entries,op,target,rev):
        for role in ("recovery","witness"):
            checked(signed(pins[role],role,entries[role])==
                    {"action":op,"realm":realm,"revision":rev,"target":target})
    for cert in packet["certificates"]:
        body=signed(pins["anchor"],"anchor",cert)
        ticket=body["ticket"]
        checked(body["realm"]==realm and body["revision"]<=retained["revision"])
        checked({k:v for k,v in body.items() if k not in ("realm","revision")}==retained["terminal"][ticket["token"]])
        if body["status"]=="COMMITTED":
            key=pins["gate"]
            for generation in body["lineage"]:
                votes(generation["votes"],"replace",generation["pin"],generation["revision"])
                key=generation["pin"]
            checked(ticket["generation"]==1+len(body["lineage"]) and key==body["gate_pin"])
            checked(signed(key,"gate-commit",body["proof"])==ticket and retained["journal"].count(ticket)==1)
        else:
            checked(body["status"]=="NOT_COMMITTED" and ticket not in retained["journal"])
            votes(body["votes"],"resolve",ticket["token"],body["fence_revision"]-1)
        statuses.append(body["status"])
    checked(statuses==["NOT_COMMITTED","COMMITTED","COMMITTED"])
    checked(len(retained["journal"])==len(set(retained["used"]))==2 and retained["pending"]["phase"]=="ARMED")
    rows=[json.loads(line) for line in Path(matrix_file).read_text().splitlines()]
    expected=json.loads(Path(__file__).with_name("severance_expected.json").read_bytes())
    checked(rows==expected)
    print("PASS: two positive receipts, one cancellation fence, one unresolved armed loss; crash matrix matched")


if __name__=="__main__":
    verify(*sys.argv[1:])
