"""Offline, local-only credential preparation by an individual replica custodian."""
import argparse
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from quorum_node import initialize
from quorum_rules import MEMBERS, hash_of, initial
from resurrection_node import provision
from verifier import require, wire


def main():
    args=argparse.ArgumentParser()
    args.add_argument("action",choices=["generate","initialize"])
    args.add_argument("member",choices=MEMBERS)
    args.add_argument("directory",type=Path)
    args.add_argument("--genesis",type=Path)
    args.add_argument("--pin")
    opt=args.parse_args()
    path=opt.directory.resolve()
    if opt.action=="generate":
        path.mkdir(mode=0o700)
        seed=secrets.token_bytes(32)
        pub=MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw().hex()
        (path/"custody").write_bytes(wire({"member":opt.member,"seed":seed.hex(),
                                          "links":{r:secrets.token_hex(32) for r in ("gate1","gate2")}}))
        print(json.dumps({"member":opt.member,"public_key":pub}))
        return
    require(opt.genesis and opt.pin,"public genesis and separately confirmed pin required")
    cfg=json.loads(opt.genesis.read_bytes())
    keys=json.loads((path/"custody").read_bytes())
    pub=MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(keys["seed"])).public_key().public_bytes_raw().hex()
    require(hash_of(cfg)==opt.pin and keys["member"]==opt.member and cfg["replicas"][opt.member]==pub,"provisioning pin")
    initial(cfg)
    # A fully initialized, fresh slot is published with one local rename.
    destination=path/"active"
    require(not destination.exists(),"volume already exists")
    with tempfile.TemporaryDirectory(dir=path) as temp:
        staging=Path(temp)/"volume"
        staging.mkdir(mode=0o700)
        (staging/"identity").write_bytes(wire(dict(keys,public=cfg)))
        initialize(staging,cfg)
        provision(staging)
        staging.rename(destination)


if __name__=="__main__":
    os.umask(0o077)
    main()
