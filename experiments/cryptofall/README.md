# CRYPTOFALL laboratory preservation

This directory preserves the standalone prototype and the disposable counter experiments. The production package, CLI, plugin and release workflows have no entry points into this directory. Independent-host custody, native WolfAlibi integration and actual human approval remain NOT_RUN. Production is BLOCKED.

The source ancestry preserves the corrected WT-002 candidate, WT-004 durable witness, WT-005 reconciliation, WT-006 target ledger, WT-007 distributed ledger and WT-008 governed view recovery. The original WT-001 ZIP had no Git revision. Its extracted source and archived test transcript are under prototype-v1. A separately labeled WT-003 artifact was unavailable. The private offline archive retains the earlier 49-case WT-002 packet, exact original archives, signed fixture proofs and all checkout states.

The qualification directory contains byte-preserved deterministic results, crash matrices, safety assumptions, bounded-model counterexamples and the independent-host handoff. Its checksum list identifies the complete offline packets. Replaying the live suites generates new disposable keys and proofs. Use the pinned cryptography 50.0.0 backend and the extension digest enforced by verifier.py. Earlier suites also require Linux namespaces, bubblewrap and loopback TCP.

From this directory, the following commands reproduce the prototype and final experiment locally.

```sh
(cd prototype-v1 && python -B -m unittest -v)
out=$(mktemp -d)
python -B resurrection_lab.py "$out"
python -B resurrection_proof.py "$out"
python -B resurrection_mutations.py "$out"
python -B resurrection_model.py
python -B resurrection_model_controls.py
cmp "$out/matrix.json" qualification/008/matrix.json
```

The published history retains the original laboratory dependency manifest for reproducibility. WolfTrap's static source guard flags this manifest for dependency review. The preservation PR carries that open signal.
