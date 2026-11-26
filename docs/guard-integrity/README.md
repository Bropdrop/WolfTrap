# Public guard qualification

This candidate changes the static guard and its qualification material on the main lineage. It assesses historical source through Git object IDs. The target supplies data only. The default scan continues to report the historical CRYPTOFALL dependency manifest.

## Contact findings

The original scanner saw an address-shaped substring in one GeoTrace rejection case and in two Python repository-origin checks. The corrected scanner identifies the quoted literal by its Python syntax, repository-relative path, tuple values, variable and comparison operator or test loop. Only the source span of the address-shaped token receives the reviewed interpretation. Another occurrence on the same line, in another file or in a report receives full screening. The credential scanner still examines the complete source. The three minimal fixtures and six exact candidate scans are recorded in [the replay evidence](evidence/replay.json).

## Opt-in historical laboratory assessment

`--cryptofall-lab-evidence DIR` selects a read-only policy for the reviewed research tree, the exact historical manifest bytes and the reviewed CPython 3.12 Linux x86-64 wheel selection. The scanner independently pins the entire Git tree, the manifest SHA-256 and both evidence-file digests. It enables workflow dependency screening. A different product tree, lab tree, manifest, lock or publication record fails the assessment. The CLI reports its active policy. A favorable result grants no install, execution, merge or production authority.

The attestation from PyPI was independently verified during WT-CONSOLIDATION-002 against the pyca/cryptography GitHub publisher. The guard checks continuity of those exact evidence bytes. Wheel selection and distribution integrity for cffi and pycparser are based on PyPI digests. Publisher authentication was established only for cryptography. The external review packet preserves the historical manifest and offline wheel inputs. [Platform lock](evidence/proposed-cp312-linux-x86_64.lock) · [Publication attestation](evidence/cryptography-provenance.json)

## Independent replay

Use Python 3.12, the repository's pinned qualification YAML parser and a clean Git repository retaining main and research/consolidation-pr-31 through pr-36 and research/cryptofall-v1. Run from this candidate's checkout. The separate Git database supplies historical objects. The mutation driver uses disposable copies of the guard. Its baseline must pass, and a mutant counts as detected only when the test suite reports an assertion failure.

```sh
PYTHONPATH=src python -B -m unittest discover -s tests
python -B scripts/qualify-guard-integrity.py
python -B scripts/replay-guard-integrity.py /path/to/WolfTrap
PYTHONPATH=src python -B -m wolftrap.public_guard --repo /path/to/WolfTrap ff8059c1d24018c36e03688539184b65537b7334 --cryptofall-lab-evidence docs/guard-integrity/evidence
```

[Mutation results](evidence/mutations.json) · [Protected-runtime runner handoff](runner.md)
