# Pretrained CPU dependencies

The reference ran on Linux x86-64 with Python 3.12.14, Torch 2.15.0+cpu and Transformers 5.24.0. All 39 installed distributions matched the version lock from NeuralScope v0.3.0a1. The public receipts include official wheel URLs, lengths and SHA-256. The historical version lock recorded package versions. The hashes identify the wheel artifacts used in this reproduction. [Version lock](reference/version-lock.txt) · [Wheel receipts](reference/wheel-receipts.json) · [Observed versions](runtime-check.json)

Run in the research directory. Set `run` to an absolute directory outside the checkout. The first command deliberately fetches the 39 exact wheels. Installation and verification consume local inputs. Use Python 3.12.14 as `python`.

```sh
run=${run:-$(mktemp -d)}
python dependencies/acquire.py pretrained "$run/wheelhouse-reference"
python offline/offline_exec.py -- sh dependencies/install_offline.sh "$run/wheelhouse-reference" "$run/venv"
python offline/offline_exec.py -- "$run/venv/bin/python" -B dependencies/verify_installed.py dependencies/reference/version-lock.txt
```

An initial download with four top-level pins produced five differences in its resolved package list. Only the fully pinned reference wheelhouse populated the qualification environment. The import receipts retain implementation hashes, and the difference list records that earlier acquisition. [Implementation hashes](implementation-receipts.json) · [Acquisition differences](acquisition-differences.json)
