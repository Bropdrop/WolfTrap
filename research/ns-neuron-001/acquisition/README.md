# Pinned study inputs

The 4,821,036-byte NeuralScope v0.3.0a1 source ZIP matched SHA-256 `392dcc885ac32688d803d841335a29f2e545db9ccb99f86e42841e1c0f77121a`. All 89 entries declared by its bundle inventory matched. Its historical pretrained and attention summaries are excerpts and omit 63 and 48 raw trace files respectively. The release and standalone pilot specify identical DistilGPT2 file hashes and revision. [Release confirmation](release-recovery.json) · [Release inventory](release-bundle-check.json) · [Model pin](distilgpt2-pin.json)

At revision `2290a62682d06624634c1f46a6ad5be0f47f38aa` the seven public snapshot files matched their specified sizes and SHA-256. Every receipt states the revision-specific source URL and actual digest. The safetensors file is 352,824,413 bytes with SHA-256 `e1ff18884359fe8beb795a5f414feb85a6ce3d929ad019c0d958c039d2b94a1b`. [Acquisition receipt](model-attempt-001/summary.json) · [Weight receipt](model-attempt-001/model.safetensors.json)

Run from the research directory. Use a new external work directory. This command explicitly acquires the seven model files. It checks both pin sets, HTTP and TLS results, byte lengths and SHA-256 before promoting the new directory to read-only. The separate measurement process loads this verified directory offline.

```sh
run=${run:-$(mktemp -d)}
python acquisition/acquire_snapshot.py --dest "$run/model" --attempt "$run/model-acquisition"
```

With a copy of the historical source ZIP, verify its exact archive and member digests using `python acquisition/verify_bundle.py path/to/release.zip`.
