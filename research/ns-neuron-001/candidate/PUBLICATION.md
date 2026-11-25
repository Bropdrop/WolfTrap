# Publication copies of the source trees

The candidate contains the qualified source and tests for version `0.3.0a1+ns.neuron.1`. The recovered tree contains the source and tests from `0.3.0a1`. In each tree, three historical output-directory fields now show the original run basename. This changes two JSON files per tree. All other files match their corresponding private source trees byte for byte, including the protocols, test code, toy traces and constructed fixture weights. [Field-level changes and SHA-256 digests](publication-delta.json)

The recovered tree's `bundle-inventory.json` and the candidate's `historical/v0.3.0a1-bundle-inventory.json` retain the original receipt for the recovered archive. Entries for the two edited JSON files identify their original bytes. The separately preserved [candidate review inventory](qualified-review-inventory.json) identifies the 96 private candidate source files before redaction. The candidate builder added this receipt as the 97th archive member. Archive digests in the source documentation identify the original containers. The publication checksum list covers the actual 186 files in the two public source trees. Run the following command from the NS-NEURON-001 research directory. [Publication file hashes](source-trees.SHA256SUMS)

```sh
sha256sum -c candidate/source-trees.SHA256SUMS
```
