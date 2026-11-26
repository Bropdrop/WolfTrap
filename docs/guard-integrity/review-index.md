# Independent review index

Review the MCP and Cursorial integration first, followed by WolfPrint and WolfNet in dependency order. Review CRYPTOFALL separately as opt-in laboratory research. Historical PR heads differ from the prepared integration commits for the first three packets. Approvals are outstanding.

| PR | Review focus | Exact packet commit | Packet SHA-256 |
|---|---|---|---|
| [#16](https://github.com/Bropdrop/WolfTrap/pull/16) | MCP inspection and causal evidence | [`a43099d84d063ccc8f62175f0697eb2b9c641323`](https://github.com/Bropdrop/WolfTrap/commit/a43099d84d063ccc8f62175f0697eb2b9c641323) | `04c28bff9b7c14f3ff1b86a6e7c7f6b2c31a5d21c06dd71a7e1fe18b6a3dfdaa` |
| [#17](https://github.com/Bropdrop/WolfTrap/pull/17) | Fictional identity and scoped delegation | [`f556b0b5bc50bf19e1c491e2d57b077b42cce903`](https://github.com/Bropdrop/WolfTrap/commit/f556b0b5bc50bf19e1c491e2d57b077b42cce903) | `90eefc778158892808b80adc58004023c81656daaf9f24095a7d9bbca118da02` |
| [#22](https://github.com/Bropdrop/WolfTrap/pull/22) | Advisory signatures, checkpoints and subscriber authority | [`1af8b94c52822c05da795aa7d848cace3980ba0f`](https://github.com/Bropdrop/WolfTrap/commit/1af8b94c52822c05da795aa7d848cace3980ba0f) | `af76ba96d9218c5233e47ede1719c7b4fe4cc4b45c30a8d7032fab75cfc8333c` |
| [#39](https://github.com/Bropdrop/WolfTrap/pull/39) | Lab isolation, wheel provenance and guard scope | [`ff8059c1d24018c36e03688539184b65537b7334`](https://github.com/Bropdrop/WolfTrap/commit/ff8059c1d24018c36e03688539184b65537b7334) | `8d5305a539a5c0cc90125a8171b70427c5f087e73565a2da0f4bc03d66ddf384` |

In the offline index archive, unpack review-16.zip, review-17.zip or review-22.zip into separate directories and run python3 verify.py in each. Inspect REVIEW.md, both complete diffs, hosted.json and the hostile controls. Each verifier independently applies both diffs to reconstruct the reviewed tree. For review-39.zip, start with dependency/REVIEW.md and run sha256sum -c SHA256SUMS. Compare requirements.txt with the Git blob and inspect the historical.patch, the publisher-attestation log and the new guard assessments. The included wheels support the documented offline replay.

The original research PR still has two failing hosted checks on its historical head. A separate scanner replay does not supersede them. Record the commit, tree, findings and outstanding conditions before any merge decision.
