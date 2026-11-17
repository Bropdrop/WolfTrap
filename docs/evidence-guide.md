# Evidence guide

Treat a status as a claim about a specific revision, input and bound. Record status alongside the experiment or observation to which it applies.

| Status | Evidence required |
| --- | --- |
| `SYNTHETICALLY VERIFIED` | A bounded authored case ran, met its independent expectations, passed the required controls, and replay reproduced the relevant evidence. |
| `STATIC REVIEW SIGNAL` | A supported input matched a documented conditional review rule. Review the configuration and its effective authority separately. |
| `LIVE VERIFIED` | A named, explicitly authorized genuine implementation was exercised in its documented environment, with independent evidence of the observed behavior. State the exact scope. |
| `INCONCLUSIVE` | An attempted evaluation had insufficient evidence, unsupported input, unstable source, unknown state or an integrity failure. Preserve the reason. |
| `NOT TESTED` | The relevant environment, behavior or input was outside the exercised scope. |

A scanner's `NO_PATTERN_MATCH` means that no supported rule matched the inspected inputs. A synthetic `CONFIRMED` finding requires reproduction of a specific invariant violation in the model. Neither result supports certification, live intrusion detection or prevention. A review signal can arise from harmless automation. Synthetic misses show concrete gaps in rule coverage. They do not estimate rates on production traffic.

## Record exact scope

For each evaluation, retain the repository commit, tree and dirty state, the report and manifest schemas, OS and Python version, applicable dependency versions, the run and verification commands, and network isolation method. Keep source provenance separate from the case input and from the observed effect records. Some command reports include a source revision directly. When the format lacks environment or revision fields, capture them alongside the output at run time and mark any missing information.

A complete case should make the expected outcome, what the system returned, what the effect ledger independently showed, and the oracle verdict separately inspectable. If a suite writes only summarized outcomes, consult its bound case corpus and replay commands before using the aggregate to support a claim.

The fixed cloud-authority suite crosses 160 traces with 12 authority conditions for 1,920 synthetic checks. The authority funnel's 3,019 synthetic proposals come from 20 authored cases. These units count inputs and assertions under authored conditions. They do not count real intrusions or unique techniques.

## Verify and share

1. Check out the recorded commit and verify the recorded tree. Use a clean checkout for qualification.
2. Check that each manifest is complete and use the suite-specific verifier against the listed artifacts. For external sanitized inputs, retain the exact input in its authorized environment and follow the scanner's replay instructions.
3. Run the same challenge into a fresh directory. Compare the outcome and review the positive controls, negative controls, known misses and any unsupported cases.
4. Treat overwritten, incomplete, unexpected or symlinked evidence as untrusted. A matching unkeyed hash shows byte integrity relative to that manifest. Obtain the expected hashes or source revision through a trusted channel to establish provenance.
5. Review any proposed external evidence for private source, tenant data, identifiers, paths, credentials and configuration. Publish only authorized material. Keep environment notes about private systems with their custodian.

See the [offline demo](evaluation-demo.md), [research lifecycle terms](research-status.md), [technique mapping](threat-mapping.md) and [disclosure process](../SECURITY.md).
