# Independent bounded model and interpretation

The finite model explores one uncommitted height at a fixed certified parent. There are four identities, two different valid payloads and four voting views numbered 0 through 3. A certificate needs three signatures. Identity D can equivocate, lie about its local observations and withhold evidence. A Byzantine report claiming to carry a prepared value must still supply an obtainable prepare certificate. Fixing the faulty identity is without loss of generality because the members have identical consensus privileges. Taking D to be maximally cooperative with either conflicting value covers its ability to withhold or send fewer votes for safety purposes.

An exploration state is the latest commit-voted preparation of each honest member, the set of obtainable prepared certificates from earlier views, and any possibly decided value. A signed integer encodes the block and view of each preparation. Zero is an absent lock. For each round the explorer enumerates every subset of three or four reporters and every admissible Byzantine report. Each honest prepare signer may see a different report set and may omit its vote. For every obtainable prepare certificate, every subset of honest commit voters is explored. Two honest signers and the Byzantine identity are sufficient for a possible decision. Assuming the Byzantine signer supplies its signature whenever it could creates a stronger agreement check. Possible decisions do not restrict later vote choices.

The model groups asynchronous actions by view. An honest participant cannot vote in a lower view after promising a higher one. A delayed signature produced earlier stays available. Honest report inclusion is determined by the last earlier commit vote, even if a coordinator never observed it. Independent choices of report sets over-approximate coordination and message delivery. Restart of an honest participant is a stuttering step. Loss of its durable lock uses the single faulty identity budget. The model stores candidate certificates even if they have not yet reached a coordinator and allows missing payloads to result in no prepare. It merges only states identical in all recorded fields. There is no random schedule sampler or implementation-network import.

| View | Entering states | Honest prepare assignments | Explored transitions | Distinct successor states |
|---|---:|---:|---:|---:|
| 0 | 1 | 27 | 125 | 17 |
| 1 | 17 | 307 | 1,413 | 139 |
| 2 | 139 | 2,195 | 10,077 | 827 |
| 3 | 827 | 12,715 | 58,341 | 4,183 |

**69,956 transitions produced zero conflicting within-view prepare certificates and zero conflicting decisions.** Of the 4,183 final states, 2,313 remained undecided. These counts describe a finite abstract state space. They are neither probabilities nor measurements of recovery time.

Two weakened models produced counterexamples. Ignoring a carried lock allowed a negative-value decision in view zero and a positive-value decision in view one. Lowering the prepare threshold to two allowed honest signers to split between opposite values and the faulty identity to complete both certificates in view zero. Exact encoded witnesses are in model-controls.json.

The model covers agreement. The intersection and induction argument in the pre-implementation specification explains the intended extension to further views and ledger prefixes. It is a pen-and-paper argument. Only the stated finite bounds were machine-checked. Cryptography, application ownership, permit deadlines, serialization, transport authenticity, actual disk persistence and human governance are outside the abstract transition system. Their applicable local tests and exclusions are recorded separately.
