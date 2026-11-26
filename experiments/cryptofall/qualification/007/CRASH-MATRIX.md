# Crash, partition and recovery observations

Each observation matched in the original run and a fresh-key replay from the applied patch. The last column identifies checks that can also be repeated from retained signed proof bytes. Process and network observations require live replay.

| Observation | Expected and observed | Public proof replay |
|---|---|---|
| two reachable voters | `2` | Live experiment |
| unsafe threshold | `UNRESOLVED` | Yes |
| copied ordinary block | `UNRESOLVED` | Yes |
| vote lock survived process death | `locked` | Live experiment |
| compromised A double voted with isolated D | `UNRESOLVED` | Yes |
| relay killed after durable third vote | `-9` | Live experiment |
| no finalized log after third vote | `[]` | Live experiment |
| two new relays recover using client bytes alone | `["COMMITTED", "COMMITTED"]` | Live experiment |
| signed receipt disclosed from surviving locks | `COMMITTED` | Yes |
| read-only recovery left installed logs empty | `[]` | Live experiment |
| two replacement gates recover lost certificate | `["COMMITTED", "COMMITTED"]` | Live experiment |
| three signatures after lost reply | `COMMITTED` | Yes |
| stale replica D | `UNRESOLVED` | Yes |
| D verified and installed majority branch | `COMMITTED` | Yes |
| substituted disclosure evidence | `UNRESOLVED` | Yes |
| delayed duplicate at next height | `UNRESOLVED` | Live experiment |
| one logical increment at all replicas | `[1, 1, 1, 1]` | Live experiment |
| conflicting commitments | `UNRESOLVED` | Yes |
| rollback against retained floor | `UNRESOLVED` | Yes |
| authority substitution | `UNRESOLVED` | Yes |
| revocation wins against outstanding vote | `POLICY` | Live experiment |
| delayed pre-revocation proposal lacks quorum | `UNRESOLVED` | Live experiment |
| old algorithm rejected at new parent | `UNRESOLVED` | Live experiment |
| revocation alone leaves effect unresolved | `UNRESOLVED` | Yes |
| ordered dual-authority cancellation | `NOT_COMMITTED` | Live experiment |
| proved non-commitment | `NOT_COMMITTED` | Yes |
| independently authorized PQ-only recovery | `POLICY` | Live experiment |
| fresh PQ-only effect | `COMMITTED` | Live experiment |
| historical fence and PQ recovery chain | `COMMITTED` | Yes |
| two competing recovery proposals under partition | `["UNRESOLVED", "UNRESOLVED"]` | Live experiment |
| split locks remain blocked after healing | `["UNRESOLVED", "UNRESOLVED"]` | Live experiment |
| competing dual-approved execution identities | `["REPLACE", "UNRESOLVED"]` | Live experiment |
| replaced executor packet rejected | `UNRESOLVED` | Live experiment |
| old key cannot sign for new generation | `UNRESOLVED` | Live experiment |
| winner alone admits fresh increment | `COMMITTED` | Yes |
| historical decision survives later revocation | `COMMITTED` | Yes |
| 31-second hybrid claim denied by all four | `0` | Live experiment |
| no fresh third vote after expiry | `["A", "B"]` | Live experiment |
| one identity repeated under another label | `UNRESOLVED` | Yes |
| all four locks occupied by two exact proposals | `UNRESOLVED` | Live experiment |
| expired claim recovers only already-durable votes | `["A", "B", "C"]` | Live experiment |
| expired exact request has historical proof | `COMMITTED` | Yes |
| changed receipt breaks commitment proof | `UNRESOLVED` | Yes |
| replica killed between writes | `-9` | Live experiment |
| atomic SQL rows between writes | `[0, 0, 0, 0]` | Live experiment |
| reinstalled replica D exact recovery | `COMMITTED` | Yes |
| replica killed after commit | `-9` | Live experiment |
| atomic SQL rows after commit | `[1, 1, 1, 1]` | Live experiment |
| reinstalled replica C exact recovery | `COMMITTED` | Yes |
