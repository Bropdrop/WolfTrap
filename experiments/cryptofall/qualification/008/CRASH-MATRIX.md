# WT-008 crash, partition and governance matrix

Each observation matched its frozen expectation both in the original run and after applying the patch to a clean WT-007 checkout. Socket partitions used a loopback endpoint that closed the affected TCP connections. SIGKILL stopped real local processes. A database restore copied a disposable genesis backup over a stopped member’s volume.

| Observation | Expected and observed | Verification |
|---|---|---|
| altered promise rejected | `0` | Live replay |
| alternate chain against retained checkpoint | `UNRESOLVED` | Public decision proof |
| authenticated new-view transcript | `true` | Public view-change signatures |
| competing request still unresolved | `UNRESOLVED` | Live replay |
| concurrent promises never regress | `0` | Live replay |
| conflicting proposal after decision | `0` | Live replay |
| coordinator killed after third commit | `-9` | Live replay |
| delayed historic certificate installed | `installed` | Live replay |
| different views certify same block | `COMMITTED` | Public decision proof |
| duplicate application absent | `1` | Live replay |
| duplicate install | `already installed` | Live replay |
| exact request from durable votes | `COMMITTED` | Public decision proof |
| expiry is insufficient evidence | `UNRESOLVED` | Public decision proof |
| fresh prepares denied after permit expiry | `0` | Live replay |
| highest certificate selects y | `true` | Public view-change signatures |
| highest prepared value survives third view | `COMMITTED` | Public decision proof |
| live permit reached prepared quorum | `3` | Live replay |
| lower prepared view cannot win | `0` | Live replay |
| minority cannot reopen slot | `0` | Live replay |
| minority commit lock superseded by safe quorum | `COMMITTED` | Public decision proof |
| new view same decision idempotent | `already installed` | Live replay |
| no installed copy after coordinator death | `[]` | Live replay |
| old prepare cannot authorize fresh commit | `0` | Live replay |
| old prepared x excluded | `false` | Public view-change signatures |
| one prepare for competing proposals | `1` | Live replay |
| one rolled-back identity cannot certify fork | `1` | Live replay |
| partition only two promises | `2` | Live replay |
| permit expired while claim live | `true` | Live replay |
| permit expires between prepare and commit | `0` | Live replay |
| persistent split | `2` | Live replay |
| policy certificate alone leaves request open | `UNRESOLVED` | Public decision proof |
| prepared certificate alone never discloses a receipt | `UNRESOLVED` | Live replay |
| quarantine decided during recovery | `4` | Live replay |
| quorum without owner authorization | `UNRESOLVED` | Public decision proof |
| replacement selected carried block | `true` | Live replay |
| restarted B retained prepare proof | `true` | Live replay |
| restored A equivocated | `1` | Live replay |
| retry highest promise | `4` | Live replay |
| revoked claim at current parent | `0` | Live replay |
| split healed in new view | `COMMITTED` | Public decision proof |
| stale old-parent commits fenced | `0` | Live replay |
| stale promises cannot enter next view | `false` | Public view-change signatures |
| stateless coordinator recovered carried authorization | `COMMITTED` | Public decision proof |
| substituted recovery input | `UNRESOLVED` | Live replay |
| tampered view transcript | `false` | Public view-change signatures |
| two different prepared views reported | `[0, 1]` | Live replay |
| two incompatible valid histories | `UNRESOLVED` | Public decision proof |
| two promises insufficient | `false` | Public view-change signatures |
| two replacement coordinators | `["COMMITTED", "COMMITTED"]` | Live replay |
| two signatures | `UNRESOLVED` | Public decision proof |
