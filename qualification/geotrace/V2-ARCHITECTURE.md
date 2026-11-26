# GeoTrace v2 integration design

**Decision: BLOCKED pending recovery of the original v1 archive and reproduction of its reported 21-test baseline.** R00 is an offline inventory tool. Its output can identify the exact bytes reviewed for recovery. Only a separate custody decision can approve those bytes for baseline execution.

## Proposed evidence contract

The host selects local input handles, a trusted versioned ISO 3166-1 reference, an evaluation time and an approved jurisdiction policy before analysis. Keep each observation as a separately sourced record with subject, observation type, acquisition method, source digest, time of observation, validity interval, uncertainty and applicable issuer evidence. Bind the records to a single task and workload session. Preserve unnormalized input for audit in a separately authorized local capture. Export only the fictional or sanitized fields approved for reporting.

| Question | Proposed independent evidence | Missing or conflicting evidence |
|---|---|---|
| Who controls the operation? | Authenticated principal and tenant, with current issuer and session binding | Unknown/conflicting principal. Geography supplies no fallback identity |
| Which workload proposed it? | Independently reviewed workload identity and evidence of the active session | Keep operator and workload classifications separate |
| Where did it execute? | Time-bounded host observation of execution environment and reported region | Keep execution region unknown when only an egress observation exists |
| Where did traffic exit? | Explicit, local, versioned network observation with uncertainty and collection time | Record VPN, cloud, relay and proxy ambiguity. Multiple exits remain distinct |
| Which provider and intermediaries participated? | Provider identity plus ordered, source-attributed hops | Preserve gaps and disagreement between providers |
| What was the destination? | Exact resource, recipient and separately supported destination observation | Destination substitution invalidates the prepared decision |
| Which policy applies? | Independently selected policy digest, generation, country reference and evaluation time | Missing, stale or contradictory required inputs yield INCONCLUSIVE |
| Is the effect authorized? | Host checks the current owner grant, principal, task, resource, destination and effect digest immediately before commit | Geographic eligibility can constrain an existing authorization. It cannot create one |

## Integration sequence

1. Inventory the original ZIP inertly outside the repository. Retain its exact bytes, independently selected pin if available, custody history and redistribution review. Inspect the actual dependency and test inventory before any execution.
2. Reproduce the original baseline offline from fresh state. Record discovered, run, passed, failed and skipped counts. Check the 249-country reference against a separately selected, versioned reference. Preserve discrepancies without changing the historical record.
3. Derive v2 input and output schemas from those recovered contracts. Use separate channels for policy, issuer, runtime, egress and destination. A signature can authenticate a location statement; the observed geography still needs corroboration. WolfPrint, WolfAlibi and Ground Truth remain optional blocked integrations until their exact interfaces qualify.
4. Use deterministic fictional captures for misleading IP, VPN exit substitution, mismatched cloud region, multi-hop paths, disagreeing providers, expired/invalid or absent data, stale records, provider/workload substitution, cross-border grants, changed destinations and conflicting witnesses. Pair each prohibited case with an authorized control. A separately authored oracle should compare normalized observations, policy decisions and independent effect-ledger deltas.
5. Run single-control mutations for freshness, provenance, conflict handling, egress-to-origin inference and destination binding. Require fresh restoration and a separate evidence reread. An unqueryable effect stays HOLD. These v2 mutations are UNEXECUTED.
6. Qualify the proposed read-only scan-geotrace and verify-geotrace entry points against the pinned engine, strict local scopes and outside-tree evidence. Only then add them to plugin discovery, packaging and compatibility tests. The current release gate and plugin catalog stay at the decisions recorded in PR #29.

Source pins, reports and independent verification must travel together at each stage. R00 produces no geographic finding, runtime policy grant or release approval.
