# WT-API-GEO-001 — Evidence-based country attribution for all API providers

## Threat model

The purpose is to catch **unexpected jurisdiction exposure, geography mismatches and unrecognized API endpoints** in an authorized organization's outbound AI-agent/API traffic. The tool neither labels countries as hostile nor asserts that a particular IP geolocation is factual ground truth. Real controls must be based on an owner-defined authorization/policy context, not on nationality.

### Normalize first; scan second

External data may originate from Zeek `conn.log` and `ssl.log` (when SNI exists), DNS logs, proxy/firewall logs or cloud flow logs, but a separate trusted collector must parse and normalize those sources. The v1 scanner consumes already normalized JSON and never reaches the internet. It rejects arbitrary payloads/headers to avoid credentials and customer content entering evidence.

**Input** `wolftrap.api-geotrace-input/v1`:

```json
{
  "schema": "wolftrap.api-geotrace-input/v1",
  "snapshot_date": "2026-11-22",
  "synthetic": true,
  "providers": [{
    "id": "example-fr", "name": "Synthetic France Provider",
    "origin_country": "FR", "domains": ["api.fr.test"],
    "evidence_ref": "reviewed-registry-revision", "verified_on": "2026-11-22"
  }],
  "geo_ranges": [{
    "network": "192.0.2.0/24", "country": "CA",
    "evidence_ref": "test-geo-ca", "verified_on": "2026-11-22",
    "valid_until": "2027-01-01"
  }],
  "events": [{
    "id": "event-1", "source_ip": "192.0.2.10",
    "destination_ip": "198.51.100.45", "tls_sni": "api.fr.test",
    "source_role": "client_egress", "destination_role": "api_endpoint"
  }],
  "policy": {
    "allowed_provider_countries": ["CA", "FR", "US"],
    "allowed_source_countries": ["CA"],
    "allowed_destination_countries": ["US", "CA"],
    "review_unknowns": true
  }
}
```

In examples with non-global reserved test IPs, set `synthetic=true`. With `synthetic=false`, non-global addresses are **not** geolocatable. A provider catalogue is deliberately supplied rather than baked into the code: a CN, CA, US, FR, BR, JP, ZA or other supported country is simply a field with independent evidence.

### Interpretation and severity

- `PROVIDER_COUNTRY_OUTSIDE_POLICY`: registry-identified API provider country was not in the caller's **configured** jurisdiction list. Not an attack verdict.
- `SOURCE_EGRESS_COUNTRY_OUTSIDE_POLICY`: network egress IP's **estimated** country not allowed by owner policy. Does not prove the user's actual location.
- `DESTINATION_HOP_COUNTRY_OUTSIDE_POLICY`: destination hop IP estimate outside policy. Proxy/CDN hop caveats apply.
- `HOST_SNI_CONFLICT`: SNI and Host disagree, so **no provider is selected**.
- `DNS_HINT_ONLY`: a DNS lookup alone does not establish an API call.
- `UNATTRIBUTED_PROVIDER`: observed hostname does not match the curated registry. No nationality inferred.
- `UNKNOWN_*`: missing current geo evidence; never convert to a clean allowlist match.
- `SOURCE_IS_INTERMEDIARY_NOT_CLIENT_ORIGIN`, `DESTINATION_IS_INTERMEDIARY_NOT_FINAL_API_REGION`: intermediary warning.

The output **always** labels itself `NOT_A_SECURITY_CERTIFICATION`, records its input SHA-256, provides source evidence references for each classified country, and omits raw network identifiers. Verification replays the same input against the current implementation and compares the full report structure. A successful verification means integrity/reproducibility, not truth of the underlying provider/GeoIP facts.

### Regression controls

21 local tests cover: universal country handling, differing provider/egress/destination countries, Chinese-provider policy, DNS-only evidence, suffix spoofing, subdomain matching, mismatched SNI and Host, longest-prefix geo lookup, expired geo source, non-global live IP refusal, invalid ISO code rejection, overlapping provider domain conflicts, duplicate CIDR denial, forbidden secrets and HTTP bodies, URL/hostname parsing, redacted reports, policy off/on, no live socket calls, source/report tampering, duplicate JSON keys and malformed sources.

### Integration sequence

1. Add a small, locally curated **real provider endpoint registry** with official source references and a named date/revision; update it separately from the scanner.
2. Build an **offline GeoIP importer** (and metadata for the DB release, license and confidence), independent of the provider registry.
3. Add read-only, opted-in **Zeek/proxy/DNS normalization** for owned networks, with careful provenance and authorized scopes.
4. Extend WolfTrap's top-level `wolftrap` CLI with `scan-api-geo` and `verify-api-geo` only after contract review. The drop-in `python -m wolftrap.api_geotrace` command works already.
5. Test on redacted, authorized telemetry with benign control traffic and proxy/CDN/ECH cases, and record false positives / false negatives. Do not declare `LIVE VERIFIED` from synthetic tests.
6. For enforcement, require an independent Ground Truth-style policy authority and owner review. This module is advisory only.

This is a standalone experimental prototype, **not a pushed WolfTrap PR**.
