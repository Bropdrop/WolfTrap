# WolfTrap API GeoTrace v1 — offline prototype

**Purpose:** attribute observed outbound API metadata to **any country of origin** when the evidence is available, without conflating the source egress network, the API provider's organization, and the destination network endpoint.

This package is a drop-in **experimental module** for the public WolfTrap Python package. It is deliberately **not** a live network scanner and is **not pushed or merged** into `GovernableIntelligence/WolfTrap`. It uses the Python standard library only (Python 3.11+). The example registry and IP data are invented and use RFC 5737 TEST-NET IP ranges and `.test` hostnames.

## Run

```bash
cd wolftrap-api-geotrace-v1
PYTHONPATH=src python -m wolftrap.api_geotrace scan \
  --input examples/synthetic-multi-country.json \
  --output /tmp/wolftrap-api-geotrace-report.json
PYTHONPATH=src python -m wolftrap.api_geotrace verify \
  --input examples/synthetic-multi-country.json \
  --output /tmp/wolftrap-api-geotrace-report.json
python3 -m unittest discover -s tests -v
```

The output path **must not already exist**. The original WolfTrap installation can use the module by copying `src/wolftrap/api_geotrace.py` into its `src/wolftrap/` directory, together with the tests and documentation. It operates as `python -m wolftrap.api_geotrace`, with no change to the existing `wolftrap` CLI yet.

## Attribution vocabulary

| Field | What it means | What it does **not** prove |
|---|---|---|
| `provider_origin.country` | An **offline curated registry claim** about the provider operating organization, with an evidence reference and verification date | Cloud region, customer data residency, threat-actor nationality, ownership/investment jurisdictions |
| `source_egress.country` | An **estimated** country for the IP from which the monitored network flow appeared to originate, using supplied offline CIDR evidence | Physical location or nationality of the end user behind NAT, VPN, corporate network or proxy |
| `destination_hop.country` | An **estimated** country for the observed IP destination hop | Actual AI model processing or storage location, particularly with CDNs/anycast/proxies |
| `processing_country.country` | `null` in v1 | No assertion is made about model inference or data storage residency |
| `network_path_countries` | `null` in v1 | Intermediate transit countries are not reconstructible from a single network flow |

Never infer an API provider's country from a domain's top-level suffix, code comments or a model's language. Never infer a malicious intent from the country alone. Country policy is **opt-in**. The implementation recognizes all 249 ISO 3166-1 alpha-2 codes in its built-in snapshot (including CN, US, CA, FR, BR, JP, ZA, AU, IN and others).

## Data sources required for real telemetry

The module needs a **trusted local normalization step** that extracts the observed source/destination IP, TLS SNI and/or HTTP Host, and optionally DNS query as context, from **authorized telemetry**. It does not parse packets itself, doesn't connect to APIs, and does not read secrets or HTTP bodies. DNS queries alone are reported as `DNS_HINT_ONLY`, not proof of a connection. SNI/Host disagreement produces a conflict and no provider attribution. If HTTPS encrypts SNI (ECH) or the client uses a tunnel, the domain may be unknown; **unknown is a valid result**.

A curated, revision-controlled `providers` registry must map exact domain labels to an operating provider, independently evidenced country and verification date. All country assignments are external evidence assertions and should be reviewed; this package intentionally ships **no asserted real provider-country mappings**.

An offline `geo_ranges` database must provide CIDR -> ISO country, evidence reference and verification date (and optional expiration). Longest-prefix match wins; expired records are ignored. A real implementation could import licensed MaxMind GeoLite2 country or equivalent datasets through a separate offline adapter with appropriate license and freshness controls; this prototype does not download or bundle any such database.

## Safety and limitations

- `synthetic=true` permits TEST-NET ranges in fixtures. `synthetic=false` refuses to geolocate non-global addresses even if the local CIDR registry claims a country.
- The report omits raw IP addresses and hostnames, but **unsalted SHA-256 digests are linkable and potentially reversible by enumeration**. Treat the output as sensitive operational data and restrict retention and distribution.
- The input schema rejects unexpected fields such as `headers`, `api_key`, and `request_body`, blocks duplicate JSON keys, constrains list sizes, and rejects ambiguous provider ownership.
- IP country estimates may be wrong or may describe a VPN/CDN/anycast hop. Check the evidence source and its date. No IP geolocation method proves a person's precise location.
- A permissive policy is not proof that the call was authorized; no authorization or protected effects are checked.
- This code has **21/21 focused local unit tests passing**, but no external sensor/telemetry qualification and no production deployment. Status: **EXPERIMENTAL / NOT LIVE VERIFIED**.

See [docs/api-geotrace.md](docs/api-geotrace.md) for schema details and next integration milestones.
