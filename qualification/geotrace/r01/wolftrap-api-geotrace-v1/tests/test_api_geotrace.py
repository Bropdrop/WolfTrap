"""Offline qualification for WolfTrap API GeoTrace, no network and no credentials."""

import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from wolftrap import api_geotrace as wt


class GeoTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / "examples" / "synthetic-multi-country.json").read_text())

    def fixture_copy(self):
        return copy.deepcopy(self.fixture)

    def test_arbitrary_countries_independent_fields(self):
        report = wt.analyze(self.fixture_copy())
        event = report["events"][0]
        self.assertEqual(event["source_egress"]["country"], "CA")
        self.assertEqual(event["provider_origin"]["country"], "FR")
        self.assertEqual(event["destination_hop"]["country"], "US")
        self.assertIsNone(event["processing_country"]["country"])
        self.assertFalse(event["malicious_attribution"])
        self.assertFalse(report["network_contacted"])

    def test_detect_china_only_as_independent_provider_jurisdiction(self):
        report = wt.analyze(self.fixture_copy())
        event = report["events"][1]
        self.assertEqual(event["provider_origin"]["country"], "CN")
        self.assertEqual(event["source_egress"]["country"], "JP")
        self.assertEqual(event["destination_hop"]["country"], "US")
        self.assertIn("PROVIDER_COUNTRY_OUTSIDE_POLICY", event["flags"])
        self.assertIn("DESTINATION_IS_INTERMEDIARY_NOT_FINAL_API_REGION", event["flags"])
        self.assertIn("SOURCE_IS_INTERMEDIARY_NOT_CLIENT_ORIGIN", event["flags"])
        self.assertFalse(event["malicious_attribution"])

    def test_unknown_provider_not_mislabeled_by_network_country(self):
        event = wt.analyze(self.fixture_copy())["events"][3]
        self.assertIsNone(event["provider_origin"]["country"])
        self.assertEqual(event["source_egress"]["country"], "CA")
        self.assertEqual(event["destination_hop"]["country"], "US")
        self.assertIn("UNATTRIBUTED_PROVIDER", event["flags"])
        self.assertEqual(event["policy_status"], "REVIEW_REQUIRED")

    def test_suffix_spoofing_cannot_attrib_provider(self):
        d = self.fixture_copy()
        d["events"][0]["tls_sni"] = "api.fr.test.attacker.invalid"
        x = wt.analyze(d)["events"][0]
        self.assertIsNone(x["provider_id"])
        self.assertIn("UNATTRIBUTED_PROVIDER", x["flags"])

    def test_subdomain_of_registered_provider_attributed(self):
        d = self.fixture_copy()
        d["events"][0]["tls_sni"] = "v1.api.fr.test"
        self.assertEqual(wt.analyze(d)["events"][0]["provider_id"], "example-fr")

    def test_dns_hint_is_not_attributed(self):
        d = self.fixture_copy()
        d["events"][0].pop("tls_sni")
        d["events"][0]["dns_qname"] = "api.fr.test"
        x = wt.analyze(d)["events"][0]
        self.assertIsNone(x["provider_id"])
        self.assertIn("DNS_HINT_ONLY", x["flags"])

    def test_tls_sni_http_host_conflict_cannot_attrib(self):
        d = self.fixture_copy()
        d["events"][0]["http_host"] = "api.br.test"
        x = wt.analyze(d)["events"][0]
        self.assertEqual(x["host_observation"], "CONFLICTING_NETWORK_HOSTS")
        self.assertIsNone(x["provider_id"])
        self.assertIn("HOST_SNI_CONFLICT", x["flags"])

    def test_cidr_longest_prefix_wins(self):
        d = self.fixture_copy()
        d["geo_ranges"].append({
            "network": "192.0.2.0/25", "country": "ZA",
            "evidence_ref": "synthetic-more-specific-za", "verified_on": "2026-11-22"
        })
        self.assertEqual(wt.analyze(d)["events"][0]["source_egress"]["country"], "ZA")

    def test_expired_geo_evidence_yields_unknown(self):
        d = self.fixture_copy()
        d["geo_ranges"][0]["verified_on"] = "2026-08-01"
        d["geo_ranges"][0]["valid_until"] = "2026-11-21"
        x = wt.analyze(d)["events"][0]
        self.assertIsNone(x["source_egress"]["country"])
        self.assertIn("UNKNOWN_SOURCE_EGRESS_COUNTRY", x["flags"])

    def test_non_global_addresses_cannot_be_geolocated_as_live(self):
        d = self.fixture_copy()
        d["synthetic"] = False
        x = wt.analyze(d)["events"][0]
        self.assertIsNone(x["source_egress"]["country"])
        self.assertEqual(x["source_egress"]["basis"], "NON_GLOBAL_ADDRESS_NOT_GEOLOCATABLE")
        self.assertIsNone(x["destination_hop"]["country"])

    def test_any_country_code_accepted_without_jurisdiction_blacklist(self):
        for code in ("AU", "IN", "ZA", "SG", "KR", "GB", "IL", "DE", "BR", "CA", "US", "CN", "FR"):
            with self.subTest(code=code):
                d = self.fixture_copy()
                d["providers"][0]["origin_country"] = code
                x = wt.analyze(d)["events"][0]
                self.assertEqual(x["provider_origin"]["country"], code)
                self.assertFalse(x["malicious_attribution"])

    def test_invalid_country_code_rejected(self):
        d = self.fixture_copy()
        d["providers"][0]["origin_country"] = "ZZ"
        with self.assertRaises(wt.GeoTraceError):
            wt.analyze(d)

    def test_overlapping_provider_domain_ownership_rejected(self):
        d = self.fixture_copy()
        d["providers"][1]["domains"] = ["fr.test"]
        with self.assertRaises(wt.GeoTraceError):
            wt.analyze(d)

    def test_duplicate_geo_cidr_rejected(self):
        d = self.fixture_copy()
        d["geo_ranges"].append(copy.deepcopy(d["geo_ranges"][0]))
        with self.assertRaises(wt.GeoTraceError):
            wt.analyze(d)

    def test_raw_credentials_or_header_payload_rejected(self):
        for value in ({"headers": {"Authorization": "Bearer secret"}},
                      {"request_body": "secret"}, {"api_key": "secret"}):
            with self.subTest(value=value):
                d = self.fixture_copy()
                d["events"][0].update(value)
                with self.assertRaises(wt.GeoTraceError):
                    wt.analyze(d)

    def test_deny_url_and_not_confuse_host_with_tld(self):
        for value in ("https://api.fr.test/v1", "api.fr.test/path", "api.fr.test@evil.test", "api.fr.test:443"):
            with self.subTest(value=value):
                d = self.fixture_copy()
                d["events"][0]["tls_sni"] = value
                with self.assertRaises(wt.GeoTraceError):
                    wt.analyze(d)

    def test_no_raw_ips_in_report(self):
        output = json.dumps(wt.analyze(self.fixture_copy()))
        for value in ("192.0.2.10", "198.51.100.45", "203.0.113.44", "api.fr.test"):
            self.assertNotIn(value, output)
        self.assertIn("sha256:", output)

    def test_disabled_unknown_review_does_not_make_a_country_claim(self):
        d = self.fixture_copy()
        d["policy"].pop("allowed_provider_countries")
        d["policy"]["review_unknowns"] = False
        event = wt.analyze(d)["events"][3]
        self.assertIsNone(event["provider_origin"]["country"])
        self.assertEqual(event["policy_status"], "ADVISORY_ONLY")

    def test_scan_verify_and_mutations_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source, report = root / "events.json", root / "report.json"
            source.write_text(json.dumps(self.fixture_copy()))
            with patch("socket.socket", side_effect=AssertionError("network attempted")):
                outcome = wt.scan(source, report)
                self.assertEqual(outcome["summary"]["events"], 4)
                self.assertTrue(wt.verify(source, report))
                with self.assertRaises(wt.GeoTraceError):
                    wt.scan(source, report)
                source.write_text(json.dumps(self.fixture_copy()).replace("api.fr.test", "api.unknown.test"))
                self.assertFalse(wt.verify(source, report))
                source.write_text(json.dumps(self.fixture_copy()))
                saved = json.loads(report.read_text())
                saved["summary"]["events"] = 999
                report.write_text(json.dumps(saved))
                self.assertFalse(wt.verify(source, report))

    def test_parse_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "bad.json"
            path.write_text('{"schema": "a", "schema": "b"}')
            with self.assertRaises(wt.GeoTraceError):
                wt.load_document(path)

    def test_malformed_input_and_missing_source_do_not_succeed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            f = root / "input.json"
            f.write_text('{"schema":"invalid"}')
            self.assertEqual(wt.main(["scan", "--input", str(f), "--output", str(root / "out.json")]), 2)
            self.assertFalse((root / "out.json").exists())
            self.assertEqual(wt.main(["scan", "--input", str(root / "missing.json"), "--output", str(root / "out.json")]), 2)


if __name__ == "__main__":
    unittest.main()
