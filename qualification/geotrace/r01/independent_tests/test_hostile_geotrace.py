"""Independent, synthetic-only admission and confinement probes for GeoTrace v1.
These tests must not be confused with the 21 preserved upstream baseline tests.
All writes remain in TemporaryDirectory objects. The two `exposure_` probes
record current v1 limitations, not passing integration safeguards.
"""
import copy, json, pathlib, tempfile, unittest, sys
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "wolftrap-api-geotrace-v1" / "src"))
from wolftrap import api_geotrace as wt
class AdditionalGeoTraceProbes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads((Path(__file__).resolve().parents[1] / 'wolftrap-api-geotrace-v1' / 'examples' / 'synthetic-multi-country.json').read_text())
    def sample(self): return copy.deepcopy(self.fixture)
    def test_inert_unknown_processing_region(self):
        x=wt.analyze(self.sample())
        self.assertTrue(all(v['processing_country']['country'] is None for v in x['events']))
        self.assertTrue(all(v['network_path_countries'] is None for v in x['events']))
    def test_normalized_sni_mismatch_fails_attribution(self):
        d=self.sample();d['events'][0]['http_host']='API.BR.TEST.'
        x=wt.analyze(d)['events'][0]
        self.assertIsNone(x['provider_id']); self.assertIn('HOST_SNI_CONFLICT',x['flags'])
    def test_non_global_no_live_geo(self):
        d=self.sample();d['synthetic']=False
        x=wt.analyze(d)['events'][0]
        self.assertIsNone(x['source_egress']['country'])
        self.assertIsNone(x['destination_hop']['country'])
    def test_bad_credential_field_rejected(self):
        d=self.sample(); d['events'][0]['Authorization']='synthetic-example'
        with self.assertRaises(wt.GeoTraceError):wt.analyze(d)
    def test_source_digest_linkable_not_anonymous(self):
        d=self.sample(); x=wt.analyze(d)['events'][0]
        self.assertEqual(x['source_ip_digest'],wt.alias(d['events'][0]['source_ip']))
    def test_unexpected_duplicate_key_input_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'duplicate.json';p.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaises(wt.GeoTraceError):wt.load_document(p)
    def test_exposure_output_inside_source_is_permitted_by_v1(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=pathlib.Path(tmp)/'scanned-repo';src.mkdir()
            input_path=src/'events.json';input_path.write_text(json.dumps(self.sample()))
            output_path=src/'report.json'
            with patch('socket.socket',side_effect=AssertionError('network attempted')):
                wt.scan(input_path,output_path)
            self.assertTrue(output_path.is_file(), 'v1 lacks an outside-source output guard')
    def test_exposure_symlinked_output_parent_is_permitted_by_v1(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=pathlib.Path(tmp);scanned=base/'scanned';scanned.mkdir()
            outside=base/'outside';outside.mkdir()
            (scanned/'out-link').symlink_to(outside,target_is_directory=True)
            inp=scanned/'events.json';inp.write_text(json.dumps(self.sample()))
            with patch('socket.socket',side_effect=AssertionError('network attempted')):
                wt.scan(inp,scanned/'out-link'/'receipt.json')
            self.assertTrue((outside/'receipt.json').is_file(), 'v1 lacks output-parent confinement')
if __name__=='__main__':unittest.main()
