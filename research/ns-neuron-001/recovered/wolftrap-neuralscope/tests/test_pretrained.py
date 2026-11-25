"""Offline tests for pinned acquisition, strict identity, and legacy buffers."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import numpy as np

from neuralscope import pretrained as p


class Response(io.BytesIO):
    def __init__(self, data, *, headers=None, status=200, url="https://huggingface.co/test"):
        super().__init__(data)
        self.headers = {} if headers is None else headers
        self.status, self.url = status, url

    def geturl(self):
        return self.url


class PretrainedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture_pin(self):
        pin = copy.deepcopy(p.PIN)
        data = {name: ("pinned " + name).encode() for name in pin["files"]}
        pin["files"] = {
            name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest(),
                   "git_blob_sha1": "a" * 40}
            for name, value in data.items()
        }
        return pin, data

    def populate(self, directory, data):
        directory.mkdir()
        for name, value in data.items():
            (directory / name).write_bytes(value)

    def test_packaged_pin_matches_constants(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "distilgpt2-pin.json"
        self.assertEqual(p.load_pin(path), p.PIN)
        first = p.load_pin()
        first["files"]["config.json"]["bytes"] = 0
        self.assertNotEqual(first, p.load_pin())

    def test_modified_pin_is_rejected(self):
        path = self.root / "pin.json"
        altered = p.load_pin()
        altered["revision"] = "f" * 40
        path.write_text(json.dumps(altered))
        with self.assertRaises(ValueError):
            p.load_pin(path)
        with self.assertRaises(ValueError):
            p.verify_model(self.root, pin=altered)

    def test_network_requires_explicit_true_without_creating_directory(self):
        destination = self.root / "model"
        for value in (False, None, 1, "true"):
            with self.subTest(value=value), patch.object(p.urllib.request, "build_opener") as opened:
                with self.assertRaises(ValueError):
                    p.fetch_model(destination, allow_network=value)
                opened.assert_not_called()
                self.assertFalse(destination.exists())

    def test_url_and_redirect_allowlist_rejects_before_request(self):
        rejected = ["http://huggingface.co/x", "https://huggingface.co.attacker.example/x",
                    "https://attacker.example/x", "https://user:pass@huggingface.co/x",
                    "https://huggingface.co:444/x", "https://huggingface.co/x#fragment"]
        handler = p._PinnedRedirect()
        req = p.urllib.request.Request("https://huggingface.co/test")
        for url in rejected:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    p._https_url(url)
                with self.assertRaises(ValueError):
                    handler.redirect_request(req, None, 302, "redirect", {}, url)
        self.assertEqual(p._https_url("https://us.aws.cdn.hf.co/x?signature=example"),
                         "https://us.aws.cdn.hf.co/x?signature=example")

    def test_unknown_asset_cannot_construct_download(self):
        for name in ("../../config.json", "model.py", "pytorch_model.bin"):
            with self.assertRaises(ValueError):
                p._asset_url(name)

    def test_valid_stream_is_installed_after_digest_match(self):
        data = b"validated numeric bytes"
        expected = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        opener = Mock()
        opener.open.return_value = Response(data, headers={"Content-Length": str(len(data))})
        out = self.root / "asset"
        p._download_file(opener, "https://huggingface.co/test", out, expected, 20)
        self.assertEqual(out.read_bytes(), data)
        self.assertEqual(list(self.root.iterdir()), [out])
        self.assertEqual(out.stat().st_nlink, 1)
        request = opener.open.call_args.args[0]
        self.assertNotIn("Authorization", request.headers)
        self.assertNotIn("Cookie", request.headers)

    def test_wrong_hash_short_long_and_partial_responses_leave_no_file(self):
        data = b"expected"
        expected = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        variants = [(b"EXPected", {}, 200), (b"short", {}, 200),
                    (b"too much data", {}, 200), (data, {}, 206),
                    (data, {"Content-Length": "999"}, 200),
                    (data, {"Content-Encoding": "gzip"}, 200)]
        for payload, headers, status in variants:
            with self.subTest(payload=payload, headers=headers, status=status):
                opener = Mock()
                opener.open.return_value = Response(payload, headers=headers, status=status)
                with self.assertRaises(ValueError):
                    p._download_file(opener, "https://huggingface.co/test", self.root / "asset", expected, 20)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_download_refuses_existing_destination(self):
        out = self.root / "asset"
        out.write_bytes(b"original")
        opener = Mock()
        with self.assertRaises(ValueError):
            p._download_file(opener, "https://huggingface.co/test", out, {}, 20)
        opener.open.assert_not_called()
        self.assertEqual(out.read_bytes(), b"original")

    def test_offline_verifier_checks_inventory_and_all_bytes(self):
        pin, data = self.fixture_pin()
        out = self.root / "model"
        self.populate(out, data)
        with patch.object(p, "PIN", pin), patch.object(p.urllib.request, "build_opener") as opened:
            self.assertEqual(p.verify_model(out)["status"], "PINNED_MODEL_MATCH")
            opened.assert_not_called()
            (out / "model.py").write_text("unwanted")
            with self.assertRaises(ValueError):
                p.verify_model(out)
            (out / "model.py").unlink()
            (out / "config.json").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                p.verify_model(out)

    def test_symlink_model_and_file_are_rejected(self):
        pin, data = self.fixture_pin()
        out = self.root / "model"
        self.populate(out, data)
        with patch.object(p, "PIN", pin):
            link = self.root / "alias"
            link.symlink_to(out, target_is_directory=True)
            with self.assertRaises(ValueError):
                p.verify_model(link)
            (out / "config.json").unlink()
            (self.root / "config").write_bytes(data["config.json"])
            (out / "config.json").symlink_to(self.root / "config")
            with self.assertRaises((OSError, ValueError)):
                p.verify_model(out)

    def test_fetch_uses_fixed_assets_and_cleans_partial_failure(self):
        pin, data = self.fixture_pin()
        out = self.root / "model"
        def success(opener, url, destination, expected, timeout):
            destination.write_bytes(data[destination.name])
        with patch.object(p, "PIN", pin), patch.object(p, "_download_file", side_effect=success) as download:
            result = p.fetch_model(out, allow_network=True)
            self.assertEqual(result["network_requests"], 7)
            self.assertEqual(download.call_count, 7)
            with self.assertRaises(ValueError):
                p.fetch_model(out, allow_network=True)
            self.assertEqual(p.verify_model(out)["status"], "PINNED_MODEL_MATCH")
        fresh = self.root / "failure"
        calls = []
        def failure(opener, url, destination, expected, timeout):
            calls.append(destination.name)
            if len(calls) == 3:
                raise TimeoutError("synthetic timeout")
            destination.write_bytes(data[destination.name])
        with patch.object(p, "PIN", pin), patch.object(p, "_download_file", side_effect=failure):
            with self.assertRaises(TimeoutError):
                p.fetch_model(fresh, allow_network=True)
            self.assertFalse(fresh.exists())
            self.assertEqual(len(calls), 3)


class LegacyMaskTests(unittest.TestCase):
    def setUp(self):
        self.config = {"model_type": "gpt2", "n_layer": 2, "n_positions": 7}
        self.mask = np.tril(np.ones((7, 7), np.float32))[None, None]

    def test_canonical_masks_are_reported_without_mutating_input(self):
        learned = np.array([1.5], np.float32)
        weights = {"transformer.h.0.attn.bias": self.mask.copy(),
                   "transformer.h.1.attn.bias": self.mask.copy(),
                   "transformer.ln_f.weight": learned}
        cleaned, exclusions = p.normalize_gpt2_weights(self.config, weights)
        self.assertEqual(set(cleaned), {"transformer.ln_f.weight"})
        self.assertIs(cleaned["transformer.ln_f.weight"], learned)
        self.assertEqual(len(weights), 3)
        self.assertEqual(len(exclusions), 2)
        self.assertEqual(exclusions[0]["sha256"], hashlib.sha256(self.mask.tobytes()).hexdigest())

    def test_unknown_extra_remains_for_strict_model_validation(self):
        weights = {"transformer.h.2.attn.bias": self.mask,
                   "transformer.h.0.attn.masked_bias": np.array(-1e4, np.float32),
                   "something_else": np.array(3, np.float32)}
        cleaned, exclusions = p.normalize_gpt2_weights(self.config, weights)
        self.assertEqual(set(cleaned), set(weights))
        self.assertEqual(exclusions, [])

    def test_noncanonical_masks_are_rejected(self):
        altered = self.mask.copy()
        altered[0, 0, 2, 5] = 1
        diagonal = self.mask.copy()
        diagonal[0, 0, 3, 3] = 0
        nonfinite = self.mask.copy()
        nonfinite[0, 0, 1, 1] = np.nan
        for value in (altered, diagonal, nonfinite, self.mask[0], self.mask.astype(np.float64)):
            with self.subTest(shape=value.shape, dtype=value.dtype):
                with self.assertRaises(ValueError):
                    p.normalize_gpt2_weights(self.config, {"transformer.h.0.attn.bias": value})

    def test_bounds_checked_before_mask_allocation(self):
        for size in (0, 8193, True, "7"):
            with self.assertRaises(ValueError):
                p.normalize_gpt2_weights({**self.config, "n_positions": size}, {})


if __name__ == "__main__":
    unittest.main()
