import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

import numpy as np

from neuralscope.weights import (WeightFormatError, compare_weights, inspect_weights,
                                load_weights, write_safetensors)


class WeightIntakeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "weights.safetensors"

    def raw(self, header, data=b""):
        if not isinstance(header, bytes):
            header = json.dumps(header, separators=(",", ":")).encode()
        self.path.write_bytes(struct.pack("<Q", len(header)) + header + data)
        return self.path

    @staticmethod
    def tensor(dtype="F32", shape=None, offsets=None):
        return {"dtype": dtype, "shape": [1] if shape is None else shape,
                "data_offsets": [0, 4] if offsets is None else offsets}

    def test_roundtrip_and_reproducible_bytes(self):
        tensors = {"b": np.arange(6, dtype=np.float16).reshape(2, 3),
                   "a": np.array([[-1.5, 2.5]], dtype=np.float32)}
        write_safetensors(self.path, tensors, {"source": "synthetic fixture"})
        second = self.path.with_name("second.safetensors")
        write_safetensors(second, dict(reversed(list(tensors.items()))),
                          {"source": "synthetic fixture"})
        self.assertEqual(self.path.read_bytes(), second.read_bytes())
        result = inspect_weights(self.path)
        self.assertEqual(result["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(result["parameter_count"], 8)
        self.assertEqual(result["tensors"][0]["finite_min"], -1.5)
        self.assertEqual(result["tensors"][1]["finite_max"], 5.0)
        loaded = load_weights(self.path)
        for name, array in tensors.items():
            np.testing.assert_array_equal(loaded[name], array)
            self.assertEqual(loaded[name].dtype, np.dtype("float32"))

    def test_bfloat16_decodes(self):
        bits = np.array([0x3F80, 0xC000, 0x0000], dtype="<u2")
        self.raw({"x": self.tensor("BF16", [3], [0, 6])}, bits.tobytes())
        np.testing.assert_array_equal(load_weights(self.path)["x"], [1.0, -2.0, 0.0])
        self.assertEqual(inspect_weights(self.path)["tensors"][0]["finite_count"], 3)

    def test_metadata_and_unicode(self):
        write_safetensors(self.path, {"α": np.ones(2, dtype=np.float32)}, {"note": "wolf 🐺"})
        self.assertEqual(inspect_weights(self.path)["metadata"], {"note": "wolf 🐺"})

    def test_no_overwrite(self):
        self.path.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            write_safetensors(self.path, {"x": np.ones(2, dtype=np.float32)})
        self.assertEqual(self.path.read_bytes(), b"existing")

    def test_duplicate_tensor_key_rejected(self):
        self.raw(b'{"x":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},'
                 b'"x":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}', b"\x00" * 4)
        with self.assertRaisesRegex(WeightFormatError, "duplicate"):
            inspect_weights(self.path)

    def test_duplicate_nested_key_rejected(self):
        self.raw(b'{"x":{"dtype":"F32","dtype":"F16","shape":[1],"data_offsets":[0,2]}}', b"\x00" * 2)
        with self.assertRaisesRegex(WeightFormatError, "duplicate"):
            inspect_weights(self.path)

    def test_json_nan_and_nested_or_typed_metadata_rejected(self):
        for header in (b'{"__metadata__":{"bad":NaN}}', {"__metadata__": {"x": {}}},
                       {"__metadata__": ["x"]}):
            with self.subTest(header=header):
                self.raw(header)
                with self.assertRaises(WeightFormatError):
                    inspect_weights(self.path)

    def test_offsets_overlap_gap_and_trailer_rejected(self):
        cases = [
            ({"a": self.tensor(), "b": self.tensor(offsets=[0, 4])}, b"\x00" * 4),
            ({"a": self.tensor(offsets=[4, 8])}, b"\x00" * 8),
            ({"a": self.tensor()}, b"\x00" * 5),
            ({"a": self.tensor(offsets=[0, 8])}, b"\x00" * 8),
            ({"a": self.tensor(offsets=[4, 0])}, b"\x00" * 4),
        ]
        for header, data in cases:
            with self.subTest(header=header):
                self.raw(header, data)
                with self.assertRaises(WeightFormatError):
                    inspect_weights(self.path)

    def test_truncated_or_absurd_header_rejected(self):
        for data in (b"short", struct.pack("<Q", 2 ** 63) + b"{}", struct.pack("<Q", 99) + b"{}"):
            self.path.write_bytes(data)
            with self.assertRaises(WeightFormatError):
                inspect_weights(self.path)

    def test_header_and_file_budget(self):
        self.raw({"x": self.tensor()}, b"\x00" * 4)
        with self.assertRaises(WeightFormatError):
            inspect_weights(self.path, max_header_bytes=16)
        with self.assertRaises(WeightFormatError):
            inspect_weights(self.path, max_file_bytes=16)
        for invalid in (False, 0, -1, 1.5):
            with self.assertRaises(WeightFormatError):
                inspect_weights(self.path, max_file_bytes=invalid)

    def test_invalid_shapes_and_types(self):
        shapes = ([True], [-1], [2.0], [2 ** 200], [2 ** 29, 2 ** 29], [1] * 33, "1")
        for shape in shapes:
            with self.subTest(shape=shape):
                self.raw({"x": self.tensor(shape=shape)}, b"\x00" * 4)
                with self.assertRaises(WeightFormatError):
                    inspect_weights(self.path)
        for offsets in ([False, 4], [0.0, 4], [0, 4, 8]):
            self.raw({"x": self.tensor(offsets=offsets)}, b"\x00" * 4)
            with self.assertRaises(WeightFormatError):
                inspect_weights(self.path)

    def test_nonfinite_values_reported_and_inference_rejected(self):
        values = np.array([np.nan, np.inf, -np.inf, 2], dtype=np.float32)
        write_safetensors(self.path, {"x": values})
        item = inspect_weights(self.path)["tensors"][0]
        self.assertEqual(item["finite_count"], 1)
        self.assertEqual(item["nan_count"], 1)
        self.assertEqual(item["positive_infinity_count"], 1)
        self.assertEqual(item["negative_infinity_count"], 1)
        self.assertEqual(item["nonfinite_count"], 3)
        self.assertEqual(item["finite_min"], 2.0)
        self.assertEqual(item["finite_max"], 2.0)
        with self.assertRaisesRegex(WeightFormatError, "non-finite"):
            load_weights(self.path)

    def test_inventory_can_skip_value_scan(self):
        write_safetensors(self.path, {"x": np.array([1, 2], dtype=np.float32)})
        item = inspect_weights(self.path, scan_values=False)["tensors"][0]
        self.assertEqual(item["value_scan"], "NOT_SCANNED")
        self.assertNotIn("finite_count", item)
        self.assertEqual(len(item["sha256"]), 64)

    def test_finite_integer_inventory_but_no_integer_inference(self):
        write_safetensors(self.path, {"x": np.array([0, 2 ** 64 - 1], dtype=np.uint64)})
        item = inspect_weights(self.path)["tensors"][0]
        self.assertEqual(item["finite_max"], 2 ** 64 - 1)
        with self.assertRaisesRegex(WeightFormatError, "only F32"):
            load_weights(self.path)

    def test_scalar_empty_and_zero_data_file(self):
        self.raw({"scalar": self.tensor(shape=[]),
                  "empty": self.tensor(shape=[0, 3], offsets=[4, 4])}, struct.pack("<f", 7))
        values = load_weights(self.path)
        self.assertEqual(values["scalar"].shape, ())
        self.assertEqual(values["scalar"].item(), 7)
        self.assertEqual(values["empty"].shape, (0, 3))
        self.raw({"empty": self.tensor(shape=[0], offsets=[0, 0])})
        self.assertEqual(inspect_weights(self.path)["parameter_count"], 0)

    def test_decoded_budget_applies_to_upcast(self):
        write_safetensors(self.path, {"x": np.ones(10, dtype=np.float16)})
        with self.assertRaisesRegex(WeightFormatError, "decoded"):
            load_weights(self.path, max_decoded_bytes=30)

    def test_loader_pins_inspected_file(self):
        write_safetensors(self.path, {"x": np.ones(2, dtype=np.float32)})
        pin = inspect_weights(self.path)["sha256"]
        self.assertEqual(load_weights(self.path, expected_sha256=pin)["x"].shape, (2,))
        with self.assertRaisesRegex(WeightFormatError, "does not match"):
            load_weights(self.path, expected_sha256="0" * 64)

    def test_writer_supports_scalar_and_empty(self):
        write_safetensors(self.path, {"scalar": np.array(3, dtype=np.float32),
                                     "empty": np.empty((0, 2), dtype=np.float16)})
        actual = load_weights(self.path)
        self.assertEqual(actual["scalar"].shape, ())
        self.assertEqual(actual["scalar"].item(), 3)
        self.assertEqual(actual["empty"].shape, (0, 2))

    def test_writer_rejects_invalid_key_before_sort(self):
        with self.assertRaises(WeightFormatError):
            write_safetensors(self.path, {"a": np.ones(1), 1: np.ones(1)})

    def test_symlink_and_pickle_rejected(self):
        write_safetensors(self.path, {"x": np.ones(1, dtype=np.float32)})
        link = self.path.with_name("link.safetensors")
        link.symlink_to(self.path)
        with self.assertRaises(WeightFormatError):
            inspect_weights(link)
        other = self.path.with_suffix(".bin")
        other.write_bytes(self.path.read_bytes())
        with self.assertRaises(WeightFormatError):
            load_weights(other)

    def test_fifo_rejected_without_blocking(self):
        fifo = self.path.with_name("fifo.safetensors")
        os.mkfifo(fifo)
        with self.assertRaises(WeightFormatError):
            inspect_weights(fifo)

    def test_unknown_dtype_and_extra_keys_rejected(self):
        for entry in (self.tensor("F8_E4M3"), {**self.tensor(), "code": "do not run"}):
            self.raw({"x": entry}, b"\x00" * 4)
            with self.assertRaises(WeightFormatError):
                inspect_weights(self.path)

    def test_compare_reports_observed_changes(self):
        write_safetensors(self.path, {"x": np.ones(2, dtype=np.float32),
                                     "old": np.ones(1, dtype=np.float32)})
        second = self.path.with_name("second.safetensors")
        write_safetensors(second, {"x": np.zeros(2, dtype=np.float32),
                                  "new": np.ones(1, dtype=np.float32)})
        result = compare_weights(self.path, second)
        self.assertFalse(result["same_file_bytes"])
        self.assertEqual(result["added"], ["new"])
        self.assertEqual(result["removed"], ["old"])
        self.assertEqual(result["changed"][0]["changed_fields"], ["sha256"])


if __name__ == "__main__":
    unittest.main()
