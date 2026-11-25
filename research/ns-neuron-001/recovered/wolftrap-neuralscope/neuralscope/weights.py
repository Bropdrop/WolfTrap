"""Bounded, read-only inspection of a supported subset of safetensors.

This module does not load Python pickle, execute model code, or fetch a model.
It reports file identity and numeric facts; neither is a security certificate.
The format is documented at https://github.com/safetensors/safetensors#format.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
from typing import BinaryIO

import numpy as np


DEFAULT_MAX_FILE_BYTES = 1 << 30
DEFAULT_MAX_HEADER_BYTES = 1 << 20
_CHUNK_BYTES = 1 << 20
_MAX_RANK = 32
_MAX_TENSORS = 20_000
_DTYPES = {
    "BOOL": np.dtype("?"), "U8": np.dtype("u1"), "I8": np.dtype("i1"),
    "U16": np.dtype("<u2"), "I16": np.dtype("<i2"),
    "U32": np.dtype("<u4"), "I32": np.dtype("<i4"),
    "U64": np.dtype("<u8"), "I64": np.dtype("<i8"),
    "F16": np.dtype("<f2"), "BF16": np.dtype("<u2"),
    "F32": np.dtype("<f4"), "F64": np.dtype("<f8"),
}
_INFERENCE_DTYPES = frozenset(("F16", "BF16", "F32"))
_WRITE_DTYPES = {
    ("b", 1): "BOOL", ("u", 1): "U8", ("i", 1): "I8",
    ("u", 2): "U16", ("i", 2): "I16", ("u", 4): "U32", ("i", 4): "I32",
    ("u", 8): "U64", ("i", 8): "I64", ("f", 2): "F16",
    ("f", 4): "F32", ("f", 8): "F64",
}


class WeightFormatError(ValueError):
    """Unsupported, malformed, changing, or over-budget local weight file."""


def _integer(value: object, description: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise WeightFormatError(f"{description} must be an integer >= {minimum}")
    return value


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise WeightFormatError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str):
    raise WeightFormatError("non-finite JSON constant")


def _snapshot(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    value = stream.read(count)
    if len(value) != count:
        raise WeightFormatError("truncated or changing weight file")
    return value


@contextmanager
def _opened(path, max_file_bytes: int, max_header_bytes: int):
    """Keep one descriptor for header, hashes, data, and change detection."""
    _integer(max_file_bytes, "max_file_bytes", 8)
    _integer(max_header_bytes, "max_header_bytes", 2)
    source = Path(path)
    if source.suffix != ".safetensors":
        raise WeightFormatError("only local .safetensors files are supported")
    if not hasattr(os, "O_NOFOLLOW"):
        raise WeightFormatError("this platform cannot enforce final-path no-symlink reads")
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise WeightFormatError("cannot open regular non-symlink weight file") from exc
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise WeightFormatError("weight input must be a regular file")
        if not 10 <= info.st_size <= max_file_bytes:
            raise WeightFormatError("weight file is truncated or exceeds max_file_bytes")
        initial = _snapshot(info)
        prefix = _read_exact(stream, 8)
        header_size = struct.unpack("<Q", prefix)[0]
        if not 2 <= header_size <= min(max_header_bytes, info.st_size - 8):
            raise WeightFormatError("invalid or oversized safetensors header")
        raw_header = _read_exact(stream, header_size)
        if raw_header[:1] != b"{":
            raise WeightFormatError("safetensors header must begin with an object")
        try:
            header = json.loads(raw_header.decode("utf-8"), object_pairs_hook=_object,
                                parse_constant=_constant)
        except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
            raise WeightFormatError("invalid safetensors JSON header") from exc
        if not isinstance(header, dict):
            raise WeightFormatError("safetensors header must be an object")
        metadata = header.pop("__metadata__", {})
        if not isinstance(metadata, dict) or any(not isinstance(v, str) for v in metadata.values()):
            raise WeightFormatError("metadata must map strings to strings")
        if len(header) > _MAX_TENSORS:
            raise WeightFormatError("too many tensor entries")
        data_start = 8 + header_size
        data_size = info.st_size - data_start
        tensors = []
        for name, entry in header.items():
            if not isinstance(name, str) or not name or len(name) > 4096:
                raise WeightFormatError("invalid tensor name")
            if not isinstance(entry, dict) or set(entry) != {"dtype", "shape", "data_offsets"}:
                raise WeightFormatError("tensor entries must contain dtype, shape, data_offsets")
            dtype = entry["dtype"]
            if not isinstance(dtype, str) or dtype not in _DTYPES:
                raise WeightFormatError("unsupported tensor dtype")
            shape = entry["shape"]
            if not isinstance(shape, list) or len(shape) > _MAX_RANK:
                raise WeightFormatError("invalid tensor shape or excessive rank")
            elements = 1
            for dim in shape:
                _integer(dim, "shape dimension")
                if dim > max_file_bytes:
                    raise WeightFormatError("shape dimension exceeds file budget")
                elements *= dim
                if elements > max_file_bytes:
                    raise WeightFormatError("tensor shape exceeds file budget")
            byte_count = elements * _DTYPES[dtype].itemsize
            offsets = entry["data_offsets"]
            if not isinstance(offsets, list) or len(offsets) != 2:
                raise WeightFormatError("invalid data_offsets")
            begin, end = (_integer(v, "data offset") for v in offsets)
            if end < begin or end > data_size or end - begin != byte_count:
                raise WeightFormatError("tensor size, shape, dtype, and offsets disagree")
            tensors.append({"name": name, "dtype": dtype, "shape": shape,
                            "elements": elements, "bytes": byte_count,
                            "data_offsets": [begin, end]})
        # Empty tensors occupy no interval. They must occur at a real boundary.
        ordered = sorted((t for t in tensors if t["bytes"]), key=lambda t: t["data_offsets"])
        cursor = 0
        boundaries = {0}
        for tensor in ordered:
            begin, end = tensor["data_offsets"]
            if begin != cursor:
                raise WeightFormatError("overlapping tensors or an unindexed data gap")
            cursor = end
            boundaries.add(cursor)
        if cursor != data_size:
            raise WeightFormatError("unindexed or trailing bytes in weight file")
        if any(t["bytes"] == 0 and t["data_offsets"][0] not in boundaries for t in tensors):
            raise WeightFormatError("empty tensor offset is not at a data boundary")
        context = {"stream": stream, "prefix": prefix + raw_header,
                   "data_start": data_start, "size_bytes": info.st_size,
                   "tensors": sorted(tensors, key=lambda t: t["name"]), "metadata": metadata}
        yield context
        if _snapshot(os.fstat(stream.fileno())) != initial:
            raise WeightFormatError("weight file changed while being inspected")


def _chunks(context: dict, tensor: dict):
    stream = context["stream"]
    begin, end = tensor["data_offsets"]
    stream.seek(context["data_start"] + begin)
    remaining = end - begin
    while remaining:
        chunk = _read_exact(stream, min(_CHUNK_BYTES, remaining))
        remaining -= len(chunk)
        yield chunk


def _numeric(chunk: bytes, dtype: str) -> np.ndarray:
    array = np.frombuffer(chunk, dtype=_DTYPES[dtype])
    if dtype == "BF16":
        return (array.astype(np.uint32) << 16).view(np.float32)
    return array


def _scan_tensor(context: dict, tensor: dict, scan_values: bool) -> dict:
    result = {key: value for key, value in tensor.items() if key != "data_offsets"}
    digest = hashlib.sha256()
    finite = nan = positive_infinity = negative_infinity = 0
    minimum = maximum = None
    for chunk in _chunks(context, tensor):
        digest.update(chunk)
        if not scan_values:
            continue
        values = _numeric(chunk, tensor["dtype"])
        finite_mask = np.isfinite(values)
        finite += int(finite_mask.sum())
        if values.dtype.kind == "f":
            nan += int(np.isnan(values).sum())
            positive_infinity += int(np.isposinf(values).sum())
            negative_infinity += int(np.isneginf(values).sum())
        usable = values[finite_mask]
        if usable.size:
            low, high = usable.min().item(), usable.max().item()
            minimum = low if minimum is None else min(low, minimum)
            maximum = high if maximum is None else max(high, maximum)
    result["sha256"] = digest.hexdigest()
    result["value_scan"] = "SCANNED" if scan_values else "NOT_SCANNED"
    if scan_values:
        result.update({"finite_count": finite, "nan_count": nan,
                       "positive_infinity_count": positive_infinity,
                       "negative_infinity_count": negative_infinity,
                       "nonfinite_count": nan + positive_infinity + negative_infinity,
                       "finite_min": minimum, "finite_max": maximum})
    return result


def _file_hash(context: dict) -> str:
    digest = hashlib.sha256()
    stream = context["stream"]
    stream.seek(0)
    remaining = context["size_bytes"]
    while remaining:
        block = _read_exact(stream, min(_CHUNK_BYTES, remaining))
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest()


def inspect_weights(path, *, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
                    scan_values: bool = True) -> dict:
    """Validate and hash a local safetensors file, optionally scan numeric values.

    No tensor is allocated according to its declared shape. Numeric scans operate
    on at most 1 MiB of file bytes at a time. File and tensor hashes identify bytes;
    they do not establish who published them or whether their behavior is safe.
    """
    if type(scan_values) is not bool:
        raise WeightFormatError("scan_values must be a boolean")
    with _opened(path, max_file_bytes, max_header_bytes) as context:
        tensors = [_scan_tensor(context, tensor, scan_values) for tensor in context["tensors"]]
        result = {"schema": "wolftrap.neuralscope.weight-inventory/v1",
                  "format": "safetensors-supported-subset", "sha256": _file_hash(context),
                  "size_bytes": context["size_bytes"], "tensors": tensors,
                  "tensor_count": len(tensors),
                  "parameter_count": sum(t["elements"] for t in tensors),
                  "metadata": context["metadata"],
                  "publisher_authenticity": "NOT_ESTABLISHED",
                  "behavioral_safety": "NOT_ASSESSED"}
    return result


def load_weights(path, *, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
                 max_decoded_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 expected_sha256: str | None = None) -> dict[str, np.ndarray]:
    """Copy finite F32/F16/BF16 tensors into bounded float32 arrays.

    This is deliberately narrower than the inventory parser. Integer,
    quantized, float64, sharded, and remote-code checkpoints are not supported
    by this inference adapter. This function never uses pickle or np.load.
    """
    _integer(max_decoded_bytes, "max_decoded_bytes", 1)
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256)):
        raise WeightFormatError("expected_sha256 must be a lowercase SHA-256 hex digest")
    with _opened(path, max_file_bytes, max_header_bytes) as context:
        if expected_sha256 is not None and _file_hash(context) != expected_sha256:
            raise WeightFormatError("weight file does not match expected_sha256")
        for tensor in context["tensors"]:
            if tensor["dtype"] not in _INFERENCE_DTYPES:
                raise WeightFormatError("inference supports only F32, F16, and BF16 tensors")
        if sum(t["elements"] * 4 for t in context["tensors"]) > max_decoded_bytes:
            raise WeightFormatError("decoded float32 weights exceed memory budget")
        result = {}
        for tensor in context["tensors"]:
            values = np.empty(tensor["elements"], dtype=np.float32)
            cursor = 0
            for chunk in _chunks(context, tensor):
                part = _numeric(chunk, tensor["dtype"])
                if not bool(np.isfinite(part).all()):
                    raise WeightFormatError("non-finite inference weights")
                values[cursor:cursor + part.size] = part
                cursor += part.size
            result[tensor["name"]] = values.reshape(tensor["shape"])
    return result


def write_safetensors(path, tensors: dict[str, np.ndarray], metadata: dict[str, str] | None = None,
                      *, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                      max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES) -> None:
    """Write a new deterministic fixture file; refuse to overwrite existing paths.

    Inputs must already be NumPy arrays. This helper is for local fixtures, not
    for converting pickle files or interpreting a third-party model program.
    """
    _integer(max_file_bytes, "max_file_bytes", 8)
    _integer(max_header_bytes, "max_header_bytes", 2)
    path = Path(path)
    if path.suffix != ".safetensors":
        raise WeightFormatError("output must have .safetensors suffix")
    if not isinstance(tensors, dict) or len(tensors) > _MAX_TENSORS:
        raise WeightFormatError("tensors must be a bounded dictionary")
    if metadata is not None and (not isinstance(metadata, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items())):
        raise WeightFormatError("metadata must map strings to strings")
    header, arrays = {}, []
    offset = 0
    if any(not isinstance(name, str) or not name or name == "__metadata__" or len(name) > 4096
           for name in tensors):
        raise WeightFormatError("invalid tensor name")
    for name in sorted(tensors):
        array = tensors[name]
        if type(array) is not np.ndarray or array.ndim > _MAX_RANK:
            raise WeightFormatError("tensor values must be plain NumPy arrays")
        dtype_name = _WRITE_DTYPES.get((array.dtype.kind, array.dtype.itemsize))
        if dtype_name is None:
            raise WeightFormatError("unsupported tensor dtype for writing")
        if array.nbytes > max_file_bytes or offset + array.nbytes > max_file_bytes:
            raise WeightFormatError("fixture exceeds output budget")
        normalized = np.ascontiguousarray(array.astype(_DTYPES[dtype_name], copy=False))
        header[name] = {"dtype": dtype_name, "shape": list(array.shape),
                        "data_offsets": [offset, offset + array.nbytes]}
        arrays.append(normalized)
        offset += array.nbytes
    if metadata is not None:
        header["__metadata__"] = metadata
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    encoded += b" " * ((-len(encoded)) % 8)
    if len(encoded) > max_header_bytes or 8 + len(encoded) + offset > max_file_bytes:
        raise WeightFormatError("fixture header or file exceeds output budget")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(struct.pack("<Q", len(encoded)))
        stream.write(encoded)
        for array in arrays:
            if array.size:
                stream.write(memoryview(array).cast("B"))


def compare_weights(path_a, path_b, **inspection_options) -> dict:
    """Report byte and structural changes without guessing their motivation."""
    left = inspect_weights(path_a, **inspection_options)
    right = inspect_weights(path_b, **inspection_options)
    old = {t["name"]: t for t in left["tensors"]}
    new = {t["name"]: t for t in right["tensors"]}
    changed = []
    for name in sorted(old.keys() & new.keys()):
        fields = [field for field in ("dtype", "shape", "sha256") if old[name][field] != new[name][field]]
        if fields:
            changed.append({"name": name, "changed_fields": fields,
                            "before": old[name], "after": new[name]})
    return {"schema": "wolftrap.neuralscope.weight-comparison/v1",
            "before_sha256": left["sha256"], "after_sha256": right["sha256"],
            "same_file_bytes": left["sha256"] == right["sha256"],
            "added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()),
            "changed": changed, "metadata_changed": left["metadata"] != right["metadata"],
            "interpretation": "Differences are observations, not evidence of malicious intent."}
