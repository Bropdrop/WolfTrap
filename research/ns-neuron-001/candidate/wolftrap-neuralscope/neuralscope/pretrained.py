"""Pinned numeric-only acquisition and local verification for DistilGPT2.

The public checkpoint download is an explicit operation. It reads no model API
credentials, loads no repository Python, and accepts only the seven pinned files.
Successful hashing establishes consistency with these pins, not a signature or
an independent claim about the model publisher. Local checks assume quiescent
files and directories; they are not a hostile-filesystem sandbox.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import urllib.parse
import urllib.request

from .evidence import digest, read_json

REPO_ID = "distilbert/distilgpt2"
REVISION = "2290a62682d06624634c1f46a6ad5be0f47f38aa"
_ALLOWED_HOSTS = frozenset(("huggingface.co", "us.aws.cdn.hf.co"))
_CHUNK_BYTES = 1 << 20
PIN = {
    "schema": "wolftrap.neuralscope.pretrained-pin/v1",
    "repo_id": REPO_ID,
    "revision": REVISION,
    "source_url": "https://huggingface.co/" + REPO_ID + "/tree/" + REVISION,
    "license": "Apache-2.0",
    "license_basis": "The pinned README model card declares Apache-2.0; the repository has no standalone LICENSE file.",
    "pin_basis": "Small files matched the repository API Git blob IDs; the weight SHA-256 and size come from its Git LFS pointer. Acquisition verifies every full file against SHA-256 and size.",
    "publisher_signature": "NOT_VERIFIED",
    "files": {
        "README.md": {"bytes": 10992, "sha256": "111f8d09ac565c745d91df88929147159eaa62b2e58e03943a2e03c1a1439ad7", "git_blob_sha1": "86f7c9ae4422de194e6b6104b0acc9c8b9d2cd0a"},
        "config.json": {"bytes": 762, "sha256": "4ec5947c1d59fee6212cdf3b0ec1a53eac02092554c5ff0a733488cbd2c64f3a", "git_blob_sha1": "fed02aafb76b46aa5da200966f9e42262e758023"},
        "merges.txt": {"bytes": 456318, "sha256": "1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5", "git_blob_sha1": "226b0752cac7789c48f0cb3ec53eda48b7be36cc"},
        "model.safetensors": {"bytes": 352824413, "sha256": "e1ff18884359fe8beb795a5f414feb85a6ce3d929ad019c0d958c039d2b94a1b", "git_blob_sha1": "4a39931cbb1d0cbf2285b4f9afde21d69fca9dce"},
        "tokenizer.json": {"bytes": 1355256, "sha256": "8414cab924d8b9b33013f0d221c5862f365ee9be39c5c2bfae8a5a9e970478a6", "git_blob_sha1": "4b988bccc9dc5adacd403c00b4704976196548f8"},
        "tokenizer_config.json": {"bytes": 26, "sha256": "5e04eb606e3a1583530a42e36c2a6b6615c86f34fe77e44d9ddeb43ff940931f", "git_blob_sha1": "be4d21d94f3b4687e5a54d84bf6ab46ed0f8defd"},
        "vocab.json": {"bytes": 1042301, "sha256": "196139668be63f3b5d6574427317ae82f612a97c5d1cdaf36ed2256dbf636783", "git_blob_sha1": "1f1d9aaca301414e7f6c9396df506798ff4eb9a6"},
    },
}


def load_pin(path=None):
    """Return a copy of the built-in pin, optionally checking its saved JSON."""
    if path is not None and read_json(path) != PIN:
        raise ValueError("pin file differs from this release's fixed model pin")
    return copy.deepcopy(PIN)


def _https_url(url):
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid download port") from exc
    if (parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS
            or parsed.username is not None or parsed.password is not None
            or port not in (None, 443) or parsed.fragment):
        raise ValueError("download or redirect is outside the fixed HTTPS host allowlist")
    return url


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _asset_url(name):
    if name not in PIN["files"]:
        raise ValueError("file is outside the pinned asset inventory")
    return f"https://huggingface.co/{REPO_ID}/resolve/{REVISION}/{name}?download=true"


def _download_file(opener, url, destination, expected, timeout):
    """Stream a bounded response to a private temporary file, then publish it."""
    _https_url(url)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("refusing to replace a downloaded asset")
    descriptor, temporary = tempfile.mkstemp(prefix=".download-", dir=destination.parent)
    temporary = Path(temporary)
    try:
        request = urllib.request.Request(url, headers={
            "User-Agent": "WolfTrap-NeuralScope/0.3.0a1",
            "Accept-Encoding": "identity",
        }, method="GET")
        with os.fdopen(descriptor, "wb") as target:
            descriptor = None
            with opener.open(request, timeout=timeout) as response:
                _https_url(response.geturl())
                if response.status != 200:
                    raise ValueError("full asset download requires HTTP 200")
                encoding = response.headers.get("Content-Encoding", "identity")
                if encoding.lower() != "identity":
                    raise ValueError("unexpected encoded asset response")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) != expected["bytes"]):
                    raise ValueError("asset Content-Length differs from its pin")
                count = 0
                sha = hashlib.sha256()
                while True:
                    chunk = response.read(min(_CHUNK_BYTES, expected["bytes"] - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > expected["bytes"]:
                        raise ValueError("download exceeds its pinned size")
                    sha.update(chunk)
                    target.write(chunk)
                if count != expected["bytes"] or sha.hexdigest() != expected["sha256"]:
                    raise ValueError("downloaded bytes do not match the pinned asset")
            target.flush()
            os.fsync(target.fileno())
        # link() cannot replace an existing destination, including a symlink.
        os.link(temporary, destination)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def verify_model(directory, *, pin=None):
    """Verify the complete seven-file local model, without making a request."""
    if pin is not None and pin != PIN:
        raise ValueError("only this release's fixed model pin is supported")
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("model directory must be an existing real directory")
    found = {path.name for path in directory.iterdir()}
    if found != set(PIN["files"]):
        raise ValueError("model directory does not match the closed pinned inventory")
    identities = {}
    for name, expected in PIN["files"].items():
        actual = digest(directory / name)
        if actual != {key: expected[key] for key in ("bytes", "sha256")}:
            raise ValueError(f"local model asset differs from pin: {name}")
        identities[name] = copy.deepcopy(expected)
    return {
        "status": "PINNED_MODEL_MATCH", "repo_id": REPO_ID, "revision": REVISION,
        "files": identities, "license": PIN["license"],
        "publisher_signature": "NOT_VERIFIED", "network_requests": 0,
        "scope": "byte identity of this checkpoint and tokenizer, not behavioral safety",
    }


def fetch_model(directory, *, allow_network=False, timeout=30):
    """Explicitly fetch the fixed checkpoint into a fresh private directory.

    A failed download removes the directory created by this invocation. Each
    successful file is published only after its complete size and hash match.
    There are no application retries and no model API calls. Standard system
    HTTPS proxy configuration may apply; provider API credentials are not read.
    """
    if allow_network is not True:
        raise ValueError("model acquisition requires explicit allow_network=True")
    if type(timeout) not in (int, float) or not 1 <= timeout <= 120:
        raise ValueError("download timeout must be between 1 and 120 seconds")
    directory = Path(directory).absolute()
    if directory.exists() or directory.is_symlink():
        raise ValueError("choose a fresh model directory")
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.mkdir(mode=0o700, exist_ok=False)
    try:
        opener = urllib.request.build_opener(_PinnedRedirect())
        for name, expected in PIN["files"].items():
            _download_file(opener, _asset_url(name), directory / name, expected, timeout)
        result = verify_model(directory)
        result["network_requests"] = len(PIN["files"])
        result["network_requests_scope"] = "initial GET operations; HTTPS redirects are additional requests"
        return result
    except BaseException:
        shutil.rmtree(directory)
        raise


def normalize_gpt2_weights(config, weights):
    """Validate and remove only obsolete serialized GPT-2 causal-mask buffers.

    The original safetensors file remains unchanged. Every accepted buffer must
    be exactly a lower-triangular 0/1 mask of the configured context size. Modern
    GPT-2 implementations and NeuralScope regenerate this deterministic mask.
    All other entries remain for strict model-inventory validation by the caller.
    No arbitrary missing or unexpected learned weights are permitted here.
    """
    import numpy as np
    from collections.abc import Mapping

    if not isinstance(config, Mapping) or not isinstance(weights, Mapping):
        raise ValueError("configuration and weights must be mappings")
    layers, positions = config.get("n_layer"), config.get("n_positions")
    if (type(layers) is not int or not 1 <= layers <= 24
            or type(positions) is not int or not 1 <= positions <= 8192):
        raise ValueError("invalid GPT-2 dimensions for causal-mask normalization")
    cleaned = dict(weights)
    exclusions = []
    columns = np.arange(positions)
    for layer in range(layers):
        for prefix in ("transformer.", ""):
            name = f"{prefix}h.{layer}.attn.bias"
            if name not in cleaned:
                continue
            value = cleaned[name]
            if (not isinstance(value, np.ndarray) or value.shape != (1, 1, positions, positions)
                    or value.dtype not in (np.dtype("float32"), np.dtype("bool"))):
                raise ValueError(f"unsupported legacy causal-mask buffer: {name}")
            for start in range(0, positions, 128):
                end = min(positions, start + 128)
                expected = columns[None, :] <= np.arange(start, end)[:, None]
                if not np.array_equal(value[0, 0, start:end], expected):
                    raise ValueError(f"noncanonical legacy causal-mask values: {name}")
            exclusions.append({
                "name": name, "shape": list(value.shape), "dtype": str(value.dtype),
                "bytes": value.nbytes,
                "sha256": hashlib.sha256(value.tobytes(order="C")).hexdigest(),
                "reason": "exact deterministic lower-triangular causal mask regenerated by both engines",
            })
            del cleaned[name]
    return cleaned, exclusions


def load_pinned_model(directory):
    """Load the verified original numeric checkpoint and report normalization."""
    from .weights import load_weights

    provenance = verify_model(directory)
    directory = Path(directory)
    config = read_json(directory / "config.json")
    weights = load_weights(directory / "model.safetensors",
                           expected_sha256=PIN["files"]["model.safetensors"]["sha256"])
    cleaned, exclusions = normalize_gpt2_weights(config, weights)
    provenance["excluded_nonparameter_buffers"] = exclusions
    provenance["stored_elements"] = sum(value.size for value in weights.values())
    provenance["learned_parameters"] = sum(value.size for value in cleaned.values())
    return config, cleaned, provenance
