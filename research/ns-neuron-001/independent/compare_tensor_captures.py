"""Full logit and intermediate comparison across independently implemented runtimes."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np


def main(reference, torch_a, torch_b, report):
    errors, fields, total = [], {}, 0
    tolerance = 2e-5  # Float64 vs FP32, fixed before making live Torch captures.
    with np.load(reference, allow_pickle=False) as ref, np.load(torch_a, allow_pickle=False) as a, np.load(torch_b, allow_pickle=False) as b:
        if set(ref.files) != set(a.files) or set(ref.files) != set(b.files):
            raise ValueError("Capture inventories differ")
        for name in sorted(ref.files):
            x,y,z = ref[name],a[name],b[name]
            if not (x.shape == y.shape == z.shape):
                raise ValueError(f"Capture shape mismatch for {name}")
            diff = np.abs(x-y)
            finite = np.isfinite(diff).all() and np.isfinite(z).all()
            same = y.dtype == z.dtype and y.tobytes() == z.tobytes()
            if not finite or np.max(diff) > tolerance or not same:
                errors.append(name)
            fields[name] = dict(shape=list(x.shape), max_abs=float(np.max(diff)), mean_abs=float(np.mean(diff)),
                                torch_replays_bitwise_equal=same)
            total += x.size
    checks_equal = (torch_a.parent/"checks.json").read_bytes() == (torch_b.parent/"checks.json").read_bytes()
    controls_equal = (torch_a.parent/"frozen.json").read_bytes() == (torch_b.parent/"frozen.json").read_bytes()
    if not checks_equal or not controls_equal:
        errors.append("Torch JSON controls or hook checks differ across processes")
    data = dict(atol=tolerance, max_abs=max(f["max_abs"] for f in fields.values()), fields=fields,
                tensor_count=len(fields), scalar_count=total, torch_checks_repeat=checks_equal,
                torch_selection_repeat=controls_equal, failures=errors,
                npz_sha256=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (reference,torch_a,torch_b)])
    report.write_text(json.dumps(data, sort_keys=True, indent=2, allow_nan=False)+"\n")
    print(f"{len(fields)} arrays, {total} entries; largest absolute cross-runtime error {data['max_abs']:.8g}; failures {errors}")
    if errors:
        raise ValueError("Numerical comparison failure")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("reference","torch_a","torch_b","report"):
        parser.add_argument(arg,type=Path)
    main(**vars(parser.parse_args()))
