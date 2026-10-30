#!/usr/bin/env python3
"""Measure the native Python API without changing source or dependencies.

Run with RAYON_NUM_THREADS=4 .venv/bin/python benchmarks/benchmark_python.py.
Results are median microseconds per call, including output allocation and the
Python/native boundary. Use an idle machine and the same interpreter and thread
count for comparisons. This script tests synthetic input, not Telegram traffic.
"""

import argparse
import json
import os
import platform
import statistics
import time
from pathlib import Path

import tgcryptors


def measure(repeats: int) -> dict[str, float]:
    key = bytes(range(32))
    iv = bytes(range(16))
    iv_ige = bytes(range(32))
    results = {}
    for size in [64, 1024, 16384, 262144, 1048576]:
        data = bytes(size)
        loops = max(16, min(10000, 16 * 1024 * 1024 // size))
        ctr = tgcryptors.Ctr256(key, iv)
        ige = tgcryptors.Ige256(key, iv_ige)
        operations = [
            ("ctr", lambda: tgcryptors.ctr256_encrypt(data, key, iv, b"\0")),
            ("cbc_enc", lambda: tgcryptors.cbc256_encrypt(data, key, iv)),
            ("cbc_dec", lambda: tgcryptors.cbc256_decrypt(data, key, iv)),
            ("ige", lambda: tgcryptors.ige256_encrypt(data, key, iv_ige)),
            ("ctr_stream", lambda: ctr.update(data)),
            ("ige_stream", lambda: ige.encrypt(data)),
        ]
        for name, operation in operations:
            for _ in range(4):
                operation()
            values = []
            for _ in range(repeats):
                start = time.perf_counter()
                for _ in range(loops):
                    operation()
                values.append((time.perf_counter() - start) / loops)
            results[f"{name}/{size}"] = round(statistics.median(values) * 1e6, 3)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the report as JSON")
    parser.add_argument("--repeats", type=int, default=3, help="Timing batches (default: 3)")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    report = {
        "unit": "microseconds_per_call",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runtime": tgcryptors.runtime_info(),
        "rayon_num_threads": os.environ.get("RAYON_NUM_THREADS", "default"),
        "repeats": args.repeats,
        "timings": measure(args.repeats),
    }
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
