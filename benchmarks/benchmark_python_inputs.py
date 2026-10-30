#!/usr/bin/env python3
"""Compare bytes/mutable CTR input and stream-construction overhead.

Run with RAYON_NUM_THREADS=4 .venv/bin/python benchmarks/benchmark_python_inputs.py.
Timings include the Python/native boundary. Use the same idle machine and
interpreter for comparisons; this is not a Telegram network throughput test.
"""

import argparse
import json
import os
import platform
import statistics
import timeit
from pathlib import Path

import tgcryptors


def measure(repeats):
    key = bytes(range(32))
    iv = bytes(range(16))
    state = b"\0"
    timings = {}
    for size in (16, 64, 1024, 16384, 1048576):
        data = bytes(size)
        variants = {
            "bytes": (data, key, iv, state),
            "mutable_key": (data, bytearray(key), iv, state),
            "mutable_carry": (data, key, bytearray(iv), bytearray(state)),
            "mutable_all": (bytearray(data), bytearray(key), bytearray(iv), bytearray(state)),
        }
        loops = max(100, min(100000, 16 * 1024 * 1024 // size))
        for name, inputs in variants.items():
            operation = lambda: tgcryptors.ctr256_encrypt(*inputs)
            operation()
            elapsed = statistics.median(timeit.repeat(operation, number=loops, repeat=repeats))
            timings[f"{name}/{size}"] = round(elapsed / loops * 1e6, 3)
    for name, operation in (
        ("ige_construct", lambda: tgcryptors.Ige256(key, key)),
        ("ctr_construct", lambda: tgcryptors.Ctr256(key, iv)),
    ):
        elapsed = statistics.median(timeit.repeat(operation, number=100000, repeat=repeats))
        timings[name] = round(elapsed / 100000 * 1e6, 3)
    return timings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
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
