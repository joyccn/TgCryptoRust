# Performance measurements

TgCryptoRust 2.0.0 uses RustCrypto AES and batches eight independent blocks for
CTR and CBC decryption. This fills the backend's AES-NI parallel lanes; the
four-block remainder remains available for shorter inputs. Short Python calls
also avoid releasing and reacquiring the GIL below 16 KiB. Safety checks, output
initialization, and key zeroization remain enabled.

## Reproduce

Build the release native extension, then run from the repository root:

```sh
.venv/bin/maturin develop --release --locked
RAYON_NUM_THREADS=4 .venv/bin/python benchmarks/benchmark_python.py --output /tmp/tgcryptors-timings.json
```

The script reports median microseconds per call over three timing batches. Each
operation warms up four times; each batch performs
`max(16, min(10000, 16 * 1024 * 1024 // size))` calls. Both versions used this same
workload. Output allocation and the Python/native call are included; the
`*_stream` cases retain the expanded key and cipher state between calls.

To measure Rust without the Python boundary:

```sh
cargo bench -p tgcryptors-core --bench benchmark --locked
```

The `preexpanded` group reuses a key and output buffer. Other groups include key
expansion and allocation. Sizes include small messages and bulk transfers rather
than only very large buffers.

## Observed comparison

These measurements used the same managed Linux x86_64 environment on an AMD EPYC
9V74 CPU, CPython 3.14.8, Rust 1.99.1, the repository's release profile, hardware
AES, and four Rayon threads. The 1.3.1 baseline was captured before the changes;
2.0.0 was measured after rebuilding the final native extension with eight-block
batching. No compiler process was active when the final sample began.

Times are microseconds per call; smaller is better. Changes below a few percent
should be treated as noise.

| Operation | Input | 1.3.1 | 2.0.0 | Time change |
| --- | ---: | ---: | ---: | ---: |
| CTR | 64 B | 0.491 | 0.365 | -26% |
| IGE encrypt | 64 B | 0.532 | 0.373 | -30% |
| CTR | 1 KiB | 1.242 | 0.946 | -24% |
| CBC encrypt | 1 KiB | 2.680 | 1.883 | -30% |
| CBC decrypt | 1 KiB | 1.232 | 0.689 | -44% |
| IGE encrypt | 1 KiB | 2.363 | 1.953 | -17% |
| CTR | 16 KiB | 12.306 | 10.071 | -18% |
| CBC decrypt | 16 KiB | 10.993 | 7.897 | -28% |
| IGE encrypt | 16 KiB | 26.314 | 26.412 | +0.4% |
| CTR | 1 MiB | 333.799 | 307.271 | -8% |
| CBC encrypt | 1 MiB | 2601.927 | 1608.517 | -38% |
| CBC decrypt | 1 MiB | 301.427 | 246.803 | -18% |
| IGE encrypt | 1 MiB | 2085.782 | 1816.696 | -13% |
| CTR streaming | 1 MiB | 377.354 | 250.445 | -34% |

All recorded operations and sizes are available in
[the 1.3.1 baseline](../benchmarks/results/1.3.1.json) and
[the 2.0.0 report](../benchmarks/results/2.0.0.json).

These are short synthetic microbenchmarks on a shared cloud CPU, without CPU
pinning, frequency control, or statistical confidence intervals. Scheduling,
CPU quotas, caches, and Rayon wakeups can affect results, especially the larger
parallel cases. They do not establish a universal speedup, software-backend or
ARM performance, network throughput, or TDLib application performance. Compare
on your deployment hardware with a representative workload before selecting
thread counts or making latency guarantees.

## Python input and object overhead

A follow-up review of `python/` and its binding retained direct native exports,
removed three small CTR `Vec` snapshots in favor of fixed-size arrays, and
removed the duplicate IGE expanded key. IV/state buffer leases and mutable data
snapshots remain in place. The Python guide explains when to choose immutable
inputs or reusable stream objects.

Reproduce this workload with:

```sh
RAYON_NUM_THREADS=4 .venv/bin/python benchmarks/benchmark_python_inputs.py --output /tmp/tgcryptors-input-timings.json
```

Both samples use CPython 3.14.8 and four Rayon threads on the same machine. The
baseline precedes these binding changes, after the original 2.0.0 AES changes;
both were development builds reporting version 2.0.0 before publication.
The JSON phase and source revision distinguish them; the version string alone
does not.

| Operation | Before (µs) | After (µs) | Time change |
| --- | ---: | ---: | ---: |
| IGE object construction | 0.636 | 0.375 | -41% |
| CTR 16 B, mutable key | 0.363 | 0.300 | -17% |
| CTR 16 B, mutable IV/state | 0.415 | 0.370 | -11% |
| CTR 1 KiB, mutable IV/state | 1.208 | 0.987 | -18% |
| CTR 1 KiB, all mutable inputs | 1.428 | 1.225 | -14% |
| CTR 1 KiB, immutable inputs | 0.902 | 0.956 | +6% |

The immutable 1 KiB sample was slower by 0.054 µs; other immutable sizes varied
in both directions. These short shared-CPU measurements do not establish a
speedup for every input. Large mutable inputs still pay the necessary snapshot
cost, and the large parallel samples are particularly sensitive to scheduling.

On this build, `Ige256.__basicsize__` fell from 1,984 to 1,024 bytes, a 48.4%
reduction in fixed instance size. This excludes allocator overhead and any
caller-owned buffers, and sizes may differ across builds and platforms.

Full samples: [before](../benchmarks/results/python-inputs-before.json) and
[after](../benchmarks/results/python-inputs-after.json).
