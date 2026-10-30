# Performance measurements

The 2.0.0 release uses RustCrypto AES and batches eight independent blocks for
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
cargo bench -p tgcryptors-core --bench benchmark
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
