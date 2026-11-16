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

## Telegram handling follow-up (unreleased)

CTR now generates each four/eight-block counter batch using full-width wrapping
arithmetic instead of repeated bytewise carry loops. IGE selects RustCrypto's
backend once per complete call using safe backend closures. Counter order,
opaque zeroized schedules and hardware/software compatibility are retained.

These historical comparisons used Rust 1.89.0 and hardware AES on the same
Linux x86_64 AMD EPYC 9V74 machine. Each Criterion comparison kept the AES
dependency fixed: 0.9.3 for CTR and 0.9.4 for IGE. Both retain output and an
expanded key and reset their counter/IV per iteration. Samples used 30
measurements, two seconds measurement time and one second warm-up.

| Encryption workload | Bytes | Before (ns) | After (ns) | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| CTR | 64 | 52.22 | 37.70 | 27.8% |
| CTR | 1,024 | 551.79 | 355.23 | 35.6% |
| CTR | 16,384 | 8,721.93 | 5,504.48 | 36.9% |
| IGE | 64 | 160.13 | 114.44 | 28.5% |
| IGE | 1,024 | 2,299.24 | 2,080.79 | 9.5% |
| IGE | 16,384 | 35,813.25 | 32,907.46 | 8.1% |

Recorded estimates and commands:
[CTR counter batching](../benchmarks/results/ctr-counter-comparison.json) and
[IGE dispatch](../benchmarks/results/ige-dispatch-comparison.json).

The final Python extension was also rebuilt and measured against baseline
commit `74b216b` on CPython 3.14.10 with four Rayon threads and five timing
batches. Both extensions report 2.0.0; labels, source revision/dirty state and
AES version distinguish the unreleased build. These end-to-end samples include
the dependency refresh, output allocation and Python/native call overhead.

| Python operation | Input | Before (µs) | After (µs) | Time change |
| --- | ---: | ---: | ---: | ---: |
| CTR | 64 B | 0.363 | 0.308 | -15.2% |
| CTR | 1 KiB | 0.915 | 0.654 | -28.5% |
| CTR | 16 KiB | 9.450 | 6.021 | -36.3% |
| IGE encrypt | 64 B | 0.412 | 0.315 | -23.5% |
| IGE encrypt | 1 KiB | 2.641 | 2.272 | -14.0% |
| IGE encrypt | 16 KiB | 38.239 | 33.429 | -12.6% |
| CBC decrypt | 256 KiB | 90.478 | 103.383 | +14.3% |
| CBC decrypt | 1 MiB | 198.103 | 243.460 | +22.9% |

Large parallel CBC-decryption samples were slower and remain in the report.
Scheduling affects these cases; the data does not establish an improvement in
every mode or size. On the final build, reusable 64-byte CBC encryption took
0.206 µs per call versus 0.329 µs one-shot, and decryption 0.132 versus 0.244 µs.
Streaming advances state across calls; one-shot samples restart it. Choose
message boundaries correctly rather than selecting an API solely by timing.

```sh
RAYON_NUM_THREADS=4 .venv/bin/python benchmarks/benchmark_python.py \
  --repeats 5 --label my-built-revision --output /tmp/telegram-refresh.json
```

The Rust compiler must be on PATH to record its version. Source metadata
identifies the checkout, not an independently verified binary; rebuild first.
Python reports: [before](../benchmarks/results/telegram-refresh-before.json)
and [after](../benchmarks/results/telegram-refresh-after.json).

An executor reset removed the original local benchmark files before commit.
The follow-up JSON reports were recovered from the recorded tool output:
point estimates and Python timings are exact; Criterion confidence intervals
are explicitly marked as console-rounded. Original raw samples and
full-precision interval metadata are unavailable. These are historical results,
not a new measurement on the recovered executor.

The synthetic shared-CPU results do not measure Telegram network latency,
authentication, ARM, software-backend performance or Python 3.15 performance.
Benchmark representative workloads on deployment hardware before changing
Rayon thread counts or promising latency/throughput guarantees.
