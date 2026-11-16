# Dependency refresh and compatibility review

This update checked crates.io's authoritative sparse index and PyPI package
metadata for the latest non-yanked stable versions. GitHub Action releases and
their resolved commit pins were checked against the upstream repositories.
Prerelease interpreters/packages are not selected merely because they have a
higher version number. Rust 1.89 remains the minimum toolchain.

## Direct dependencies and build tools

| Dependency | Before | Selected | Relevant upstream changes and migration |
| --- | --- | --- | --- |
| RustCrypto AES | 0.9.3 | **0.9.4** | Compact software-backend round keys and an inline-related performance regression fix; public APIs and Rust 1.89 requirement remain compatible. Keep `zeroize` enabled. |
| PyO3 | 0.30.1 | 0.30.1 | Already latest. The 0.30 line supports final Python 3.15, removes Python 3.8 support and deprecates unsound buffer slice APIs. Bindings use buffer leases and snapshots rather than the deprecated slice APIs. |
| Rayon | 1.12.0 | 1.12.0 | Already latest. Includes an invalid-character-range correction. The earlier `repeatn` deprecation does not require a migration here; this project does not use it. |
| zeroize | 1.9.1 | 1.9.1 | Already latest. Includes opaque debug output and an uninitialized-read fix in an optimization-barrier fallback. Expanded keys and owned secret snapshots retain zeroization. |
| Criterion | 0.8.2 | 0.8.2 | Already latest. Benchmark fixes include unsupported-target `alloca` handling and uniform-distribution panic handling; its Rust 1.86 minimum fits this workspace. |
| Maturin | 1.16.0 | 1.16.0 | Already latest. Includes TLS/root-bundle fixes and Python 3.15 filename support. Development/CI installs pin this version; package builds retain the declared minimum. |
| patchelf Python distribution | 0.19.3.0 | 0.19.3.0 | Already latest on PyPI; used for Linux wheel tooling, not a Python runtime dependency. |

Release notes reviewed:

- [AES 0.9.4 changelog](https://github.com/RustCrypto/block-ciphers/blob/aes-v0.9.4/aes/CHANGELOG.md)
- [PyO3 0.30.1 changelog](https://github.com/PyO3/pyo3/blob/v0.30.1/CHANGELOG.md)
- [Rayon 1.12.0 release notes](https://github.com/rayon-rs/rayon/blob/v1.12.0/RELEASES.md)
- [zeroize 1.9.1 changelog](https://github.com/RustCrypto/utils/blob/zeroize-v1.9.1/zeroize/CHANGELOG.md)
- [Criterion 0.8.2 changelog](https://github.com/criterion-rs/criterion.rs/blob/criterion-v0.8.2/CHANGELOG.md)
- [Maturin 1.16.0 changelog](https://github.com/PyO3/maturin/blob/v1.16.0/Changelog.md)
- [patchelf PyPI metadata](https://pypi.org/pypi/patchelf/json)

## Compatible transitive updates

`cargo update` refreshed the following locked dependencies within the direct
dependencies' supported ranges. It did not force unrelated incompatible major
versions into the graph.

| Package | Before → after | Release-note finding |
| --- | --- | --- |
| bumpalo | 3.20.3 → 3.20.4 | Fixes undefined behavior for zero-sized allocations under multithreading, tracked as GHSA-j7wg-xg3h-2pr6. Present through the WASM benchmark dependency graph. |
| cc | 1.10.0 → 1.11.2 | GCC AddressSanitizer globals fix, reproducible CodeView and MSVC/`.cc` correctness changes. |
| inout | 0.2.5 → 0.2.6 | Corrects Stacked Borrows/Tree Borrows behavior. |
| itoa | 1.0.18 → 1.0.19 | Fixes a `no-panic` linking issue. |
| syn | 3.0.9 → 3.0.10 | Avoids rescanning failed operands in parsing. The separate compatible Syn 2 dependency remains resolved independently. |
| target-lexicon | 0.13.5 → 0.13.6 | Adds `arm64_32` Apple Watch architecture recognition and a z/OS host test. The release page has no narrative notes; the upstream source comparison was inspected. No migration is needed here. |

Sources:
[bumpalo](https://github.com/fitzgen/bumpalo/blob/3.20.4/CHANGELOG.md),
[cc](https://github.com/rust-lang/cc-rs/blob/cc-v1.11.2/CHANGELOG.md),
[inout](https://github.com/RustCrypto/utils/blob/inout-v0.2.6/inout/CHANGELOG.md),
[itoa](https://github.com/dtolnay/itoa/releases/tag/1.0.19),
[syn](https://github.com/dtolnay/syn/releases/tag/3.0.10), and
[target-lexicon source comparison](https://github.com/bytecodealliance/target-lexicon/compare/v0.13.5...v0.13.6).

Dependency release notes and checks do not replace an advisory scan or a review
of this project's mode code. Any historical scan recorded in AUDIT.md applies
to its stated lockfile/database, not automatically to this refreshed graph.

## Python 3.15.2

The package's Python range now includes CPython 3.10 through 3.15
(`>=3.10,<3.16`), with a Python 3.15 classifier and CI/release matrix entries.
Python 3.9 support was removed after GitHub's Ubuntu 26.04 runner migration:
the official setup-python manifest has no Python 3.9 build for that OS. The
manifest provides Ubuntu 26.04 x64/arm64 builds for every retained minor version,
so Python 3.10–3.15 can continue using the current runner. See the
[official interpreter manifest](https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json).
CPython's official [`v3.15.2` tag](https://github.com/python/cpython/tree/v3.15.2)
resolves to `5e58eaad7c58df58dfa8ea549c87996e01dd1077`; its
[`patchlevel.h`](https://github.com/python/cpython/blob/v3.15.2/Include/patchlevel.h)
identifies a final 3.15.2 release. The development environment downloaded and
executed that interpreter. PyO3 0.30.1 and Maturin 1.16.0 already provide the
required 3.15 support, so no forward-compatibility bypass is needed.

Metadata, an available interpreter and configured CI are separate from a
passing native wheel test. See [AUDIT.md](AUDIT.md) for the actual extension
build/test results on each local interpreter. Free-threaded Python and the
3.16 prerelease are not added to the supported/tested matrix by this update.

## GitHub Actions

All actions retain immutable full commit pins. This update advances:

| Action | Selected version/pin | Review |
| --- | --- | --- |
| `softprops/action-gh-release` | 3.0.4, `8a0cd651e5b2365bd640854a3fa5dfc70e4875f3` | Upstream describes maintenance with updated dependencies; `action.yml` inputs/outputs remain unchanged. |
| `dtolnay/rust-toolchain` | stable, `39008827e6b4319a349e9a42dfc90579dd25f1ca` | Latest stable-branch pin; action definition is unchanged. The MSRV job still explicitly requests and verifies Rust 1.89.0. |

Already-current pins were retained for checkout 7.0.1, setup-python 7.1.0,
rust-cache 2.9.3, maturin-action 1.51.0, upload-artifact 7.0.2,
download-artifact 8.0.2 and PyPI publishing 1.14.3. The Python wheel matrix gains
3.15; the release artifact check now expects 30 wheels and one source
distribution. Wheel smoke tests exercise the additive CBC streaming API
against an independent NIST vector.

[action-gh-release 3.0.4 notes](https://github.com/softprops/action-gh-release/releases/tag/v3.0.4)
and the pinned workflow files record the exact action selections. YAML and
embedded Python were parsed, and Actionlint 1.7.9 passed all three workflow
files. `cargo fetch --locked` and `uv lock --check` also passed during the
refresh. These local checks do not claim that the expanded GitHub OS/ARM
matrix or a release publication has run.
