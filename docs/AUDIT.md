# Dependency and implementation review

## Unreleased Telegram/performance follow-up

This follow-up starts from `74b216b7cff77a73cf9c984a15ec7703ba454025`.
Changes were implemented independently after reviewing WarpCrypto and TDLib;
no WarpCrypto source was copied. The six TgCrypto functions, mutable CTR
semantics and direct native Python exports remain compatible.

| Finding/opportunity | Change | Regression evidence |
| --- | --- | --- |
| CBC expanded keys for each small chunk | Rust preexpanded helpers and native `Cbc256` | NIST vectors across chunk splits, empty calls and validation atomicity |
| CTR counter batches repeated bytewise carry loops | Full-width wrapping counter batches | Independent block-at-a-time oracle across residual offsets, carry/wrap and parallel boundaries |
| IGE selected its backend per block | Safe backend closure for each complete call | Independent IGE vector, chaining and hardware/software tests |
| CDN offsets differ from generic CTR addition | Checked `cdn256_iv` replaces the final four IV bytes | TDLib rule, byte-order fixtures, limits and full-stream/range equivalence |
| Mutable payload allocation could abort | Fallible reserve mapped to `MemoryError` | Isolated Linux address-space-limit regression, unchanged state and released exports |
| Invalid fixed arguments caused an unnecessary payload copy | Validate key/IV/state first | Python buffer-hook and invalid-argument cleanup regressions |
| Python support metadata stopped at 3.14 | Metadata, CI and wheel matrix through 3.15 | Real Python 3.15.2 extension and independently installed wheel |

The initial validation, before the executor reset, passed these checks on
Linux x86_64 with Rust 1.89.0 and AES 0.9.4:

| Check | Result |
| --- | --- |
| Rust release, hardware and forced-software backends | 23 unit + 7 integration tests on each backend; no ignored tests |
| CPython 3.15.2 and 3.14.10 | 34 passed on each; zero skipped |
| CPython 3.9.25 installed wheel | 33 passed, one expected Python 3.12+ buffer-hook skip |
| Rustfmt / Clippy / MSRV | All-targets/all-features checks passed on Rust 1.89, warnings denied |
| Wheel and source-distribution contents | New APIs/type files present; wheels declare `>=3.9,<3.16`; sdist contains `telegram.rs` |
| Strict Mypy 2.4.1 against installed 3.15 wheel | Valid calls pass; two deliberately invalid CBC/CDN calls rejected |
| Workflow validation | YAML/embedded Python parse; Actionlint 1.7.9 passed all three workflows |
| Lockfiles | `cargo fetch --locked` and `uv lock --check` passed |

After reconnection the platform restored the original checkout, without the
uncommitted changes. The implementation was recovered from recorded patches
and independently revalidated before commit/push. Historical benchmark reports
were recovered from tool output and labelled accordingly; original raw timing
samples are unavailable. See [PERFORMANCE.md](PERFORMANCE.md).

Fresh recovery checks passed: the same 30 core tests on both hardware and
forced-software AES, Rustfmt, Clippy with warnings denied, and frozen-lock
validation. Independently rebuilt/installed wheels passed 34 tests on Python
3.15.2 and 3.14.10; Python 3.9.25 passed 33 with the expected buffer-hook skip.
All three wheels include the native APIs/type files and correct Python bounds;
the rebuilt source distribution includes the new Telegram module and stubs.

The dependency/changelog review is in [DEPENDENCIES.md](DEPENDENCIES.md), and
the protocol contracts and pinned TDLib sources are in
[TELEGRAM.md](TELEGRAM.md). Telegram's web pages returned HTTP 403, so the review
used authoritative TDLib source. No live Telegram session was used. OS/ARM and
the complete Python matrix remain CI checks; free-threaded Python is outside
the tested matrix. The historical RustSec scan below does not cover the new
lockfile. These results do not constitute an independent cryptographic audit.

## Historical 2.0.0 review

This review covers TgCryptoRust 2.0.0, developed from
`bc33cf603f7742337d53ae125602a1836e8dc51e` and including the Python binding
follow-up. It is an implementation review with targeted tests, not an independent
cryptographic certification or a claim that every bug was found. Release
publication and CI outcomes are recorded by GitHub Actions; this document
separates local evidence from that cross-platform validation.

## Findings addressed

| Finding | Change | Regression evidence |
| --- | --- | --- |
| AES key expansion indexed an S-box with secret key bytes, including on the AES-NI path; software blocks used secret-indexed T tables | Replace both with RustCrypto AES 0.9.3, enable key zeroization, hide raw schedules | FIPS 197 and NIST SP 800-38A AES vectors on hardware and forced software |
| CTR wrote back into mutable Python buffers after releasing the GIL, assuming their original lengths | Export the buffers across the operation, check lengths defensively, release exports with RAII | Concurrent resize raises `BufferError`; error and success paths release exports |
| Native output allocation relied on raw Python pointers and unchecked casting | Use PyO3's safe bytes initializer and preserve panic isolation | Empty and one-byte output tests; complete Python API suite |
| Owned temporary key arrays and mutable snapshots were dropped without explicit clearing | Wrap these owned copies in `Zeroizing` | Type-level expanded-key zeroization check plus existing behavioral tests; no claim about all compiler copies |
| Runtime metadata reported compile-time AES feature rather than active hardware | Query RustCrypto's selected backend; expose `hardware_accelerated` and `backend` | Metadata consistency regression test |
| New backend's four-block batches missed its eight-block AES-NI processing path | Add eight-block CTR/CBC-decryption loops and keep shorter tails | Independent mode vectors and chunk/counter-boundary tests; measured comparisons in PERFORMANCE.md |
| Dependabot requested nonexistent labels and omitted GitHub Actions | Remove invalid label requirements; add action update checks | Configuration inspection and workflow validation |
| CI dependencies used movable action tags | Pin verified release commits and retain version comments; reduce token permissions | Actionlint and YAML validation |
| PR #10 changed the MSRV action to a commit whose default toolchain is stable | Accept the updated action and explicitly request `toolchain: 1.89.0`; assert the installed compiler version | Local Rust 1.89 check and the MSRV CI job |

## Dependency refresh

The crates.io sparse index was checked for the latest non-yanked stable direct
dependencies: PyO3 0.30.1, AES 0.9.3, zeroize 1.9.1, Rayon 1.12.0, Criterion
0.8.2. Maturin 1.16.0 was checked against PyPI. `cargo update` refreshes
transitive packages to the newest versions allowed by their dependency ranges;
it does not force incompatible transitive major versions. Lockfiles are saved.

AES 0.9.3 requires Rust 1.89. The Rust raw-schedule API removal is a breaking
change, so package metadata moves to 2.0.0. The Python API stays compatible.
Migration details are in the README and [CHANGELOG.md](../CHANGELOG.md).

## Validation

- Core release suite: 21 unit tests and 5 integration tests passed, on hardware
  and with `RUSTFLAGS='--cfg aes_backend="soft"'`.
- Python API, package, and ownership suite: 27 tests passed on Python 3.14.8
  and on separately built/installed Python 3.9.25 and 3.14.8 wheels.
- `cargo +1.89.0 check --all-targets --all-features --locked` passed.
- Rustfmt, Clippy with warnings denied, and Actionlint passed.
- `cargo audit` 0.22.2 examined 93 locked dependencies against 1,395 RustSec
  advisories, database commit `2295466c4e9df26647fd67d8fa1c705ac2fc7f81`:
  zero reported vulnerabilities and no warnings. Advisory coverage is limited
  to that database and does not assess this project's custom mode code.

The TDLib AES implementation in `tdutils/td/utils/crypto.cpp` was inspected for
IGE IV ordering and CTR streaming/counter semantics. The live
`core.telegram.org` documentation could not be fetched because the environment
proxy denied that destination. This is not an end-to-end TDLib or MTProto test.
No Telegram login, network transport, or schema implementation was added.

See [SECURITY.md](../SECURITY.md) for caller responsibilities and
[PERFORMANCE.md](PERFORMANCE.md) for the reproducible measurements and their
limits. Cross-platform runtime checks and the full Python CI matrix remain for
GitHub CI; the local environment runs Linux x86_64 only.

## Python API follow-up

The Python review keeps the entry points as direct native objects and
adds shipped PEP 561 stubs for both import names. CTR fixed-size key, IV, and
state snapshots now use arrays rather than three small `Vec` allocations. The
mutable key needs no retained export after copying; IV/state and mutable data
keep their buffer leases. IGE reuses one opaque encryption/decryption schedule.

The expanded Python suite has 27 tests and passes on separately installed
Python 3.9 and 3.14 wheels, including all fixed-argument mutability combinations,
residual offsets, invalid-input cleanup, subclasses, and an OpenSSL IGE vector.
Both wheels and the source distribution contain the typing files. Strict Mypy
checks pass for valid installed-package usage, and six invalid examples are
rejected as expected. Clippy and the Rust 1.89 all-targets/all-features check also
pass. See PYTHON.md and PERFORMANCE.md for usage and comparative measurements.

## Release checks

The release pipeline validates matching package versions and the tag's commit,
runs the reusable CI suite, and builds the native OS/ARM wheel matrices and
source distribution before publishing GitHub release assets. PyPI publishing
runs in the top-level `pypi.yml` workflow with the existing `pypi` environment
and trusted publishing; it does not rely on a bot-created release event to
start another workflow. See [RELEASING.md](RELEASING.md) for the procedure and
failure recovery. A queued or dispatched run is not evidence of a passing run.
