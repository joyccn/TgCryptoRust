# Changelog

## Unreleased

- Drop Python 3.9 support after the Ubuntu 26.04 setup-python compatibility
  failure. The supported range is now CPython 3.10–3.15; CI/release matrices
  and distribution checks cover 30 wheels plus one source distribution.
- Support CPython 3.15, including 3.15.2, with matching package metadata,
  classifiers, locked Python requirements and CI/wheel release matrices.
- Add native `Cbc256` aligned streaming and Rust CBC preexpanded-key helpers
  to reuse one AES schedule across chunks without changing one-shot APIs.
- Generate CTR counter batches with full-width wrapping arithmetic and select
  the IGE AES backend once per call, retaining hardware/software compatibility.
- Add `cdn256_iv` with explicit alignment/range validation for Telegram CDN
  offsets; replace the IV's final four bytes as required by the protocol.
- Validate fixed CTR arguments before copying mutable payloads and map
  fallible snapshot allocation failures to Python `MemoryError`.
- Update RustCrypto AES to 0.9.4, compatible locked transitive dependencies,
  and verified GitHub Action pins; retain Rust 1.89 as the minimum.
- Expand protocol, dependency/changelog and performance documentation, with
  additional known-answer, state, CDN and allocation regressions.

## 2.0.0 — 2026-10-31

### Security and correctness

- Replace custom AES S-box key expansion and software T tables with RustCrypto
  AES 0.9.3, using runtime hardware acceleration or a constant-time fixsliced
  software implementation. Expanded schedules remain zeroized on drop.
- Keep mutable CTR buffers exported through native processing and state
  write-back, preventing concurrent resize panics. Snapshot mutable inputs and
  zeroize owned secret copies.
- Use PyO3's safe output allocator and retain error/panic isolation.
- Add independent AES/CBC/CTR NIST vectors, OpenSSL IGE vectors, counter/chunk
  boundaries, ownership, validation, and concurrency regression coverage.

### Python API and performance

- Retain the public `tgcryptors` API and `tgcrypto` compatibility imports, with
  direct native exports and PEP 561 type hints for both packages.
- Process eight independent CTR/CBC-decryption blocks per AES batch and avoid
  GIL release overhead for calls below 16 KiB.
- Replace small mutable CTR key/IV/state heap snapshots with fixed-size arrays.
  Reuse one IGE expanded key for both encryption and decryption.
- Report the selected `backend` and `hardware_accelerated` status accurately.
  `aesni` now describes active x86 hardware AES rather than a compile-time flag.
- Publish reproducible benchmark scripts and before/after measurements. Results
  depend on input size, mutability, CPU, and scheduling; not every sample improved.

### Breaking Rust changes

- Minimum Rust is now 1.89; Python support remains CPython 3.9–3.14.
- Remove exposed raw key schedules and helpers: `ExpandedKey.words`,
  `set_encryption_key`, `set_decryption_key`, `encrypt_block_soft`,
  `decrypt_block_soft`, and the `ExpandedKey` `Zeroize` implementation. Use the
  opaque key constructors and block/mode APIs. Automatic drop zeroization remains.
- Retain `aesni` and `neon` as compatibility flags; backend selection is automatic.
  Use `RUSTFLAGS='--cfg aes_backend="soft"'` to test software AES explicitly.

### Dependencies and delivery

- Update PyO3 to 0.30.1, zeroize to 1.9.1, Maturin minimum to 1.16.0, and refresh
  compatible transitive dependencies and pinned GitHub Actions.
- Merge PR #10's Rust toolchain action update while explicitly retaining Rust
  1.89.0 for MSRV validation.
- Gate release artifacts on the full CI suite and version/tag checks, then use
  GitHub trusted publishing for PyPI. See [release procedure](docs/RELEASING.md).

See [migration guidance](README.md#migrating-to-20), [security scope](SECURITY.md),
[validation evidence](docs/AUDIT.md), and [benchmarks](docs/PERFORMANCE.md).

## 1.3.1

- Accept `bytes` and `bytearray` in CTR functions; mutable IV/state advance in
  place for TgCrypto-compatible transport streaming.

## 1.3.0

- Raise the previous minimum Rust version to 1.86.
- Use zeroize for expanded keys, refresh PyO3 configuration, and add MSRV CI.
- Change the project license to MIT.
