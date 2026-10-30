# TgCryptoRust

> [!NOTE]
> This project is provided for educational and experimental purposes. The
> implementation follows public AES specifications and is tested against known
> vectors, but it has not received a formal third-party security audit. Do not
> treat it as a certified cryptographic module.

Rust-powered, AES-NI accelerated cryptography for Telegram clients.

[![CI](https://github.com/joyccn/TgCryptoRust/actions/workflows/ci.yml/badge.svg)](https://github.com/joyccn/TgCryptoRust/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9--3.14-brightgreen)
![Rust](https://img.shields.io/badge/rust-1.89%2B-orange)

**TgCryptoRust** is a drop-in replacement for [TgCrypto](https://github.com/pyrogram/tgcrypto),
implemented in Rust and packaged for Python through PyO3 and Maturin.
It implements the cryptographic algorithms Telegram requires, namely:

- **`AES-256-IGE`** — used in [MTProto v2.0](https://core.telegram.org/mtproto).
- **`AES-256-CTR`** — used for [CDN encrypted files](https://core.telegram.org/cdn).
- **`AES-256-CBC`** — used for [encrypted passport credentials](https://core.telegram.org/passport).

## Requirements

- Python 3.9 through 3.14
- Rust 1.89+ (only when building from source)

Prebuilt wheels are available for common desktop and server platforms.
Rust is only required when a wheel is not available for your platform.

## Installation

```bash
pip install TgCryptoRust
```

Or with `uv`:

```bash
uv add TgCryptoRust
uv sync
```

## API

```python
def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...

def ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...
def ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: bytes) -> bytes: ...

def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
```

## Usage

### IGE Mode

**Note**: Data must be padded to a multiple of the block size (16 bytes).

```python
import os
import tgcrypto

data = os.urandom(1024)
key = os.urandom(32)
iv = os.urandom(32)

encrypted = tgcrypto.ige256_encrypt(data, key, iv)
decrypted = tgcrypto.ige256_decrypt(encrypted, key, iv)

assert decrypted == data
```

### CTR Mode

CTR accepts arbitrary-length data. The `state` argument is a one-byte offset
inside the current keystream block, kept for TgCrypto compatibility.

```python
import os
import tgcryptors

data = os.urandom(1000)
key = os.urandom(32)
iv = os.urandom(16)
state = b"\x00"

encrypted = tgcryptors.ctr256_encrypt(data, key, iv, state)
decrypted = tgcryptors.ctr256_decrypt(encrypted, key, iv, state)

assert decrypted == data
```

TgCrypto-compatible `bytearray` mode: `data`, `key`, `iv`, and `state` may also
be passed as `bytearray`. When `iv` or `state` are `bytearray`, they are
updated **in place** — after the call they hold the advanced counter and
residual offset, so passing the same objects to the next call continues the
stream across chunks. This is how pyrogram and its forks (kurigram, pyrofork,
...) drive the obfuscated TCP transports and CDN file downloads:

```python
import os
import tgcrypto

key = os.urandom(32)
iv = bytearray(os.urandom(16))
state = bytearray(1)

first = tgcrypto.ctr256_encrypt(data[:100], key, iv, state)   # iv/state advance in place
second = tgcrypto.ctr256_encrypt(data[100:], key, iv, state)   # continues the stream
```

Passing plain `bytes` behaves as a stateless one-shot call.

### CBC Mode

**Note**: Data must be padded to a multiple of the block size (16 bytes).

```python
import os
import tgcrypto

data = os.urandom(1024)
key = os.urandom(32)
iv = os.urandom(16)

encrypted = tgcrypto.cbc256_encrypt(data, key, iv)
decrypted = tgcrypto.cbc256_decrypt(encrypted, key, iv)

assert decrypted == data
```

### Streaming API

Use the streaming classes when processing one logical stream in chunks.
The key schedule is expanded once and reused.

```python
import os
import tgcryptors

key = os.urandom(32)
iv = os.urandom(16)
data = os.urandom(1024)

stream = tgcryptors.Ctr256(key, iv)
encrypted = stream.update(data[:300]) + stream.update(data[300:])
```

IGE streaming is also available for block-aligned chunks:

```python
import os
import tgcrypto

key = os.urandom(32)
iv = os.urandom(32)
data = os.urandom(1024)

stream = tgcrypto.Ige256(key, iv)
encrypted = stream.encrypt(data[:512]) + stream.encrypt(data[512:])
```

### Runtime Metadata

```python
import tgcryptors

print(tgcryptors.__version__)
print(tgcryptors.runtime_info())
```

## Imports

Existing TgCrypto users can keep importing `tgcrypto`:

```python
import tgcrypto
```

New code can import the branded module directly:

```python
import tgcryptors
```

Both modules expose the same API.

## Compatibility

TgCryptoRust is a full drop-in replacement. All function names, argument orders,
return types, and validation behavior match the original TgCrypto:

| Function | Arguments |
|----------|-----------|
| `ige256_encrypt` | `(data, key, iv)` |
| `ige256_decrypt` | `(data, key, iv)` |
| `ctr256_encrypt` | `(data, key, iv, state)` |
| `ctr256_decrypt` | `(data, key, iv, state)` |
| `cbc256_encrypt` | `(data, key, iv)` |
| `cbc256_decrypt` | `(data, key, iv)` |

## Architecture

- **`tgcryptors-core`** — Rust AES primitive and Telegram block modes (IGE, CTR, CBC).
- **`tgcryptors-python`** — PyO3 extension module exposing the native API.
- **`python/tgcrypto`** — Compatibility shim re-exporting `tgcryptors` for existing imports.
- **`tests/`** — Python unit tests covering the public API.

RustCrypto AES selects AES-NI on supported x86 CPUs and ARM AES instructions on
supported ARM CPUs at runtime. Other platforms use a constant-time fixsliced
software implementation, including during key expansion. Expanded keys are
zeroized on drop. `runtime_info()` reports the selected backend and whether
hardware acceleration is active.

See [security and protocol boundaries](SECURITY.md) before integrating these
primitives. This package supplies AES modes, not a complete Telegram/TDLib client.

See the [Python performance guide](docs/PYTHON.md) for choosing stream APIs and
avoiding copies. Both Python import names ship type hints (`py.typed`) while
continuing to call native functions directly.

## Migrating to 2.0

The Python API and `tgcrypto` compatibility imports are retained. Minimum Rust is
now 1.89, required by the updated AES dependency. Rust callers must migrate from
raw schedules (`ExpandedKey.words`, `set_encryption_key`, `set_decryption_key`,
`encrypt_block_soft`, `decrypt_block_soft`, and the `ExpandedKey` `Zeroize` trait)
to `ExpandedKey::new_encrypt` / `new_decrypt` and the block or mode APIs. Key
schedules remain zeroized automatically when dropped.

The Cargo `aesni` and `neon` features remain accepted as compatibility flags;
hardware selection is automatic even with `--no-default-features`. To exercise
the software implementation explicitly:

```bash
RUSTFLAGS='--cfg aes_backend="soft"' cargo test -p tgcryptors-core --release --locked
```

`runtime_info()["aesni"]` now reflects active x86 hardware acceleration rather
than a compile-time feature. The new `hardware_accelerated` and `backend` keys
also cover ARM and forced software builds. Mutable CTR buffers are exported for
the duration of an operation: resizing them concurrently raises `BufferError`.
Synchronize callers that share mutable IV/state objects.

## Migrating From TgrCrypto

`TgrCrypto` is deprecated in favor of `TgCryptoRust`.

```bash
pip uninstall TgrCrypto
pip install TgCryptoRust
```

Existing code that imports `tgcrypto` can remain unchanged.

## Development

```bash
# Set up environment
uv sync --frozen --python 3.14

# Build and install the native module
uv run --with "maturin[patchelf]==1.16.0" maturin develop --release --locked

# Run Python tests
.venv/bin/python -m unittest discover -s tests -v
```

Run the Rust checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test -p tgcryptors-core --release --locked
```

Build a wheel:

```bash
uv build --wheel
```

## Changelog

### 2.0.0 (unreleased)

- Ship precise Python type hints for both import names without runtime wrappers.
- Remove small CTR key/IV/state heap snapshots and share the IGE encryption/
  decryption schedule; retain mutable state exports and key zeroization.

- Update PyO3 to 0.30.1, RustCrypto AES to 0.9.3, zeroize to 1.9.1, Maturin
  minimum to 1.16.0, and refresh transitive dependencies and CI actions.
- Replace secret-indexed AES tables and key expansion with hardware AES or
  constant-time software AES; keep backend schedules private and zeroize on drop.
- Pin mutable Python buffers during native calls, use PyO3's safe bytes
  allocator, and zeroize owned temporary key/mutable-input copies.
- Avoid GIL release overhead for inputs smaller than 16 KiB; add representative
  transport-size and preexpanded-key benchmarks.
- Add independent NIST/OpenSSL vectors, CTR counter/chunk boundary tests, and
  Python concurrency/ownership regression coverage; test software AES in CI.


### 1.3.1

- `ctr256_encrypt`/`ctr256_decrypt` now accept `bytearray` (and `bytes`) for
  `data`, `key`, `iv`, and `state`. When `iv` or `state` are passed as
  `bytearray`, the advanced counter and residual byte offset are written back
  in place, matching TgCrypto's stateful semantics. This fixes a crash at
  connect time with pyrogram and its forks, whose obfuscated TCP transports
  and CDN downloads pass `bytearray` and rely on the in-place carry (issue #4).

### 1.3.0

- Bumped MSRV from Rust 1.83 to 1.86.
- Replaced manual key zeroization with the `zeroize` crate for guaranteed
  compiler-resistant memory clearing.
- Removed deprecated `generate-import-lib` feature (no-op since PyO3 0.29).
- Added CI job to verify MSRV compliance.
- Fixed clippy warnings and imprecise documentation comments.
- Changed license from LGPLv3+ to MIT.

## License

[MIT](LICENSE) — Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software.

© 2026-Present Joy.
