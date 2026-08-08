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
![Rust](https://img.shields.io/badge/rust-1.86%2B-orange)

**TgCryptoRust** is a drop-in replacement for [TgCrypto](https://github.com/pyrogram/tgcrypto),
implemented in Rust and packaged for Python through PyO3 and Maturin.
It implements the cryptographic algorithms Telegram requires, namely:

- **`AES-256-IGE`** — used in [MTProto v2.0](https://core.telegram.org/mtproto).
- **`AES-256-CTR`** — used for [CDN encrypted files](https://core.telegram.org/cdn).
- **`AES-256-CBC`** — used for [encrypted passport credentials](https://core.telegram.org/passport).

## Requirements

- Python 3.9 through 3.14
- Rust 1.86+ (only when building from source)

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

On x86 and x86_64, AES-NI is detected at runtime when the crate is built with
the default `aesni` feature. Other targets use a software fallback (T-table based,
not guaranteed constant-time on every CPU).

Expanded key material is zeroized on drop using the [`zeroize`](https://crates.io/crates/zeroize)
crate, which guarantees the compiler will not optimize away the clearing.

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
uv sync --python 3.14

# Build and install the native module
uv run maturin develop --release

# Run Python tests
.venv/bin/python -m unittest discover -s tests -v
```

Run the Rust checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
```

Build a wheel:

```bash
uv build --wheel
```

## Changelog

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

© 2025-Present Joy.
