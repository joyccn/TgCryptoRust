# TgCryptoRS

Rust-powered, AES-NI accelerated cryptography for Telegram clients.

[![CI](https://github.com/joyccn/TgCryptoRS/actions/workflows/ci.yml/badge.svg)](https://github.com/joyccn/TgCryptoRS/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-LGPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.9--3.14-brightgreen)
![Rust](https://img.shields.io/badge/rust-1.83%2B-orange)

TgCryptoRS is a drop-in replacement for TgCrypto, implemented in Rust and
packaged for Python through PyO3 and maturin. It provides the Telegram-focused
AES-256 modes used by MTProto clients:

- AES-256-IGE for MTProto message encryption
- AES-256-CTR for CDN file encryption
- AES-256-CBC for Telegram Passport credentials

> [!IMPORTANT]
> This project is provided for educational and experimental purposes. The
> implementation follows public AES specifications and is tested against known
> vectors, but it has not received a formal third-party security audit. Do not
> treat it as a certified cryptographic module.

## Requirements

- Python 3.9 through 3.14
- Rust 1.83 or newer when building from source

Prebuilt wheels are intended for common desktop and server platforms. Rust is
only required when a wheel is not available for your platform or when you are
developing the project locally.

## Installation

```bash
uv add TgCryptoRS
uv pip install TgCryptoRS
pip install TgCryptoRS
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

## Usage

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
inside the current keystream block and is kept for TgCrypto compatibility.

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

CBC input must be aligned to 16-byte AES blocks.

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

## Streaming API

Use the streaming classes when processing one logical stream in chunks. The key
schedule is expanded once and reused.

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

## Compatibility

TgCryptoRS keeps the TgCrypto-compatible function names, argument order, return
types, and validation behavior for:

- `ige256_encrypt(data, key, iv)`
- `ige256_decrypt(data, key, iv)`
- `ctr256_encrypt(data, key, iv, state)`
- `ctr256_decrypt(data, key, iv, state)`
- `cbc256_encrypt(data, key, iv)`
- `cbc256_decrypt(data, key, iv)`

The PyPI package name is `TgCryptoRS`. The native module is `tgcryptors`, and
the compatibility module is `tgcrypto`.

## Runtime Metadata

```python
import tgcryptors

print(tgcryptors.__version__)
print(tgcryptors.runtime_info())
```

## Development

```bash
uv sync --python 3.14
uv run maturin develop --release
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

## Architecture

- `tgcryptors-core` contains the Rust AES primitive and Telegram block modes.
- `tgcryptors-python` exposes the PyO3 extension module.
- `python/tgcrypto.py` re-exports `tgcryptors` for TgCrypto compatibility.
- `tests/` covers the public Python API and import compatibility.

On x86 and x86_64, AES-NI is detected at runtime when the crate is built with
the default `aesni` feature. Other targets use the software fallback. The
software fallback uses table lookups and is not guaranteed to be constant-time
on every CPU.

## Migration From TgrCrypto

`TgrCrypto` is deprecated in favor of `TgCryptoRS`.

```bash
pip uninstall TgrCrypto
pip install TgCryptoRS
```

Existing code that imports `tgcrypto` can remain unchanged.

## License

LGPL-3.0-or-later. See [COPYING](COPYING) and
[COPYING.lesser](COPYING.lesser).
