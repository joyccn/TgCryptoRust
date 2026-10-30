# Python API and performance

`tgcryptors` and the `tgcrypto` compatibility package export the same native
functions and classes. Calls go directly to Rust; neither package adds Python
forwarding functions. Version 2.0.0 ships PEP 561 type information in both
packages, including precise accepted input types and runtime metadata fields.

## Input and state contract

| API | Input types | Key / IV lengths | State |
| --- | --- | --- | --- |
| IGE functions | `bytes` | 32 / 32 bytes | Independent one-shot call; input must be a multiple of 16 bytes |
| CBC functions | `bytes` | 32 / 16 bytes | Independent one-shot call; input must be a multiple of 16 bytes |
| CTR functions | `bytes` or `bytearray` for each argument | 32 / 16 bytes | One byte in `0..15`; mutable IV/state advance in place |
| `Ctr256` | `bytes` constructor arguments and update data | 32 / 16 bytes | Object retains counter and byte offset |
| `Ige256` | `bytes` constructor arguments and chunk data | 32 / 32 bytes | Object retains chaining state; chunks must be block aligned |

Every cipher operation returns immutable `bytes`. Empty input is accepted;
padding is never added or stripped. Convert other buffer types explicitly when
needed. In particular, `memoryview` is not an accepted input type, and passing a
`bytearray` to IGE/CBC functions or stream methods raises `TypeError`.

## Choose the API for the workload

| Workload | API | State and allocation |
| --- | --- | --- |
| One independent message | `ige256_encrypt`, `cbc256_encrypt`, or `ctr256_encrypt` | Expands the key per call and returns new `bytes` |
| Chunks of one CTR stream | `Ctr256.update` | Reuses one expanded key and retains counter/offset |
| Block-aligned chunks of one IGE stream | `Ige256.encrypt` or `.decrypt` | Reuses one expanded key and retains chaining state |
| Existing TgCrypto transport code | CTR functions with mutable IV/state | Writes the advanced counter/offset back to `bytearray` |

Use separate objects for independent streams and encryption/decryption
directions. Reusing an existing stream object for an unrelated message changes
the ciphertext; reusing a CTR keystream for different plaintext is insecure.

```python
import tgcryptors

# key and iv must come from the appropriate protocol derivation.
def encrypt_chunks(key: bytes, iv: bytes, chunks: list[bytes]) -> list[bytes]:
    stream = tgcryptors.Ctr256(key, iv)
    return [stream.update(chunk) for chunk in chunks]
```

The complete stream surface is `Ctr256(key, iv).update(data)` and
`Ige256(key, iv).encrypt(data)` / `.decrypt(data)`. Construct a fresh decoder
with the original IV to decrypt the resulting stream; a stream that has already
advanced is not a fresh decoder. Do not switch IGE directions on one object.

## Avoid unnecessary copies

For CTR, pass immutable `bytes` for data and keys when possible. They are read
without copying the input. Mutable `bytearray` data requires a snapshot because
Python threads may overwrite it while native work runs. That copy remains
intentional; removing it would compromise memory safety.

The CTR key, counter, and one-byte offset are copied directly into fixed-size
Rust arrays. Mutable IV/state retain buffer exports through write-back, so they
cannot be resized during an operation. Key snapshots do not need an export
after copying. Caller-owned key buffers are not cleared by the library.

Output allocation and initialization, plus zeroization of owned secret copies,
remain enabled. The library cannot erase caller-owned immutable keys or all
compiler/register copies. Reusing a stream avoids repeated key expansion, but
does not remove output allocation or make arbitrary input buffers zero-copy.

## Concurrency and bulk data

Operations below 16 KiB stay attached to Python to avoid GIL transition costs.
Operations of at least 16 KiB release the GIL. CTR and CBC decryption can also
use Rayon for sufficiently large buffers. CBC encryption and IGE chaining
cannot be parallelized in the same way.

Do not concurrently mutate shared IV/state or use one stream object from
overlapping operations. Buffer exports prevent resizing, not in-place content
changes. Use independent stream objects for independent work.

Rayon thread counts are a deployment choice. If benchmarking shows a benefit,
set `RAYON_NUM_THREADS` before the process first uses the Rayon pool. More
threads do not guarantee lower latency for small messages. Check
`tgcryptors.runtime_info()` for the selected hardware/software AES backend.

## Diagnostics and validation

`runtime_info()` returns `version`, `crate_version`, `implementation`, `aesni`,
`hardware_accelerated`, and `backend`. The implementation is `"rust"`; the
backend is `"rustcrypto-hardware"` or `"rustcrypto-fixslice"`. `aesni` describes
active x86 hardware acceleration, while `hardware_accelerated` also covers ARM.
Checking metadata once during startup is sufficient; it is not needed per chunk.

From a built source checkout, run the 27 Python tests with:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Coverage includes native export identity, both import names, input validation,
all combinations of CTR mutable/immutable arguments, independent known-answer
vectors, streaming continuity, and buffer lifetime regressions. Type hints are
also checked against representative valid and invalid calls. These checks do
not establish end-to-end Telegram authentication or TDLib compatibility.

See [PERFORMANCE.md](PERFORMANCE.md) for measurements and reproduction
commands, and [SECURITY.md](../SECURITY.md) for protocol responsibilities.
