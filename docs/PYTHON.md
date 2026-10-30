# Python API and performance

`tgcryptors` and the `tgcrypto` compatibility package export the same native
functions and classes. Calls go directly to Rust; neither package adds Python
forwarding functions. Both packages ship PEP 561 type information.

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

## Avoid unnecessary copies

For CTR, pass immutable `bytes` for data and keys when possible. They are read
without copying the input. Mutable `bytearray` data requires a snapshot because
Python threads may overwrite it while native work runs. That copy remains
intentional; removing it would compromise memory safety.

The CTR key, counter, and one-byte offset are copied directly into fixed-size
Rust arrays. Mutable IV/state retain buffer exports through write-back, so they
cannot be resized during an operation. Key snapshots do not need an export
after copying. Caller-owned key buffers are not cleared by the library.

The return value is always a fresh `bytes` object, except that Python may reuse
its immutable empty value. Output allocation, initialization, and zeroization
of owned secret copies remain enabled. IGE/CBC functions and stream methods
accept `bytes`; use `bytes(value)` explicitly if a conversion is required.

## Concurrency and bulk data

Operations below 16 KiB stay attached to Python to avoid GIL transition costs.
Larger operations release the GIL. CTR and CBC decryption can also use Rayon
for sufficiently large buffers; encryption modes with chaining dependencies
cannot be parallelized in the same way.

Do not concurrently mutate shared IV/state or use one stream object from
overlapping operations. Buffer exports prevent resizing, not in-place content
changes. Use independent stream objects for independent work.

Rayon thread counts are a deployment choice. If benchmarking shows a benefit,
set `RAYON_NUM_THREADS` before the process first uses the Rayon pool. More
threads do not guarantee lower latency for small messages. Check
`tgcryptors.runtime_info()` for the selected hardware/software AES backend.

See [PERFORMANCE.md](PERFORMANCE.md) for measurements and reproduction
commands, and [SECURITY.md](../SECURITY.md) for protocol responsibilities.
