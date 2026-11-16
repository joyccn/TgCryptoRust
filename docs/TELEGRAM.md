# Telegram cipher contracts

TgCryptoRust supplies AES-256 modes and a CDN IV-construction helper. A Telegram
client still supplies the correct keys, protocol framing, randomness, integrity
checks and session state. The same AES primitive appears in several Telegram
protocols with different derivations and validation rules.

| Use | Primitive | Parameters | Validation outside this library |
| --- | --- | --- | --- |
| MTProto 2 encrypted messages | AES-256-IGE | Direction-derived 32-byte key and 32-byte IV | Message key, framing, padding, session, message ID, sequence and replay checks |
| Stateful transport encryption | AES-256-CTR | Transport-derived 32-byte key, 16-byte counter and residual byte offset | Transport handshake/framing and the enclosing protocol's authentication |
| CDN file ranges | AES-256-CTR | Server key and IV with a range-specific 32-bit counter suffix | Plaintext SHA-256 against trusted origin-supplied `fileHash` ranges |
| Passport secure values | AES-256-CBC | Key/IV derived from the value secret and value hash | Random-prefix structure and SHA-256 of the complete padded plaintext |

The modes add no padding and provide no independent authenticity. A successful
decryption call means that the cipher operation completed; it does not approve
the resulting bytes for use by an application.

## IGE state and MTProto 2

IGE uses a 32-byte IV containing two 16-byte blocks:

```text
iv = previous_ciphertext || previous_plaintext
C[i] = AES(key, P[i] XOR C[i-1]) XOR P[i-1]
P[i] = AES_inverse(key, C[i] XOR P[i-1]) XOR C[i-1]
```

Both chaining blocks advance after each block. Reversing their order produces
different ciphertext. Rust `_into` APIs update their IV; Python one-shot IGE
functions use a private IV copy. `Ige256` retains both blocks between calls.
Use separate objects for encryption and decryption and a fresh derived IV for
each independent MTProto message.

For MTProto 2, the client-to-server direction uses `x = 0`; server-to-client
uses `x = 8`. With a Telegram authorization key and the received/generated
16-byte `msg_key`, the SHA-256 derivation is:

```text
a = SHA256(msg_key || auth_key[x : x+36])
b = SHA256(auth_key[40+x : 76+x] || msg_key)
aes_key = a[0:8] || b[8:24] || a[24:32]
aes_iv  = b[0:8] || a[8:24] || b[24:32]

msg_key = SHA256(auth_key[88+x : 120+x] || padded_plaintext)[8:24]
```

Here `padded_plaintext` includes the salt, session ID, message ID, sequence
number, body length, body and random padding. Padding contains 12 through 1024
bytes, and the complete plaintext must align to 16 bytes. The serialized body
length must align to four bytes. MTProto padding is not PKCS#7 and is included
when recomputing `msg_key`.

An implementation receiving a message must check the message key using a
constant-time comparison, then validate lengths, padding, session/salt, message
ID/time/direction, sequence and replay rules before dispatching the body. Do
not substitute a cipher round-trip test for these checks. This library does not
expose a partial `pack_message`/`unpack_message` API that would imply that those
checks have been performed.

## Generic CTR and TgCrypto compatibility

Generic CTR encrypts successive big-endian 128-bit counter blocks. Its one-byte
`state` is the next offset within the current 16-byte keystream block, in
`0..15`. A partially consumed block retains its current counter; finishing that
block increments the counter with carry across all 16 bytes and resets the
offset to zero. Preserve both the counter and offset when splitting a stream.

Python CTR functions accept `bytes` or `bytearray` independently for data, key,
IV and state. Mutable IV/state advance in place; immutable IV/state make a
one-shot call. If only one carry argument is mutable, the caller must preserve
the other carry component itself. `Ctr256.update` keeps the complete carry
internally and expands its key once.

Mutable payloads are snapshotted before native processing. Buffer exports pin
mutable data and carry buffers until the operation/write-back ends; they
prevent resizing, not another thread overwriting existing bytes. Synchronize
shared carry buffers and avoid overlapping calls on a stream object.

The generic low-level API preserves TgCrypto's wrapping-counter behavior.
Callers must prevent counter-space exhaustion and must never use the same
key/counter keystream for different plaintexts. Backend acceleration and Rayon
parallelism do not change the stream's counter ordering.

## CDN file ranges

Telegram CDN ranges have a specific IV rule. For an aligned starting byte
offset, retain the server IV's first 12 bytes and **replace** its last four
bytes with the big-endian integer `offset // 16`. Adding that number to the
original server IV tail is incorrect.

```python
import tgcryptors

def decrypt_cdn_range(ciphertext: bytes, key: bytes, server_iv: bytes,
                      offset: int) -> bytes:
    if offset + len(ciphertext) > 2**36:
        raise ValueError("CDN range exceeds its counter space")
    iv = tgcryptors.cdn256_iv(server_iv, offset)
    return tgcryptors.ctr256_decrypt(ciphertext, key, iv, b"\0")
```

`cdn256_iv` validates a 16-byte IV, a nonnegative aligned offset, and a block
index representable as `u32`: `0 <= offset < 2**36` and `offset % 16 == 0`.
The Rust helper returns `Result<[u8; 16], CdnOffsetError>`. Python raises
`ValueError` for invalid alignment/counter-domain/IV length and `OverflowError`
when an offset cannot be represented as an unsigned 64-bit integer.

The helper validates the starting offset, not the complete download length.
Keep `offset + len(ciphertext) <= 2**36` for the range. A final chunk can have
an arbitrary length; a request starting inside a block must fetch/decrypt from
an aligned boundary and discard its leading bytes.

The example only performs decryption. Buffer the relevant plaintext range and
verify SHA-256 against authenticated origin-supplied `fileHash` metadata before
consuming it. Hash ranges and download chunks can have different boundaries;
an arbitrary chunk cannot be validated using a hash of a larger range alone.
Handle redirects, reuploads, hash retrieval and retries at the client layer.

## Passport CBC

Passport value encryption uses a random prefix followed by the value:

```text
padded_value = random_prefix || value
value_hash = SHA256(padded_value)
material = SHA512(value_secret || value_hash)
aes_key = material[0:32]
aes_iv  = material[32:48]
ciphertext = AES_256_CBC(aes_key, aes_iv, padded_value)
```

The prefix's first byte encodes its complete length, including that byte.
The documented prefix-length domain is 32 through 255; choose a prefix length
that makes the complete plaintext a multiple of 16 bytes. TDLib's generator
uses a random 32–47-byte prefix for that alignment. No PKCS#7 padding is added
or removed by CBC.

After decrypting, check the prefix length and payload bounds and verify the
SHA-256 of the complete padded value against its trusted hash before returning
the value. Deriving or wrapping the value secret with a password is a separate
operation; do not reuse the value-encryption derivation for it.

`Cbc256(key, iv).encrypt` and `.decrypt` amortize key expansion across aligned
chunks of one value. An invalid-length chunk leaves the stream state unchanged.
Use separate instances for the two directions; create a fresh instance with
the appropriate IV for each independent value. These stream methods neither
construct the Passport prefix nor verify its hash.

## Reference review and scope

The review inspected [WarpCrypto 2.2.0 at `d6adf6fd`](https://github.com/rjriajul/WarpCrypto/tree/d6adf6fd4d02b5881d8d6c5538c33444c23f5109)
for backend dispatch, stream/key reuse and API coverage. Its Apache-2.0 license
and NOTICE requirements apply to copied or derived source. The changes here
were implemented independently; WarpCrypto source was not copied. Its broader
MTProto packing/KDF surface does not establish complete protocol validation in
this library.

The live Telegram specification pages were denied by the development network
proxy. Protocol details above were cross-checked with authoritative TDLib source
at a fixed revision; this review is not a live Telegram interoperability test:

- [IGE and generic AES modes](https://github.com/tdlib/td/blob/c8828d50f5eac2fc7089ce1089d7ce9095c61b5e/tdutils/td/utils/crypto.cpp#L465)
- [MTProto 2 KDF](https://github.com/tdlib/td/blob/c8828d50f5eac2fc7089ce1089d7ce9095c61b5e/td/mtproto/KDF.cpp#L76)
- [MTProto message authentication and padding](https://github.com/tdlib/td/blob/c8828d50f5eac2fc7089ce1089d7ce9095c61b5e/td/mtproto/Transport.cpp#L215)
- [CDN counter construction](https://github.com/tdlib/td/blob/c8828d50f5eac2fc7089ce1089d7ce9095c61b5e/td/telegram/files/FileDownloader.cpp#L255)
- [CDN hash verification](https://github.com/tdlib/td/blob/c8828d50f5eac2fc7089ce1089d7ce9095c61b5e/td/telegram/files/FileDownloader.cpp#L330)
- [Passport secure storage](https://github.com/tdlib/td/blob/c8828d50f5eac2fc7089ce1089d7ce9095c61b5e/td/telegram/SecureStorage.cpp#L340)

Published specifications remain the integration references:
[MTProto 2](https://core.telegram.org/mtproto/description),
[CDN](https://core.telegram.org/cdn), and
[Passport](https://core.telegram.org/passport/encryption).
See [SECURITY.md](../SECURITY.md) for implementation limits and
[AUDIT.md](AUDIT.md) for the local validation evidence.
