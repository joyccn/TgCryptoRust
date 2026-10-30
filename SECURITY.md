# Security and Telegram compatibility

TgCryptoRust provides AES-256 block primitives and IGE, CTR, and CBC modes. It
does not implement MTProto sessions, key exchange, TL schemas, or TDLib's API.
Adding schema constructors would not authenticate ciphertext or make these
primitives a complete Telegram client.

## Implementation

Version 2.0 replaces the custom secret-indexed AES S-box key expansion and
software T tables with RustCrypto AES. The dependency selects hardware AES on
supported CPUs or its constant-time fixsliced software implementation. This
removes those table-based cache-timing paths; it is not a formal security audit
or a guarantee against every hardware or application side channel.

Expanded AES schedules and owned temporary key copies are zeroized when dropped.
The library cannot erase caller-owned Python `bytes`, all compiler/register
copies, returned plaintext, swap, or crash dumps. Keep key lifetimes short and
protect process memory in the application.

Python `bytearray` arguments are snapshotted before native processing. Mutable
IV/state and data retain buffer exports that prevent resizing during processing
and CTR state write-back. Small key snapshots use fixed-size arrays; after a key
has been copied, its caller-owned buffer need not remain exported.
Do not share a stream object or mutable CTR IV/state between unsynchronized
operations. Exports do not prevent another thread overwriting existing bytes.

## Protocol responsibilities

- IGE and CBC require block-aligned input; padding is the caller's responsibility.
- CTR accepts any length and carries a big-endian 128-bit counter plus a byte
  offset. Never reuse a key/counter keystream for different plaintext. The
  low-level API preserves TgCrypto's counter wrap semantics; callers must ensure
  a stream cannot exhaust its counter space.
- These modes provide no standalone integrity or authenticity. Verify MTProto
  message keys, padding rules, session/message identifiers, and replay/time
  checks at the protocol layer. Do not expose unauthenticated plaintext.
- Use separate encryption/decryption stream objects initialized with the proper
  direction-specific key and IV. Do not mix directions on an IGE state.
- Telegram CDN transport, Passport data, and MTProto messages have different
  derivation and validation rules; an AES key must come from the correct one.

Reference specifications and implementation:

- [MTProto 2.0 description](https://core.telegram.org/mtproto/description)
- [Telegram CDN encryption](https://core.telegram.org/cdn)
- [Telegram Passport encryption](https://core.telegram.org/passport/encryption)
- [TDLib AES modes](https://github.com/tdlib/td/blob/master/tdutils/td/utils/crypto.cpp)
- [NIST SP 800-38A mode vectors](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [RustCrypto AES](https://github.com/RustCrypto/block-ciphers/tree/master/aes)

Tests cover published AES/CBC/CTR known-answer vectors, an independently generated
OpenSSL AES-256-IGE vector, streaming boundaries, counter carries, parallel chunk
boundaries, and mutable Python buffer ownership. Passing them establishes these
specific behaviors, not complete MTProto or TDLib interoperability.

## Reporting

Report suspected vulnerabilities privately through GitHub's repository security
advisories when available. Avoid publishing keys, tokens, or exploitable details
in a public issue before maintainers can assess the report.
