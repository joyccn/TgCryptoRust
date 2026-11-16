"""Native AES-256 operations and reusable CTR/IGE/CBC streams.

Public names refer directly to the Rust extension, without Python forwarding
functions. Reuse ``Ctr256``, ``Ige256`` or ``Cbc256`` for chunks of one logical stream to
avoid expanding its key for each call. Each independent stream needs its own
key/IV state; never reuse a CTR keystream for different plaintext.
"""

from ._native import (  # noqa: F401
    Cbc256,
    Ctr256,
    Ige256,
    __version__,
    cbc256_decrypt,
    cbc256_encrypt,
    cdn256_iv,
    ctr256_decrypt,
    ctr256_encrypt,
    ige256_decrypt,
    ige256_encrypt,
    runtime_info,
)

__all__ = [
    "__version__",
    "ige256_encrypt",
    "ige256_decrypt",
    "ctr256_encrypt",
    "ctr256_decrypt",
    "cbc256_encrypt",
    "cbc256_decrypt",
    "cdn256_iv",
    "runtime_info",
    "Ctr256",
    "Ige256",
    "Cbc256",
]
