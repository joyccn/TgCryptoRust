"""Native AES-256 operations and reusable CTR/IGE streams.

Public names refer directly to the Rust extension, without Python forwarding
functions. Reuse ``Ctr256`` or ``Ige256`` for chunks of one logical stream to
avoid expanding its key for each call. Each independent stream needs its own
key/IV state; never reuse a CTR keystream for different plaintext.
"""

from ._native import (  # noqa: F401
    Ctr256,
    Ige256,
    __version__,
    cbc256_decrypt,
    cbc256_encrypt,
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
    "runtime_info",
    "Ctr256",
    "Ige256",
]
