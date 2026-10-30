"""Compatibility shim for projects that import TgCrypto as ``tgcrypto``.

TgCryptoRust exposes its native extension as ``tgcryptors`` and re-exports the
same API here so existing Telegram clients can switch packages without code
changes.
"""

from tgcryptors import (  # noqa: F401
    Ctr256,
    Ige256,
    __all__ as __all__,
    __version__,
    cbc256_decrypt,
    cbc256_encrypt,
    ctr256_decrypt,
    ctr256_encrypt,
    ige256_decrypt,
    ige256_encrypt,
    runtime_info,
)

__all__ = __all__.copy()
