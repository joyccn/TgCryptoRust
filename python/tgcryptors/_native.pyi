"""Types for the native extension; no Python runtime wrappers are involved."""

from typing import Literal, TypedDict, Union

_CtrInput = Union[bytes, bytearray]

class _RuntimeInfo(TypedDict):
    version: str
    crate_version: str
    implementation: Literal["rust"]
    aesni: bool
    hardware_accelerated: bool
    backend: Literal["rustcrypto-hardware", "rustcrypto-fixslice"]

__version__: str

def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ctr256_encrypt(
    data: _CtrInput, key: _CtrInput, iv: _CtrInput, state: _CtrInput
) -> bytes:
    """Mutable IV/state advance in place; synchronize access to shared buffers."""
    ...
def ctr256_decrypt(
    data: _CtrInput, key: _CtrInput, iv: _CtrInput, state: _CtrInput
) -> bytes: ...
def runtime_info() -> _RuntimeInfo: ...

class Ctr256:
    """A reusable key schedule and counter for one logical CTR stream."""
    def __init__(self, key: bytes, iv: bytes) -> None: ...
    def update(self, data: bytes) -> bytes: ...

class Ige256:
    """A reusable key schedule and chaining state for one IGE direction."""
    def __init__(self, key: bytes, iv: bytes) -> None: ...
    def encrypt(self, data: bytes) -> bytes: ...
    def decrypt(self, data: bytes) -> bytes: ...
