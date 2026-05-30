//! Core AES-256 primitives and Telegram-specific block modes.
//!
//! The crate exposes the AES-256 block cipher plus the modes Telegram relies on:
//! - `ige256` for MTProto message encryption
//! - `ctr256` for CDN file encryption
//! - `cbc256` for passport credentials
//!
//! On x86 and x86_64, the `aesni` feature enables runtime AES-NI dispatch.
//! Other targets use the software fallback.
//!
//! # Security Notice
//!
//! The software fallback uses table lookups, which are not constant-time on
//! all CPUs. If hardware AES acceleration is unavailable, evaluate that risk
//! against your deployment model. The `neon` feature flag is reserved for a
//! future ARM implementation and is not active yet.

pub mod aes256;
pub mod cbc256;
pub mod ctr256;
pub mod ige256;

/// Whether the crate was compiled with the AES-NI feature enabled.
pub const AESNI_FEATURE_ENABLED: bool = cfg!(feature = "aesni");

/// Re-export the main APIs for convenience.
pub use aes256::ExpandedKey;
pub use cbc256::{cbc256_decrypt, cbc256_decrypt_into, cbc256_encrypt, cbc256_encrypt_into};
pub use ctr256::{ctr256_decrypt, ctr256_encrypt, ctr256_encrypt_into, ctr256_encrypt_into_ek};
pub use ige256::{
    ige256_decrypt, ige256_decrypt_into, ige256_decrypt_into_ek, ige256_encrypt,
    ige256_encrypt_into, ige256_encrypt_into_ek,
};
