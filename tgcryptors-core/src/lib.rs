//! Core AES-256 primitives and Telegram-specific block modes.
//!
//! The crate exposes the AES-256 block cipher plus the modes Telegram relies on:
//! - `ige256` for MTProto message encryption
//! - `ctr256` for CDN file encryption
//! - `cbc256` for passport credentials
//!
//! RustCrypto AES selects hardware acceleration at runtime on supported x86
//! and ARM CPUs, with a constant-time fixsliced software fallback. Both key
//! expansion and block processing avoid secret-indexed table lookups.
//!
//! # Security Notice
//!
//! These are unauthenticated cipher primitives, not a complete MTProto client.
//! Callers must implement the protocol's key derivation, message authentication,
//! padding, replay checks, and unique CTR key/counter management.
//! The legacy `aesni` and `neon` features remain compatibility flags; backend
//! selection is automatic. Use `aes256::hardware_accelerated()` for runtime status.

pub mod aes256;
pub mod cbc256;
pub mod ctr256;
pub mod ige256;

/// Whether the legacy compatibility feature was enabled (not CPU/backend status).
pub const AESNI_FEATURE_ENABLED: bool = cfg!(feature = "aesni");

/// AES block size in bytes (16).
pub const AES_BLOCK_SIZE: usize = aes256::AES_BLOCK_SIZE;

/// Re-export the main APIs for convenience.
pub use aes256::ExpandedKey;
pub use cbc256::{cbc256_decrypt, cbc256_decrypt_into, cbc256_encrypt, cbc256_encrypt_into};
pub use ctr256::{ctr256_decrypt, ctr256_encrypt, ctr256_encrypt_into, ctr256_encrypt_into_ek};
pub use ige256::{
    ige256_decrypt, ige256_decrypt_into, ige256_decrypt_into_ek, ige256_encrypt,
    ige256_encrypt_into, ige256_encrypt_into_ek,
};
