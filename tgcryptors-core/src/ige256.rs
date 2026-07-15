//! AES-256-IGE (Infinite Garble Extension) mode.
//!
//! Telegram uses this mode for MTProto v2.0 message encryption.
//!
//! # Side-channel notice
//!
//! On platforms without AES-NI (e.g. ARM without NEON), the software fallback
//! uses T-table lookups that are theoretically vulnerable to cache-timing
//! attacks. Production deployments on such platforms should evaluate the risk.

use crate::aes256::{self, ExpandedKey, AES_BLOCK_SIZE};

/// Encrypt aligned data into `dest`.
///
/// `iv` stores two 16-byte halves: the previous ciphertext block followed by
/// the previous plaintext block. It is updated in place so callers can process
/// data incrementally.
///
/// # Panics
///
/// Panics if the buffers differ in length or if `data` is not a multiple of
/// 16 bytes.
pub fn ige256_encrypt_into(data: &[u8], key: &[u8; 32], iv: &mut [u8; 32], dest: &mut [u8]) {
    let ek = ExpandedKey::new_encrypt(key);
    ige256_encrypt_into_ek(data, &ek, iv, dest);
}

/// Encrypt aligned data using a pre-expanded key.
pub fn ige256_encrypt_into_ek(data: &[u8], ek: &ExpandedKey, iv: &mut [u8; 32], dest: &mut [u8]) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");
    if len == 0 {
        return;
    }
    assert!(
        len % AES_BLOCK_SIZE == 0,
        "Data length must be a multiple of {AES_BLOCK_SIZE} bytes, got {len}",
    );

    let mut iv1 = [0u8; AES_BLOCK_SIZE];
    let mut iv2 = [0u8; AES_BLOCK_SIZE];
    iv1.copy_from_slice(&iv[0..16]);
    iv2.copy_from_slice(&iv[16..32]);

    let mut i = 0;
    while i < len {
        let mut buffer = [0u8; AES_BLOCK_SIZE];
        for j in 0..AES_BLOCK_SIZE {
            buffer[j] = data[i + j] ^ iv1[j];
        }

        let mut encrypted = [0u8; AES_BLOCK_SIZE];
        aes256::encrypt_block(&buffer, &mut encrypted, ek);

        for j in 0..AES_BLOCK_SIZE {
            dest[i + j] = encrypted[j] ^ iv2[j];
        }

        iv1.copy_from_slice(&dest[i..i + AES_BLOCK_SIZE]);
        iv2.copy_from_slice(&data[i..i + AES_BLOCK_SIZE]);

        i += AES_BLOCK_SIZE;
    }

    iv[0..16].copy_from_slice(&iv1);
    iv[16..32].copy_from_slice(&iv2);
}

/// Decrypt aligned data into `dest`.
///
/// # Panics
///
/// Panics if the buffers differ in length or if `data` is not a multiple of
/// 16 bytes.
pub fn ige256_decrypt_into(data: &[u8], key: &[u8; 32], iv: &mut [u8; 32], dest: &mut [u8]) {
    let dk = ExpandedKey::new_decrypt(key);
    ige256_decrypt_into_ek(data, &dk, iv, dest);
}

/// Decrypt aligned data using a pre-expanded key.
pub fn ige256_decrypt_into_ek(data: &[u8], dk: &ExpandedKey, iv: &mut [u8; 32], dest: &mut [u8]) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");
    if len == 0 {
        return;
    }
    assert!(
        len % AES_BLOCK_SIZE == 0,
        "Data length must be a multiple of {AES_BLOCK_SIZE} bytes, got {len}",
    );

    let mut iv1 = [0u8; AES_BLOCK_SIZE];
    let mut iv2 = [0u8; AES_BLOCK_SIZE];
    iv1.copy_from_slice(&iv[16..32]);
    iv2.copy_from_slice(&iv[0..16]);

    let mut i = 0;
    while i < len {
        let chunk = &data[i..i + AES_BLOCK_SIZE];

        let mut buffer = [0u8; AES_BLOCK_SIZE];
        for j in 0..AES_BLOCK_SIZE {
            buffer[j] = chunk[j] ^ iv1[j];
        }

        let mut decrypted = [0u8; AES_BLOCK_SIZE];
        aes256::decrypt_block(&buffer, &mut decrypted, dk);

        for j in 0..AES_BLOCK_SIZE {
            dest[i + j] = decrypted[j] ^ iv2[j];
        }

        iv1.copy_from_slice(&dest[i..i + AES_BLOCK_SIZE]);
        iv2.copy_from_slice(chunk);

        i += AES_BLOCK_SIZE;
    }

    iv[0..16].copy_from_slice(&iv2);
    iv[16..32].copy_from_slice(&iv1);
}

/// Encrypt aligned data and return the ciphertext.
///
/// This helper clones the IV, so the caller's IV is left unchanged.
#[must_use]
pub fn ige256_encrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut iv_clone = *iv;
    ige256_encrypt_into(data, key, &mut iv_clone, &mut out);
    out
}

/// Decrypt aligned data and return the plaintext.
///
/// This helper clones the IV, so the caller's IV is left unchanged.
#[must_use]
pub fn ige256_decrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut iv_clone = *iv;
    ige256_decrypt_into(data, key, &mut iv_clone, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(0x42))
    }

    fn test_iv() -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(0x24))
    }

    #[test]
    fn test_ige_roundtrip() {
        let key = test_key();
        let iv = test_iv();
        let data = vec![0xABu8; 64];

        let encrypted = ige256_encrypt(&data, &key, &iv);
        let decrypted = ige256_decrypt(&encrypted, &key, &iv);

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_ige_chunked_matches_one_shot() {
        let key = test_key();
        let iv = test_iv();
        let data: Vec<u8> = (0..96).map(|i| (i & 0xff) as u8).collect();

        let one_shot = ige256_encrypt(&data, &key, &iv);

        let mut chunked_iv = iv;
        let mut chunked = Vec::with_capacity(data.len());
        for chunk in data.chunks(16) {
            let mut out = vec![0u8; chunk.len()];
            ige256_encrypt_into(chunk, &key, &mut chunked_iv, &mut out);
            chunked.extend(out);
        }

        assert_eq!(one_shot, chunked);
    }

    #[test]
    fn test_ige_decrypt_chunked_matches_one_shot() {
        let key = test_key();
        let iv = test_iv();
        let data: Vec<u8> = (0..96).map(|i| (i & 0xff) as u8).collect();
        let encrypted = ige256_encrypt(&data, &key, &iv);

        let one_shot = ige256_decrypt(&encrypted, &key, &iv);

        let mut chunked_iv = iv;
        let mut chunked = Vec::with_capacity(encrypted.len());
        for chunk in encrypted.chunks(16) {
            let mut out = vec![0u8; chunk.len()];
            ige256_decrypt_into(chunk, &key, &mut chunked_iv, &mut out);
            chunked.extend(out);
        }

        assert_eq!(one_shot, chunked);
        assert_eq!(data, chunked);
    }

    #[test]
    #[should_panic(expected = "multiple of 16 bytes")]
    fn test_ige_rejects_non_aligned() {
        let key = test_key();
        let iv = test_iv();
        let data = vec![0u8; 15];
        let _ = ige256_encrypt(&data, &key, &iv);
    }

    #[test]
    fn test_ige_empty_is_allowed() {
        let key = test_key();
        let iv = test_iv();
        let result = ige256_encrypt(b"", &key, &iv);
        assert_eq!(result, b"");
    }
}
