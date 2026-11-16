//! AES-256-IGE (Infinite Garble Extension) mode.
//!
//! Telegram uses this mode for MTProto v2.0 message encryption.
//!
//! AES uses runtime hardware dispatch or constant-time software via RustCrypto.
//! IGE itself does not authenticate messages; see the crate-level security notice.

use crate::aes256::{ExpandedKey, AES_BLOCK_SIZE};
use aes::cipher::{
    consts::U16, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockSizeUser,
};

struct IgeBlocks<'a> {
    data: &'a [u8],
    dest: &'a mut [u8],
    iv: &'a mut [u8; 32],
}

impl BlockSizeUser for IgeBlocks<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for IgeBlocks<'_> {
    #[inline]
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let (iv1, iv2) = self.iv.split_at_mut(AES_BLOCK_SIZE);
        for (input, output) in self
            .data
            .as_chunks::<AES_BLOCK_SIZE>()
            .0
            .iter()
            .zip(self.dest.as_chunks_mut::<AES_BLOCK_SIZE>().0)
        {
            let mut block = aes::Block::default();
            for j in 0..AES_BLOCK_SIZE {
                block[j] = input[j] ^ iv1[j];
            }
            backend.encrypt_block_inplace(&mut block);
            for j in 0..AES_BLOCK_SIZE {
                output[j] = block[j] ^ iv2[j];
            }
            iv1.copy_from_slice(output);
            iv2.copy_from_slice(input);
        }
    }
}

impl BlockCipherDecClosure for IgeBlocks<'_> {
    #[inline]
    fn call<B: BlockCipherDecBackend<BlockSize = U16>>(self, backend: &B) {
        let (previous_ciphertext, previous_plaintext) = self.iv.split_at_mut(AES_BLOCK_SIZE);
        for (input, output) in self
            .data
            .as_chunks::<AES_BLOCK_SIZE>()
            .0
            .iter()
            .zip(self.dest.as_chunks_mut::<AES_BLOCK_SIZE>().0)
        {
            let mut block = aes::Block::default();
            for j in 0..AES_BLOCK_SIZE {
                block[j] = input[j] ^ previous_plaintext[j];
            }
            backend.decrypt_block_inplace(&mut block);
            for j in 0..AES_BLOCK_SIZE {
                output[j] = block[j] ^ previous_ciphertext[j];
            }
            previous_ciphertext.copy_from_slice(input);
            previous_plaintext.copy_from_slice(output);
        }
    }
}

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
        len.is_multiple_of(AES_BLOCK_SIZE),
        "Data length must be a multiple of {AES_BLOCK_SIZE} bytes, got {len}",
    );

    // IGE blocks depend on previous output, but backend dispatch does not.
    // Keep the whole loop inside one RustCrypto dispatch for this call.
    ek.encrypt_with_backend(IgeBlocks { data, dest, iv });
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
        len.is_multiple_of(AES_BLOCK_SIZE),
        "Data length must be a multiple of {AES_BLOCK_SIZE} bytes, got {len}",
    );

    dk.decrypt_with_backend(IgeBlocks { data, dest, iv });
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
