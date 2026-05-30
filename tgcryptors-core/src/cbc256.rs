//! AES-256-CBC (Cipher Block Chaining) mode.
//!
//! Telegram uses this mode for passport credentials.

use crate::aes256::{self, ExpandedKey, AES_BLOCK_SIZE};
use rayon::prelude::*;

const PARALLEL_THRESHOLD: usize = 256 * 1024; // 256 KB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB per thread

/// Encrypt aligned data into `dest` and update `iv` to the last ciphertext block.
///
/// # Panics
///
/// Panics if the buffers differ in length or if `data` is not a multiple of 16 bytes.
pub fn cbc256_encrypt_into(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16], dest: &mut [u8]) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");
    if len == 0 {
        return;
    }
    assert!(
        len % AES_BLOCK_SIZE == 0,
        "Data length must be a multiple of {AES_BLOCK_SIZE} bytes, got {len}",
    );

    let ek = ExpandedKey::new_encrypt(key);
    let mut i = 0;
    while i < len {
        let mut block = [0u8; AES_BLOCK_SIZE];
        for j in 0..AES_BLOCK_SIZE {
            block[j] = data[i + j] ^ iv[j];
        }

        let mut out_block = [0u8; AES_BLOCK_SIZE];
        aes256::encrypt_block(&block, &mut out_block, &ek);

        dest[i..i + AES_BLOCK_SIZE].copy_from_slice(&out_block);
        iv.copy_from_slice(&out_block);

        i += AES_BLOCK_SIZE;
    }
}

/// Decrypt aligned data into `dest` and update `iv` to the last ciphertext block.
///
/// # Panics
///
/// Panics if the buffers differ in length or if `data` is not a multiple of 16 bytes.
pub fn cbc256_decrypt_into(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16], dest: &mut [u8]) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");
    if len == 0 {
        return;
    }
    assert!(
        len % AES_BLOCK_SIZE == 0,
        "Data length must be a multiple of {AES_BLOCK_SIZE} bytes, got {len}",
    );

    let dk = ExpandedKey::new_decrypt(key);

    let mut next_iv = [0u8; 16];
    next_iv.copy_from_slice(&data[len - 16..len]);

    if len < PARALLEL_THRESHOLD {
        cbc256_decrypt_internal(data, dest, &dk, iv);
    } else {
        dest.par_chunks_mut(CHUNK_SIZE)
            .enumerate()
            .for_each(|(chunk_idx, dest_chunk)| {
                let start = chunk_idx * CHUNK_SIZE;
                let end = start + dest_chunk.len();
                let data_chunk = &data[start..end];

                let mut local_iv = [0u8; 16];
                if chunk_idx == 0 {
                    local_iv.copy_from_slice(iv);
                } else {
                    // CBC decryption needs the previous ciphertext block as the local IV.
                    local_iv.copy_from_slice(&data[start - 16..start]);
                }

                cbc256_decrypt_internal(data_chunk, dest_chunk, &dk, &mut local_iv);
            });
    }

    iv.copy_from_slice(&next_iv);
}

/// Decrypt one aligned CBC slice.
///
/// `initial_iv` must be the ciphertext block that precedes `data`, or the
/// external IV for the first slice.
fn cbc256_decrypt_internal(
    data: &[u8],
    dest: &mut [u8],
    dk: &ExpandedKey,
    initial_iv: &mut [u8; 16],
) {
    let len = data.len();
    let mut i = 0;

    let mut prev_c = *initial_iv;

    while i + 64 <= len {
        let mut cipher_blocks = [0u8; 64];
        cipher_blocks.copy_from_slice(&data[i..i + 64]);

        let mut plain_blocks = [0u8; 64];
        aes256::decrypt_block_x4(&cipher_blocks, &mut plain_blocks, dk);

        for j in 0..16 {
            dest[i + j] = plain_blocks[j] ^ prev_c[j];
        }
        for j in 0..16 {
            dest[i + 16 + j] = plain_blocks[16 + j] ^ cipher_blocks[j];
        }
        for j in 0..16 {
            dest[i + 32 + j] = plain_blocks[32 + j] ^ cipher_blocks[16 + j];
        }
        for j in 0..16 {
            dest[i + 48 + j] = plain_blocks[48 + j] ^ cipher_blocks[32 + j];
        }

        prev_c.copy_from_slice(&cipher_blocks[48..64]);
        i += 64;
    }

    while i + 16 <= len {
        let mut cipher_block = [0u8; 16];
        cipher_block.copy_from_slice(&data[i..i + 16]);

        let mut plain_block = [0u8; 16];
        aes256::decrypt_block(&cipher_block, &mut plain_block, dk);

        for j in 0..16 {
            dest[i + j] = plain_block[j] ^ prev_c[j];
        }

        prev_c = cipher_block;
        i += 16;
    }

    *initial_iv = prev_c;
}

/// Encrypt aligned data and return the ciphertext.
pub fn cbc256_encrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    cbc256_encrypt_into(data, key, iv, &mut out);
    out
}

/// Decrypt aligned data and return the plaintext.
pub fn cbc256_decrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    cbc256_decrypt_into(data, key, iv, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(0x42))
    }

    fn test_iv() -> [u8; 16] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(0x24))
    }

    #[test]
    fn test_cbc256_roundtrip() {
        let key = test_key();
        let iv = test_iv();
        let data: Vec<u8> = (0..128).map(|i| (i & 0xff) as u8).collect();

        let mut enc_iv = iv;
        let encrypted = cbc256_encrypt(&data, &key, &mut enc_iv);

        let mut dec_iv = iv;
        let decrypted = cbc256_decrypt(&encrypted, &key, &mut dec_iv);

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_cbc256_large_roundtrip() {
        // Exercises the parallel decryption path.
        let key = test_key();
        let iv = test_iv();
        let data: Vec<u8> = (0..512 * 1024).map(|i| (i & 0xff) as u8).collect();

        let mut enc_iv = iv;
        let encrypted = cbc256_encrypt(&data, &key, &mut enc_iv);

        let mut dec_iv = iv;
        let decrypted = cbc256_decrypt(&encrypted, &key, &mut dec_iv);

        assert_eq!(data, decrypted);
        assert_eq!(enc_iv, dec_iv);
        assert_eq!(&dec_iv, encrypted.last_chunk::<16>().unwrap());
    }

    #[test]
    #[should_panic(expected = "multiple of 16 bytes")]
    fn test_cbc256_rejects_non_aligned_input() {
        let key = test_key();
        let mut iv = test_iv();
        let data = vec![0u8; 15];
        let mut out = vec![0u8; data.len()];

        cbc256_encrypt_into(&data, &key, &mut iv, &mut out);
    }
}
