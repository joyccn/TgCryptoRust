//! AES-256-CTR (Counter) mode.
//!
//! Telegram uses this mode for CDN-encrypted file downloads.
//!
//! The API supports stateful streaming by carrying both the counter block in
//! `iv` and the byte offset inside the current keystream block in `state`.

use crate::aes256::{self, ExpandedKey, AES_BLOCK_SIZE};
use rayon::prelude::*;

const PARALLEL_THRESHOLD: usize = 256 * 1024; // 256 KB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB per thread
const BYTE_MASK: u128 = u8::MAX as u128;

/// Increment a 16-byte big-endian counter by 1.
#[inline]
fn increment_counter(iv: &mut [u8; 16]) {
    let mut k = AES_BLOCK_SIZE;
    while k > 0 {
        k -= 1;
        iv[k] = iv[k].wrapping_add(1);
        if iv[k] != 0 {
            break;
        }
    }
}

/// Add an offset to a 16-byte big-endian counter.
///
/// Performs a 128-bit big-endian addition of `offset` to the counter,
/// propagating carry across all 16 bytes.
#[inline]
fn add_counter(iv: &[u8; 16], offset: u64) -> [u8; 16] {
    let mut out = *iv;
    let mut carry = offset as u128;
    let mut k = AES_BLOCK_SIZE;
    while k > 0 && carry > 0 {
        k -= 1;
        let sum = out[k] as u128 + (carry & BYTE_MASK);
        out[k] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    out
}

/// Encrypt or decrypt data into `dest`.
///
/// `state` is the next byte offset inside the current keystream block and must
/// be preserved between chunked calls.
pub fn ctr256_encrypt_into(
    data: &[u8],
    key: &[u8; 32],
    iv: &mut [u8; 16],
    state: &mut u8,
    dest: &mut [u8],
) {
    let ek = ExpandedKey::new_encrypt(key);
    ctr256_encrypt_into_ek(data, &ek, iv, state, dest);
}

/// Encrypt or decrypt data using a pre-expanded key.
///
/// # Panics
///
/// Panics if the buffers differ in length or if `state` is not in `0..16`.
pub fn ctr256_encrypt_into_ek(
    data: &[u8],
    ek: &ExpandedKey,
    iv: &mut [u8; 16],
    state: &mut u8,
    dest: &mut [u8],
) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");
    assert!(
        (*state as usize) < AES_BLOCK_SIZE,
        "State must be in 0..{AES_BLOCK_SIZE}, got {}",
        *state,
    );

    if len == 0 {
        return;
    }

    if len < PARALLEL_THRESHOLD {
        ctr256_encrypt_internal(data, dest, ek, iv, state);
        return;
    }

    let mut processed = 0;
    if *state != 0 {
        // Finish the partially used keystream block before parallelizing.
        let mut chunk = [0u8; 16];
        aes256::encrypt_block(iv, &mut chunk, ek);
        let rem = AES_BLOCK_SIZE - (*state as usize);
        let advance = core::cmp::min(len, rem);

        for pos in 0..advance {
            dest[pos] = data[pos] ^ chunk[*state as usize + pos];
        }

        *state += advance as u8;
        if *state >= AES_BLOCK_SIZE as u8 {
            *state = 0;
            increment_counter(iv);
        }
        processed += advance;
    }

    if processed == len {
        return;
    }

    let rem_data = &data[processed..];
    let rem_dest = &mut dest[processed..];
    let bulk_len = (rem_data.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    if bulk_len > 0 {
        let bulk_data = &rem_data[..bulk_len];
        let bulk_dest = &mut rem_dest[..bulk_len];

        // Each chunk starts from the counter value it would have reached in the
        // sequential stream, so the work can be split safely.
        bulk_data
            .par_chunks(CHUNK_SIZE)
            .zip(bulk_dest.par_chunks_mut(CHUNK_SIZE))
            .enumerate()
            .for_each(|(chunk_idx, (chunk_data, chunk_dest))| {
                let block_offset = (chunk_idx * CHUNK_SIZE / AES_BLOCK_SIZE) as u64;
                let mut local_iv = add_counter(iv, block_offset);
                let mut local_state = 0u8;
                ctr256_encrypt_internal(
                    chunk_data,
                    chunk_dest,
                    ek,
                    &mut local_iv,
                    &mut local_state,
                );
            });

        let blocks_processed = (bulk_len / AES_BLOCK_SIZE) as u64;
        *iv = add_counter(iv, blocks_processed);
        processed += bulk_len;
    }

    if processed < len {
        let tail_data = &data[processed..];
        let tail_dest = &mut dest[processed..];
        ctr256_encrypt_internal(tail_data, tail_dest, ek, iv, state);
    }
}

/// Process one CTR slice sequentially.
///
/// The caller is responsible for passing a valid `state` in `0..16`.
fn ctr256_encrypt_internal(
    data: &[u8],
    dest: &mut [u8],
    ek: &ExpandedKey,
    iv: &mut [u8; 16],
    state: &mut u8,
) {
    let mut i = 0;
    let len = data.len();

    if *state > 0 {
        let mut chunk = [0u8; 16];
        aes256::encrypt_block(iv, &mut chunk, ek);

        while i < len && *state > 0 {
            dest[i] = data[i] ^ chunk[*state as usize];
            *state = (*state + 1) % 16;
            i += 1;
            if *state == 0 {
                increment_counter(iv);
                break;
            }
        }
    }

    // Batch four counter blocks to reuse the x4 AES primitive.
    while i + 64 <= len {
        let mut ivs = [0u8; 64];

        ivs[0..16].copy_from_slice(iv);
        increment_counter(iv);
        ivs[16..32].copy_from_slice(iv);
        increment_counter(iv);
        ivs[32..48].copy_from_slice(iv);
        increment_counter(iv);
        ivs[48..64].copy_from_slice(iv);
        increment_counter(iv);

        let mut keystream = [0u8; 64];
        aes256::encrypt_block_x4(&ivs, &mut keystream, ek);

        for j in 0..64 {
            dest[i + j] = data[i + j] ^ keystream[j];
        }
        i += 64;
    }

    while i + 16 <= len {
        let mut keystream = [0u8; 16];
        aes256::encrypt_block(iv, &mut keystream, ek);
        increment_counter(iv);

        for j in 0..16 {
            dest[i + j] = data[i + j] ^ keystream[j];
        }
        i += 16;
    }

    if i < len {
        let mut keystream = [0u8; 16];
        aes256::encrypt_block(iv, &mut keystream, ek);

        while i < len {
            dest[i] = data[i] ^ keystream[*state as usize];
            *state += 1;
            i += 1;
        }
    }
}

/// Encrypt data and return the ciphertext.
#[must_use]
pub fn ctr256_encrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16], state: &mut u8) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    ctr256_encrypt_into(data, key, iv, state, &mut out);
    out
}

#[inline]
/// Decrypt data and return the plaintext.
#[must_use]
pub fn ctr256_decrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16], state: &mut u8) -> Vec<u8> {
    ctr256_encrypt(data, key, iv, state)
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
    fn test_ctr256_roundtrip() {
        let key = test_key();
        let iv = test_iv();
        let data: Vec<u8> = (0..97).map(|i| (i & 0xff) as u8).collect();

        let mut enc_iv = iv;
        let mut enc_state = 0u8;
        let encrypted = ctr256_encrypt(&data, &key, &mut enc_iv, &mut enc_state);

        let mut dec_iv = iv;
        let mut dec_state = 0u8;
        let decrypted = ctr256_decrypt(&encrypted, &key, &mut dec_iv, &mut dec_state);

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_ctr256_chunked_matches_one_shot() {
        let key = test_key();
        let iv = test_iv();
        let data: Vec<u8> = (0..97).map(|i| (i & 0xff) as u8).collect();

        let mut one_shot_iv = iv;
        let mut one_shot_state = 0u8;
        let one_shot = ctr256_encrypt(&data, &key, &mut one_shot_iv, &mut one_shot_state);

        let mut chunked_iv = iv;
        let mut chunked_state = 0u8;
        let mut chunked = Vec::with_capacity(data.len());

        for chunk in [17usize, 23, 7, 50] {
            let start = chunked.len();
            let end = core::cmp::min(start + chunk, data.len());
            chunked.extend(ctr256_encrypt(
                &data[start..end],
                &key,
                &mut chunked_iv,
                &mut chunked_state,
            ));
            if end == data.len() {
                break;
            }
        }

        assert_eq!(one_shot, chunked);
        assert_eq!(one_shot_iv, chunked_iv);
        assert_eq!(one_shot_state, chunked_state);
    }

    #[test]
    fn test_ctr256_large_chunked_matches_one_shot() {
        let key = test_key();
        let iv = test_iv();
        let data: Vec<u8> = (0..(512 * 1024 + 31)).map(|i| (i & 0xff) as u8).collect();

        let mut one_shot_iv = iv;
        let mut one_shot_state = 0u8;
        let one_shot = ctr256_encrypt(&data, &key, &mut one_shot_iv, &mut one_shot_state);

        let mut chunked_iv = iv;
        let mut chunked_state = 0u8;
        let mut chunked = Vec::with_capacity(data.len());
        for chunk in [&data[..13], &data[13..]] {
            chunked.extend(ctr256_encrypt(
                chunk,
                &key,
                &mut chunked_iv,
                &mut chunked_state,
            ));
        }

        assert_eq!(one_shot, chunked);
        assert_eq!(one_shot_iv, chunked_iv);
        assert_eq!(one_shot_state, chunked_state);
    }

    #[test]
    fn test_ctr256_single_byte() {
        let key = test_key();
        let iv = test_iv();
        let data = vec![0xABu8; 1];

        let mut enc_iv = iv;
        let mut enc_state = 0u8;
        let encrypted = ctr256_encrypt(&data, &key, &mut enc_iv, &mut enc_state);
        assert_eq!(enc_state, 1);

        let mut dec_iv = iv;
        let mut dec_state = 0u8;
        let decrypted = ctr256_decrypt(&encrypted, &key, &mut dec_iv, &mut dec_state);
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_add_counter_basic() {
        let iv = [0u8; 16];
        let result = add_counter(&iv, 1);
        assert_eq!(result[15], 1);

        let result = add_counter(&iv, 256);
        assert_eq!(result[14], 1);
        assert_eq!(result[15], 0);
    }

    #[test]
    fn test_add_counter_carry() {
        let mut iv = [0u8; 16];
        iv[15] = u8::MAX;
        let result = add_counter(&iv, 1);
        assert_eq!(result[14], 1);
        assert_eq!(result[15], 0);
    }

    #[test]
    fn test_add_counter_propagates_past_lower_half() {
        let mut iv = [0u8; 16];
        iv[8..16].fill(u8::MAX);

        let result = add_counter(&iv, 1);

        assert_eq!(result[7], 1);
        assert!(result[8..16].iter().all(|byte| *byte == 0));
    }

    #[test]
    #[should_panic(expected = "State must be in 0..16")]
    fn test_ctr256_rejects_invalid_state() {
        let key = test_key();
        let mut iv = test_iv();
        let mut state = 16u8;
        let data = [0u8; 1];
        let mut out = [0u8; 1];

        ctr256_encrypt_into(&data, &key, &mut iv, &mut state, &mut out);
    }
}
