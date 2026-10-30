//! AES-256 block primitives backed by RustCrypto AES.
//!
//! Key expansion and block operations use hardware AES instructions when they
//! are available, with a constant-time fixsliced software fallback. The backend
//! is selected by RustCrypto at runtime on supported x86 and ARM platforms.
//! Raw key schedules are deliberately private; the backend zeroizes them on drop.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

/// An expanded AES-256 key with automatic backend selection.
///
/// Both encryption and decryption use the same opaque key type. Key schedules
/// are zeroized on drop by the AES backend's `zeroize` feature.
#[derive(Clone)]
pub struct ExpandedKey {
    cipher: aes::Aes256,
}

// The AES backend wipes its schedule when this field is dropped.
impl zeroize::ZeroizeOnDrop for ExpandedKey {}

impl ExpandedKey {
    /// Create an expanded key from the raw 32-byte AES-256 key.
    #[inline]
    pub fn new_encrypt(key: &[u8; 32]) -> Self {
        Self {
            cipher: aes::Aes256::new(key.into()),
        }
    }

    /// Create an expanded key suitable for decryption.
    #[inline]
    pub fn new_decrypt(key: &[u8; 32]) -> Self {
        Self::new_encrypt(key)
    }
}

/// Whether this build uses hardware AES on the current CPU.
///
/// This also reflects RustCrypto's `aes_backend="soft"` build override.
pub fn hardware_accelerated() -> bool {
    aes::hardware_accelerated()
}

/// Name of the selected AES implementation, without exposing key material.
pub fn backend_name() -> &'static str {
    if hardware_accelerated() {
        "rustcrypto-hardware"
    } else {
        "rustcrypto-fixslice"
    }
}

/// Encrypt one 16-byte block.
#[inline]
pub fn encrypt_block(input: &[u8; 16], output: &mut [u8; 16], ek: &ExpandedKey) {
    ek.cipher.encrypt_block_b2b(input.into(), output.into());
}

/// Decrypt one 16-byte block.
#[inline]
pub fn decrypt_block(input: &[u8; 16], output: &mut [u8; 16], ek: &ExpandedKey) {
    ek.cipher.decrypt_block_b2b(input.into(), output.into());
}

/// Encrypt four blocks together.
///
/// For long buffers, prefer eight-block batches to fill the AES-NI backend's
/// eight instruction lanes. Four-block batches serve the remaining short tail.
#[inline]
pub fn encrypt_block_x4(input: &[u8; 64], output: &mut [u8; 64], ek: &ExpandedKey) {
    let (input, _) = aes::Block::slice_as_chunks(input);
    let (output, _) = aes::Block::slice_as_chunks_mut(output);
    ek.cipher
        .encrypt_blocks_b2b(input, output)
        .expect("equal block counts");
}

/// Decrypt four blocks together.
#[inline]
pub fn decrypt_block_x4(input: &[u8; 64], output: &mut [u8; 64], ek: &ExpandedKey) {
    let (input, _) = aes::Block::slice_as_chunks(input);
    let (output, _) = aes::Block::slice_as_chunks_mut(output);
    ek.cipher
        .decrypt_blocks_b2b(input, output)
        .expect("equal block counts");
}

/// Encrypt eight blocks together to fill hardware AES instruction lanes.
#[inline]
pub fn encrypt_block_x8(input: &[u8; 128], output: &mut [u8; 128], ek: &ExpandedKey) {
    let (input, _) = aes::Block::slice_as_chunks(input);
    let (output, _) = aes::Block::slice_as_chunks_mut(output);
    ek.cipher
        .encrypt_blocks_b2b(input, output)
        .expect("equal block counts");
}

/// Decrypt eight blocks together to fill hardware AES instruction lanes.
#[inline]
pub fn decrypt_block_x8(input: &[u8; 128], output: &mut [u8; 128], ek: &ExpandedKey) {
    let (input, _) = aes::Block::slice_as_chunks(input);
    let (output, _) = aes::Block::slice_as_chunks_mut(output);
    ek.cipher
        .decrypt_blocks_b2b(input, output)
        .expect("equal block counts");
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-38A, F.1.5 and F.1.6: four independent AES-256 ECB blocks.
    #[test]
    fn test_aes256_parallel_nist() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let ciphertext = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
            0x81, 0xf8, 0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 0xdc, 0x5b, 0xa7, 0x4a,
            0x31, 0x36, 0x28, 0x70, 0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9, 0xf1, 0x53,
            0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d, 0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
            0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7,
        ];
        let enc_key = ExpandedKey::new_encrypt(&key);
        let dec_key = ExpandedKey::new_decrypt(&key);
        let mut encrypted = [0; 64];
        let mut decrypted = [0; 64];
        encrypt_block_x4(&plaintext, &mut encrypted, &enc_key);
        assert_eq!(encrypted, ciphertext);
        decrypt_block_x4(&ciphertext, &mut decrypted, &dec_key);
        assert_eq!(decrypted, plaintext);

        // Repeat the independent known-answer blocks across both halves of the
        // eight-lane path. This also exercises the fixsliced software backend.
        let mut plaintext_x8 = [0; 128];
        let mut ciphertext_x8 = [0; 128];
        plaintext_x8[..64].copy_from_slice(&plaintext);
        plaintext_x8[64..].copy_from_slice(&plaintext);
        ciphertext_x8[..64].copy_from_slice(&ciphertext);
        ciphertext_x8[64..].copy_from_slice(&ciphertext);
        let mut encrypted_x8 = [0; 128];
        let mut decrypted_x8 = [0; 128];
        encrypt_block_x8(&plaintext_x8, &mut encrypted_x8, &enc_key);
        assert_eq!(encrypted_x8, ciphertext_x8);
        decrypt_block_x8(&ciphertext_x8, &mut decrypted_x8, &dec_key);
        assert_eq!(decrypted_x8, plaintext_x8);

        // A clone must keep an independent live schedule after the source drops.
        let cloned_key = enc_key.clone();
        drop(enc_key);
        encrypt_block_x4(&plaintext, &mut encrypted, &cloned_key);
        assert_eq!(encrypted, ciphertext);
    }

    #[test]
    fn backend_zeroizes_keys_on_drop() {
        fn require_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        require_zeroize_on_drop::<aes::Aes256>();
        require_zeroize_on_drop::<ExpandedKey>();
    }

    // NIST FIPS 197 Appendix C.3: AES-256 test vector
    #[test]
    fn test_aes256_encrypt_nist() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];

        let ek = ExpandedKey::new_encrypt(&key);
        let mut output = [0u8; 16];
        encrypt_block(&plaintext, &mut output, &ek);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_aes256_decrypt_nist() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let ciphertext: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let expected: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let dk = ExpandedKey::new_decrypt(&key);
        let mut output = [0u8; 16];
        decrypt_block(&ciphertext, &mut output, &dk);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_aes256_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = [0xDEu8; 16];

        let ek = ExpandedKey::new_encrypt(&key);
        let dk = ExpandedKey::new_decrypt(&key);

        let mut encrypted = [0u8; 16];
        let mut decrypted = [0u8; 16];

        encrypt_block(&plaintext, &mut encrypted, &ek);
        decrypt_block(&encrypted, &mut decrypted, &dk);

        assert_eq!(plaintext, decrypted);
    }
}
