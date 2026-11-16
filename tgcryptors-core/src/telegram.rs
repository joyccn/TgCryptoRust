//! Helpers for applying the AES modes to Telegram-specific data.
//!
//! These helpers construct protocol inputs; they do not authenticate data or
//! implement a Telegram session. Verify downloaded CDN data against the hashes
//! supplied by the authenticated origin data center before consuming plaintext.

use core::fmt;

/// Why a Telegram CDN file offset cannot be represented as an AES counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdnOffsetError {
    /// The byte offset is not a multiple of the 16-byte AES block size.
    UnalignedOffset,
    /// The block index exceeds the CDN counter's 32-bit field.
    OffsetOutOfRange,
}

impl fmt::Display for CdnOffsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnalignedOffset => f.write_str("CDN offset must be a multiple of 16 bytes"),
            Self::OffsetOutOfRange => f.write_str("CDN offset block index must fit in 32 bits"),
        }
    }
}

impl std::error::Error for CdnOffsetError {}

/// Construct Telegram's CDN AES-256-CTR IV for an aligned file byte offset.
///
/// The first 12 bytes of the server-provided IV are preserved, and its final
/// four bytes are **replaced** with the big-endian block index `offset / 16`.
/// This is not an addition to the original IV's counter. The input is unchanged.
///
/// Pass the result to CTR with an initial byte state of zero. This operation
/// does not check download-request limits, authenticate ciphertext, or validate
/// a subsequent buffer's length. The caller must keep a CDN request within the
/// protocol's counter range and verify its plaintext against trusted file hashes.
///
/// # Errors
///
/// Returns [`CdnOffsetError::UnalignedOffset`] unless `offset` is divisible by 16,
/// or [`CdnOffsetError::OffsetOutOfRange`] if `offset / 16` does not fit in a `u32`.
/// Thus the largest accepted byte offset is `2^36 - 16`.
pub fn cdn256_iv(iv: &[u8; 16], offset: u64) -> Result<[u8; 16], CdnOffsetError> {
    if !offset.is_multiple_of(16) {
        return Err(CdnOffsetError::UnalignedOffset);
    }
    let block_index = u32::try_from(offset / 16).map_err(|_| CdnOffsetError::OffsetOutOfRange)?;
    let mut result = *iv;
    result[12..].copy_from_slice(&block_index.to_be_bytes());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdn_counter_replaces_tail_and_preserves_prefix() {
        let iv = core::array::from_fn(|i| i as u8);
        let mut expected = iv;
        expected[12..].copy_from_slice(&[0; 4]);
        assert_eq!(cdn256_iv(&iv, 0), Ok(expected));
        expected[12..].copy_from_slice(&[0, 0, 0, 1]);
        assert_eq!(cdn256_iv(&iv, 16), Ok(expected));
        expected[12..].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(cdn256_iv(&iv, 0x1234_5678 * 16), Ok(expected));
        assert_eq!(iv, core::array::from_fn(|i| i as u8));
    }

    #[test]
    fn cdn_counter_validates_alignment_and_range() {
        let iv = [0xa5; 16];
        assert_eq!(cdn256_iv(&iv, 1), Err(CdnOffsetError::UnalignedOffset));
        assert_eq!(cdn256_iv(&iv, 15), Err(CdnOffsetError::UnalignedOffset));
        assert_eq!(
            cdn256_iv(&iv, 1 << 36),
            Err(CdnOffsetError::OffsetOutOfRange)
        );
        assert_eq!(
            cdn256_iv(&iv, u64::MAX - 15),
            Err(CdnOffsetError::OffsetOutOfRange)
        );
        let max = cdn256_iv(&iv, (u32::MAX as u64) * 16).unwrap();
        assert_eq!(&max[..12], &iv[..12]);
        assert_eq!(&max[12..], &[0xff; 4]);
        assert_eq!(
            CdnOffsetError::UnalignedOffset.to_string(),
            "CDN offset must be a multiple of 16 bytes"
        );
        assert_eq!(
            CdnOffsetError::OffsetOutOfRange.to_string(),
            "CDN offset block index must fit in 32 bits"
        );
    }
}
