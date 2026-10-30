//! Independent known-answer and streaming-boundary tests for the public modes.
use tgcryptors_core::{
    aes256::{encrypt_block, ExpandedKey},
    cbc256_decrypt_into, cbc256_encrypt_into, ctr256_encrypt_into, ige256_decrypt_into,
    ige256_encrypt_into,
};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
}

const KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710"
);

#[test]
fn cbc256_nist_sp800_38a_f2_5_and_f2_6() {
    // NIST SP 800-38A, sections F.2.5 and F.2.6 (AES-256-CBC).
    let key = hex::<32>(KEY);
    let plaintext = hex::<64>(PLAINTEXT);
    let initial_iv = hex::<16>("000102030405060708090a0b0c0d0e0f");
    let ciphertext = hex::<64>(concat!(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
        "9cfc4e967edb808d679f777bc6702c7d",
        "39f23369a9d9bacfa530e26304231461",
        "b2eb05e2c39be9fcda6c19078c6a9d1b"
    ));
    let mut iv = initial_iv;
    let mut output = [0; 64];
    cbc256_encrypt_into(&plaintext, &key, &mut iv, &mut output);
    assert_eq!(output, ciphertext);
    assert_eq!(iv.as_slice(), &ciphertext[48..]);
    for split in [0, 16, 32, 48, 64] {
        let mut iv = initial_iv;
        cbc256_decrypt_into(&ciphertext[..split], &key, &mut iv, &mut output[..split]);
        cbc256_decrypt_into(&ciphertext[split..], &key, &mut iv, &mut output[split..]);
        assert_eq!(output, plaintext);
        assert_eq!(iv.as_slice(), &ciphertext[48..]);
    }
}

#[test]
fn ctr256_nist_sp800_38a_f5_5_and_f5_6() {
    // NIST SP 800-38A, sections F.5.5 and F.5.6 (AES-256-CTR).
    let key = hex::<32>(KEY);
    let plaintext = hex::<64>(PLAINTEXT);
    let initial_iv = hex::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let ciphertext = hex::<64>(concat!(
        "601ec313775789a5b7a7f504bbf3d228",
        "f443e3ca4d62b59aca84e990cacaf5c5",
        "2b0930daa23de94ce87017ba2d84988d",
        "dfc9c58db67aada613c2dd08457941a6"
    ));
    let expected_iv = hex::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03");
    let mut iv = initial_iv;
    let mut state = 0;
    let mut output = [0; 64];
    ctr256_encrypt_into(&plaintext, &key, &mut iv, &mut state, &mut output);
    assert_eq!(output, ciphertext);
    assert_eq!(iv, expected_iv);
    assert_eq!(state, 0);
    // Every split, including non-block boundaries, must reproduce the vector.
    for split in 0..=64 {
        let mut iv = initial_iv;
        let mut state = 0;
        ctr256_encrypt_into(
            &ciphertext[..split],
            &key,
            &mut iv,
            &mut state,
            &mut output[..split],
        );
        ctr256_encrypt_into(
            &ciphertext[split..],
            &key,
            &mut iv,
            &mut state,
            &mut output[split..],
        );
        assert_eq!(output, plaintext, "split={split}");
        assert_eq!(iv, expected_iv);
        assert_eq!(state, 0);
    }
}

#[test]
fn ige256_openssl_known_answer_and_chaining() {
    // Generated independently with OpenSSL 3.5.9 AES_set_encrypt_key(key, 256)
    // and AES_ige_encrypt(data, output, 64, key, iv, AES_ENCRYPT).
    // The IV order is previous ciphertext followed by previous plaintext.
    let key = core::array::from_fn(|i| i as u8);
    let initial_iv = core::array::from_fn(|i| i as u8);
    let plaintext: [u8; 64] = core::array::from_fn(|i| i as u8);
    let ciphertext = hex::<64>(concat!(
        "e28112a53e5c89c7b1ea8071c133699f",
        "d4e86b26c4bac9fc5af1ab8ce27a44a4",
        "a9b2dabae5a422acbb4422404b5950cc",
        "e880d70cef7a432da00b3a5fc79a7b35"
    ));
    let expected_iv = hex::<32>(concat!(
        "e880d70cef7a432da00b3a5fc79a7b35",
        "303132333435363738393a3b3c3d3e3f"
    ));
    for split in [0, 16, 32, 48, 64] {
        let mut iv = initial_iv;
        let mut output = [0; 64];
        ige256_encrypt_into(&plaintext[..split], &key, &mut iv, &mut output[..split]);
        ige256_encrypt_into(&plaintext[split..], &key, &mut iv, &mut output[split..]);
        assert_eq!(output, ciphertext);
        assert_eq!(iv, expected_iv);
        let mut iv = initial_iv;
        ige256_decrypt_into(&ciphertext[..split], &key, &mut iv, &mut output[..split]);
        ige256_decrypt_into(&ciphertext[split..], &key, &mut iv, &mut output[split..]);
        assert_eq!(output, plaintext);
        assert_eq!(iv, expected_iv);
    }
}

#[test]
fn ctr256_parallel_boundaries_and_full_counter_carry() {
    let key = hex::<32>(KEY);
    let ek = ExpandedKey::new_encrypt(&key);
    // Cross both the 64-bit carry boundary and the full 128-bit wrap.
    for initial_counter in [u64::MAX as u128 - 2, u128::MAX - 2] {
        for offset in 0..16u8 {
            for len in [
                0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257, 262143, 262144, 262145,
            ] {
                let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let mut output = vec![0; len];
                let mut iv = initial_counter.to_be_bytes();
                let mut state = offset;
                ctr256_encrypt_into(&data, &key, &mut iv, &mut state, &mut output);
                // A simple block-at-a-time oracle deliberately avoids the
                // production batching, counter addition, and parallel paths.
                let mut counter = initial_counter;
                let mut pos = offset as usize;
                let mut block = [0; 16];
                encrypt_block(&counter.to_be_bytes(), &mut block, &ek);
                for (i, value) in data.iter().enumerate() {
                    assert_eq!(
                        output[i],
                        value ^ block[pos],
                        "len={len} offset={offset} index={i}"
                    );
                    pos += 1;
                    if pos == 16 {
                        pos = 0;
                        counter = counter.wrapping_add(1);
                        encrypt_block(&counter.to_be_bytes(), &mut block, &ek);
                    }
                }
                assert_eq!(iv, counter.to_be_bytes());
                assert_eq!(state, pos as u8);
            }
        }
    }
}

#[test]
fn cbc256_parallel_decryption_matches_block_oracle() {
    use tgcryptors_core::aes256::decrypt_block;
    let key = hex::<32>(KEY);
    let dk = ExpandedKey::new_decrypt(&key);
    let initial_iv = hex::<16>("000102030405060708090a0b0c0d0e0f");
    for len in [65520, 65536, 65552, 262128, 262144, 262160, 327696] {
        // Nonrepeating-at-chunk-boundary ciphertext detects an incorrect
        // previous-block IV at the start of a Rayon chunk.
        let ciphertext: Vec<u8> = (0..len)
            .map(|i| ((i as u32).wrapping_mul(0x9e3779b9) >> 24) as u8)
            .collect();
        let mut iv = initial_iv;
        let mut output = vec![0; len];
        cbc256_decrypt_into(&ciphertext, &key, &mut iv, &mut output);
        let mut previous = initial_iv;
        for (input, plaintext) in ciphertext
            .as_chunks::<16>()
            .0
            .iter()
            .zip(output.as_chunks::<16>().0.iter())
        {
            let block = input;
            let mut expected = [0; 16];
            decrypt_block(block, &mut expected, &dk);
            for i in 0..16 {
                expected[i] ^= previous[i];
            }
            assert_eq!(*plaintext, expected);
            previous = *block;
        }
        assert_eq!(iv, previous);
    }
}
