import unittest

import tgcrypto
import tgcryptors


class TgCryptoApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = bytes(range(64))
        self.key = bytes(range(32))
        self.iv_ige = bytes(range(32))
        self.iv_cbc = bytes(range(16))

    def test_stateless_roundtrips(self) -> None:
        encrypted_ige = tgcrypto.ige256_encrypt(self.data, self.key, self.iv_ige)
        self.assertEqual(
            tgcrypto.ige256_decrypt(encrypted_ige, self.key, self.iv_ige),
            self.data,
        )

        encrypted_cbc = tgcrypto.cbc256_encrypt(self.data, self.key, self.iv_cbc)
        self.assertEqual(
            tgcrypto.cbc256_decrypt(encrypted_cbc, self.key, self.iv_cbc),
            self.data,
        )

        ctr_data = self.data + b"xyz"
        encrypted_ctr = tgcrypto.ctr256_encrypt(ctr_data, self.key, self.iv_cbc, b"\x00")
        self.assertEqual(
            tgcrypto.ctr256_decrypt(encrypted_ctr, self.key, self.iv_cbc, b"\x00"),
            ctr_data,
        )

    def test_ctr_stream_matches_one_shot(self) -> None:
        expected = tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, b"\x00")
        stream = tgcrypto.Ctr256(self.key, self.iv_cbc)

        actual = (
            stream.update(self.data[:17])
            + stream.update(self.data[17:41])
            + stream.update(self.data[41:])
        )

        self.assertEqual(actual, expected)

    def test_ctr_accepts_bytearray(self) -> None:
        expected = tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, b"\x00")

        ciphertext = tgcrypto.ctr256_encrypt(
            bytearray(self.data),
            bytearray(self.key),
            bytearray(self.iv_cbc),
            bytearray(1),
        )

        self.assertEqual(ciphertext, expected)

    def test_ctr_bytearray_state_carries_across_calls(self) -> None:
        data = self.data + b"payload" * 40
        expected = tgcrypto.ctr256_encrypt(data, self.key, self.iv_cbc, b"\x00")

        enc_iv = bytearray(self.iv_cbc)
        enc_state = bytearray(1)
        ciphertext = (
            tgcrypto.ctr256_encrypt(data[:100], self.key, enc_iv, enc_state)
            + tgcrypto.ctr256_encrypt(data[100:333], self.key, enc_iv, enc_state)
            + tgcrypto.ctr256_encrypt(data[333:], self.key, enc_iv, enc_state)
        )

        self.assertEqual(ciphertext, expected)

        dec_iv = bytearray(self.iv_cbc)
        dec_state = bytearray(1)
        plaintext = (
            tgcrypto.ctr256_decrypt(ciphertext[:5], self.key, dec_iv, dec_state)
            + tgcrypto.ctr256_decrypt(ciphertext[5:700], self.key, dec_iv, dec_state)
            + tgcrypto.ctr256_decrypt(ciphertext[700:], self.key, dec_iv, dec_state)
        )

        self.assertEqual(plaintext, data)

    def test_ctr_bytearray_large_chunked_roundtrip(self) -> None:
        data = bytes(range(256)) * 2048
        key = self.key
        iv0 = self.iv_cbc

        enc_iv = bytearray(iv0)
        enc_state = bytearray(1)
        ciphertext = b""
        for i in range(0, len(data), 65553):
            ciphertext += tgcrypto.ctr256_decrypt(
                data[i : i + 65553], key, enc_iv, enc_state
            )

        dec_iv = bytearray(iv0)
        dec_state = bytearray(1)
        plaintext = b""
        for i in range(0, len(ciphertext), 65553):
            plaintext += tgcrypto.ctr256_decrypt(
                ciphertext[i : i + 65553], key, dec_iv, dec_state
            )

        self.assertEqual(plaintext, data)

    def test_ctr_bytearray_mutates_iv_and_state_in_place(self) -> None:
        data = self.data + b"xyz"  # 67 bytes, not block aligned
        iv = bytearray(self.iv_cbc)
        state = bytearray(1)

        tgcrypto.ctr256_encrypt(data, self.key, iv, state)

        self.assertEqual(state[0], len(data) % 16)
        self.assertNotEqual(iv, bytearray(self.iv_cbc))

    def test_ctr_bytes_do_not_mutate_iv_or_state(self) -> None:
        data = self.data + b"xyz"  # 67 bytes, not block aligned
        iv = self.iv_cbc
        state = b"\x00"

        ciphertext1 = tgcrypto.ctr256_encrypt(data, self.key, iv, state)
        ciphertext2 = tgcrypto.ctr256_encrypt(data, self.key, iv, state)

        self.assertEqual(iv, self.iv_cbc)
        self.assertEqual(state, b"\x00")
        self.assertEqual(ciphertext1, ciphertext2)

    def test_ige_stream_matches_one_shot(self) -> None:
        expected = tgcrypto.ige256_encrypt(self.data, self.key, self.iv_ige)
        stream = tgcrypto.Ige256(self.key, self.iv_ige)

        actual = (
            stream.encrypt(self.data[:16])
            + stream.encrypt(self.data[16:32])
            + stream.encrypt(self.data[32:])
        )

        self.assertEqual(actual, expected)

        decrypt_stream = tgcrypto.Ige256(self.key, self.iv_ige)
        decrypted = (
            decrypt_stream.decrypt(expected[:16])
            + decrypt_stream.decrypt(expected[16:32])
            + decrypt_stream.decrypt(expected[32:])
        )
        self.assertEqual(decrypted, self.data)

    def test_empty_inputs_are_supported(self) -> None:
        self.assertEqual(tgcrypto.ige256_encrypt(b"", self.key, self.iv_ige), b"")
        self.assertEqual(tgcrypto.ige256_decrypt(b"", self.key, self.iv_ige), b"")
        self.assertEqual(tgcrypto.cbc256_encrypt(b"", self.key, self.iv_cbc), b"")
        self.assertEqual(tgcrypto.cbc256_decrypt(b"", self.key, self.iv_cbc), b"")
        self.assertEqual(tgcrypto.ctr256_encrypt(b"", self.key, self.iv_cbc, b"\x00"), b"")
        self.assertEqual(tgcrypto.ctr256_decrypt(b"", self.key, self.iv_cbc, b"\x00"), b"")

        self.assertEqual(tgcrypto.Ctr256(self.key, self.iv_cbc).update(b""), b"")
        self.assertEqual(tgcrypto.Ige256(self.key, self.iv_ige).encrypt(b""), b"")
        self.assertEqual(tgcrypto.Ige256(self.key, self.iv_ige).decrypt(b""), b"")

    def test_validation_errors_are_explicit(self) -> None:
        with self.assertRaisesRegex(ValueError, "Key must be exactly 32 bytes"):
            tgcrypto.ctr256_encrypt(self.data, b"\x00" * 31, self.iv_cbc, b"\x00")

        with self.assertRaisesRegex(ValueError, "IV must be exactly 16 bytes"):
            tgcrypto.cbc256_encrypt(self.data, self.key, b"\x00" * 15)

        with self.assertRaisesRegex(ValueError, "multiple of 16 bytes"):
            tgcrypto.ige256_encrypt(self.data[:-1], self.key, self.iv_ige)

        with self.assertRaisesRegex(ValueError, "State value must be in the range \\[0, 15\\]"):
            tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, b"\x10")

    def test_ctr_bytearray_validation_errors_are_explicit(self) -> None:
        with self.assertRaisesRegex(ValueError, "Key must be exactly 32 bytes"):
            tgcrypto.ctr256_encrypt(self.data, bytearray(31), self.iv_cbc, b"\x00")

        with self.assertRaisesRegex(ValueError, "IV must be exactly 16 bytes"):
            tgcrypto.ctr256_encrypt(self.data, self.key, bytearray(15), b"\x00")

        with self.assertRaisesRegex(ValueError, "State value must be in the range \\[0, 15\\]"):
            tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, bytearray(b"\x10"))

        with self.assertRaises(TypeError):
            tgcrypto.ctr256_encrypt(self.data, "not bytes", self.iv_cbc, b"\x00")

        with self.assertRaises(TypeError):
            tgcrypto.ctr256_encrypt(self.data, self.key, "not bytes", b"\x00")

    def test_docstrings_are_available(self) -> None:
        self.assertIn("Encrypt bytes with AES-256-CTR", tgcrypto.ctr256_encrypt.__doc__)
        self.assertIn("Stateful AES-256-CTR stream cipher", tgcrypto.Ctr256.__doc__)
        self.assertIn("Encrypt or decrypt the next chunk", tgcrypto.Ctr256.update.__doc__)
        self.assertIn("Stateful AES-256-IGE stream cipher", tgcrypto.Ige256.__doc__)

    def test_runtime_metadata_is_available(self) -> None:
        self.assertEqual(tgcrypto.__version__, "1.3.1")

        info = tgcrypto.runtime_info()

        self.assertEqual(info["version"], tgcrypto.__version__)
        self.assertEqual(info["crate_version"], tgcrypto.__version__)
        self.assertEqual(info["implementation"], "rust")
        self.assertIsInstance(info["aesni"], bool)

    def test_tgcrypto_and_tgcryptors_imports_match(self) -> None:
        self.assertEqual(tgcrypto.__version__, tgcryptors.__version__)
        self.assertIs(tgcrypto.Ctr256, tgcryptors.Ctr256)
        self.assertIs(tgcrypto.Ige256, tgcryptors.Ige256)

        encrypted = tgcryptors.ctr256_encrypt(
            self.data,
            self.key,
            self.iv_cbc,
            b"\x00",
        )
        decrypted = tgcrypto.ctr256_decrypt(
            encrypted,
            self.key,
            self.iv_cbc,
            b"\x00",
        )

        self.assertEqual(decrypted, self.data)


if __name__ == "__main__":
    unittest.main()
