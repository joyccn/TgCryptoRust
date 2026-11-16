import unittest

import tgcrypto
import tgcryptors


class TelegramCdnTests(unittest.TestCase):
    def test_cdn_iv_replaces_counter_and_preserves_prefix(self) -> None:
        iv = bytes(range(16))
        self.assertEqual(tgcryptors.cdn256_iv(iv, 0), iv[:12] + bytes(4))
        self.assertEqual(tgcryptors.cdn256_iv(iv, 16), iv[:12] + b"\x00\x00\x00\x01")
        self.assertEqual(
            tgcryptors.cdn256_iv(iv, 0x12345678 * 16),
            iv[:12] + b"\x12\x34\x56\x78",
        )
        self.assertEqual(tgcryptors.cdn256_iv(iv, (1 << 36) - 16), iv[:12] + b"\xff" * 4)
        self.assertEqual(iv, bytes(range(16)))
        self.assertIs(tgcrypto.cdn256_iv, tgcryptors.cdn256_iv)

    def test_cdn_iv_rejects_invalid_inputs(self) -> None:
        iv = bytes(range(16))
        for offset in (1, 15, 17):
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError, "multiple of 16"):
                    tgcryptors.cdn256_iv(iv, offset)
        for offset in (1 << 36, (1 << 64) - 16):
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError, "32 bits"):
                    tgcryptors.cdn256_iv(iv, offset)
        with self.assertRaisesRegex(ValueError, "IV must be exactly 16 bytes"):
            tgcryptors.cdn256_iv(iv[:-1], 0)
        for offset in (-1, 1 << 64):
            with self.subTest(offset=offset):
                with self.assertRaises(OverflowError):
                    tgcryptors.cdn256_iv(iv, offset)
        with self.assertRaises(TypeError):
            tgcryptors.cdn256_iv(iv, "16")

    def test_cdn_random_access_matches_whole_file_ctr(self) -> None:
        data = bytes(range(256)) * 32 + b"unaligned end"
        key = bytes(range(32))
        server_iv = bytes(range(16))
        encrypted = tgcryptors.ctr256_encrypt(
            data, key, tgcryptors.cdn256_iv(server_iv, 0), b"\x00"
        )
        for offset in (0, 16, 32, 256, 4096, 8192):
            with self.subTest(offset=offset):
                actual = tgcrypto.ctr256_decrypt(
                    encrypted[offset : offset + 65],
                    key,
                    tgcryptors.cdn256_iv(server_iv, offset),
                    b"\x00",
                )
                self.assertEqual(actual, data[offset : offset + 65])


if __name__ == "__main__":
    unittest.main()
