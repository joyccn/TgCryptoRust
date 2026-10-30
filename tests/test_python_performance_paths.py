"""Behavioral coverage for stack snapshots and the shared IGE key schedule."""

import itertools
import unittest

import tgcryptors


class PythonPerformancePathTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.iv = bytes(range(16))

    def test_ctr_fixed_inputs_preserve_every_mutability_combination(self):
        # Keep data immutable here to isolate the new fixed-size extraction
        # paths, including every residual offset and an empty update.
        for mutable_key, mutable_iv, mutable_state in itertools.product((False, True), repeat=3):
            for offset in range(16):
                for size in (0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129):
                    with self.subTest(
                        mutable_key=mutable_key,
                        mutable_iv=mutable_iv,
                        mutable_state=mutable_state,
                        offset=offset,
                        size=size,
                    ):
                        data = bytes(range(size))
                        expected = tgcryptors.ctr256_encrypt(data, self.key, self.iv, bytes([offset]))
                        key = bytearray(self.key) if mutable_key else self.key
                        iv = bytearray(self.iv) if mutable_iv else self.iv
                        state = bytearray([offset]) if mutable_state else bytes([offset])
                        result = tgcryptors.ctr256_encrypt(data, key, iv, state)
                        self.assertEqual(result, expected)
                        self.assertEqual(key, self.key)
                        advanced = offset + size
                        expected_counter = (
                            int.from_bytes(self.iv, "big") + advanced // 16
                        ).to_bytes(16, "big")
                        self.assertEqual(iv, expected_counter if mutable_iv else self.iv)
                        self.assertEqual(state, bytes([advanced % 16]) if mutable_state else bytes([offset]))
                        # Exports must end when the call returns.
                        for value in (key, iv, state):
                            if isinstance(value, bytearray):
                                value.append(0)

    def test_invalid_fixed_inputs_release_retained_state_exports(self):
        for argument, bad_value, expected_type in (
            ("key", bytearray(31), ValueError),
            ("key", bytearray(33), ValueError),
            ("key", bytearray(1024 * 1024), ValueError),
            ("iv", bytearray(15), ValueError),
            ("iv", bytearray(17), ValueError),
            ("state", bytearray(), ValueError),
            ("state", bytearray(2), ValueError),
            ("state", bytearray([16]), ValueError),
            ("key", memoryview(self.key), TypeError),
            ("iv", memoryview(self.iv), TypeError),
            ("state", 0, TypeError),
        ):
            with self.subTest(argument=argument, bad_type=type(bad_value)):
                values = {
                    "key": bytearray(self.key),
                    "iv": bytearray(self.iv),
                    "state": bytearray(1),
                }
                values[argument] = bad_value
                before = {name: bytes(value) for name, value in values.items() if isinstance(value, bytearray)}
                with self.assertRaises(expected_type):
                    tgcryptors.ctr256_encrypt(b"payload", **values)
                for name, value in values.items():
                    if isinstance(value, bytearray):
                        self.assertEqual(value, before[name])
                        value.append(0)

    def test_fixed_bytearray_subclasses_are_read_without_python_coercion(self):
        class NativeBytearray(bytearray):
            def __bytes__(self):
                raise AssertionError("native extraction must not call __bytes__")

            def __len__(self):
                raise AssertionError("native extraction must not call __len__")

        iv = NativeBytearray(self.iv)
        state = NativeBytearray(1)
        expected = tgcryptors.ctr256_encrypt(b"payload", self.key, self.iv, b"\0")
        self.assertEqual(
            tgcryptors.ctr256_encrypt(b"payload", NativeBytearray(self.key), iv, state),
            expected,
        )
        iv.append(0)
        state.append(0)

    def test_ige_shared_schedule_encrypts_and_decrypts_known_vector(self):
        # Independent OpenSSL AES-256-IGE vector also used by the Rust mode
        # suite; validates both directions after removing duplicate schedules.
        iv = bytes(range(32))
        plaintext = bytes(range(64))
        ciphertext = bytes.fromhex(
            "e28112a53e5c89c7b1ea8071c133699f"
            "d4e86b26c4bac9fc5af1ab8ce27a44a4"
            "a9b2dabae5a422acbb4422404b5950cc"
            "e880d70cef7a432da00b3a5fc79a7b35"
        )
        for split in (0, 16, 32, 48, 64):
            with self.subTest(split=split):
                enc = tgcryptors.Ige256(self.key, iv)
                dec = tgcryptors.Ige256(self.key, iv)
                self.assertEqual(enc.encrypt(plaintext[:split]) + enc.encrypt(plaintext[split:]), ciphertext)
                self.assertEqual(dec.decrypt(ciphertext[:split]) + dec.decrypt(ciphertext[split:]), plaintext)


if __name__ == "__main__":
    unittest.main()
