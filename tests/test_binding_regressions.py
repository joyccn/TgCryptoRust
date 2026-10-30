"""Regression coverage for native buffer ownership and state validation."""

import threading
import time
import unittest

import tgcryptors


class BindingRegressionTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.iv = bytes(range(16))

    def test_rejected_state_does_not_advance_mutable_iv(self):
        for bad_state in (bytearray(), bytearray(b"\x10"), bytearray(2)):
            with self.subTest(state=bad_state):
                iv = bytearray(self.iv)
                with self.assertRaises(ValueError):
                    tgcryptors.ctr256_encrypt(b"payload", self.key, iv, bad_state)
                self.assertEqual(iv, self.iv)
                # Validation must release any exported buffers on failure.
                iv.append(0)
                bad_state.append(0)

    def test_mutable_input_exports_are_released_on_success(self):
        data = bytearray(b"message")
        key = bytearray(self.key)
        iv = bytearray(self.iv)
        state = bytearray(1)
        expected = tgcryptors.ctr256_encrypt(bytes(data), self.key, self.iv, b"\x00")
        self.assertEqual(tgcryptors.ctr256_encrypt(data, key, iv, state), expected)
        for value in (data, key, iv, state):
            value.append(0)

    def test_state_buffers_cannot_resize_while_native_call_runs(self):
        # Large enough to observe GIL release even on AES-accelerated machines.
        data = bytes(64 * 1024 * 1024)
        blocked = set()
        # A descheduled observer may miss one entire native call. Allow another
        # scheduling opportunity, while still requiring actual BufferErrors and
        # failing immediately on every native exception or leaked export.
        for _ in range(3):
            iv = bytearray(self.iv)
            state = bytearray(1)
            started = threading.Event()
            finished = threading.Event()
            failures = []

            def encrypt():
                started.set()
                try:
                    tgcryptors.ctr256_encrypt(data, self.key, iv, state)
                except BaseException as error:
                    failures.append(error)
                finally:
                    finished.set()

            worker = threading.Thread(target=encrypt)
            worker.start()
            self.assertTrue(started.wait(10), "cipher thread did not start")
            # The worker keeps the GIL through snapshot/export and releases it
            # for the bulk operation. Yield so it can enter that operation.
            time.sleep(0.001)
            try:
                while not finished.is_set():
                    for name, value in (("iv", iv), ("state", state)):
                        try:
                            value.append(0)
                        except BufferError:
                            blocked.add(name)
                        else:
                            value.pop()
                    if len(blocked) == 2:
                        break
            finally:
                worker.join(30)
            self.assertFalse(worker.is_alive(), "native cipher call did not finish")
            self.assertEqual(failures, [])
            # The export must not leak beyond the operation, including attempts
            # where the observer missed the native processing window.
            iv.append(0)
            state.append(0)
            if len(blocked) == 2:
                break
        self.assertEqual(blocked, {"iv", "state"})

    def test_short_cipher_output_does_not_modify_cached_python_bytes(self):
        empty = b""
        one = b"\x00"
        outputs = [
            tgcryptors.ctr256_encrypt(bytes([i]), self.key, self.iv, b"\x00")
            for i in range(256)
        ]
        self.assertEqual(empty, b"")
        self.assertEqual(one, bytes([0]))
        self.assertEqual(len(set(outputs)), 256)
        self.assertEqual(tgcryptors.ctr256_encrypt(empty, self.key, self.iv, b"\x00"), empty)

    def test_invalid_stream_chunk_does_not_advance_stream(self):
        stream = tgcryptors.Ige256(self.key, self.key)
        with self.assertRaises(ValueError):
            stream.encrypt(b"unaligned")
        data = bytes(range(64))
        self.assertEqual(stream.encrypt(data), tgcryptors.ige256_encrypt(data, self.key, self.key))

    def test_runtime_metadata_reports_selected_backend(self):
        info = tgcryptors.runtime_info()
        self.assertIsInstance(info["hardware_accelerated"], bool)
        self.assertEqual(
            info["backend"],
            "rustcrypto-hardware" if info["hardware_accelerated"] else "rustcrypto-fixslice",
        )
        if info["aesni"]:
            self.assertTrue(info["hardware_accelerated"])


if __name__ == "__main__":
    unittest.main()
