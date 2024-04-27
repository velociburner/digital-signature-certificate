import os
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization

import src.digital_signature as ds
from src.digital_signature import SignedFile


class TestDigitalSignature(unittest.TestCase):
    """Unittests for functions in `digital_signature.py`."""

    def setUp(self):
        self.public_key, self.private_key = ds.gen_keypair()

    def test_signature(self):
        file = SignedFile(Path("tests/data/input.txt"))
        signature = file.sign(self.private_key)
        self.assertTrue(file.verify(self.public_key, signature))

        # signature on same file
        same_file = SignedFile(Path("tests/data/input.txt"))
        self.assertTrue(same_file.verify(self.public_key, signature))

        # wrong signature on same file
        self.assertFalse(same_file.verify(self.public_key, b"wrong signature"))

        # correct signature on different file with same contents
        duplicate_file = SignedFile(Path("tests/data/input2.txt"))
        self.assertTrue(duplicate_file.verify(self.public_key, signature))

        # correct signature on different file with different contents
        duplicate_file = SignedFile(Path("tests/data/input3.txt"))
        self.assertFalse(duplicate_file.verify(self.public_key, signature))

    def test_keys(self):
        public_key_path = Path("tests/rsa_key.pub")
        private_key_path = Path("tests/rsa_key")
        ds.write_public_key(public_key_path, self.public_key)
        ds.write_private_key(private_key_path, self.private_key, b"password")

        # read public key
        public_key = ds.read_public_key(public_key_path)
        self.assertEqual(self.public_key, public_key)

        # read private key with correct password
        private_key = ds.read_private_key(private_key_path, b"password")
        kwargs = {
            "encoding": serialization.Encoding.PEM,
            "format": serialization.PrivateFormat.PKCS8,
            "encryption_algorithm": serialization.NoEncryption(),
        }
        self.assertEqual(
            self.private_key.private_bytes(**kwargs),
            private_key.private_bytes(**kwargs)
        )

        # read private key with incorrect password
        with self.assertRaises(ValueError):
            private_key = ds.read_private_key(private_key_path, b"wrong")

        os.remove(public_key_path)
        os.remove(private_key_path)

    def test_algorithms(self):
        # SHA256 hash
        sha = SignedFile(Path("tests/data/input.txt"), algorithm=hashes.SHA256())
        sha_signature = sha.sign(self.private_key)
        self.assertTrue(sha.verify(self.public_key, sha_signature))

        # MD5 hash
        md5 = SignedFile(Path("tests/data/input.txt"), algorithm=hashes.MD5())
        md5_signature = md5.sign(self.private_key)
        self.assertTrue(md5.verify(self.public_key, md5_signature))

        # signature with different hash algorithm from file should not match
        self.assertFalse(md5.verify(self.public_key, sha_signature))
        self.assertFalse(sha.verify(self.public_key, md5_signature))
