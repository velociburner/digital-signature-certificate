import time
import unittest
from datetime import timedelta

from cryptography.hazmat.primitives import hashes

import src.digital_signature as ds
from src.certificate import CertificateAuthority, gen_csr, is_valid_cert


class TestCertificate(unittest.TestCase):
    """Unittests for functions in `certificate.py`."""

    def setUp(self):
        self.ca_public_key, self.ca_private_key = ds.gen_keypair()
        self.public_key, self.private_key = ds.gen_keypair()
        self.algorithm = hashes.SHA256()
        self.ca = CertificateAuthority(
            "US",
            "MA",
            "Waltham",
            "root",
            self.ca_private_key,
            self.algorithm
        )
        csr = gen_csr(
            "US",
            "MA",
            "Waltham",
            "Josh",
            self.private_key,
            self.algorithm
        )
        self.cert = self.ca.gen_cert(csr, timedelta(0, 2, 0))

    def test_certificate_authority(self):
        # check the CA's self signature
        self.assertTrue(is_valid_cert(self.ca.cert, self.ca_public_key))

    def test_validity(self):
        # certificate should be valid on CA public key
        self.assertTrue(is_valid_cert(self.cert, self.ca_public_key))
        # but invalid on any other key
        self.assertFalse(is_valid_cert(self.cert, self.public_key))

    def test_expiration(self):
        time.sleep(3)  # certificate is set to expire after 2 seconds
        self.assertFalse(is_valid_cert(self.cert, self.ca_public_key))
