from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from src.utils import verify_key_signature


class CertificateAuthority:
    """A (self-signed) Certificate Authority which can sign other
    certificates."""

    def __init__(
        self,
        country: str,
        state: str,
        city: str,
        name: str,
        key: rsa.RSAPrivateKeyWithSerialization,
        algorithm: hashes.HashAlgorithm
    ):
        self.issuer_name = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, city),
                x509.NameAttribute(NameOID.COMMON_NAME, name)
            ]
        )
        self.subject_name = self.issuer_name
        self.key = key
        self.algorithm = algorithm
        csr = gen_csr(country, state, city, name, key, algorithm)
        self.cert = self.gen_cert(csr)

    def gen_cert(
        self,
        csr: x509.CertificateSigningRequest,
        valid_for: timedelta = timedelta(30, 0, 0)
    ) -> x509.Certificate:
        """Generates a new certificate from the given request that is only
        valid starting from the current time and for the given duration."""
        cert = x509.CertificateBuilder(
            issuer_name=self.issuer_name,
            subject_name=csr.subject,
            public_key=csr.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.now(UTC),
            not_valid_after=datetime.now(UTC) + valid_for
        )
        cert.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False
        )
        return cert.sign(self.key, self.algorithm)


def is_valid_cert(cert: x509.Certificate, public_key: rsa.RSAPublicKey):
    """Verifies that the certificate was signed by the given public key and
    (importantly) that it has not expired yet."""
    verified = verify_key_signature(
        public_key,
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )
    not_expired = cert.not_valid_before_utc < datetime.now(UTC) < cert.not_valid_after_utc
    return verified and not_expired


def gen_csr(
    country: str,
    state: str,
    city: str,
    name: str,
    private_key: rsa.RSAPrivateKeyWithSerialization,
    algorithm: hashes.HashAlgorithm
):
    """Generates a certificate signing request, which can be handed to a
    Certificate Authority to sign."""
    csr = x509.CertificateSigningRequestBuilder(
        subject_name=x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
    )
    return csr.sign(private_key, algorithm)


def read_certificate(path: Path):
    """Reads a file containing a certificate."""
    with path.open('rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def write_certificate(path: Path, cert: x509.Certificate):
    """Serializes and writes a certificate."""
    with path.open('wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
