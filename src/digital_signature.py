from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.utils import verify_key_signature


class SignedFile:
    """The contents (bytes) of a file and operations to sign and verify it
    using RSA keys."""

    def __init__(
        self,
        fp: Path,
        algorithm: hashes.HashAlgorithm = hashes.SHA256()
    ):
        self._data = read_bytes(fp)
        self.algorithm = algorithm
        self.padding = padding.PSS(
            mgf=padding.MGF1(algorithm=self.algorithm),
            salt_length=padding.PSS.MAX_LENGTH
        )

    @property
    def data(self) -> bytes:
        return self._data

    def sign(self, private_key: rsa.RSAPrivateKey) -> bytes:
        """Cryptographically signs the data using a private RSA key."""
        return private_key.sign(
            self.data,
            self.padding,
            self.algorithm
        )

    def verify(self, public_key: rsa.RSAPublicKey, signature: bytes) -> bool:
        """Verifies the signature for the file data."""
        return verify_key_signature(
            public_key,
            signature,
            self.data,
            self.padding,
            self.algorithm
        )


def gen_keypair(
    public_exponent: int = 65537,
    key_size: int = 2048
) -> tuple[rsa.RSAPublicKey, rsa.RSAPrivateKeyWithSerialization]:
    """Generates a random RSA public/private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return public_key, private_key


def read_bytes(fp: Path) -> bytes:
    """Reads the bytes contained in the given file."""
    with fp.open('rb') as f:
        return f.read()


def write_bytes(fp: Path, string: bytes):
    """Writes the bytes to the given file."""
    with fp.open('wb') as f:
        f.write(string)


def read_public_key(path: Path) -> rsa.RSAPublicKey:
    """Reads a file containing an RSA public key."""
    with path.open('rb') as f:
        return serialization.load_pem_public_key(f.read())


def write_public_key(path: Path, key: rsa.RSAPublicKey):
    """Serializes and writes an RSA public key."""
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with path.open('wb') as keyfile:
        keyfile.write(pem)


def read_private_key(path: Path, password: bytes) -> rsa.RSAPrivateKey:
    """Reads a password protected file containing an RSA private key."""
    with path.open('rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def write_private_key(
    path: Path,
    key: rsa.RSAPrivateKeyWithSerialization,
    password: bytes
):
    """Serializes and writes an RSA private key."""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with path.open('wb') as keyfile:
        keyfile.write(pem)
