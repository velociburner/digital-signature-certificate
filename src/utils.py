from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def verify_key_signature(
    public_key: rsa.RSAPublicKey,
    signature: bytes,
    data: bytes,
    padding: Union[padding.PSS, padding.PKCS1v15],
    algorithm: hashes.HashAlgorithm
) -> bool:
    """Verifies the signature for the data using the RSA public key."""
    try:
        public_key.verify(
            signature,
            data,
            padding,
            algorithm
        )
        return True
    except InvalidSignature:
        return False
