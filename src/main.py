from datetime import timedelta
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

import src.certificate as ct
import src.digital_signature as ds
from src.certificate import CertificateAuthority
from src.digital_signature import SignedFile

KEYDIR = Path("keys/")
SIGDIR = Path("sigs/")
CERTDIR = Path("certs/")
ALGORITHM = hashes.SHA256()


def gen_and_save_keypair(
    name: str,
) -> tuple[rsa.RSAPublicKey,
           rsa.RSAPrivateKeyWithSerialization]:
    """Creates a new public/private RSA keypair and saves them to disk."""
    public_key, private_key = ds.gen_keypair()
    password = getpass()
    confirm = getpass(prompt="Confirm password: ")
    assert password == confirm

    ds.write_public_key((KEYDIR / name).with_suffix(".pub"), public_key)
    ds.write_private_key(KEYDIR / name, private_key, str.encode(password))
    return public_key, private_key


def sign_file(datafile: Path, keyfile: Path):
    """Signs a file using a private RSA key."""
    assert (KEYDIR / keyfile).is_file(), "Key doesn't exist"
    assert datafile.suffix != ".pem", "Data file is already a signature file"

    password = getpass()
    key = ds.read_private_key(KEYDIR / keyfile, str.encode(password))
    data = SignedFile(datafile, algorithm=ALGORITHM)
    signature = data.sign(key)
    ds.write_bytes(SIGDIR / datafile.with_suffix(".pem").name, signature)


def verify_signature(datafile: Path, keyfile: Path):
    """Verifies a signature with the corresponding public key of the user that
    generated it. Exits with an error if the signature is invalid."""
    sigfile = SIGDIR / datafile.with_suffix(".pem").name
    assert sigfile.is_file(), f"No signature for {datafile}"
    assert (KEYDIR / keyfile).is_file(), "Key doesn't exist"

    data = SignedFile(datafile, algorithm=ALGORITHM)
    public_key = ds.read_public_key(KEYDIR / keyfile.with_suffix(".pub"))
    signature = ds.read_bytes(sigfile)
    if not data.verify(public_key, signature):
        print("Invalid signature")
        exit(1)


def gen_ca(name: str, country: str, state: str, city: str):
    """Generates a new Certificate Authority and a keypair for it to use. Also
    generates a self-signed certificate."""
    print(f"Generating keypair for {name}")
    ca_public_key, ca_private_key = gen_and_save_keypair(name)
    ca = CertificateAuthority(
        country,
        state,
        city,
        name,
        ca_private_key,
        ALGORITHM
    )
    ct.write_certificate((CERTDIR / name).with_suffix(".pem"), ca.cert)


def gen_certificate(
    keyfile: Path,
    name: str,
    country: str,
    state: str,
    city: str,
    days: int,
    minutes: int
):
    """Generates a certificate for a user signed by a Certificate Authority."""
    # load CA
    password = getpass(prompt="CA password: ")
    ca_private_key = ds.read_private_key((KEYDIR / name).with_suffix(""),
                                         str.encode(password))
    ca = CertificateAuthority(
        country,
        state,
        city,
        name,
        ca_private_key,
        ALGORITHM
    )

    # generate csr for user
    password = getpass(prompt=f"{keyfile} password: ")
    private_key = ds.read_private_key(KEYDIR / keyfile.with_suffix(""),
                                      str.encode(password))
    csr = ct.gen_csr(country, state, city, name, private_key, ALGORITHM)

    # generate certificate using the csr and CA
    cert = ca.gen_cert(csr, valid_for=timedelta(days, minutes * 60, 0))
    certfile = f"{name}-{keyfile.with_suffix('').name}"
    ct.write_certificate((CERTDIR / certfile).with_suffix(".pem"), cert)


def verify_certificate(certfile: Path, keyfile: Path):
    """Verifies a certificate with the corresponding public key of the
    Certificate Authority that generated it. Exits with an error if the
    certificate is invalid."""
    cert = ct.read_certificate(CERTDIR / certfile.with_suffix(".pem"))
    public_key = ds.read_public_key(KEYDIR / keyfile.with_suffix(".pub"))
    if not ct.is_valid_cert(cert, public_key):
        print("Invalid certificate")
        exit(1)


def get_args():
    import argparse

    parser = argparse.ArgumentParser()

    # sub-commands
    subparser = parser.add_subparsers(title='actions', dest='action', required=True)

    # generation
    generate = subparser.add_parser('generate')
    generate_subparser = generate.add_subparsers(dest='object', required=True)
    generate_key = generate_subparser.add_parser('key')
    generate_ca = generate_subparser.add_parser('ca')
    generate_ca.add_argument(
        '--country',
        type=str,
        default="US",
        help='2 letter country code for Certificate Authority'
    )
    generate_ca.add_argument(
        '--state',
        type=str,
        default="Massachusetts",
        help='State for Certificate Authority'
    )
    generate_ca.add_argument(
        '--city',
        type=str,
        default="Waltham",
        help='City for Certificate Authority'
    )

    generate_cert = generate_subparser.add_parser('certificate')
    generate_cert.add_argument(
        'keyfile',
        type=Path,
        help='Name of file with RSA key'
    )
    generate_cert.add_argument(
        '--country',
        type=str,
        default="US",
        help='2 letter country code for certificate holder'
    )
    generate_cert.add_argument(
        '--state',
        type=str,
        default="Massachusetts",
        help='State for certificate holder'
    )
    generate_cert.add_argument(
        '--city',
        type=str,
        default="Waltham",
        help='City for certificate holder'
    )
    generate_cert.add_argument(
        '--days',
        type=int,
        default=30,
        help='Number of days before certificate expiration'
    )
    generate_cert.add_argument(
        '--minutes',
        type=int,
        default=0,
        help='Number of minutes before certificate expiration'
    )

    # signing
    sign = subparser.add_parser('sign')
    sign.add_argument(
        'datafile',
        type=Path,
        help='Name of file with data'
    )
    sign.add_argument(
        'keyfile',
        type=Path,
        help='Name of file with RSA key of user'
    )

    # verification
    verify = subparser.add_parser('verify')
    verify_subparser = verify.add_subparsers(dest='object', required=True)
    verify_sig = verify_subparser.add_parser('signature')
    verify_sig.add_argument(
        'datafile',
        type=Path,
        help='Name of file with data'
    )
    verify_sig.add_argument(
        'keyfile',
        type=Path,
        help='Name of file with RSA key of signer'
    )

    verify_cert = verify_subparser.add_parser('certificate')
    verify_cert.add_argument(
        'certfile',
        type=Path,
        help='Name of certificate file'
    )
    verify_cert.add_argument(
        'keyfile',
        type=Path,
        help='Name of file with RSA key of Certificate Authority'
    )

    args = parser.parse_args()
    return args


def run():
    args = get_args()

    KEYDIR.mkdir(parents=True, exist_ok=True)
    SIGDIR.mkdir(parents=True, exist_ok=True)
    CERTDIR.mkdir(parents=True, exist_ok=True)

    if args.action == "generate":
        if args.object == "key":
            name = input("Assign name to key: ")
            assert name != "", "Empty name"
            gen_and_save_keypair(name)
        elif args.object == "ca":
            name = input("Assign name to Certificate Authority: ")
            assert name != "", "Empty name"
            gen_ca(name, args.country, args.state, args.city)
        elif args.object == "certificate":
            name = input("Name of Certificate Authority: ")
            gen_certificate(
                args.keyfile,
                name,
                args.country,
                args.state,
                args.city,
                args.days,
                args.minutes
            )
    elif args.action == "sign":
        sign_file(args.datafile, args.keyfile)
    elif args.action == "verify":
        if args.object == "signature":
            verify_signature(args.datafile, args.keyfile)
        elif args.object == "certificate":
            verify_certificate(args.certfile, args.keyfile)


if __name__ == "__main__":
    run()
