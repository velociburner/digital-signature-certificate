# digital-signature-certificate
Final project for COSI 107a Introduction to Computer Security

**Note: This is not a secure application. It is merely a proof-of-concept for a
project. Please don't use it for real purposes.**

## Installation
*Requires Python>=3.12*

Clone the repository and install it as a Python package in your current virtual environment.
```sh
git clone https://github.com/velociburner/digital-signature-certificate.git
cd digital-signature-certificate
pip install -e .
```

This will install the required Python packages and create the commands for running the CLI.

## Tests
Run the test suite using `pytest`, or run individual files in `tests/` by adding them as an argument
(e.g. `pytest tests/test_digital_signature.py`). The tests may take a few seconds to run.

## Description
There are three main commands: generate, sign, and verify. Each one may contain additional subcommands and positional
or optional arguments.

### Generation
You can generate keys, Certificate Authorities, or certificates.

Run `dsc generate key` to generate a new randomly generated RSA keypair. It will prompt you for a name for the key,
as well as a password to encrypt the private key.

Run `dsc generate ca` to create a new Certificate Authority and keypair associated with it. It will prompt you for a
name for the CA and password to encrypt the private key.

Run `dsc generate certificate <keyfile>` and provide the name of a key to use. It will prompt you for the name of the
Certificate Authority to use for generating the certificate. The certificate name will be a concatenation of the CA and
key, so the "root" CA and "key" key would create the "root-key" certificate. You can also specify an expiration with
`--days` or `--minutes` (default is 30 days, 0 minutes).

### Signing
You can sign the contents of a file using a private key. Run `dsc sign <datafile> <keyfile>` with the data you want to
sign and key to use for signing. It will prompt you for the password of the private key and generate a signature from
the bytes of that file.

### Verification
You can verify signatures or certificates.

Run `dsc verify signature <datafile> <keyfile>` with the data that was signed and key that was used to sign it. It will
check the signature using the public key.

Run `dsc verify certificate <certfile> <keyfile>` with the name of the certificate and the key of the Certificate
Authority used to generate that certificate. You can also use this to verify certificates in a certificate chain all
the way up to the root CA, but it must be done one at a time.

## Running
The root command to run the project is `dsc`.
```sh
$ dsc -h
usage: dsc [-h] {generate,sign,verify} ...

options:
  -h, --help            show this help message and exit

actions:
  {generate,sign,verify}
```

The CLI contains subcommands for each of the different actions. You can also print the help messages for each
subcommand, e.g.
```sh
$ dsc sign -h
usage: dsc sign [-h] datafile keyfile

positional arguments:
datafile    Name of file with data
keyfile     Name of file with RSA key of user

options:
  -h, --help  show this help message and exit
```

## Future Considerations
- make CLI more robust
- more key types
- CA chains
- containerized web app
- TLS/SSL
