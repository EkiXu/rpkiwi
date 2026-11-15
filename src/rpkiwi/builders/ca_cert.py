from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_ca_cert_and_key(ca_source_cert_path: str, ca_source_key_path: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    with open(ca_source_cert_path, 'rb') as f:
        ca_cert = x509.load_der_x509_certificate(f.read())

    with open(ca_source_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    return ca_cert, ca_key
