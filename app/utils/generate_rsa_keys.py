from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys(key_size=2048):
    """
    Generates RSA public and private keys.

    :param key_size: Size of the key in bits (2048 is a common key size).
    :return: tuple containing the private key and public key.
    """
    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Generate the public key from the private key
    public_key = private_key.public_key()
    
    return private_key, public_key


def serialize_private_key(private_key):
    """
    Serializes the private RSA key to PEM format.

    :param private_key: The private key object.
    :return: PEM-formatted private key as bytes.
    """
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return pem_private_key


def serialize_public_key(public_key):
    """
    Serializes the public RSA key to PEM format.

    :param public_key: The public key object.
    :return: PEM-formatted public key as bytes.
    """
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_public_key



