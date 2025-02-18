import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

def generate_md5_key():
    random_hex = secrets.token_hex(32)
    md5_hash = hashlib.md5(random_hex.encode()).hexdigest()
    return md5_hash

def encrypt_content_blowfish(content, key):
    backend = default_backend()
    cipher = Cipher(algorithms.Blowfish(key.encode()), modes.CBC(b'00000000'), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
    padded_data = padder.update(content.encode()) + padder.finalize()
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(encrypted_content).decode()
