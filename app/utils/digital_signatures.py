# digital_signatures.py

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

#private_key = RSA.import_key(open('private.pem').read())
#public_key = RSA.import_key(open('public.pem').read())

def sign_note_content(note_title, note_content, private_key_file):
    private_key = RSA.import_key(open(private_key_file).read())
    combined_content = f'{note_title}:{note_content}'
    h = SHA256.new(combined_content.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(h)
    return signature.hex()

def verify_note_content(note_title, note_content, signature, public_key_file):
    public_key = RSA.import_key(open(public_key_file).read())
    combined_content = f'{note_title}:{note_content}'
    h = SHA256.new(combined_content.encode('utf-8'))
    try:
        pkcs1_15.new(public_key).verify(h, bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False
