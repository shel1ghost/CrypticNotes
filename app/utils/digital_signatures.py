from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

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

def get_hash_and_signature(note_title, note_content, private_key_file, public_key_file):
    # Step 1: Use the existing function to sign the note content
    digital_signature = sign_note_content(note_title, note_content, private_key_file)

    # Step 2: Compute the hash of the combined content (consistent logic)
    combined_content = f'{note_title}:{note_content}'
    computed_hash = SHA256.new(combined_content.encode('utf-8')).hexdigest()

    # Step 3: Verify the signature and get the verified hash
    public_key = RSA.import_key(open(public_key_file).read())
    h = SHA256.new(combined_content.encode('utf-8'))
    
    try:
        pkcs1_15.new(public_key).verify(h, bytes.fromhex(digital_signature))
        verified_hash = h.hexdigest()  # Verification successful
    except (ValueError, TypeError):
        verified_hash = None  # Verification failed

    # Step 4: Return all the relevant details
    return {
        'computed_hash': computed_hash,
        'verified_hash': verified_hash,
        'digital_signature': digital_signature
    }
