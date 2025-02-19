import struct

# Blowfish constants and initializations (same as before)
P = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
    0x082EFA98, 0xEC4E6C89, 0x9B88A5A5, 0x7A8A41B1, 0x6A14A7A1, 0xBCB6A6A3,
    0xDCFC7E38, 0xAFB7B1FC, 0x989CFB6F, 0x0D89F1F6, 0x76302B5B, 0xD1A0C3C4
]  # 18 subkeys

S = [
    [0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0x5A883F30, 0x8D8B6A05,  # S1
     0x7A8B9A9C, 0xD08D2A5D, 0xB8D4D5B8, 0x121E4D76, 0x49A9E9A7, 0x59406E6B, 0xF1D7D6D3, 0x7A2F24AA],
    # Additional S-boxes should be defined here.
]

# Function to initialize the subkeys and S-boxes with the given key
def blowfish_key_schedule(key):
    key_len = len(key)
    data = bytearray(key)
    
    # Initialize P and S with the given key
    subkeys = P[:]
    
    for i in range(18):
        subkeys[i] ^= data[i % key_len]  # XOR each byte of the key to the subkeys P

    # Key expansion: Generate S-boxes by applying a permutation function on P
    for i in range(0, 18, 2):
        subkeys[i] ^= (subkeys[i - 1] + 0x1A2B3C4D) # Just a placeholder for example
        
    return subkeys

# The round function of Blowfish
def blowfish_round(L, R, subkeys, round_num):
    # Perform XOR of the left and right halves with the corresponding subkeys
    L_new = L ^ subkeys[0]
    R_new = R ^ subkeys[1]
    
    # Print the intermediate L and R at each round
    #print(f"Round {round_num}: L = {L_new:#010x}, R = {R_new:#010x}")
    
    return L_new, R_new

# The main Blowfish encryption function
def blowfish_encrypt(block, subkeys):
    # Ensure the block is split into two 32-bit integers (L and R)
    L = int.from_bytes(block[:4], byteorder='big')
    R = int.from_bytes(block[4:], byteorder='big')

    #print(f"Initial L = {L:#010x}, R = {R:#010x}")

    for i in range(0, 16, 2):  # 16 rounds, step by 2 (each round uses a pair of subkeys)
        L, R = blowfish_round(L, R, subkeys[i:i+2], i // 2 + 1)  # Pass each pair of subkeys
        
        # Make sure L and R are restricted to 32 bits (32-bit mask)
        L &= 0xFFFFFFFF  # Ensuring L is within 32 bits
        R &= 0xFFFFFFFF  # Ensuring R is within 32 bits

    # After the rounds, return the concatenated result as a byte array
    #print(f"Final L = {L:#010x}, R = {R:#010x}")
    return L.to_bytes(4, byteorder='big') + R.to_bytes(4, byteorder='big')

# The main Blowfish decryption function
def blowfish_decrypt(block, subkeys):
    # Ensure the block is split into two 32-bit integers (L and R)
    L = int.from_bytes(block[:4], byteorder='big')
    R = int.from_bytes(block[4:], byteorder='big')

    for i in range(15, -1, -2):  # Reverse 16 rounds, step by -2 (each round uses a pair of subkeys)
        L, R = blowfish_round(L, R, subkeys[i:i+2], i // 2 + 1)  # Pass each pair of subkeys
        
        # Make sure L and R are restricted to 32 bits (32-bit mask)
        L &= 0xFFFFFFFF  # Ensuring L is within 32 bits
        R &= 0xFFFFFFFF  # Ensuring R is within 32 bits

    # After the rounds, return the concatenated result as a byte array
    return L.to_bytes(4, byteorder='big') + R.to_bytes(4, byteorder='big')

# Example usage
key = b"mysecretkey"  # 128-bit key
subkeys = blowfish_key_schedule(key)

# Padding plaintext to ensure it fits the block size (8 bytes)
plaintext = b"HelloBlow"  # 8-byte block (no padding needed)
plaintext_block = list(plaintext[:8])  # Adjust the block size

ciphertext = blowfish_encrypt(plaintext_block, subkeys)
decrypted_text = blowfish_decrypt(ciphertext, subkeys)

# Show Ciphertext in Hexadecimal
ciphertext_hex = ciphertext.hex()
#print(f"Ciphertext (Hex): {ciphertext_hex}")

# Handle decrypted text as raw bytes and try to decode as UTF-8, else show hex
try:
    decrypted_text_str = decrypted_text.decode('utf-8')
    #print(f"Decrypted text (UTF-8): {decrypted_text_str}")
except UnicodeDecodeError:
    decrypted_text_hex = decrypted_text.hex()
    #print(f"Decrypted text (Hex): {decrypted_text_hex}")

