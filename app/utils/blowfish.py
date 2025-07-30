import struct

P = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
    0x082EFA98, 0xEC4E6C89, 0x9B88A5A5, 0x7A8A41B1, 0x6A14A7A1, 0xBCB6A6A3,
    0xDCFC7E38, 0xAFB7B1FC, 0x989CFB6F, 0x0D89F1F6, 0x76302B5B, 0xD1A0C3C4
]  

S = [
    [0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0x5A883F30, 0x8D8B6A05,  # S1
     0x7A8B9A9C, 0xD08D2A5D, 0xB8D4D5B8, 0x121E4D76, 0x49A9E9A7, 0x59406E6B, 0xF1D7D6D3, 0x7A2F24AA],
]


def blowfish_key_schedule(key):
    key_len = len(key)
    data = bytearray(key)
    
    
    subkeys = P[:]
    
    for i in range(18):
        subkeys[i] ^= data[i % key_len]  

    
    for i in range(0, 18, 2):
        subkeys[i] ^= (subkeys[i - 1] + 0x1A2B3C4D) 
        
    return subkeys


def blowfish_round(L, R, subkeys, round_num):
    L_new = L ^ subkeys[0]
    R_new = R ^ subkeys[1]
    
    #print(f"Round {round_num}: L = {L_new:#010x}, R = {R_new:#010x}")
    
    return L_new, R_new


def blowfish_encrypt(block, subkeys):
    L = int.from_bytes(block[:4], byteorder='big')
    R = int.from_bytes(block[4:], byteorder='big')

    for i in range(0, 16, 2): 
        L, R = blowfish_round(L, R, subkeys[i:i+2], i // 2 + 1)  
        
        L &= 0xFFFFFFFF  
        R &= 0xFFFFFFFF  
    return L.to_bytes(4, byteorder='big') + R.to_bytes(4, byteorder='big')


def blowfish_decrypt(block, subkeys):
    L = int.from_bytes(block[:4], byteorder='big')
    R = int.from_bytes(block[4:], byteorder='big')

    for i in range(15, -1, -2):  
        L, R = blowfish_round(L, R, subkeys[i:i+2], i // 2 + 1)  
        
        
        L &= 0xFFFFFFFF  
        R &= 0xFFFFFFFF 

    return L.to_bytes(4, byteorder='big') + R.to_bytes(4, byteorder='big')


key = b"mysecretkey"  
subkeys = blowfish_key_schedule(key)

plaintext = b"HelloBlow"  
plaintext_block = list(plaintext[:8])  

ciphertext = blowfish_encrypt(plaintext_block, subkeys)
decrypted_text = blowfish_decrypt(ciphertext, subkeys)


ciphertext_hex = ciphertext.hex()

try:
    decrypted_text_str = decrypted_text.decode('utf-8')
    #print(f"Decrypted text (UTF-8): {decrypted_text_str}")
except UnicodeDecodeError:
    decrypted_text_hex = decrypted_text.hex()
    #print(f"Decrypted text (Hex): {decrypted_text_hex}")

