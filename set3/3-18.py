"""
Implement CTR, the stream cipher mode
"""

from Crypto.Cipher import AES
from struct import *

# Returns bitwise XOR of two hex strings
def xor(hex1, hex2):
    length = len(hex1)
    if len(hex1) != len(hex2):
        print "[*] Hexadecimal strings are not of the same length."
        exit(0)
    int1 = int(hex1, 16)
    int2 = int(hex2, 16)
    xor_hex = (hex(int1 ^ int2)[2:]).translate(None, "L")
    # Appends leading zeros to maintain original length
    while (len(xor_hex) < length):
        xor_hex = "0" + xor_hex
    return xor_hex


# plaintext is hex-encoded
# key is ascii
def ctr_encrypt(plaintext, key, nonce=0):
    aes = AES.new(key, AES.MODE_ECB)
    encrypted = ""
    ctr = nonce
    keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))

    # while there is more than '1 block' left (16 bytes = 32 hex characters)
    while len(plaintext) >= 32:
        encrypted += xor(plaintext[:32], keystream.encode('hex'))
        plaintext = plaintext[32:]
        ctr = ctr+1
        keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))

    if len(plaintext) != 0:
        leftover_length = len(plaintext)/2
        keystream = keystream[0:leftover_length]
        encrypted += xor(plaintext[:leftover_length*2], keystream.encode('hex'))

    # returns hex-encoded ciphertext
    return encrypted


# ciphertext is hex-encoded
# key is ascii
def ctr_decrypt(ciphertext, key, nonce=0):
    aes = AES.new(key, AES.MODE_ECB)
    decrypted = ""
    ctr = nonce
    keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))

    # while there is more than '1 block' left (16 bytes = 32 hex characters)
    while len(ciphertext) >= 32:
        decrypted += xor(ciphertext[:32], keystream.encode('hex')).decode('hex')
        ciphertext = ciphertext[32:]
        ctr = ctr+1
        keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))

    if len(ciphertext) != 0:
        leftover_length = len(ciphertext)/2
        keystream = keystream[0:leftover_length]
        decrypted += xor(ciphertext[:leftover_length*2], keystream.encode('hex')).decode('hex')

    # returns decrypted plaintext in ascii
    return decrypted


key = "YELLOW SUBMARINE"
ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".decode('base64').encode('hex')

print ctr_decrypt(ciphertext, key)