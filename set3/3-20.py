"""
Break fixed-nonce CTR statistically
"""

from Crypto.Cipher import AES
from struct import *
import os


# Creates a 1-character hex pad of a number (0 - 255) with the specified length (in hex)
def generate_pad(num, length):
    h = hex(num)[2:]
    if len(h) == 1:
        h = "0" + h
    return h*(length/2)


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


# Takes a hex string as input and scores it based on how many characters it uses from the English language
def score(str):
    length = len(str) / 2
    str = str.decode('hex')
    characters = list(str)
    score = 0
    for char in characters:
        # Uppercase
        if ord(char) >= 65 and ord(char) <= 90:
            score += 1
        # Lowercase
        elif ord(char) >= 97 and ord(char) <= 122:
            score += 1
        # Space
        elif ord(char) == 32:
            score += 1
    # Return a percentage between 0.0 and 1.0        
    return float(score) / length


# open file with base64-encoded plaintext
with open("3-20.txt") as file:
    lines = file.readlines()
    
# plaintext is now hex-encoded
plaintexts = [l.strip("\n").decode('base64').encode('hex') for l in lines]

#key = os.urandom(16)
key = "YELLOW SUBMARINE"

# all the plaintexts encrypted under the same key with nonce fixed to 0
ciphertexts = [ctr_encrypt(plaintext, key) for plaintext in plaintexts]

# length of the shortest ciphertext (in hex)
shortest = reduce(min, map(len, ciphertexts))

# truncate all ciphertexts to the length of the shortest one
ciphertexts = [c[:shortest] for c in ciphertexts]

# first block in list is the first byte of each ciphertext, etc
transposed_blocks = []
for i in range(0, shortest/2):
    temp = ""
    for c in ciphertexts:
        temp += c.decode('hex')[i]
    transposed_blocks.append(temp.encode('hex'))


key = "56d1cb4bafa246e2e3af035d6c13c372d2ec6cdc986d12decfda1f93afee73182da08eeb117b374bc3dab726b2fc84cdc180ab3549"
"""
for k in range(0, shortest/2):
    for i in range(0, 256):
        pad = generate_pad(i, len(transposed_blocks[k]))
        decrypted = xor(transposed_blocks[k], pad)
        if score(decrypted) > 0.8:
            print "%s: %s" % (k, pad[0:2])
"""

for c in ciphertexts:
    print xor(c[:len(key)], key).decode('hex')