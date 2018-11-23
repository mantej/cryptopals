"""
Recover the key from CBC with IV=Key
"""
from cbc import CBC
import os

# INPUT:  ASCII key
# OUTPUT: HEX-encoded ciphertext
def setup(key):
    global cbc
    cbc = CBC(key, key.encode('hex')) # key == IV
    user_input = "mantej"
    plaintext = ("comment1=cooking%20MCs;userdata=" + user_input + ";comment2=%20like%20a%20pound%20of%20bacon").encode('hex')
    ciphertext = cbc.cbc_encrypt(plaintext)
    return ciphertext

key = os.urandom(16)
print "Original Key/IV is:  %s" % (key.encode('hex'))
ciphertext = setup(key)

block_size=16
# multiply by 2 because ciphertext is hex-encoded
first_block = ciphertext[:2*block_size]
zero_block = "00"*16

# C_1, C_2, C_3 -> C_1, 0, C_1
modified_ciphertext = first_block + zero_block + first_block
plaintext = cbc.cbc_decrypt(modified_ciphertext)

# P'_1 XOR P'_3
p1 = plaintext[:16].encode('hex')
p3 = plaintext[-16:].encode('hex')
print "Extracted Key/IV is: %s" % (cbc.xor(p1, p3))
