"""
CBC bitflipping attacks
"""

from cbc import CBC
import os

# INPUT:  HEX-encoded ciphertext, integer position, character to inject
# OUTPUT: HEX-encoded ciphertext with injection character inserted at position
def bitflipping_attack(ciphertext, pos, injection):
    previous_ciphertext_block = ciphertext[32:64]

    intermediate_byte = ord(previous_ciphertext_block.decode('hex')[pos]) ^ ord("*")
    injected_byte = intermediate_byte ^ ord(injection)
    previous_ciphertext_block = previous_ciphertext_block[:pos*2] + chr(injected_byte).encode('hex') + previous_ciphertext_block[(1+pos)*2:]

    return (ciphertext[:32] + previous_ciphertext_block + ciphertext[64:])


# INPUT:  HEX-encoded ciphertext, ASCII match string, ASCII key
# OUTPUT: TRUE if match string found in decrypted ciphertext
def verify(ciphertext, match, key):
    cbc = CBC(key)
    return cbc.cbc_decrypt(ciphertext).find(match) != -1

# prepends "comment1=cooking%20MCs;userdata="
# appends ";comment2=%20like%20a%20pound%20of%20bacon"
# then, removes = and ; from user input, and encrypts with CBC
# INPUT:  ASCII input and ASCII key
# OUTPUT: HEX-encdoed ciphertext
def setup(user_input, key):
    cbc = CBC(key)
    user_input = user_input.translate(None, '=;')
    plaintext = ("comment1=cooking%20MCs;userdata=" + user_input + ";comment2=%20like%20a%20pound%20of%20bacon").encode('hex')
    ciphertext = cbc.cbc_encrypt(plaintext)
    return ciphertext



key = os.urandom(16)
user_input = "*admin*true"
ciphertext = setup(user_input, key)

# modify the 1st and 7th bytes in the previous ciphertext block
ciphertext = bitflipping_attack(ciphertext, 0, ";")
ciphertext = bitflipping_attack(ciphertext, 6, "=")

cbc = CBC(key)
if verify(ciphertext, ";admin=true;", key):
    print "admin tuple found!"
