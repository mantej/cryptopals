"""
CTR bitflipping
"""

from ctr import CTR
import os

# INPUT:  HEX-encoded ciphertext, integer position, character to inject
# OUTPUT: HEX-encoded ciphertext with injection character inserted at position
def bitflipping_attack(ciphertext, pos, injection):
    intermediate_byte = ord(ciphertext.decode('hex')[pos-1]) ^ ord("*")
    injected_byte = intermediate_byte ^ ord(injection)
    ciphertext = ciphertext[:(pos-1)*2] + chr(injected_byte).encode('hex') + ciphertext[pos*2:]
    return ciphertext

# INPUT:  HEX-encoded ciphertext, ASCII match string, ASCII key
# OUTPUT: TRUE if match string found in decrypted ciphertext
def verify(ciphertext, match, key):
    ctr = CTR(key)
    return ctr.ctr_decrypt(ciphertext).find(match) != -1

# prepends "comment1=cooking%20MCs;userdata="
# appends ";comment2=%20like%20a%20pound%20of%20bacon"
# then, removes = and ; from user input, and encrypts with CTR
# INPUT:  ASCII input and ASCII key
# OUTPUT: HEX-encdoed ciphertext
def setup(user_input, key):
    user_input = user_input.translate(None, '=;')
    plaintext = ("comment1=cooking%20MCs;userdata=" + user_input + ";comment2=%20like%20a%20pound%20of%20bacon").encode('hex')
    ctr = CTR(key)
    ciphertext = ctr.ctr_encrypt(plaintext)
    return ciphertext


key = os.urandom(16)
user_input = "*admin*true"
ciphertext = setup(user_input, key)

# modify 33rd byte and 39th byte
ciphertext = bitflipping_attack(ciphertext, 33, ";")
ciphertext = bitflipping_attack(ciphertext, 39, "=")

ctr = CTR(key)
if verify(ciphertext, ";admin=true;", key):
    print "admin tuple found!"
