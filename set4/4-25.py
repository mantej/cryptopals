"""
Break "random access read/write" AES CTR
"""

from ctr import CTR
import os

# ciphertext is hex-encoded
# offset is an integer (0 offset = editing first letter of plaintext)
# newtext is ascii
def edit(ciphertext, offset, newtext):
    global ctr
    plaintext = ctr.ctr_decrypt(ciphertext)
    plaintext = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
    return ctr.ctr_encrypt(plaintext.encode('hex'))


# open file with plaintext to encrypt
with open("4-25.txt") as file:
    lines = file.readlines()

# join lines of plaintext together
lines = [l for l in lines]
plaintext = ''.join(lines)

key = os.urandom(16)
ctr = CTR(key)
ciphertext = ctr.ctr_encrypt(plaintext.encode('hex'))


recovered_plaintext = ""
# edits 1 character (of the plaintext) at a time
# if the resulting ciphertext matches the original ciphertext,
# then we have recovered a character from the original plaintext
for i in range(len(ciphertext)/2):
    for c in range(256):
        if ciphertext == edit(ciphertext, i, chr(c)):
            recovered_plaintext = recovered_plaintext + chr(c)
            break

print recovered_plaintext





