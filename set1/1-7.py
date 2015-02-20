"""
AES in ECB mode
"""

from Crypto.Cipher import AES

# open file with base64-encoded ciphertext 
with open("1-7.txt") as file:
    lines = file.readlines()

# ciphertext is joined and base64-decoded 
lines = [l.strip("\n") for l in lines]
ciphertext = ''.join(lines)
ciphertext = ciphertext.decode('base64')

key = "YELLOW SUBMARINE"
mode = AES.MODE_ECB

aes = AES.new(key, mode)
plaintext = aes.decrypt(ciphertext)

print plaintext