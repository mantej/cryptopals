"""
ECB cut-and-paste
"""
from Crypto.Cipher import AES
import os
from random import randint

# plaintext and key are both hex-encoded
def encrypt_ecb(plaintext, key):
    aes = AES.new(key, AES.MODE_ECB)
    # add random bytes to make multiple of 16
    while len(plaintext.decode('hex')) % 16 != 0:
        plaintext += "00"
        #plaintext += os.urandom(1).encode('hex')
    ciphertext = aes.encrypt(plaintext.decode('hex')).encode('hex')
    # hex-encoded ciphertext
    return ciphertext

# ciphertext and key are both hex-encoded
def decrypt_ecb(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = aes.decrypt(ciphertext.decode('hex')).encode('hex')
    # hex-encoded plaintext
    return plaintext

# returns encoded profile
def profile_for(email):
    email = email.translate(None, '&=')
    return "email=%s&uid=10&role=user" % email

# returns profile
def parse(encoded_profile):
    components = encoded_profile.split('&')
    for i in range(0, 3):
        k, v = components[i].split('=')
        print "%s: %s" % (k, v)

#######################################################################

key = os.urandom(16).encode('hex')

attack1 = encrypt_ecb(profile_for("msr@gmail.com").encode('hex'), key)

# first 16 bytes are "email=AAAAAAAAAA"
# "admin" is then at the beginning of the 2nd block
attack2 = encrypt_ecb(profile_for("AAAAAAAAAAadmin").encode('hex'), key)

# combine first two blocks of 1st ciphertext with second block of 2nd ciphertext
combined_blocks = attack1[:64] + attack2[32:64]

decrypted_encoded_profile = decrypt_ecb(combined_blocks, key).decode('hex')
parse(decrypted_encoded_profile)

