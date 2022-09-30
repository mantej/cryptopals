"""
Byte-at-a-time ECB decryption (Harder)
"""

from Crypto.Cipher import AES
import os
from random import randint

# plaintext and key are both hex-encoded
def encrypt_ecb(plaintext, key):
    aes = AES.new(key, AES.MODE_ECB)
    # add random bytes to make multiple of 16
    while len(plaintext.decode('hex')) % 16 != 0:
        plaintext += os.urandom(1).encode('hex')
    ciphertext = aes.encrypt(plaintext.decode('hex')).encode('hex')
    # hex-encoded ciphertext
    return ciphertext

# returns a dict with all ECB values of text+(all possible values from 00 to ff)
# len(text) should be block size - 1
def build_dict(text, key):
    v = {}
    for i in range(0,256):
        h = hex(i)[2:]
        if len(h) == 1:
            h = "0" + h
        v[encrypt_ecb(text+h, key)] = h
    return v

# discovers length of prefix (in bytes) before attacker-controlled text
# this function works specifically for prefixes of < 16 bytes
def find_random_prefix_length(prefix, secret, key):
    text = "ff"
    previous_block, prefix_offset = None, None
    for i in range(0, 1000):
        ciphertext = encrypt_ecb(prefix+(text*i)+secret, key)
        if len(ciphertext) > 64:
            if ciphertext[32:64] == previous_block:
                prefix_offset = i-1
                break
            previous_block = ciphertext[32:64]
    return 32-prefix_offset

# cracks "secret" using a byte-at-a-time oracle attack when a random-prefix is prepended
# AES_ECB(random-prefix || attacker-controlled || secret)
def break_ECB(prefix, secret, key):
    prefix_length = find_random_prefix_length(prefix, secret, key)
    
    cracked = ""
    length = len(secret)
    while len(cracked.encode('hex')) < length:
        guess = ""
        for i in xrange((15-prefix_length), -1, -1):
            text = ("A"*i).encode('hex')
            values = build_dict(prefix+text+guess.encode('hex'), key)
            try:
                guess += values[encrypt_ecb(prefix+text+secret, key)[0:32]].decode('hex')
            except:
                guess = guess[:-1]
                break
        cracked += guess
        secret = secret[(32-(prefix_length*2)):]
    return cracked

#######################################################################

key = os.urandom(16).encode('hex')
secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".decode('base64').encode('hex')
prefix = os.urandom(randint(1,16)).encode('hex')

cracked = break_ECB(prefix, secret, key)
print cracked