"""
Break a SHA-1 keyed MAC using length extension
"""

from sha1 import sha1,authSHA1
from random import randint
import binascii
import os


# returns True if the digest corresponds to the message under the secret key
def validate(message, message_digest):
    global key
    return authSHA1(key, message) == message_digest


# breaks SHA1 hash into 5 32-bit registers
def get_internal_state(sha1_decimal_digest):
    a = sha1_decimal_digest >> 128
    b = (sha1_decimal_digest >> 96) & 0xffffffff
    c = (sha1_decimal_digest >> 64) & 0xffffffff
    d = (sha1_decimal_digest >> 32) & 0xffffffff
    e = sha1_decimal_digest & 0xffffffff
    return [a, b, c, d, e]


# slightly modified copy of padding code from sha1.py
# pads message with (1 + 0s + length of message)
def glue_padding(message):
    length = len(message)*8
    bytes = ""
    for n in range(len(message)):
        bytes+='{0:08b}'.format(ord(message[n]))
    # append the bit '1' to the message
    bits = bytes+"1"
    pBits = bits
    # pad w '0's until length equals 448 mod 512
    while len(pBits)%512 != 448:
        pBits+="0"
    # append the length of the message
    pBits+='{0:064b}'.format(length)
    # convert from binary to ASCII
    n = int(pBits, 2)
    return binascii.unhexlify('%x' % n)


# forged_message = "A"*keylen || original message || glue padding || new message
# get_internal_state = breaks original message digest into [5] 32-bit registers
# forged_digest = SHA-1 digest under secret key for our forged message
def forge_message(message, message_digest, keylen, new_message):
    forged_message = glue_padding("A"*keylen + message) + new_message
    # remove key from our forged message (it's not the correct key anyways)
    forged_message = forged_message[keylen:]

    decimal_digest = int(message_digest, 16)
    h = get_internal_state(decimal_digest)
    # call SHA1 directly with fixated registers & additional data to forge
    forged_digest = sha1(new_message, h[0], h[1], h[2], h[3], h[4], (keylen+len(forged_message)) * 8)

    return (forged_message, forged_digest)


# generate random key between 1 and 32 bytes (inclusive)
random = randint(1,32)
key = os.urandom(random)
print
print "[*] Actual key length is %s" % (len(key))

# message & SHA1 message digest
#pmessage = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
message = b'user=mantej;'
message_digest = authSHA1(key, message)

# taking stabs at the key length until we guess correctly & forge a MAC
for i in range(1, 33):
    m, d = forge_message(message, message_digest, i, b';admin=true')
    if validate(m, d):
        print
        print "[*] Secret-Prefix MAC Generated!"
        print "[*] My Guessed Key Length is %s" % (i)
        print "[*] Forged Message: %s" % (m)
        print "[*] Forged Digest under Secret Key: %s" % (d)
