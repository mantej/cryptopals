"""
Break an MD4 keyed MAC using length extension
"""

from md4 import md4,authMD4
from random import randint
import binascii
import struct
import os


# returns True if the digest corresponds to the message under the secret key
def validate(message, message_digest):
    global key
    return authMD4(key, message) == message_digest


# pads message with (1 + 0s + length of message)
def glue_padding(message):
    length = len(message)*8 # length of message in bits
    padded_message = message + '\x80' # 10000000
    # message needs to be congruent to 448 modulo 512 bits (56 modulo 64 in bytes)
    padded_message = padded_message + '\x00' * ((56 - (len(padded_message) % 64)) % 64)
    # append length of message (w/o padding) in bits
    padded_message += struct.pack('<Q', length)
    return padded_message.encode('hex')


# breaks MD4 hash into 4 32-bit registers
def get_internal_state(md4_decimal_digest):
    a = md4_decimal_digest >> 96
    b = (md4_decimal_digest >> 64) & 0xffffffff
    c = (md4_decimal_digest >> 32) & 0xffffffff
    d = md4_decimal_digest & 0xffffffff
    return [a, b, c, d]


# forged_message = "A"*keylen || original message || glue padding || new message
# get_internal_state = breaks original message digest into [4] 32-bit registers
# forged_digest = MD4 digest under secret key for our forged message
def forge_message(message, message_digest, keylen, new_message):
    forged_message = glue_padding("A"*keylen + message) + new_message
    # remove key from our forged message (it's not the correct key anyways)
    forged_message = forged_message[keylen:]

    decimal_digest = int(message_digest, 16)
    r = get_internal_state(decimal_digest)
    # call MD4 directly with fixated registers & additional data to forge
    forged_digest = md4(new_message, r[0], r[1], r[2], r[3], (keylen+len(forged_message)) * 8)

    return (forged_message, forged_digest)


# generate random key between 1 and 32 bytes (inclusive)
random = randint(1,32)
key = os.urandom(random)
print
print "[*] Actual key length is %s" % (len(key))


"""
# message & MD4 message digest
message = b'user=mantej;'
message_digest = authMD4(key, message)

# taking stabs at the key length until we guess correctly & forge a MAC
for i in range(1, 33):
    m, d = forge_message(message, message_digest, i, b';admin=true')
    if validate(m, d):
        print
        print "[*] Secret-Prefix MAC Generated!"
        print "[*] My Guessed Key Length is %s" % (i)
        print "[*] Forged Message: %s" % (m)
        print "[*] Forged Digest under Secret Key: %s" % (d)
"""
