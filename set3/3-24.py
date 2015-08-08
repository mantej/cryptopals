"""
Create the MT19937 stream cipher and break it
"""

from twister import Twister
import random
from random import randint
import time

# Returns bitwise XOR of two hex strings
def xor(hex1, hex2):
    length = len(hex1)
    if len(hex1) != len(hex2):
        print "[*] Hexadecimal strings are not of the same length."
        return False
    int1 = int(hex1, 16)
    int2 = int(hex2, 16)
    xor_hex = (hex(int1 ^ int2)[2:]).translate(None, "L")
    # Appends leading zeros to maintain original length
    while (len(xor_hex) < length):
        xor_hex = "0" + xor_hex
    return xor_hex

# returns a keystream of same length as message
def get_stream(generator, message):
    stream = str(generator.extract_number())
    while len(message) > len(stream):
        stream = stream + str(generator.extract_number())
    stream = stream[:len(message)]
    return stream

"""
# given a ciphertext, returns the 16-bit value that seeded the generator
def recover_seed(ciphertext):
    t = Twister()
    for i in range(0, 65535):
        t.initialize_generator(i)
        stream = get_stream(t, ciphertext)
        decrypted = encrypt_19937_stream(ciphertext, stream)
        if decrypted[-6:] == "mantej":
            return i
"""

# returns true if the password reset token is a product of
# the MT19937 PRNG seeded with the current timestamp
def is_seeded_with_current_timestamp(password_reset_token):
    t = Twister()
    t.initialize_generator(int(time.time()))
    stream = get_stream(t, password_reset_token)
    decrypted = encrypt_19937_stream(password_reset_token, stream)
    if decrypted[-6:] == "mantej":
        return True
    return False

def encrypt_19937_stream(message, stream):
    return xor(message.encode('hex'), stream.encode('hex')).decode('hex')


# 16-bit seed
#seed = int(randint(0, 65535))

coin_flip = random.choice(["Heads", "Tails"])
if coin_flip is "Heads":
    seed = int(randint(0, 65535))
    print "Actual: Not seeded with current timestamp."
else:
    seed = int(time.time())
    print "Actual: Seeded with current UNIX timestamp"

twister = Twister()
twister.initialize_generator(seed)

plaintext = "password reset token for mantej"
stream = get_stream(twister, plaintext)
password_reset_token = encrypt_19937_stream(plaintext, stream)

if is_seeded_with_current_timestamp(password_reset_token):
    print "My Guess: Seeded with current UNIX timestamp"
else:
    print "My Guess: Not seeded with current UNIX timestamp"
