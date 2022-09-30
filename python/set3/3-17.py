"""
The CBC padding oracle
"""

from cbc import CBC
import os
import random

# 10 base-64 encoded strings
messages = [
"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]

# Returns bitwise XOR of two hex strings
# INPUT:  2 hexadecimal strings of the same length
# OUTPUT: 1 hexadecimal string
def xor(hex1, hex2):
    if len(hex1) != len(hex2):
        print "[*] Hexadecimal strings are not of the same length."
        exit(0)
    int1, int2 = int(hex1, 16), int(hex2, 16)
    xor_hex = (hex(int1 ^ int2)[2:]).translate(None, "L")
    # Appends leading zeros to maintain original length
    xor_hex = "0"*(len(hex1) - len(xor_hex)) + xor_hex
    return xor_hex


# performs a CBC padding oracle attack against ciphertext
# ciphertext is hex-encoded
# returns the decrypted plaintext
def cbc_padding_attack(ciphertext):
    # preserve original ciphertext
    og_ciphertext = ciphertext
    # index of the last byte of the 2nd-to-last block
    index = 17 # since blocks are 16 bytes
    byte_index = index * -2
    # index in hex_values of the target padding value
    pad_target = 0
    # original last byte
    og_byte = ciphertext[byte_index:byte_index+2]

    # contain all intermediate values as we recover them
    intermediate_block = []
    intermediate_byte = attack_next_byte(ciphertext, byte_index, pad_target, og_byte)
    intermediate_block = [intermediate_byte] + intermediate_block

    decrypted_plaintext = ""
    while len(ciphertext) > 32:
        ciphertext = setup_block_for_next_attack(index, ciphertext, intermediate_block, pad_target)

        index = index+1
        byte_index = index * -2
        pad_target = pad_target+1
        og_byte = ciphertext[byte_index:byte_index+2]

        intermediate_byte = attack_next_byte(ciphertext, byte_index, pad_target, og_byte)
        intermediate_block = [intermediate_byte] + intermediate_block

        if pad_target == 15:
            decrypted_plaintext = xor(''.join([b for b in intermediate_block]), og_ciphertext[-64:-32]).decode('hex') + decrypted_plaintext
            og_ciphertext = og_ciphertext[:-32]
            ciphertext = og_ciphertext
            index = 17
            byte_index = index * -2
            pad_target = 0
            og_byte = ciphertext[byte_index:byte_index+2]
            if len(ciphertext) > 32:
                intermediate_block = []
                intermediate_byte = attack_next_byte(ciphertext, byte_index, pad_target, og_byte)
                intermediate_block = [intermediate_byte] + intermediate_block

    return decrypted_plaintext

hex_values = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "00"]
# sets up padding for attack on a byte
# e.g. if targeting 3rd-to-last byte, will change our ciphertext block such that
# ciphertext_byte = 03 XOR intermediate byte (which we found previously)
# for last and 2nd-to-last ciphertext_bytes
def setup_block_for_next_attack(index, ciphertext, intermediate_block, pad_target):
    while index > 16:
        for i_byte in intermediate_block:
            for num in range(0, 256):
                h = hex(num)[2:]
                if len(h) == 1:
                    h = "0" + h
                if(xor(h, i_byte) == hex_values[pad_target+1]):
                    ciphertext = ciphertext[0:(index*-2)] + h + ciphertext[(index*-2)+2:]
            index = index-1
    return ciphertext


# targets one byte of the ciphertext, incrementing it until padding is valid
# returns intermediate byte
def attack_next_byte(ciphertext, byte_index, pad_target, og_byte):
    global cbc
    for num in range(0,256):
        h = hex(num)[2:]
        if len(h) == 1:
            h = "0" + h
        if h == og_byte:
            continue
        ciphertext = ciphertext[0:byte_index] + h + ciphertext[byte_index+2:]
        if cbc.validate(ciphertext):
            #print "The value of my fake byte: ", h
            #print "Last byte of intermediate ciphertext: ", xor(h, hex_values[pad_target])
            return xor(h, hex_values[pad_target])
    #print "The value of my fake byte: ", og_byte
    #print "Last byte of intermediate ciphertext: ", xor(og_byte, hex_values[pad_target])
    return xor(og_byte, hex_values[pad_target])



# chooses a random message from those above, and encrypts it with CBC
# returns hex-encoded ciphertext
def setup():
    global cbc
    plaintext = (random.choice(messages)).decode('base64').encode('hex')
    ciphertext = cbc.cbc_encrypt(plaintext)
    return ciphertext


key = key = os.urandom(16)
iv = os.urandom(16).encode('hex')
cbc = CBC(key, iv)
ciphertext = setup()
decrypted_plaintext = cbc_padding_attack(iv+ciphertext)
print decrypted_plaintext
