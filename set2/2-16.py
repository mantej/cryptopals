"""
CBC bitflipping attacks
"""

from Crypto.Cipher import AES
import os
from random import randint

# Returns bitwise XOR of two hex strings
# INPUT:  2 hexadecimal strings of the same length
# OUTPUT: 1 hexadecimal string
def xor(hex1, hex2):
    if len(hex1) != len(hex2):
        print "[*] Hexadecimal strings are not of the same length."
        exit(0)
    int1, int2 = int(hex1, 16), int(hex2, 16)
    xor_hex = hex(int1 ^ int2)[2:-1]
    # Appends leading zeros to maintain original length
    xor_hex = "0"*(len(hex1) - len(xor_hex)) + xor_hex
    return xor_hex


# INPUT:  Hex-encoded Ciphertext. ASCII Key.
# OUTPUT: ASCII Plaintext
def cbc_decrypt(ciphertext, key, IV="00000000000000000000000000000000", bSize=16, mode=AES.MODE_ECB):
    pad = (len(ciphertext) % (bSize*2)) / 2
    if pad != 0:
        print "[*] WARNING: Last block of ciphertext needs to be padded by %s byte(s)!" % pad
        exit(0)
    # blocks contains the ciphertext split into bSize-byte blocks, hex-encoded
    blocks = []
    for i in range(0, int(len(ciphertext) / (bSize*2))):
        block = ciphertext[i*(bSize*2):(i*(bSize*2))+(bSize*2)]
        blocks.append(block)
    # Create new AES object
    aes = AES.new(key, mode)
    decrypted = ""
    for i in range(0, len(blocks)):
        block = blocks[i]
        decrypted_block = aes.decrypt(block.decode('hex'))
        if i == 0:
            decrypted_block = xor(decrypted_block.encode('hex'), IV)
            decrypted += decrypted_block.decode('hex')
        else:
            decrypted_block = xor(decrypted_block.encode('hex'), blocks[i-1])
            decrypted += decrypted_block.decode('hex')
    # Returns plaintext
    return decrypted



hex_values = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "00"]
# INPUT:  Hex-encoded Plaintext. ASCII Key.
# OUTPUT: Hex-encoded Ciphertext
def cbc_encrypt(plaintext, key, IV="00000000000000000000000000000000", bSize=16, mode=AES.MODE_ECB):
    # Pad the plaintext before encrypting
    plaintext = PKCS(plaintext, bSize)
    # blocks contains the plaintext split into bSize-byte blocks, hex-encoded
    blocks = []
    for i in range(0, int(len(plaintext) / (bSize*2))):
        block = plaintext[i*(bSize*2):(i*(bSize*2))+(bSize*2)]
        blocks.append(block)
    # Create new AES object
    aes = AES.new(key, mode)
    ciphertext = []
    for i in range(0, len(blocks)):
        block = blocks[i]
        if i == 0:
            block_to_encrypt = xor(block, IV)
        else:
            block_to_encrypt = xor(block, ciphertext[i-1])
        ciphertext.append(aes.encrypt(block_to_encrypt.decode('hex')).encode('hex'))
    # Returns ciphertext
    return ''.join([c for c in ciphertext])


# plaintext is hex-encoded
# Pads plaintext to bSize bytes
def PKCS(plaintext, bSize):
    num_pad = len(plaintext.decode('hex')) % bSize
    plaintext += hex_values[bSize-(num_pad+1)]*(bSize-num_pad)
    return plaintext


padding_values = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f"]
# plaintext is ascii
# determines if plaintext has valid PKCS#7 padding, and strips the padding off.
def PKCS_validate(plaintext):
    plaintext = plaintext.encode('hex')
    if len(plaintext) % 32 != 0:
        raise Exception("Invalid PKCS#7 padding!")
    pad = padding_values.index(plaintext[-2:])
    for i in range(0, pad):
        byte = plaintext[-2:]
        plaintext = plaintext[:-2]
        if byte != padding_values[pad]:
            raise Exception("Invalid PKCS#7 padding!")
    return plaintext.decode('hex')


# prepends "comment1=cooking%20MCs;userdata="
# appends ";comment2=%20like%20a%20pound%20of%20bacon"
# then, removes = and ;, and encrypts with AES CBC
# user_input is ascii
# key is ascii
def setup(user_input, key):
    user_input = user_input.translate(None, '=;')
    plaintext = ("comment1=cooking%20MCs;userdata=" + user_input + ";comment2=%20like%20a%20pound%20of%20bacon").encode('hex')
    ciphertext = cbc_encrypt(plaintext, key)
    return ciphertext


# ciphertext is hex-encoded
# key is ascii
def bitflipping_attack(ciphertext, key):
    previous_ciphertext_block = ciphertext[32:64]

    for num in range(0,256):
        h = hex(num)[2:]
        if len(h) == 1:
            h = "0" + h
        previous_ciphertext_block = h + previous_ciphertext_block[2:]
        tampered = cbc_decrypt(ciphertext[:32] + previous_ciphertext_block + ciphertext[64:], key)
        if tampered[32] == ";":
            break

    for num in range(0,256):
        h = hex(num)[2:]
        if len(h) == 1:
            h = "0" + h
        previous_ciphertext_block = previous_ciphertext_block[:12] + h + previous_ciphertext_block[14:]
        tampered = cbc_decrypt(ciphertext[:32] + previous_ciphertext_block + ciphertext[64:], key)
        if tampered[38] == "=":
            break

    tampered = tampered[32:]
    plaintext = cbc_decrypt(ciphertext, key)[0:32] + tampered
    return PKCS_validate(plaintext)


key = os.urandom(16)
user_input = "*admin*true"

# prepends/appends text, then removes = and ;, and encrypts with CBC
ciphertext = setup(user_input, key)

admin_plaintext = bitflipping_attack(ciphertext, key)
print admin_plaintext
