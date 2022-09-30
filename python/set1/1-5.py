"""
Implement repeating-key XOR
"""

# Creates a repeating key of size length (in hex)
# INPUT:  Key in ASCII. Length of the desired hexadecimal key
# OUTPUT: Key in hexadecimal
def generate_repeating_xor_key(key, length):
    key *= length / (2*len(key))
    diff = (length/2) - len(key)
    key += key[0:diff]
    return key.encode('hex')

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

english_text = "Burning 'em, if you ain't quick and nimble\
                I go crazy when I hear a cymbal".encode('hex')

key = generate_repeating_xor_key("ICE", len(english_text))
encrypted = xor(key, english_text)
print encrypted
