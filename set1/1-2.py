"""
Fixed XOR
"""

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

str1 = "1c0111001f010100061a024b53535009181c"
str2 = "686974207468652062756c6c277320657965"

print xor(str1, str2)
