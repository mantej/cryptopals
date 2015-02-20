"""
Single-byte xor cipher
"""

# Creates a 1-character hex pad of a number (0 - 255) with the specified length (in hex)
def generate_pad(num, length):
    h = hex(num)[2:]
    if len(h) == 1:
        h = "0" + h
    return h*(length/2)

# Returns bitwise XOR of two hex strings
def xor(hex1, hex2):
    length = len(hex1)
    if len(hex1) != len(hex2):
        print "[*] Hexadecimal strings are not of the same length."
        return False
    int1 = int(hex1, 16)
    int2 = int(hex2, 16)
    xor_hex = hex(int1 ^ int2)[2:-1]
    # Appends leading zeros to maintain original length
    while (len(xor_hex) < length):
        xor_hex = "0" + xor_hex
    return xor_hex

# Takes a hex string as input and scores it based on how many characters it uses from the English language
def score(str):
    length = len(str) / 2
    str = str.decode('hex')
    characters = list(str)
    score = 0
    for char in characters:
        # Uppercase
        if ord(char) >= 65 and ord(char) <= 90:
            score += 1
        # Lowercase
        elif ord(char) >= 97 and ord(char) <= 122:
            score += 1
        # Space
        elif ord(char) == 32:
            score += 1
    # Return a percentage between 0.0 and 1.0        
    return float(score) / length
    
    

hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
length = len(hex_string)

for i in range(0, 256):
    pad = generate_pad(i, length)
    decrypt = xor(hex_string, pad)
    if score(decrypt) > 0.9:
        print decrypt.decode('hex')
        print "Score: ", score(decrypt)
    
