"""
Break repeating-key XOR
"""

# Creates a 1-character hex pad of a number (0 - 255) with the specified length (in hex)
def generate_pad(num, length):
    h = hex(num)[2:]
    if len(h) == 1:
        h = "0" + h
    return h*(length/2)

# Creates a repeating key (ascii) of size length (in hex)
def generate_repeating_xor_key(key, length):
    key *= length / (2*len(key))
    diff = (length/2) - len(key)
    key += key[0:diff]
    return key.encode('hex')

# Returns bitwise XOR of two hex strings
def xor(hex1, hex2):
    if len(hex1) != len(hex2):
        print "[*] Hexadecimal strings are not of the same length."
        exit(0)
    int1, int2 = int(hex1, 16), int(hex2, 16)
    xor_hex = hex(int1 ^ int2)[2:-1]
    # Appends leading zeros to maintain original length
    xor_hex = "0"*(len(hex1) - len(xor_hex)) + xor_hex
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

# Returns the hamming distance between two hex strings
def hamming_distance(hex1, hex2):
    differing_bits = xor(hex1, hex2)
    binary = bin(int(differing_bits, 16))[2:]
    return binary.count('1')


#str1 = "this is a test".encode('hex')
#str2 = "wokka wokka!!!".encode('hex')
#print hamming_distance(str1, str2)

# open file with base64-encoded ciphertext
with open("1-6.txt") as file:
    lines = file.readlines()

# ciphertext is now the hex-encoded ciphertext
lines = [l.strip("\n") for l in lines]
ciphertext = ''.join(lines)
ciphertext = ciphertext.decode('base64').encode('hex')

"""
keysize = None
shortest_hamming = 100
for ksize in range(14, 40):
    str1 = ciphertext[0:ksize*2]
    str2 = ciphertext[ksize*2:ksize*4]
    str3 = ciphertext[ksize*4:ksize*6]
    str4 = ciphertext[ksize*6:ksize*8]
    hamming1 = hamming_distance(str1, str2)
    hamming2 = hamming_distance(str3, str4)
    hamming = (hamming1 + hamming2) / (2.0 * float(ksize))
    #print "The hamming distance for keysize %s is %s. " % (ksize, hamming)
    if hamming < shortest_hamming:
        shortest_hamming = hamming
        keysize = ksize
"""
keysize = 29

#print ciphertext

bytes = keysize*2 # each byte is 2 characters
blocks = []
for i in range(0, 1+len(ciphertext)/bytes):
    blocks.append(ciphertext[bytes*i:bytes*(i+1)])
    i = i+1

#print blocks

# 3 bytes per block at this point. Need to transpose into 3 blocks.
transposed = []
for k in range(0, keysize):
    transposed.append("")

for block in blocks:
    for i in range(0, keysize):
        transposed[i] += block[(i*2):((i*2)+2)]

"""
for k in range(0, keysize):
    for i in range(0, 256):
        pad = generate_pad(i, len(transposed[k]))
        decrypted = xor(transposed[k], pad)
        if score(decrypted) > 0.8:
            print "%s: %s" % (k, pad[0:2])
"""

key = "5465726d696e61746f7220583a204272696e6720746865206e6f697365"
pad = generate_repeating_xor_key(key.decode('hex'), len(ciphertext))
plaintext = xor(ciphertext, pad)
print plaintext.decode('hex')
