"""
Break fixed-nonce CTR statistically
"""

from ctr import CTR

# Creates a 1-character hex pad of a number (0 - 255) with the specified length (in hex)
def generate_pad(num, length):
    h = hex(num)[2:]
    if len(h) == 1:
        h = "0" + h
    return h*(length/2)


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


# open file with base64-encoded plaintext
with open("3-20.txt") as file:
    lines = file.readlines()
    
# plaintext is now hex-encoded
plaintexts = [l.strip("\n").decode('base64').encode('hex') for l in lines]

key = "YELLOW SUBMARINE"
ctr = CTR(key)

# all the plaintexts encrypted under the same key with nonce fixed to 0
ciphertexts = [ctr.ctr_encrypt(plaintext) for plaintext in plaintexts]

# length of the shortest ciphertext (in hex)
shortest = reduce(min, map(len, ciphertexts))

# truncate all ciphertexts to the length of the shortest one
ciphertexts = [c[:shortest] for c in ciphertexts]

# first block in list is the first byte of each ciphertext, etc
transposed_blocks = []
for i in range(0, shortest/2):
    temp = ""
    for c in ciphertexts:
        temp += c.decode('hex')[i]
    transposed_blocks.append(temp.encode('hex'))


key = "56d1cb4bafa246e2e3af035d6c13c372d2ec6cdc986d12decfda1f93afee73182da08eeb117b374bc3dab726b2fc84cdc180ab3549"
"""
for k in range(0, shortest/2):
    for i in range(0, 256):
        pad = generate_pad(i, len(transposed_blocks[k]))
        decrypted = xor(transposed_blocks[k], pad)
        if score(decrypted) > 0.8:
            print "%s: %s" % (k, pad[0:2])
"""

for c in ciphertexts:
    print ctr.xor(c[:len(key)], key).decode('hex')
