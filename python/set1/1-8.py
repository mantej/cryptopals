"""
Detect AES in ECB mode
"""

# open file with hex-encoded ciphertext
with open("1-8.txt") as file:
    lines = file.readlines()

# returns True if the hex-encoded ciphertext is encrypted with ECB
def detect_ecb(ciphertext, bSize=16):
    blocks = []
    for i in range(0, int(len(ciphertext) / (bSize*2))):
        blocks.append(ciphertext[i*(bSize*2):(i*(bSize*2))+(bSize*2)])
    if len(blocks) != len(set(blocks)):
        return True
    return False

for ciphertext in lines:
    if detect_ecb(ciphertext):
        print ciphertext
