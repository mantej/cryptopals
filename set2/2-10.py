"""
Implement CBC mode
"""
from Crypto.Cipher import AES

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

# Ciphertext is hex-encoded
# Key is ASCII 
def cbc_decrypt(ciphertext, key, mode, bSize=16, IV="00000000000000000000000000000000"):
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
    # Returns decrypted plaintext
    return decrypted
    
    

# open file with base64-encoded ciphertext 
with open("2-10.txt") as file:
    lines = file.readlines()
    
# ciphertext is now hex-encoded
lines = [l.strip("\n") for l in lines]
ciphertext = ''.join(lines)
ciphertext = ciphertext.decode('base64').encode('hex')

key = "YELLOW SUBMARINE"
plaintext = cbc_decrypt(ciphertext, key, AES.MODE_ECB)
print plaintext