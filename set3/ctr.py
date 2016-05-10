"""
Implement CTR, the stream cipher mode
"""

from Crypto.Cipher import AES
from struct import *

class CTR:
    def __init__(self, key="YELLOW SUBMARINE", nonce=0):
        self.key = key # key is ASCII
        self.nonce = nonce
        self.mode = AES.MODE_ECB

    # ciphertext is hex-encoded
    def ctr_decrypt(self, ciphertext):
        aes = AES.new(self.key, self.mode)
        decrypted = ""
        ctr = self.nonce
        keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))
        
        # while there is more than '1 block' left (16 bytes = 32 hex characters)
        while len(ciphertext) >= 32:
            decrypted += self.xor(ciphertext[:32], keystream.encode('hex')).decode('hex')
            ciphertext = ciphertext[32:]
            ctr = ctr+1
            keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))
        
        if len(ciphertext) != 0:
            leftover_length = len(ciphertext)/2
            keystream = keystream[0:leftover_length]
            decrypted += self.xor(ciphertext[:leftover_length*2], keystream.encode('hex')).decode('hex')
        
        # returns decrypted plaintext in ascii
        return decrypted

    # plaintext is hex-encoded
    def ctr_encrypt(self, plaintext):
        aes = AES.new(self.key, self.mode)
        encrypted = ""
        ctr = self.nonce
        keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))
        
        # while there is more than '1 block' left (16 bytes = 32 hex characters)
        while len(plaintext) >= 32:
            encrypted += self.xor(plaintext[:32], keystream.encode('hex'))
            plaintext = plaintext[32:]
            ctr = ctr+1
            keystream = aes.encrypt(pack("<Q",0)+pack("<Q", ctr))
        
        if len(plaintext) != 0:
            leftover_length = len(plaintext)/2
            keystream = keystream[0:leftover_length]
            encrypted += self.xor(plaintext[:leftover_length*2], keystream.encode('hex'))
        
        # returns hex-encoded ciphertext
        return encrypted

    # Returns bitwise XOR of two hex strings
    def xor(self, hex1, hex2):
        length = len(hex1)
        if len(hex1) != len(hex2):
            print "[*] Hexadecimal strings are not of the same length."
            exit(0)
        int1 = int(hex1, 16)
        int2 = int(hex2, 16)
        xor_hex = (hex(int1 ^ int2)[2:]).translate(None, "L")
        # Appends leading zeros to maintain original length
        while (len(xor_hex) < length):
            xor_hex = "0" + xor_hex
        return xor_hex




