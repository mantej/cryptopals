from Crypto.Cipher import AES

class CBC:
	def __init__(self, key="YELLOW SUBMARINE", iv="00000000000000000000000000000000"):
		self.key = key	# key is ASCII
		self.IV = iv
		self.bSize = 16
		self.mode = AES.MODE_ECB


	# INPUT:  Hex-encoded Ciphertext
	# OUTPUT: ASCII Plaintext
	def cbc_decrypt(self, ciphertext):
	    pad = (len(ciphertext) % (self.bSize*2)) / 2
	    if pad != 0:
	        print "[*] WARNING: Last block of ciphertext needs to be padded by %s byte(s)!" % pad
	        exit(0)
	    # blocks contains the ciphertext split into bSize-byte blocks, hex-encoded
	    blocks = []
	    for i in range(0, int(len(ciphertext) / (self.bSize*2))):
	        block = ciphertext[i*(self.bSize*2):(i*(self.bSize*2))+(self.bSize*2)]
	        blocks.append(block)
	    # Create new AES object
	    aes = AES.new(self.key, self.mode)
	    decrypted = ""
	    for i in range(0, len(blocks)):
	        block = blocks[i]
	        decrypted_block = aes.decrypt(block.decode('hex'))
	        if i == 0:
	            decrypted_block = self.xor(decrypted_block.encode('hex'), self.IV)
	            decrypted += decrypted_block.decode('hex')
	        else:
	            decrypted_block = self.xor(decrypted_block.encode('hex'), blocks[i-1])
	            decrypted += decrypted_block.decode('hex')
	    # Returns decrypted plaintext in ASCII
	    return decrypted


	# INPUT:  Hex-encoded Plaintext
	# OUTPUT: Hex-encoded Ciphertext
	def cbc_encrypt(self, plaintext):
	    # Pad the plaintext before encrypting
	    plaintext = self.PKCS(plaintext)
	    # blocks contains the plaintext split into bSize-byte blocks, hex-encoded
	    blocks = []
	    for i in range(0, int(len(plaintext) / (self.bSize*2))):
	        block = plaintext[i*(self.bSize*2):(i*(self.bSize*2))+(self.bSize*2)]
	        blocks.append(block)
	    # Create new AES object
	    aes = AES.new(self.key, self.mode)
	    ciphertext = []
	    for i in range(0, len(blocks)):
	        block = blocks[i]
	        if i == 0:
	            block_to_encrypt = self.xor(block, self.IV)
	        else:
	            block_to_encrypt = self.xor(block, ciphertext[i-1])
	        ciphertext.append(aes.encrypt(block_to_encrypt.decode('hex')).encode('hex'))
	    # Returns hex-encoded ciphertext
	    return ''.join([c for c in ciphertext])


	# Returns bitwise XOR of two hex strings
	# INPUT:  2 hexadecimal strings of the same length
	# OUTPUT: 1 hexadecimal string
	def xor(self, hex1, hex2):
	    if len(hex1) != len(hex2):
	        print "[*] Hexadecimal strings are not of the same length."
	        exit(0)
	    int1, int2 = int(hex1, 16), int(hex2, 16)
	    xor_hex = (hex(int1 ^ int2)[2:]).translate(None, "L")
	    # Appends leading zeros to maintain original length
	    xor_hex = "0"*(len(hex1) - len(xor_hex)) + xor_hex
	    return xor_hex

	hex_values = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "00"]
	# plaintext is hex-encoded
	# Pads plaintext to bSize bytes
	def PKCS(self, plaintext):
	    num_pad = len(plaintext.decode('hex')) % self.bSize
	    plaintext += CBC.hex_values[self.bSize-(num_pad+1)]*(self.bSize-num_pad)
	    return plaintext


	# FIXED
	# determines if plaintext has valid PKCS#7 padding
	# plaintext is hex-encoded
	def PKCS_validate(self, plaintext):
	    padding_values = [CBC.hex_values[-1]] + CBC.hex_values[:-1]
	    if len(plaintext) % 32 != 0:
	        return False
	    if plaintext[-2:] not in padding_values:
	        return False
	    pad = padding_values.index(plaintext[-2:])
	    if pad == 0 and plaintext[-32:] != ("00"*16):
	        return False
	    for i in range(0, pad):
	        byte = plaintext[-2:]
	        plaintext = plaintext[:-2]
	        if byte != padding_values[pad]:
	            return False
	    return True


	# ciphertext is hex-encoded
	# returns true if the ciphertext decrypts to a plaintext with valid PKCS padding
	def validate(self, ciphertext):
	    plaintext = self.cbc_decrypt(ciphertext)
	    return self.PKCS_validate(plaintext.encode('hex'))
