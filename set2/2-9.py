"""
Implement PKCS#7 padding
"""

padding_values = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f"]

# Takes a block (ascii) and pads it to length.
def pad_block(block, length):
    i = length - len(block)
    block = block.encode('hex')
    for j in range(0, i):
        block += padding_values[i]
    return block.decode('hex')
    

block = "YELLOW SUBMARINE"
block = pad_block(block, 20)
print block