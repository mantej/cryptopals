"""
PKCS#7 padding validation
"""

padding_values = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f"]

# determines if plaintext has valid PKCS#7 padding, and strips the padding off.
# plaintext is hex-encoded
def PKCS_validate(plaintext):
    if len(plaintext) % 32 != 0:
        raise Exception("Invalid PKCS#7 padding!")
    pad = padding_values.index(plaintext[-2:])
    for i in range(0, pad):
        byte = plaintext[-2:]
        plaintext = plaintext[:-2]
        if byte != padding_values[pad]:
            raise Exception("Invalid PKCS#7 padding!")
    return plaintext.decode('hex')
    

plaintext = "49434520494345204241425904040404"
print PKCS_validate(plaintext)