"""
Implement CTR, the stream cipher mode
"""

from ctr import CTR

ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
ciphertext = ciphertext.decode('base64').encode('hex')

ctr = CTR()
print ctr.ctr_decrypt(ciphertext)