"""
Break fixed-nonce CTR mode using substitions
"""

from ctr import CTR
import os

plaintexts = [
"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
"U2hlIHJvZGUgdG8gaGFycmllcnM/",
"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
]

# Returns bitwise XOR of two hex strings
def xor(hex1, hex2):
    length = len(hex1)
    if len(hex1) != len(hex2):
        # FIXED
        # if strings are not of the same length,
        # the longer string is truncated
        shorter = min(len(hex1), len(hex2))
        hex1 = hex1[:shorter]
        hex2 = hex2[:shorter]
        #print "[*] Hexadecimal strings are not of the same length."
        #exit(0)
    int1 = int(hex1, 16)
    int2 = int(hex2, 16)
    xor_hex = (hex(int1 ^ int2)[2:]).translate(None, "L")
    # Appends leading zeros to maintain original length
    while (len(xor_hex) < length):
        xor_hex = "0" + xor_hex
    return xor_hex


key = os.urandom(16)
ctr = CTR(key)

# all the plaintexts encrypted under the same key with nonce fixed to 0
ciphertexts = [ctr.ctr_encrypt(p.decode('base64').encode('hex')) for p in plaintexts]


# "I have" was the most reasonable
"""
testkey1 = xor("I h".encode('hex'), ciphertexts[0][:6])
testkey2 = xor("I l".encode('hex'), ciphertexts[0][:6])
testkey3 = xor("I w".encode('hex'), ciphertexts[0][:6])
testkey4 = xor("I d".encode('hex'), ciphertexts[0][:6])
for i, c in enumerate(ciphertexts):
    r1 = xor(c[:6], testkey1).decode('hex')
    r2 = xor(c[:6], testkey2).decode('hex')
    r3 = xor(c[:6], testkey3).decode('hex')
    r4 = xor(c[:6], testkey4).decode('hex')
    print i, r1, r2, r3, r4
"""

# "Transform" was the most reasonable
"""
testkey1 = xor("I have".encode('hex'), ciphertexts[4][:12])
testkey2 = xor("I had ".encode('hex'), ciphertexts[4][:12])
for i, c in enumerate(ciphertexts):
    r1 = xor(c[:12], testkey1).decode('hex')
    r2 = xor(c[:12], testkey2).decode('hex')
    print i, r1, r2
"""

# "So sensitive" was the most reasonable
"""
testkey = xor("Transform".encode('hex'), ciphertexts[38][:18])
for i, c in enumerate(ciphertexts):
    result = xor(c[:18], testkey).decode('hex')
    print i, result
"""

# "Eighteenth-century" was the most reasonable
"""
guess = "So sensitive"
testkey = xor(guess.encode('hex'), ciphertexts[28][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""

# "Her nights in argument" was the most reasonable
"""
guess = "Eighteenth-century"
testkey = xor(guess.encode('hex'), ciphertexts[3][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""


# "When young and beautiful" was the most reasonable
"""
guess = "Her nights in argument"
testkey = xor(guess.encode('hex'), ciphertexts[18][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""

# "This man had kept a school" was the most reasonable
"""
guess = "When young and beautiful"
testkey = xor(guess.encode('hex'), ciphertexts[21][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""

# "To some who are near my heart" was the most reasonable
"""
guess = "This man had kept a school"
testkey = xor(guess.encode('hex'), ciphertexts[23][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""

# "This other his helper and friend" was the most reasonable
"""
guess = "To some who are near my heart"
testkey = xor(guess.encode('hex'), ciphertexts[33][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""

# "I have passed with a nod of the head" was the most reasonable
"""
guess = "This other his helper and friend"
testkey = xor(guess.encode('hex'), ciphertexts[25][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""

# "He, too, has been changed in his turn" was the most reasonable
"""
guess = "I have passed with a nod of the head"
testkey = xor(guess.encode('hex'), ciphertexts[4][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print i, result
"""

guess = "He, too, has been changed in his turn"
testkey = xor(guess.encode('hex'), ciphertexts[37][:len(guess)*2])
for i, c in enumerate(ciphertexts):
    result = xor(c[:len(guess)*2], testkey).decode('hex')
    print result
