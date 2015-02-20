"""
An ECB/CBC detection oracle
"""

from Crypto.Cipher import AES
import os
from random import randint

plaintext = "I'm back and I'm ringin' the bell \n\
A rockin' on the mike while the fly girls yell \n\
In ecstasy in the back of me \n\
Well that's my DJ Deshay cuttin' all them Z's \n\
Hittin' hard and the girlies goin' crazy \n\
Vanilla's on the mike, man I'm not lazy. \n\n\
\
I'm lettin' my drug kick in \n\
It controls my mouth and I begin \n\
To just let it flow, let my concepts go \n\
My posse's to the side yellin', Go Vanilla Go! \n\n\
\
Smooth 'cause that's the way I will be \n\
And if you don't give a damn, then \n\
Why you starin' at me \n\
So get off 'cause I control the stage \n\
There's no dissin' allowed \n\
I'm in my own phase \n\
The girlies sa y they love me and that is ok \n\
And I can dance better than any kid n' play \n\n\
\
Stage 2 -- Yea the one ya' wanna listen to \n\
It's off my head so let the beat play through \n\
So I can funk it up and make it sound good \n\
1-2-3 Yo -- Knock on some wood \n\
For good luck, I like my rhymes atrocious \n\
Supercalafragilisticexpialidocious \n\
I'm an effect and that you can bet \n\
I can take a fly girl and make her wet. \n\n\
\
I'm like Samson -- Samson to Delilah \n\
There's no denyin', You can try to hang \n\
But you'll keep tryin' to get my style \n\
Over and over, practice makes perfect \n\
But not if you're a loafer. \n\n\
\
You'll get nowhere, no place, no time, no girls \n\
Soon -- Oh my God, homebody, you probably eat \n\
Spaghetti with a spoon! Come on and say it! \n\n\
\
VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n\
Intoxicating so you stagger like a wino \n\
So punks stop trying and girl stop cryin' \n\
Vanilla Ice is sellin' and you people are buyin' \n\
'Cause why the freaks are jockin' like Crazy Glue \n\
Movin' and groovin' trying to sing along \n\
All through the ghetto groovin' this here song \n\
Now you're amazed by the VIP posse. \n\n\
\
Steppin' so hard like a German Nazi \n\
Startled by the bases hittin' ground \n\
There's no trippin' on mine, I'm just gettin' down \n\
Sparkamatic, I'm hangin' tight like a fanatic \n\
You trapped me once and I thought that \n\
You might have it \n\
So step down and lend me your ear \n\
'89 in my time! You, '90 is my year. \n\n\
\
You're weakenin' fast, YO! and I can tell it \n\
Your body's gettin' hot, so, so I can smell it \n\
So don't be mad and don't be sad \n\
'Cause the lyrics belong to ICE, You can call me Dad \n\
You're pitchin' a fit, so step back and endure \n\
Let the witch doctor, Ice, do the dance to cure \n\
So come up close and don't be square \n\
You wanna battle me -- Anytime, anywhere \n\n\
\
You thought that I was weak, Boy, you're dead wrong \n\
So come on, everybody and sing this song \n\n\
\
Say -- Play that funky music Say, go white boy, go white boy go \n\
play that funky music Go white boy, go white boy, go \n\
Lay down and boogie and play that funky music till you die. \n\n\
\
Play that funky music Come on, Come on, let me hear \n\
Play that funky music white boy you say it, say it \n\
Play that funky music A little louder now \n\
Play that funky music, white boy Come on, Come on, Come on \n\
Play that funky music".encode('hex')


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
def cbc_decrypt(ciphertext, key, IV="00000000000000000000000000000000", bSize=16, mode=AES.MODE_ECB):
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
    # Returns plaintext
    return decrypted


hex_values = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f"]
# Plaintext is hex-encoded
# Key is ASCII 
def cbc_encrypt(plaintext, key, IV="00000000000000000000000000000000", bSize=16, mode=AES.MODE_ECB):
    # Pad the plaintext before encrypting
    plaintext = PKCS(plaintext, bSize)
    # blocks contains the plaintext split into bSize-byte blocks, hex-encoded
    blocks = []
    for i in range(0, int(len(plaintext) / (bSize*2))):
        block = plaintext[i*(bSize*2):(i*(bSize*2))+(bSize*2)]
        blocks.append(block)
    # Create new AES object
    aes = AES.new(key, mode)
    ciphertext = []
    for i in range(0, len(blocks)):
        block = blocks[i]
        if i == 0:
            block_to_encrypt = xor(block, IV)
        else:
            block_to_encrypt = xor(block, ciphertext[i-1])
        ciphertext.append(aes.encrypt(block_to_encrypt.decode('hex')).encode('hex'))
    # Returns ciphertext
    #return 
    return ''.join([c for c in ciphertext])


# Plaintext is hex-encoded
# Pads plaintext to bSize bytes
def PKCS(plaintext, bSize):
    num_pad = len(plaintext.decode('hex')) % bSize
    plaintext += hex_values[bSize-(num_pad+1)]*(bSize-num_pad)
    return plaintext


#######################################################################

def random_encrypt(plaintext, key):
    r1 = randint(5,10)
    r2 = randint(5,10)
    plaintext = os.urandom(r1).encode('hex') + plaintext + os.urandom(r2).encode('hex')
    
    choice = randint(0,1)
    if choice == 0:
        print "Encrypting with ECB..."
        aes = AES.new(key, AES.MODE_ECB)
        # add random bytes to make multiple of 16
        while len(plaintext.decode('hex')) % 16 != 0:
            plaintext += os.urandom(1).encode('hex')
        ciphertext = aes.encrypt(plaintext.decode('hex')).encode('hex')
    else:
        print "Encrypting with CBC..."
        ciphertext = cbc_encrypt(plaintext, key, os.urandom(16).encode('hex'))
    
    # hex-encoded ciphertext
    return ciphertext

# ciphertext is hex-encoded
# ECB IS NOT ALWAYS DETECTED PROPERLY =/
def detection_oracle(ciphertext, bSize=16):
    blocks = []
    for i in range(0, int(len(ciphertext) / (bSize*2))):
        blocks.append(ciphertext[i*(bSize*2):(i*(bSize*2))+(bSize*2)])
    if len(blocks) != len(set(blocks)):
        print "ECB-encrypted ciphertext detected."
    else:
        print "CBC-encrypted ciphertext detected"
    

#######################################################################

key = os.urandom(16)
ciphertext = random_encrypt(plaintext, key)
detection_oracle(ciphertext)

#ciphertext = cbc_encrypt(plaintext, key)
#plaintext = cbc_decrypt(ciphertext, key)
#print plaintext








