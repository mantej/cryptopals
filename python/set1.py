import base64

from Crypto.Cipher import AES

def challenge1():
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectedResult = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    b64 = base64.b64encode(bytes.fromhex(hex)).decode()
    if b64 != expectedResult:
        raise ValueError(f"Challenge 1 failed: got {b64}, expected {expectedResult}")
    else:
        print("[*] challenge 1 passed")


def xor(hex1: str, hex2: str) -> bytes:
    """
    Takes two hex strings and returns their XOR combination

    Args:
        hex1 (str): First hexadecimal string
        hex2 (str): Second hexadecimal string

    Returns:
        bytes: Bytes representation of the XOR combination of hex1 and hex2
    """
    if len(hex1) != len(hex2):
        raise ValueError("Hex strings must be same length")
        
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)
    xored = bytes(a ^ b for a,b in zip(bytes1, bytes2))
    
    return xored


def challenge2():
    hex1 = "1c0111001f010100061a024b53535009181c"
    hex2 = "686974207468652062756c6c277320657965"
    result = xor(hex1, hex2).hex()
    expectedResult = "746865206b696420646f6e277420706c6179"
    
    if result != expectedResult:
        raise ValueError(f"Challenge 2 failed: got {result}, expected {expectedResult}")
    else:
        print("[*] challenge 2 passed")


def score(input: bytes) -> float:
    """
    Takes a string and returns a score based on how many English language characters are used

    Args:
        input (bytes): string to check against the English alphabet

    Returns:
        float: Score between 0.0 and 1.0
    """
    length = len(input)
    score = 0
    
    for char in input:
        # uppercase
        if 65 <= char <= 90:
            score += 1
        # lowercase 
        elif 97 <= char <= 122:
            score += 1
        # space
        elif char == 32:
            score += 1
            
    return float(score) / length


def challenge3():
    hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    expectedResult = b"Cooking MC's like a pound of bacon"

    for i in range(256):
        key = bytes([i] * (len(hex) // 2))
        key_hex = key.hex()

        result = xor(hex, key_hex)
        if score(result) > 0.9:
            if result != expectedResult:
                raise ValueError(f"Challenge 3 failed: got {result}, expected {expectedResult}")
            else:
                print("[*] challenge 3 passed")


def challenge4():
    expectedResult = b"Now that the party is jumping\n"
    with open("files/1-4.txt") as file:
        files = file.readlines()
    files = [f.strip("\n") for f in files]

    for candidate_hex in files:
        for i in range(256):
            key = bytes([i] * (len(candidate_hex) // 2))
            key_hex = key.hex()

            result = xor(candidate_hex, key_hex)
            if score(result) > 0.9:
                if result != expectedResult:
                    raise ValueError(f"Challenge 4 failed: got {result}, expected {expectedResult}")
                else:
                    print("[*] challenge 4 passed")


def repeating_key_xor(text: str, key: str) -> bytes:
    """
    Takes a key and text and returns their XOR combination

    Args:
        key (str): ASCII key for repeating key XOR
        text (str): ASCII text to be encrypted or decrypted

    Returns:
        bytes: Bytes representation of the XOR combination of key and text
    """
    key_hex = bytes(key, "ascii").hex()
    text_hex = bytes(text, "ascii").hex()
    key_repeating = (key_hex * (len(text_hex) // len(key_hex) + 1))[:len(text_hex)]

    return xor(key_repeating, text_hex)


def challenge5():
    key = "ICE"
    stanza = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    
    expectedResult = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    
    result = repeating_key_xor(stanza, key)

    if result.hex() != expectedResult:
        raise ValueError(f"Challenge 5 failed: got {result.hex()}, expected {expectedResult}")
    else:
        print("[*] challenge 5 passed")


def hamming_distance(str1: str, str2: str) -> int:
    """
    Returns hamming distance between two strings

    Args:
        str1 (str): first string
        str2 (str): second string
    
    Returns:
        int: hamming disntace between str1 and str2
    """
    str1_hex = bytes(str1, "ascii").hex()
    str2_hex = bytes(str2, "ascii").hex()
    result = xor(str1_hex, str2_hex)
    return bin(int.from_bytes(result, byteorder='big')).count('1')
    

EXPECTED_RESULT = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
def challenge6():    
    with open("files/1-6.txt") as file:
        lines = file.readlines()
    lines = [l.strip("\n") for l in lines]
    ciphertext = ''.join(lines)
    ciphertext = base64.b64decode(ciphertext).decode('ascii')
    
    keysize, shortest_distance = None, 100.0
    for ks in range(15,40):
        # take four keysize chunks
        chunk1 = ciphertext[0:ks]
        chunk2 = ciphertext[ks:ks*2]
        chunk3 = ciphertext[ks*2:ks*3] 
        chunk4 = ciphertext[ks*3:ks*4]

        # calculate normalized hamming distances
        dist1 = hamming_distance(chunk1, chunk2) / ks
        dist2 = hamming_distance(chunk3, chunk4) / ks
        
        # average the two distances
        avg_dist = (dist1 + dist2) / 2

        if avg_dist < shortest_distance:
            shortest_distance = avg_dist
            keysize = ks
    
    # break ciphertext into blocks of keysize length
    blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
    
    # transpose blocks
    transposed = []
    for i in range(keysize):
        transposed.append(''.join([block[i] for block in blocks if i < len(block)]))

    final_key = ""
    for block in transposed:
        block = bytes(block, "ascii").hex()
        for i in range(256):
            key = bytes([i] * (len(block) // 2)).hex()
            result = xor(block, key)
            if score(result) > 0.85:
                final_key += bytes([i]).hex()
    
    result = repeating_key_xor(ciphertext, bytes.fromhex(final_key).decode('ascii'))
    if result != EXPECTED_RESULT:
        raise ValueError(f"Challenge 6 failed: got {result}, expected {expectedResult}")
    else:
        print("[*] challenge 6 passed")
    
    
def challenge7():
    key = "YELLOW SUBMARINE"
    with open("files/1-7.txt") as file:
        lines = file.readlines()
    lines = [l.strip("\n") for l in lines]
    ciphertext = ''.join(lines)
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key.encode('ascii'), AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    # remove PKCS#7 padding by checking last byte value and removing that many bytes
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    
    if plaintext != EXPECTED_RESULT:
        raise ValueError(f"Challenge 7 failed: got {plaintext}, expected {EXPECTED_RESULT}")
    else:
        print("[*] challenge 7 passed")


def detect_ecb(ciphertext: str, blockSize: int = 16) -> bool:
    """
    Detects if a hex-encoded ciphertext was encrypted using ECB mode by checking for duplicate blocks
    
    Args:
        ciphertext (str): Hex-encoded ciphertext
        blockSize (int): Size of blocks in bytes (default 16)
        
    Returns:
        bool: True if ECB mode detected, False otherwise
    """
    # convert hex to bytes
    raw = bytes.fromhex(ciphertext.strip())
    
    blocks = []
    for i in range(0, len(raw), blockSize):
        blocks.append(raw[i:i+blockSize])
        
    # check for duplicates by comparing length of blocks to length of unique blocks
    return len(blocks) != len(set(blocks))


def challenge8():
    expectedResult = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    
    ecb_block = None
    with open("files/1-8.txt") as file:
        lines = file.readlines()
    lines = [l.strip("\n") for l in lines]
    for ciphertext in lines:
        if detect_ecb(ciphertext):
            ecb_block = ciphertext
    
    if ecb_block != expectedResult:
        raise ValueError(f"Challenge 8 failed: got {ecb_block}, expected {expectedResult}")
    else:
        print("[*] challenge 8 passed")

    

if __name__ == "__main__":
    challenge1()
    challenge2()
    challenge3()
    challenge4()
    challenge5()
    challenge6()
    challenge7()
    challenge8()