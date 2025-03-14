import base64

def challenge1():
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectedResult = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    b64 = base64.b64encode(bytes.fromhex(hex)).decode()
    if b64 != expectedResult:
        raise ValueError(f"Challenge 1 failed: got {b64}, expected {expectedResult}")
    else:
        print("[*] challenge 1 passed")


def xor(hex1: str, hex2: str) -> str:
    """
    Takes two hex strings and returns their XOR combination

    Args:
        hex1 (str): First hexadecimal string
        hex2 (str): Second hexadecimal string

    Returns:
        str: Bytes representation of the XOR combination of hex1 and hex2
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


def repeating_key_xor(key: str, text: str) -> str:
    """
    Takes a key and text and returns their XOR combination

    Args:
        key (str): ASCII key for repeating key XOR
        text (str): ASCII text to be encrypted or decrypted

    Returns:
        str: Bytes representation of the XOR combination of key and text
    """
    key_hex = bytes(key, "ascii").hex()
    text_hex = bytes(text, "ascii").hex()
    key_repeating = (key_hex * (len(text_hex) // len(key_hex) + 1))[:len(text_hex)]

    return xor(key_repeating, text_hex)


def challenge5():
    key = "ICE"
    stanza = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    
    expectedResult = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    
    result = repeating_key_xor(key, stanza)

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
    
    print(keysize)

        


if __name__ == "__main__":
    challenge1()
    challenge2()
    challenge3()
    challenge4()
    challenge5()
    challenge6()