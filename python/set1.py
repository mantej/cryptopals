import base64

def challenge1():
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expectedResult = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    b64 = base64.b64encode(bytes.fromhex(hex)).decode()
    if b64 != expectedResult:
        raise ValueError(f"Challenge 1 failed: got {b64}, expected {expectedResult}")
    else:
        print("[*] challenge 1 passed")

def xor(hex1, hex2):
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



if __name__ == "__main__":
    challenge1()
    challenge2()