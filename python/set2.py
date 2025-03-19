import base64

from Crypto.Cipher import AES

def pkcs7(plaintext: str, length: int) -> bytes:
    """
    Implements PKCS#7 padding by appending bytes to reach desired block length.
    
    Args:
        plaintext (str): The text to pad
        length (int): The desired block length
        
    Returns:
        bytes: Padded text as bytes, where padding bytes equal the number of bytes added
        
    Example:
        pkcs7("YELLOW SUBMARINE", 20) returns b"YELLOW SUBMARINE\x04\x04\x04\x04"
    """
    if len(plaintext) == length:
        return plaintext.encode()
    
    padding_byte = length - len(plaintext)
    padding = bytes([padding_byte] * padding_byte)
    
    return plaintext.encode() + padding


def challenge9():
    expectedResult = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    plaintext = "YELLOW SUBMARINE"
    padded = pkcs7(plaintext, 20)

    if padded != expectedResult:
        raise ValueError(f"Challenge 9 failed: got {padded}, expected {expectedResult}")
    else:
        print("[*] challenge 9 passed")


def xor(bytes1: bytes, bytes2: bytes) -> bytes:
    """
    Takes two bytes objects and returns their XOR combination

    Args:
        bytes1 (bytes): First bytes object
        bytes2 (bytes): Second bytes object

    Returns:
        bytes: XOR combination of bytes1 and bytes2
    """        
    return bytes(a ^ b for a,b in zip(bytes1, bytes2))


def cbc_decrypt(ciphertext: bytes, key: bytes, blockSize: int = 16, IV: bytes = b"00000000000000000000000000000000"):
    blocks = []


def challenge10():
    with open("files/2-10.txt") as file:
        lines = file.readlines()
    lines = [l.strip("\n") for l in lines]
    ciphertext = ''.join(lines)
    ciphertext = base64.b64decode(ciphertext)

    key = b"YELLOW SUBMARINE"
    plaintext = cbc_decrypt(ciphertext, key)
    print(plaintext)

if __name__ == "__main__":
    challenge9()
    challenge10()