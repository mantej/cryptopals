
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


if __name__ == "__main__":
    challenge9()