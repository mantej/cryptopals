
import base64
import os
import random

from set1 import detect_ecb

from Crypto.Cipher import AES

def pkcs7(plaintext: str, length: int) -> bytes:
    """
    Implements PKCS#7 padding by appending bytes to reach desired block length
    
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


def cbc_decrypt(ciphertext: bytes, key: bytes, blockSize: int = 16, IV: bytes = b"0000000000000000") -> bytes:
    """
    Decrypts ciphertext using AES in CBC mode
    
    Args:
        ciphertext (bytes): The encrypted data to decrypt
        key (bytes): The AES key used for decryption
        blockSize (int, optional): Block size in bytes (default 16)
        IV (bytes, optional): Initialization vector (default b"0000000000000000")
        
    Returns:
        bytes: The decrypted plaintext
    """
    blocks = []
    blocks = [IV]
    for i in range(0, len(ciphertext), blockSize):
        blocks.append(ciphertext[i:i+blockSize])
    
    aes = AES.new(key, AES.MODE_ECB)

    decrypted = b""
    for i, block in enumerate(blocks[1:]):
        decrypted_block = aes.decrypt(block)
        decrypted_block = xor(decrypted_block, blocks[i])
        decrypted += decrypted_block
    
    return decrypted


def cbc_encrypt(plaintext: bytes, key: bytes, blockSize: int = 16, IV: bytes = b"0000000000000000") -> bytes:
    """
    Encrypts plaintext using AES in CBC mode
    
    Args:
        plaintext (bytes): The data to encrypt
        key (bytes): The AES key used for encryption
        blockSize (int, optional): Block size in bytes (default 16)
        IV (bytes, optional): Initialization vector (default b"0000000000000000")
        
    Returns:
        bytes: The encrypted ciphertext
    """
    padding = blockSize - (len(plaintext) % blockSize)
    if padding < blockSize:
        plaintext += bytes([padding]) * padding
    
    blocks = []
    for i in range(0, len(plaintext), blockSize):
        blocks.append(plaintext[i:i+blockSize])
    
    aes = AES.new(key, AES.MODE_ECB)
    
    encrypted = b""
    prev_block = IV
    for block in blocks:
        xored_block = xor(block, prev_block)
        encrypted_block = aes.encrypt(xored_block)
        encrypted += encrypted_block
        prev_block = encrypted_block
        
    return encrypted


def challenge10():
    with open("files/2-10.txt") as file:
        lines = file.readlines()
    lines = [l.strip("\n") for l in lines]
    ciphertext = ''.join(lines)
    ciphertext = base64.b64decode(ciphertext)

    key = b"YELLOW SUBMARINE"
    plaintext = cbc_decrypt(ciphertext, key)
    
    if "Play that funky music".encode() not in plaintext:
        raise ValueError(f"Challenge 10 failed: got {plaintext}")
    else:
        print("[*] challenge 10 passed")


def encryption_oracle(plaintext: bytes) -> tuple[bytes, str]:
    """
    Encrypts plaintext with random padding in either ECB or CBC mode
    
    Args:
        plaintext (bytes): The data to encrypt
        
    Returns:
        bytes: The encrypted ciphertext
    """
    prefix = os.urandom(random.randint(5, 10))
    suffix = os.urandom(random.randint(5, 10))
    
    padded_plaintext = prefix + plaintext + suffix
    
    key = os.urandom(16)
    
    if random.randint(0, 1):
        aes = AES.new(key, AES.MODE_ECB)
        padding = 16 - (len(padded_plaintext) % 16)
        if padding < 16:
            padded_plaintext += bytes([padding]) * padding
        return aes.encrypt(padded_plaintext), "ecb"
    else:
        # CBC mode with random IV
        iv = os.urandom(16)
        return cbc_encrypt(padded_plaintext, key, IV=iv), "cbc"


def challenge11():
    with open("files/2-10.txt") as file:
        lines = file.readlines()
    lines = [l.strip("\n") for l in lines]
    ciphertext = ''.join(lines)
    ciphertext = base64.b64decode(ciphertext)

    key = b"YELLOW SUBMARINE"
    plaintext = cbc_decrypt(ciphertext, key)

    for _ in range(16):
        ciphertext, mode = encryption_oracle(plaintext)

        oracle_result_ecb = detect_ecb(ciphertext.hex())

        if oracle_result_ecb:
            if mode == "cbc":
                raise ValueError(f"Challenge 11 failed: got {mode}, expected ecb")
        else:
            if mode == "ecb":
                raise ValueError(f"Challenge 11 failed: got {mode}, expected cbc")
            
    print("[*] challenge 11 passed")

if __name__ == "__main__":
    challenge9()
    challenge10()
    challenge11()