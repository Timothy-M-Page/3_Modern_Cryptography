import os
import binascii

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def aes_encrypt(data: str, key: bytes) -> [bytes, str]:
    """
    Create a random initialization vector.
    Create a cipher object with cipher block chaining.
    PKCS7 padded plaintext = a multiple of block size.
    Call cipher object to encrypt.
    Return the IV + encrypted data in hexadecimal.
    """

    if len(key) not in (16, 24, 32):
        return 'Error : Key must be 16, 24, or 32 bytes long.'

    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(iv + encrypted_data)


def aes_decrypt(encrypted_data: bytes, key: bytes) -> [str]:
    """
    Hex decoding.
    Separate the IV and the actual encrypted ciphertext.
    Decrypt the ciphertext calling the cipher object.
    Un-pad from PKCS7 padding.
    """

    if len(key) not in (16, 24, 32):
        return 'Error : Key must be 16, 24, or 32 bytes long.'

    encrypted_data = binascii.unhexlify(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode()
