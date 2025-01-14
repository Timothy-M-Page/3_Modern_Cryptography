import binascii
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad


def des_encrypt(data: str, key: bytes) -> [bytes, str]:
    """
    Create a cipher object with cipher block chaining.
    Add padding so that the plaintext is a multiple of the block size.
    Encrypt with an implicit initialisation vector (iv).
    Join the iv with the encrypted message to form the ciphertext
    """

    if len(key) != 8:
        return 'Error : Key must be 8 bytes long.'

    cipher = DES.new(key, DES.MODE_CBC)
    padded_message = pad(data.encode(), DES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(cipher.iv + encrypted_message)


def des_decrypt(encrypted_data: bytes, key: bytes) -> [str]:
    """
    Separate the iv from the actual ciphertext.
    Decrypt the ciphertext with the cipher object.
    Un-pad having used PKCS7 padding.
    """

    if len(key) != 8:
        return 'Error : Key must be 8 bytes long.'

    encrypted_data = binascii.unhexlify(encrypted_data)
    iv = encrypted_data[:DES.block_size]
    cipher_text = encrypted_data[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(cipher_text), DES.block_size)
    return decrypted_data.decode()


def triple_des_encrypt(data: str, key: bytes) -> [bytes, str]:

    if len(key) not in (16, 24):
        return 'Error : Key must be 16 or 24 bytes long.'

    cipher = DES3.new(key, DES3.MODE_CBC)
    padded_data = pad(data.encode(), DES3.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(cipher.iv + encrypted_data)


def triple_des_decrypt(encrypted_data: bytes, key: bytes) -> [str]:

    if len(key) not in (16, 24):
        return 'Error : Key must be 16 or 24 bytes long.'

    encrypted_data = binascii.unhexlify(encrypted_data)
    iv = encrypted_data[:DES3.block_size]
    cipher_text = encrypted_data[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(cipher_text), DES3.block_size)
    return decrypted_data.decode()
