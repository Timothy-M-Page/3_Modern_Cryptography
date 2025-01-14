import os
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
public_key = private_key.public_key()


def rsa_encrypt(plaintext: str, key: rsa.RSAPublicKey) -> bytes:
    plaintext = plaintext.encode()
    ciphertext = key.encrypt(plaintext, padding.OAEP(
                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None))
    return ciphertext


def rsa_decrypt(ciphertext: bytes, key: rsa.RSAPrivateKey) -> str:
    plaintext = key.decrypt(ciphertext, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None))
    return plaintext.decode()





# Manual Implementation :

private_numbers = private_key.private_numbers()
public_numbers = public_key.public_numbers()

p = private_numbers.p   # First prime
q = private_numbers.q   # Second prime
n = public_numbers.n    # Modulus = p*q
e = public_numbers.e    # Public exponent
d = private_numbers.d   # Private exponent = inv(e) mod n


def mgf1(input_bytes: bytes, length: int) -> bytes:
    """
    Use a mask to randomise the plaintext, this strengthens the cipher
    against patterns in outputs and known plaintext attacks.
    Big-Endian storage is the cryptography standard.
    Append hash(input + counter) to the output, until the desired length.
    """
    output = b""
    counter = 0
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        output += hashlib.sha256(input_bytes + counter_bytes).digest()
        counter += 1
    return output[:length]


def oaep_pad(data: bytes, lab: bytes = b"", modulus_size: int = 256) -> bytes:
    """
    Hash the label
    Pad the message
    Add length indicator
    SGenerate a random seed
    Mask the padded message (db) and seed
    Combine masked_seed and masked_db
    """
    hash_function = hashlib.sha256
    hash_len = hash_function().digest_size
    max_message_length = modulus_size - 2 * hash_len - 2

    if len(data) > max_message_length:
        raise ValueError("Message is too long.")

    l_hash = hash_function(lab).digest()
    padding_zeros = b"\x00" * (max_message_length - len(data))
    padded_message = data + padding_zeros
    db = l_hash + b"\x00" + padded_message
    seed = os.urandom(hash_len)
    db_mask = mgf1(seed, len(db))
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, len(seed))
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


test_message = b"hello"
test_label = b"label"
test_modulus_size = 256  # 2048-bit key (256 bytes)
padded_message_example = oaep_pad(test_message, test_label, test_modulus_size)
print("OAEP Padded Message:", padded_message_example.hex())
