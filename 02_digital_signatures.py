import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa


def sha_3_256(string: str) -> str:
    sha3_256_hash = hashlib.sha3_256(string.encode()).hexdigest()
    return sha3_256_hash


def fast_power(g: int, t: int, mod: int) -> int:
    """
    Fast power returns an exponent in O(log_2(n)) calculations.

    The exponent is written as a binary string.
    A list stores g to successive powers of 2.
    The power is calculated using these powers and the binary string.
    """
    binary = bin(t)[2:][::-1]

    powers = [g]
    power = g
    for x in range(1, len(binary)):
        power = power ** 2 % mod
        powers.append(power)

    result = 1
    for index in range(len(binary)):
        if int(binary[index]) == 1:
            result = result * powers[index] % mod
    return result


"""
Digital signatures allow the receiver of a message to verify the
authenticity of the sender. Based on RSA, the sender may raise a 
hash value to the private key mod n and send it with a message.
A receiver may raise this value to the public key to retrieve the 
original hash and compare it to a hash of the message. 
Demonstrating that the sender must know the private key.
"""

# Generate a private and public key.
private_key_example = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048)
public_key_example = private_key_example.public_key()

e = public_key_example.public_numbers().e
n = public_key_example.public_numbers().n
d = private_key_example.private_numbers().d


def digital_signature(message: str, private_key: int, mod: int) -> int:
    """
    A signature is the hash value of a message raised to d, mod n.
    """
    sha3_hash = hashlib.sha3_256(message.encode()).digest()
    hash_int = int.from_bytes(sha3_hash, byteorder='big')
    sig = fast_power(hash_int, private_key, mod)
    return sig


def verify(message: str, signature: int, public_key: int, mod: int) -> str:
    """
    To Verify, a receiver may check that the signature to the e
    is equal to the hash of the function with no exponent.
    This verifies the sender knows d, the inverse of e.
    """
    sha3_hash = hashlib.sha3_256(message.encode()).digest()
    hash_int = int.from_bytes(sha3_hash, byteorder='big')
    signature_e = fast_power(signature, public_key, mod)

    if hash_int == signature_e:
        return 'Message signature verified.'
    else:
        return 'Message signature not valid.'
