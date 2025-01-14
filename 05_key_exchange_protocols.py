from Crypto.Random import random
from Crypto.Util.number import getPrime
from cryptography.hazmat.primitives.asymmetric import ec

"""
The Diffie-Hellman and elliptic curve Diffie-Hellman key exchange algorithms
allow Alice and Bob to construct a shared public key from private keys
independently, without having to transmit the keys themselves at any point.

This is done by exchanging a shared group generator raised to the power of 
the private keys, and raising this to one own private key to form a public key.

The two public keys are necessarily equal by the commutativity of exponents.
The private keys are not deductible from interception of Alice and Bob's
public values, due to the NP nature of the discrete logarithm problem.
"""


def diffie_hellman_key_exchange(prime_size: int) -> tuple[int, int]:
    # Typically use 2048 bit primes.
    prime = getPrime(prime_size)
    generator = 2

    alice_private = random.randint(1, prime-1)
    alice_public = pow(generator, alice_private, prime)

    bob_private = random.randint(1, prime-1)
    bob_public = pow(generator, bob_private, prime)

    alice_shared_key = pow(bob_public, alice_private, prime)
    bob_shared_key = pow(alice_public, bob_private, prime)

    return alice_shared_key, bob_shared_key


"""
Elliptic Curve Diffie-Hellman may also be implemented. In this algorithm the
generator of the group is a point on an elliptic curve.

Elliptic curves provides greater security with the use of a smaller key, due to
the increased difficulty of the elliptic curve discrete logarithm problem.
"""


def elliptic_diffie_hellman(curve: ec.EllipticCurve) -> tuple[bytes, bytes]:
    # The elliptic curve SECP256R1 from the ec module is chosen.
    alice_private_key = ec.generate_private_key(curve)
    alice_public_key = alice_private_key.public_key()

    bob_private_key = ec.generate_private_key(curve)
    bob_public_key = bob_private_key.public_key()

    alice_shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)
    bob_shared_key = bob_private_key.exchange(ec.ECDH(), alice_public_key)

    return alice_shared_key, bob_shared_key


def verify_keys(key1: int, key2: int) -> str:
    if key1 == key2:
        return 'Shared keys match.'
    else:
        return 'Shared keys do not match.'
