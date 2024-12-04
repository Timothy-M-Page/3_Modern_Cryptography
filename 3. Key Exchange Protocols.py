from Crypto.Random import random
from Crypto.Util.number import getPrime
from cryptography.hazmat.primitives.asymmetric import ec

# Below the Diffie-Hellman and elliptic curve Diffie-Hellman key
# exchange algorithms are implemented using the above packages.

prime_size = 2048
p = getPrime(prime_size)
g = 2                            # g denotes any generator of the group integers_mod_p, g = 2 is typically chosen.

alice_private = random.randint(1, p-1)    # Alice's private key
alice_public = pow(g, alice_private, p)   # Alice's public key

bob_private = random.randint(1, p-1)      # Bob's private key
bob_public = pow(g, bob_private, p)       # Bob's public key

alice_shared_secret = pow(bob_public, alice_private, p)     # Calculate the shared key by raising each other's
bob_shared_secret = pow(alice_public, bob_private, p)       # public value to one's own private value.

if alice_shared_secret == bob_shared_secret:                # Verify matching values.
    print("Shared RSA secrets match.")
else:
    print("Shared RSA secrets do not match.")

# These two shared secrets are necessarily equal by the commutativity of exponents.
# Moreover, the shared key is not deductible from interception of Alice and Bob's
# public values, due to the NP nature of the discrete logarithm problem.


# Elliptic Curve Diffie-Hellman may also be implemented. Elliptic curves provides a greater level of security
# with the use of a smaller key, this is due to the greater difficulty of the elliptic curve discrete
# logarithm problem.

alice_private_key = ec.generate_private_key(ec.SECP256R1())   # SECP256R1 is a widely used elliptic curve,
alice_public_key = alice_private_key.public_key()             # offering strong security with a 256-bit key size
                                                              # equivalent to a 3072-bit RSA key.
bob_private_key = ec.generate_private_key(ec.SECP256R1())
bob_public_key = bob_private_key.public_key()

alice_elliptic_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
bob_elliptic_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)

if alice_elliptic_shared_secret == bob_elliptic_shared_secret:
    print("Shared elliptic secrets match.")
else:
    print("Shared elliptic secrets do not match.")