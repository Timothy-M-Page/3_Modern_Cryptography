import hashlib

# A hash function is a mathematical function that takes an input (or "message") and returns a fixed-size string or
# number, typically represented as a hash code, which is usually much smaller than the original input.
# Here are the key points:

# 1. Injective/Deterministic: The same input will always produce the same output (hash).
# 2. Fixed Size: No matter how large or small the input is, the output (hash) has a fixed length.
#    For example, the SHA-256 hash always produces a 256-bit output.
# 3. Efficient: A good hash function computes the hash quickly for any input.
# 4. Pre-image Resistance: It’s difficult (ideally impossible) to reverse the process and derive the original input from
#    its hash value.
# 5. Collision Resistance: It’s hard (ideally impossible) for two different inputs to produce the same hash value.
# 6. Uniform Distribution: Hash functions typically distribute input values evenly across the hash space, reducing the
#    chance of "clustering."


def sha256(string):
    hash_value = hashlib.sha256(string.encode()).hexdigest()
    return hash_value


def sha_3_256(string):
    sha3_256_hash = hashlib.sha3_256(string.encode()).hexdigest()
    return sha3_256_hash


# sha256 belongs to the sha2 family, sha_3_256 belongs to the sha3 family.
# Both these hash functions are used today, with sha_256 being dominant for
# applications such as  blockchain, digital signatures, data integrity,
# and password hashing.

# sha_3_256 is a more secure and more versatile hash function, using
# NIST's Kaccak construction providing resistance to length extension attacks.
# However, sha256 remains the most popular choice of hash algorithm.




