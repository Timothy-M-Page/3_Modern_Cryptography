from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


message = "Hello World!"

# 1. Generate a private and public key

private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
public_key = private_key.public_key()

e = public_key.public_numbers().e
n = public_key.public_numbers().n
d = private_key.private_numbers().d


# 2. Sign the message using the private key

signature = private_key.sign(           # The signature mathematically is the hash raised to d, mod n.
    message.encode(),
    padding.PKCS1v15(),  # Padding to ensure the correct length and add security
    hashes.SHA256())     # Hash using sha256


# 3 Verify the signature


try:
    public_key.verify(          # The receiver re-hashes the original message.
        signature,              # If the signature raised to the e mod n is equal to the hash
        message.encode(),       # Then the message is verified to have been sent using the private key.
        padding.PKCS1v15(),
        hashes.SHA256())
    print("Signature is valid!")
except Exception as e:
    print("Signature is invalid:", e)     # If the decoded signature is not equal to the hash
                                          # raise an error to alert the user.