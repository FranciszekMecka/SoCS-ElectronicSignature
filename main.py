import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Generate an RSA key pair
def generate_key_pair(pin):
    """
    Generate a new RSA key pair and encrypt the private key using AES with the provided PIN.

    Parameters:
        pin (bytes): PIN as bytes.

    Returns:
        tuple: (encrypted_private_key, public_key) as serialized bytes.
    """
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Serialize the private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the private key using AES
    aes_key = pin.ljust(32)[:32]  # Use PIN as AES key, padding if necessary
    iv = os.urandom(16)  # Generate a random IV

    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = aes_cipher.encryptor()
    encrypted_private_key = encryptor.update(private_key_bytes) + encryptor.finalize()

    # Serialize the public key
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_private_key, public_key_bytes


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    keys = generate_key_pair(b'1234')
    for k in keys:
        print(k)
