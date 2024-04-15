import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2


def encrypt_private_key(private_key_bytes, pin):
    """
    Encrypts the private key bytes using AES with the provided PIN.

    Parameters:
        private_key_bytes (bytes): Serialized private key.
        pin (bytes): PIN as bytes.

    Returns:
        bytes: Encrypted private key bytes.
    """
    # random 32-bit salt
    salt = b"P\x0c&\x8e\xf3c\x8b\xdd\x00.y\xa3D:\x82\x88\xea\xfc\xe3\xd8*\x1d\xa0h'\xc1 x\x1a\x9e\xe6\xf9"

    # Derive a key from the PIN using PBKDF2
    key = PBKDF2(pin, salt, dkLen=32)  # 32 bytes for AES-256

    # Create AES cipher with the derived key
    cipher = AES.new(key, AES.MODE_CBC)

    # Encrypt the padded private key bytes
    encrypted_private_key = cipher.encrypt(pad(private_key_bytes, AES.block_size))

    return cipher.iv + encrypted_private_key


def decrypt_private_key(encrypted_private_key, pin):
    """
    Decrypts the encrypted private key bytes using AES with the provided PIN and salt.

    Parameters:
        encrypted_private_key (bytes): Encrypted private key bytes.
        pin (bytes): PIN as bytes.
        salt (bytes): Salt used for key derivation.

    Returns:
        bytes: Decrypted private key bytes.
    """
    # Extract IV from the encrypted private key
    iv = encrypted_private_key[:16]

    # Extract the encrypted private key bytes (excluding IV)
    encrypted_data = encrypted_private_key[16:]

    salt = b"P\x0c&\x8e\xf3c\x8b\xdd\x00.y\xa3D:\x82\x88\xea\xfc\xe3\xd8*\x1d\xa0h'\xc1 x\x1a\x9e\xe6\xf9"

    # Derive the key from the PIN using PBKDF2
    key = PBKDF2(pin, salt, dkLen=32)

    # Create AES cipher with the derived key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the private key bytes
    decrypted_private_key = cipher.decrypt(encrypted_data)

    # Unpad the decrypted data
    return unpad(decrypted_private_key, AES.block_size)


# Generate an RSA key pair
def generate_key_pair(pin):
    """
    Generate a new RSA key pair and encrypt the private key using AES with the provided PIN.

    Returns:
        tuple: (encrypted_private_key, public_key) as serialized bytes.
    """
    # Generate RSA key pair
    rsa_key_pair = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Serialize the private key
    private_key_bytes = rsa_key_pair.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_private_key_bytes = encrypt_private_key(private_key_bytes, pin)

    # Serialize the public key
    public_key = rsa_key_pair.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_private_key_bytes, public_key_bytes


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    keys = generate_key_pair(b'1234')
    for k in keys:
        print(k)

    print(decrypt_private_key(keys[0], b'1234'))
