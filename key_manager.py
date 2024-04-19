from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

KEY_SIZE = 4096


class KeyManager:

    def __init__(self) -> None:
        # Initialize a fixed salt for key derivation
        self.salt = b"P\x0c&\x8e\xf3c\x8b\xdd\x00.y\xa3D:\x82\x88\xea\xfc\xe3\xd8*\x1d\xa0h'\xc1 x\x1a\x9e\xe6\xf9"

    @staticmethod
    def generate_key_pair():
        rsa_keys = RSA.generate(KEY_SIZE)
        private_key = rsa_keys.exportKey()
        public_key = rsa_keys.publickey().exportKey()
        return private_key, public_key

    def encrypt_private_key(self, private_key_bytes, pin):
        key = PBKDF2(pin, self.salt, dkLen=32)  # 32 bytes for AES-256
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_private_key = cipher.encrypt(pad(private_key_bytes, AES.block_size))
        return cipher.iv + encrypted_private_key

    def decrypt_private_key(self, encrypted_private_key, pin):
        iv = encrypted_private_key[:16]
        encrypted_data = encrypted_private_key[16:]
        key = PBKDF2(pin, self.salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_private_key = cipher.decrypt(encrypted_data)
        return unpad(decrypted_private_key, AES.block_size)

    def write_key(self, file_path, key, pin=None):
        if pin is not None:
            key = self.encrypt_private_key(key, pin)
        with open(file_path, 'wb') as f:
            f.write(key)

    def read_key(self, file_path, pin=None):
        with open(file_path, 'rb') as f:
            bytes_key = f.read()
        if pin is not None:
            try:
                bytes_key = self.decrypt_private_key(bytes_key, pin)
            except ValueError:
                print('Given PIN is incorrect.')
                return
        return RSA.import_key(bytes_key)
