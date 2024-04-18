from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384


class Encryptor:
    def __init__(self):
        # Initialize a fixed salt for key derivation
        self.salt = b"P\x0c&\x8e\xf3c\x8b\xdd\x00.y\xa3D:\x82\x88\xea\xfc\xe3\xd8*\x1d\xa0h'\xc1 x\x1a\x9e\xe6\xf9"

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

    @staticmethod
    def generate_key_pair():
        rsa_keys = RSA.generate(4096)
        private_key = rsa_keys.exportKey()
        public_key = rsa_keys.publickey().exportKey()
        return private_key, public_key

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

    # https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa ask how to
    # handle 'limitless files'
    @staticmethod
    def encrypt_file(file_path_to_encrypt, output_file_path, recipient_public_key):
        with open(file_path_to_encrypt, 'rb') as f:
            data = f.read()
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        encrypted_data = cipher_rsa.encrypt(data)

        #         this will need to be replaced by gui
        with open(output_file_path, 'wb') as f:
            data = f.write(encrypted_data)

    @staticmethod
    def decrypt_file(file_path_to_decrypt, output_file_path, recipient_private_key):
        with open(file_path_to_decrypt, 'rb') as f:
            data = f.read()
        cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
        decrypted_data = cipher_rsa.decrypt(data)

        #         this will need to be replaced by gui
        with open(output_file_path, 'wb') as f:
            data = f.write(decrypted_data)

    @staticmethod
    def sign_document(file_to_sign, output_signature_file, signer_private_key):
        # see https://pycryptodome.readthedocs.io/en/latest/src/signature/signature.html for reference
        with open(file_to_sign, 'rb') as f:
            data = f.read()
        hash_object = SHA384.new(data)
        signature = pkcs1_15.new(signer_private_key).sign(hash_object)
        with open(output_signature_file, 'wb') as f:
            f.write(signature)

    @staticmethod
    def verify_signature(signed_file, signature_file, signer_public_key):
        # see https://pycryptodome.readthedocs.io/en/latest/src/signature/signature.html for reference
        verifier = pkcs1_15.new(signer_public_key)
        with open(signed_file, 'rb') as f:
            data = f.read()
        hash_object = SHA384.new(data)
        try:
            verifier.verify(hash_object, open(signature_file, 'rb').read())
        except (ValueError, TypeError):
            print("Signature is not valid.")


if __name__ == '__main__':
    encryptor = Encryptor()
    # keys = encryptor.generate_key_pair()
    # for k in keys:
    #     print(k)

    private_key = encryptor.read_key("private.pem", '1234')

    public_key = encryptor.read_key("public.pem")
    encryptor.encrypt_file("wiosna.txt", "wiosna_encrypted.bin", public_key)
    encryptor.decrypt_file("wiosna_encrypted.bin", "wiosna_decrypted.txt", private_key)

    encryptor.sign_document("wiosna.txt", "wiosna.sig", private_key)
    encryptor.verify_signature("wiosna.txt", "wiosna.sig", public_key)
