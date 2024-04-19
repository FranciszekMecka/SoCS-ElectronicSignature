from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from Crypto.Util.Padding import pad

from key_manager import KEY_SIZE  # KEY_SIZE is in bytes

from key_manager import KeyManager


class Encryptor:
    # https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa ask how to
    # handle 'limitless files'
    @staticmethod
    def encrypt_file(file_path_to_encrypt, output_file_path, recipient_public_key):
        with open(file_path_to_encrypt, 'rb') as f:
            data = f.read()
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)

        block_size = cipher_rsa._key.size_in_bytes() - 2 * cipher_rsa._hashObj.digest_size - 2
        partitioned_data = [data[i:i + block_size] for i in
                            range(0, len(data), block_size)]
        partitioned_encrypted_data = []
        for value in partitioned_data:
            partitioned_encrypted_data.append(cipher_rsa.encrypt(value))

        # this will need to be replaced by gui
        encrypted_data = b''.join(partitioned_encrypted_data)
        with open(output_file_path, 'wb') as f:
            f.write(bytes(encrypted_data))

    @staticmethod
    def decrypt_file(file_path_to_decrypt, output_file_path, recipient_private_key):
        with open(file_path_to_decrypt, 'rb') as f:
            data = f.read()
        cipher_rsa = PKCS1_OAEP.new(recipient_private_key)

        block_size = cipher_rsa._key.size_in_bytes()
        partitioned_data_encrypted = [data[i:i + block_size] for i in
                            range(0, len(data), block_size)]

        partitioned_data = []
        for value in partitioned_data_encrypted:
            partitioned_data.append(cipher_rsa.decrypt(value))

        #    this will need to be replaced by gui
        data = b''.join(partitioned_data)
        with open(output_file_path, 'wb') as f:
            f.write(data)

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
    key_manager = KeyManager()
    private_key = key_manager.read_key("private_key.pem", '1234')
    public_key = key_manager.read_key("public_key.pem")
    print(private_key)
    print(public_key)

    encryptor.encrypt_file("wiosna.txt", "wiosna_encrypted.bin", public_key)
    encryptor.decrypt_file("wiosna_encrypted.bin", "wiosna_decrypted.txt", private_key)
    print(open("wiosna_decrypted.txt", 'r').read())
    print(len(open("wiosna_encrypted.bin", 'rb').read()))
