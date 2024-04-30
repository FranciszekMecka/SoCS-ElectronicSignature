import os.path
from datetime import datetime

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
from lxml import etree as ET
import xml.dom.minidom
import os
from key_manager import KeyManager


class Encryptor:
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
            return True
        except (ValueError, TypeError):
            print("Signature is not valid.")
            return False

    @staticmethod
    def generate_xml_info(file_path, username):

        # Create the root element
        root = ET.Element("SignedProperties")

        signer_username = ET.SubElement(root, "Signer")
        signer_username.text = username
        # Create SignedSignatureProperties element and its children
        signed_signature_properties = ET.SubElement(root, "SignedSignatureProperties")
        signing_time = ET.SubElement(signed_signature_properties, "SigningTime")
        signing_time.text = datetime.now().isoformat()  # Set current timestamp
        file_name = ET.SubElement(signed_signature_properties, "FileName")
        file_name.text = os.path.splitext(file_path)[-2]
        extension = ET.SubElement(signed_signature_properties, "Extension")
        extension.text = os.path.splitext(file_path)[-1]
        file_size_bytes = ET.SubElement(signed_signature_properties, "FileSizeBytes")
        file_size_bytes.text = str(os.path.getsize(file_path))
        # Serialize the XML tree to a string
        xml_string = ET.tostring(root, encoding="unicode", method="xml")

        # Print the XML string to the console
        xml_pretty_string = xml.dom.minidom.parseString(xml_string).toprettyxml(indent="  ")

        with open(file_path + ".xml", 'w') as f:
            f.write(xml_pretty_string)

        return root
