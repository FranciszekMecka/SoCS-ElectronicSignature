import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QFileDialog, QLabel, \
    QInputDialog, QDialog
from encryptor import Encryptor
from key_manager import KeyManager
import os


class PopupDialog(QDialog):
    def __init__(self, message):
        super().__init__()

        layout = QVBoxLayout()
        self.setWindowTitle("Notification")

        label = QLabel(message)
        layout.addWidget(label)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)  # Close the dialog when OK button is clicked
        layout.addWidget(ok_button)

        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.private_key = None
        self.public_key = None

        self.encryptor = Encryptor()
        self.key_manager = KeyManager()

        self.setWindowTitle("Sign and Encrypt app")
        self.setGeometry(960, 540, 400, 200)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        self.button_import_private_key = QPushButton("Import private key")
        self.button_import_private_key.clicked.connect(self.import_private_key)
        self.layout.addWidget(self.button_import_private_key)

        self.private_key_label = QLabel("No file selected.")
        self.layout.addWidget(self.private_key_label)

        self.button_import_public_key = QPushButton("Import public key")
        self.button_import_public_key.clicked.connect(self.import_public_key)
        self.layout.addWidget(self.button_import_public_key)

        self.public_key_label = QLabel("No file selected.")
        self.layout.addWidget(self.public_key_label)

        self.button_sign_file = QPushButton("Sign a file")
        self.button_sign_file.clicked.connect(self.sign_file)
        self.layout.addWidget(self.button_sign_file)

        self.button_verify_signature = QPushButton("Verify signature")
        self.button_verify_signature.clicked.connect(self.verify_signature)
        self.layout.addWidget(self.button_verify_signature)

        self.button_encrypt_file = QPushButton("Encrypt a file")
        self.button_encrypt_file.clicked.connect(self.encrypt_file)
        self.layout.addWidget(self.button_encrypt_file)

        self.button_decrypt_file = QPushButton("Decrypt a file")
        self.button_decrypt_file.clicked.connect(self.decrypt_file)
        self.layout.addWidget(self.button_decrypt_file)

    def import_private_key(self):
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("Private Key Files (*.pem)")

        if file_dialog.exec():
            pin, ok = QInputDialog.getText(self, "Input Dialog", "Enter PIN for the private key:")
            if not ok:
                return  # User canceled the input dialog
            file_path = file_dialog.selectedFiles()[0]
            self.private_key_label.setText(f"Selected file: {file_path}")
            self.private_key = self.key_manager.read_key(file_path, pin)

    def import_public_key(self):
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("Public Key Files (*.pem)")

        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            self.public_key_label.setText(f"Selected file: {file_path}")
            self.public_key = self.key_manager.read_key(file_path)
            print(self.public_key)

    def sign_file(self):
        if self.private_key is None:
            return
        file_dialog = QFileDialog(self)

        if file_dialog.exec():
            file_path_to_sign = file_dialog.selectedFiles()[0]
            self.encryptor.sign_document(file_path_to_sign, file_path_to_sign + ".sig", self.private_key)

            username, ok = QInputDialog.getText(self, "Input Dialog", "Enter your username:")
            if not ok:
                return  # User canceled the input dialog
            self.encryptor.generate_xml_info(file_path_to_sign, username)

    def verify_signature(self):
        if self.public_key is None:
            return
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("All files (*)")

        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            if self.encryptor.verify_signature(file_path, file_path + ".sig", self.public_key):
                pd = PopupDialog("Verification successful.")
                pd.exec()
            else:
                pd = PopupDialog("Verification not successful.")
                pd.exec()

    def encrypt_file(self):
        if self.public_key is None:
            return
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("All files (*)")

        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            output_file_path = str(file_path) + '.bin'
            self.encryptor.encrypt_file(file_path, output_file_path, self.public_key)

    def decrypt_file(self):
        if self.private_key is None:
            return
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("bin files (*.bin)")

        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            self.encryptor.decrypt_file(file_path, file_path.replace(".bin", ".txt"), self.private_key)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())