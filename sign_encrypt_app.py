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

        self.setup_ui()

    def create_button_section(self, text, function):
        button = QPushButton(text)
        button.clicked.connect(function)
        self.layout.addWidget(button)

    def setup_ui(self):
        self.create_button_section("Import private key", self.import_private_key)
        self.private_key_label = QLabel("No file selected.")
        self.layout.addWidget(self.private_key_label)

        self.create_button_section("Import public key", self.import_public_key)
        self.public_key_label = QLabel("No file selected.")
        self.layout.addWidget(self.public_key_label)

        self.create_button_section("Sign a file", self.sign_file)
        self.create_button_section("Verify signature", self.verify_signature)
        self.create_button_section("Encrypt a file", self.encrypt_file)
        self.create_button_section("Decrypt a file", self.decrypt_file)

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
            file_path_output = file_dialog.getExistingDirectory(self.central_widget, "select directory")
            file_name_with_extension = os.path.basename(file_path_to_sign)
            self.encryptor.sign_document(file_path_to_sign,
                                         os.path.join(file_path_output, file_name_with_extension + ".sig"),
                                         self.private_key)

            username, ok = QInputDialog.getText(self, "Input Dialog", "Enter your username:")
            if not ok:
                return  # User canceled the input dialog
            self.encryptor.generate_xml_info(file_path_to_sign, username,
                                             os.path.join(file_path_output, file_name_with_extension))

    def verify_signature(self):
        if self.public_key is None:
            return
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("All files (*)")
        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            file_path_sig = file_dialog.getOpenFileName(self.central_widget, "Select signature file")[0]
            try:
                if file_path is not None and file_path_sig is not None and self.encryptor.verify_signature(file_path,
                                                                                                           file_path_sig,
                                                                                                           self.public_key):
                    pd = PopupDialog("Verification successful.")
                    pd.exec()
                else:
                    pd = PopupDialog("Verification not successful.")
                    pd.exec()
            except:
                return

    def encrypt_file(self):
        if self.public_key is None:
            return
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("All files (*)")

        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            file_path_output = file_dialog.getExistingDirectory(self.central_widget, "select directory")
            file_name_with_extension = os.path.basename(file_path)
            output_file_path = str(os.path.join(file_path_output, file_name_with_extension)) + '.bin'
            self.encryptor.encrypt_file(file_path, output_file_path, self.public_key)

    def decrypt_file(self):
        if self.private_key is None:
            return
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("bin files (*.bin)")

        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            file_path_output = file_dialog.getExistingDirectory(self.central_widget, "select directory")
            file_name_with_extension = os.path.basename(file_path)
            self.encryptor.decrypt_file(file_path, os.path.join(file_path_output, file_name_with_extension),
                                        self.private_key)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
