import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QFileDialog, QLabel, \
    QInputDialog
from key_manager import KeyManager


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.key_manager = KeyManager()

        self.setWindowTitle("File Input and Output App")
        self.setGeometry(960, 540, 400, 200)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        self.button_generate_keys = QPushButton("Generate keys")
        self.button_generate_keys.clicked.connect(self.generate_and_save_keys)
        self.layout.addWidget(self.button_generate_keys)

        self.selected_file = None
        self.file_content = None
        self.public_key = None
        self.private_key = None

        self.message_label = QLabel("")
        self.layout.addWidget(self.message_label)

    def generate_and_save_keys(self):
        pin, ok = QInputDialog.getText(self, "Input Dialog", "Enter PIN for the private key:")

        if not ok:
            return  # User canceled the input dialog

        private_key, public_key = self.key_manager.generate_key_pair()

        private_key_path, _ = QFileDialog.getSaveFileName(self, "Save private key", "", "All Files (*)")
        if private_key_path:
            self.key_manager.write_key(private_key_path, private_key, pin)

        public_key_path, _ = QFileDialog.getSaveFileName(self, "Save public key", "", "All Files (*)")
        if public_key_path:
            self.key_manager.write_key(public_key_path, public_key)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
