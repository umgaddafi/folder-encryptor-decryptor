import os
import zipfile
import base64
import shutil

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QFileDialog, QVBoxLayout, QHBoxLayout, QMessageBox,QComboBox,
    QProgressBar, QCheckBox, QTabWidget, QFrame, QStyle,
    QToolButton
)
from PyQt6.QtGui import QIcon, QPixmap, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# === Core Crypto and Utility Functions ===
def generate_salt():
    return os.urandom(16)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def zip_folder(folder_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                zipf.write(full_path, arcname)

def unzip_folder(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)

def encrypt_file(input_path, output_path, password, progress_bar, export_hashes=False):
    salt = generate_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, 'rb') as file:
        data = file.read()
    progress_bar.setValue(50)

    encrypted = fernet.encrypt(data)
    with open(output_path, 'wb') as file:
        file.write(salt + encrypted)

    if export_hashes:
        hash_path = output_path + ".hash"
        with open(hash_path, 'wb') as hash_file:
            hash_file.write(salt)

    progress_bar.setValue(100)

def decrypt_file(input_path, output_path, password, progress_bar, import_hashes=False):
    with open(input_path, 'rb') as file:
        content = file.read()

    if import_hashes:
        hash_file = input_path + ".hash"
        with open(hash_file, 'rb') as hf:
            salt = hf.read()
        encrypted = content
    else:
        salt, encrypted = content[:16], content[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    with open(output_path, 'wb') as file:
        file.write(decrypted)

    progress_bar.setValue(100)

def encrypt_folder(folder_path, output_encrypted_path, password, progress_bar, delete_after, export_hashes):
    temp_zip = folder_path + ".zip"
    zip_folder(folder_path, temp_zip)
    progress_bar.setValue(25)
    encrypt_file(temp_zip, output_encrypted_path, password, progress_bar, export_hashes)
    os.remove(temp_zip)
    if delete_after:
        shutil.rmtree(folder_path)

def decrypt_folder(encrypted_path, password, progress_bar, import_hashes):
    file_dir = os.path.dirname(encrypted_path)
    base_name = os.path.splitext(os.path.basename(encrypted_path))[0]
    output_folder_path = os.path.join(file_dir, base_name)
    os.makedirs(output_folder_path, exist_ok=True)
    temp_zip = output_folder_path + ".zip"
    decrypt_file(encrypted_path, temp_zip, password, progress_bar, import_hashes)
    unzip_folder(temp_zip, output_folder_path)
    os.remove(temp_zip)
    os.remove(encrypted_path)
    


# === Custom Drag-and-Drop Widget ===
class DragDropWidget(QFrame):
    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self.setAcceptDrops(True)
        self.setFixedSize(600, 200)
        self.setStyleSheet("""
            QFrame {
                border: 2px dashed #aaa;
                border-radius: 10px;
                background-color: #f8f8f8;
            }
        """)
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label = QLabel()
        self.icon_label.setPixmap(QPixmap("./images/cloud.jpeg").scaled(90, 70, Qt.AspectRatioMode.KeepAspectRatio))
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.text_label = QLabel("Drag & Drop folder here")
        self.text_label.setStyleSheet("color: #666; font-size: 18px;")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.or_label = QLabel("Or")
        self.or_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        

        self.browse_button = QPushButton("Browse")
        self.browse_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_button.setStyleSheet("""
            QPushButton {
                background-color: #0078D4;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005ea6;
            }
        """)
        self.browse_button.clicked.connect(self.browse_folder)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)
        layout.addWidget(self.or_label)
        layout.addWidget(self.browse_button)
        
        self.setLayout(layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            path = event.mimeData().urls()[0].toLocalFile()
            if os.path.isdir(path):
                self.text_label.setText(path)
                if self.callback:
                    self.callback(path)

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.text_label.setText(folder)
            if self.callback:
                self.callback(folder)

class FileDragDropWidget(QFrame):
    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self.setAcceptDrops(True)
        self.setFixedSize(600, 200)
        self.setStyleSheet("""
            QFrame {
                border: 2px dashed #aaa;
                border-radius: 10px;
                background-color: #f8f8f8;
            }
        """)
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label = QLabel()
        self.icon_label.setPixmap(QPixmap("./images/cloud.jpeg").scaled(90, 70, Qt.AspectRatioMode.KeepAspectRatio))
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.text_label = QLabel("Drag & Drop encrypted file here")
        self.text_label.setStyleSheet("color: #666; font-size: 18px;")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.or_label = QLabel("Or")
        self.or_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        

        self.browse_button = QPushButton("Browse")
        self.browse_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_button.setStyleSheet("""
            QPushButton {
                background-color: #0078D4;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005ea6;
            }
        """)
        self.browse_button.clicked.connect(self.browse_encrypted_file)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)
        layout.addWidget(self.or_label)
        layout.addWidget(self.browse_button)
        
        
        self.setLayout(layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                if path.lower().endswith(".enc"):
                    if self.callback:
                        self.text_label.setText(path)
                        self.callback(path)
                else:
                    QMessageBox.warning(self, "Invalid File", "Only .enc files are allowed.")
            else:
                QMessageBox.warning(self, "Invalid Input", "Please drop a file, not a folder.")
    def browse_encrypted_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", filter="Encrypted Files (*.enc)")
        if file:
            self.text_label.setText(file)
# === Main Application GUI ===
class CryptoGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Folder Encryptor/Decryptor")
        self.setMinimumSize(600, 600)
        self.setWindowIcon(QIcon("images/encry.png"))
        self.dark_mode = ""

        self.tabs = QTabWidget()
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()
        self.tabs.addTab(self.encrypt_tab, "Encrypt")
        self.tabs.addTab(self.decrypt_tab, "Decrypt")

        self.init_encrypt_ui()
        self.init_decrypt_ui()

        self.theme_dropdown = QComboBox()
        self.theme_dropdown.addItems(["Light", "Dark"])
        self.theme_dropdown.setMaximumWidth(100)
        self.theme_dropdown.currentTextChanged.connect(self.apply_theme)

        header_layout = QHBoxLayout()
        header_layout.addStretch()
        header_layout.addWidget(self.theme_dropdown)

        main_layout = QVBoxLayout()
        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

    def apply_theme(self, mode):
        if mode == "Dark":
            self.setStyleSheet("""
                QWidget { background-color: #2b2b2b; color: #ffffff; }
                QPushButton { background-color: #444; color: #fff; }
                QProgressBar { border: 1px solid #444; border-radius: 5px; text-align: center; }
                QProgressBar::chunk { background-color: #05B8CC; width: 20px; }
            """)
            self.dark_mode = True
        else:
            self.setStyleSheet("")
            self.dark_mode = False
    def create_password_input(self):
        pw_layout = QHBoxLayout()
        line_edit = QLineEdit()
        line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        toggle = QToolButton()
        toggle.setCheckable(True)
        toggle.setText("🙈")  
        toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        toggle.setToolTip("Show/Hide Password")
        toggle.setStyleSheet("font-size: 16px;")

        def toggle_visibility():
            if toggle.isChecked():
                line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
                toggle.setText("👁️")  
            else:
                line_edit.setEchoMode(QLineEdit.EchoMode.Password)
                toggle.setText("🙈")  

        toggle.clicked.connect(toggle_visibility)
        pw_layout.addWidget(line_edit)
        pw_layout.addWidget(toggle)
        
        return line_edit, pw_layout

        
    def init_encrypt_ui(self):
        layout = QVBoxLayout()
        self.input_path = ""
        self.drag_widget = DragDropWidget(callback=self.set_input_path)
        # layout.addWidget(QLabel("Input Folder:"))
        layout.addWidget(self.drag_widget)

        # layout.addWidget(QLabel("Password:"))
        self.password_enc, pw_layout = self.create_password_input()
        self.password_enc.setPlaceholderText("Password")
        layout.addLayout(pw_layout)
        # self.confirm_label  =   QLabel("Confirm Password:")
        # layout.addWidget(self.confirm_label)
        self.confirm_password_enc, cpw_layout = self.create_password_input()
        self.confirm_password_enc.setPlaceholderText("Confirm Password")
        layout.addLayout(cpw_layout)

        self.delete_source = QCheckBox("Delete source after encryption")
        self.export_hash = QCheckBox("Export password hash file")
        layout.addWidget(self.delete_source)
        layout.addWidget(self.export_hash)

        self.progress_enc = QProgressBar()
        self.progress_enc = QProgressBar()
        self.progress_enc.setStyleSheet("""
            QProgressBar { border: 1px solid #aaa; border-radius: 5px; text-align: center; height: 20px; }
            QProgressBar::chunk { background-color: #0078D4; }
        """)
        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_encrypt.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_encrypt.setStyleSheet("""
            QPushButton {
                width:30%;
                background-color: #0078D4;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005ea6;
            }
        """)
        self.btn_encrypt.clicked.connect(self.encrypt)

        layout.addWidget(self.progress_enc)
        layout.addWidget(self.btn_encrypt)
        self.encrypt_tab.setLayout(layout)

    def init_decrypt_ui(self):
        layout = QVBoxLayout()
        # self.file_path_display = QLineEdit()
        # self.file_path_display.setPlaceholderText("Selected .enc file will appear here")
        # self.file_path_display.setReadOnly(True)
        self.enc_file_path=""
        self.file_drop_widget = FileDragDropWidget(callback=self.set_enc_path)

        layout.addWidget(self.file_drop_widget)
        # layout.addWidget(self.file_path_display)
        
        self.password_dec, pw_layout = self.create_password_input()
        self.password_dec.setPlaceholderText("Password")
        layout.addLayout(pw_layout)

        self.import_hash = QCheckBox("Import password hash file")
        layout.addWidget(self.import_hash)

        self.progress_dec = QProgressBar()
        self.progress_dec.setStyleSheet("""
            QProgressBar { border: 1px solid #aaa; border-radius: 5px; text-align: center; height: 20px; }
            QProgressBar::chunk { background-color: #0078D4; }
        """)
        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.setStyleSheet("""
            QPushButton {
                width:30%;
                background-color: #0078D4;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005ea6;
            }
        """)
        self.btn_decrypt.clicked.connect(self.decrypt)

        layout.addWidget(self.progress_dec)
        layout.addWidget(self.btn_decrypt)
        self.decrypt_tab.setLayout(layout)

    def set_input_path(self, path):
        self.input_path = path
    def set_enc_path(self, path):
        self.enc_file_path = path
    # def handle_encrypted_file_selected(self, path):
    #     self.file_path_display.setText(path)
    #     print("Encrypted file selected for decryption:", path)
    
    def encrypt(self):
        if not self.input_path or not os.path.isdir(self.input_path):
            QMessageBox.warning(self, "Error", "Please select a valid folder.")
            return

        pwd = self.password_enc.text()
        confirm_pwd = self.confirm_password_enc.text()

        if pwd != confirm_pwd:
            QMessageBox.critical(self, "Error", "Passwords do not match.")
            return

        folder_name = os.path.basename(self.input_path)
        out_file = os.path.join(os.path.dirname(self.input_path), f"{folder_name}.enc")

        self.progress_enc.setValue(0)
        try:
            encrypt_folder(
                self.input_path,
                out_file,
                pwd,
                self.progress_enc,
                self.delete_source.isChecked(),
                self.export_hash.isChecked()
            )
            QMessageBox.information(self, "Success", "Encryption complete.")
            
            self.progress_enc.setFormat("Done")
            self.progress_enc.setTextVisible(True)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def decrypt(self):
        in_path = self.enc_file_path
        if not in_path or not os.path.isfile(in_path):
            QMessageBox.warning(self, "Error", "Please select a valid encrypted file.")
            return

        pwd = self.password_dec.text()

        self.progress_dec.setValue(0)
        try:
            decrypt_folder(
                in_path,
                pwd,
                self.progress_dec,
                self.import_hash.isChecked()
            )
            
            self.progress_dec.setFormat("Done")
            self.progress_dec.setTextVisible(True)
            QMessageBox.information(self, "Success", "Decryption complete.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def toggle_theme(self, theme_choice):
        if theme_choice == "Dark":
            self.setStyleSheet("""
                QWidget {
                    background-color: #2b2b2b;
                    color: #ffffff;
                }
                QPushButton {
                    background-color: #444444;
                    color: white;
                }
                QPushButton:hover {
                    background-color: #666666;
                }
                QLineEdit, QComboBox {
                    background-color: #3b3b3b;
                    color: white;
                    border: 1px solid #555;
                    border-radius: 4px;
                }
                QProgressBar {
                    border: 1px solid #555;
                    border-radius: 5px;
                    text-align: center;
                    color: white;
                    background-color: #3a3a3a;
                }
                QProgressBar::chunk {
                    background-color: #0078D4;
                    width: 20px;
                }
            """)
        else:
            self.setStyleSheet("")