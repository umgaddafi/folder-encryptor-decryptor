import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QProgressBar, QHBoxLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QMovie
from encrypt import CryptoGUI

class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(600, 400)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setStyleSheet("background-color: #2E8B8B;")  

        # Title
        self.title = QLabel("DATA ENCRYPTION/DECRYPTION SYSTEM")
        self.title.setStyleSheet("color: white;")
        self.title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        #designer
        self.design = QLabel("DESIGN BY UMAR M. GADDAFI")
        self.design.setStyleSheet("color: white;")
        self.design.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.design.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # GIF
        self.image = QLabel()
        self.movie = QMovie("images/data_encryption.gif")
        self.image.setMovie(self.movie)
        self.image.setAlignment(Qt.AlignmentFlag.AlignCenter)
    
        self.movie.start()

        gif_layout = QVBoxLayout()
        gif_layout.addSpacing(40)
        gif_layout.addWidget(self.image)
        

        # Loading label
        self.loading_label = QLabel("Loading... 0%")
        self.loading_label.setStyleSheet("color: white; font-size: 14px;")
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setFixedWidth(560)
        self.progress.setFixedHeight(10)
        
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #ffffff;
                text-align: center;
                color: black;
            }
            QProgressBar::chunk {
                background-color: #00BFFF;
                width: 20px;
            }
        """)
        self.progress.setTextVisible(False)
        # Center the progress bar horizontally
        progress_layout = QVBoxLayout()
        progress_layout.addStretch()
        progress_layout.addSpacing(50)
        progress_layout.addWidget(self.loading_label)
        progress_layout.addWidget(self.progress)
        progress_layout.addStretch()

        # Status and Author labels
        self.status_label = QLabel("Status: Initializing")
        self.status_label.setStyleSheet("color: white; font-size: 12px;")

        self.author_label = QLabel("Author: Umar Gaddafi")
        self.author_label.setStyleSheet("color: white; font-size: 12px;")

        # Bottom layout: status left
        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.status_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.author_label)

        # Main layout 
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 10)  
        main_layout.addWidget(self.title)
        main_layout.addWidget(self.design)
        main_layout.addLayout(gif_layout)
        
        main_layout.addLayout(progress_layout)
        main_layout.addStretch()  
        main_layout.addLayout(bottom_layout)

        self.setLayout(main_layout)

        # loading
        self.progress_value = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(50)

    def update_progress(self):
        self.progress_value += 1
        self.progress.setValue(self.progress_value)
        self.loading_label.setText(f"Loading...  {self.progress_value}%")

        # Update status label based on progress
        if self.progress_value < 25:
            self.status_label.setText("Status: Initializing")
        elif self.progress_value < 50:
            self.status_label.setText("Status: Starting")
        elif self.progress_value < 75:
            self.status_label.setText("Status: Preparing")
        elif self.progress_value < 90:
            self.status_label.setText("Status: Finishing")
        else:
            self.status_label.setText("Status: Done")

        if self.progress_value >= 100:
            self.timer.stop()
            self.accept_splash()

    def accept_splash(self):
        self.close()
        self.main = CryptoGUI()
        self.main.show()
        # splash.close()


def show_main_window():
    window = CryptoGUI()
    window.show()
    splash.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    splash = SplashScreen()
    splash.show()
    sys.exit(app.exec())

