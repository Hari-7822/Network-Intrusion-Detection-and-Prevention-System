# landing_page.py

from PyQt5.QtWidgets import QDialog,QVBoxLayout, QWidget, QLabel, QPushButton
from PyQt5.QtCore import Qt
from auth import LoginWindow
from window import MainWindow

class LandingPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NIDPS")
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.setGeometry(100, 100, 700, 300)

        label = QLabel("Welcome to NIDPS")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        btn_start = QPushButton("Login")
        btn_start.clicked.connect(self.show_login_window)
        layout.addWidget(btn_start)

    def show_login_window(self):
        login_window = LoginWindow()
        if login_window.exec_() == QDialog.Accepted:
            # User logged in successfully
            self.main_window = MainWindow()
            self.main_window.show()
            self.close()
