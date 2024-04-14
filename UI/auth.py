# login_window.py

import sqlite3
from PyQt5.QtWidgets import QDialog, QMessageBox, QVBoxLayout, QLineEdit, QPushButton
from PyQt5.QtCore import Qt

class LoginWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login")
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.login)
        layout.addWidget(login_button)

        signup_button = QPushButton("Sign Up")
        signup_button.clicked.connect(self.show_signup_window)
        layout.addWidget(signup_button)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        # Connect to SQLite database
        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()

        # Check if user exists in the database
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()

        if user:
            self.accept()  # Close the login window and return QDialog.Accepted
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def show_signup_window(self):
        self.signup_window = SignupWindow()
        self.signup_window.exec_()

class SignupWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sign Up")
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        signup_button = QPushButton("Sign Up")
        signup_button.clicked.connect(self.signup)
        layout.addWidget(signup_button)

    def signup(self):
        username = self.username_input.text()
        password = self.password_input.text()

        # Connect to SQLite database
        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()

        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            QMessageBox.warning(self, "Sign Up Failed", "Username already exists.")
        else:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            connection.commit()
            QMessageBox.information(self, "Sign Up Success", "User registered successfully.")
            self.accept()  # Close the sign-up window and return QDialog.Accepted
