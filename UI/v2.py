import sys
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QMessageBox, QLabel, QVBoxLayout, QWidget, QPushButton, QTextEdit,QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QHBoxLayout,QAbstractScrollArea,QSizePolicy, QDialog, QMenu, QLineEdit
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, QTimer
from scapy.all import *
import csv

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import seaborn as sns

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
        connection = sqlite3.connect("users.sqlite")
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
            username = login_window.username_input.text()
            self.main_window = MainWindow(username)
            self.main_window.show()
            self.close()

class MainWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()

        self.setWindowTitle("NIDPS")
        self.setGeometry(100, 100, 800, 600)

        self.create_menu_bar()

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()
        self.central_widget.setLayout(layout)

        # Create a horizontal layout for the label and buttons
        top_layout = QHBoxLayout()
        layout.addLayout(top_layout)

        self.label = QLabel(f"Scanning the Network... Welcome, {username}!")
        self.label.setAlignment(Qt.AlignTop)
        top_layout.addWidget(self.label)

        # Spacer item to push buttons to the right
        top_layout.addStretch()

        # Button layout
        button_layout = QHBoxLayout()
        top_layout.addLayout(button_layout)

        # Save button
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_packets)
        button_layout.addWidget(self.save_button)

        # Pause button
        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(self.toggle_sniffing)
        button_layout.addWidget(self.pause_button)

        # Initialize the sniffing state
        self.sniffing_paused = False

        # Table setup
        self.table = QTableWidget()
        self.table.setColumnCount(4)  # 4 columns: Source IP, Destination IP, Protocol, Message Length
        self.table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "Message Length"])
        layout.addWidget(self.table)

        # Set table properties
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Connect item clicked signal
        self.table.itemClicked.connect(self.highlight_row)
        
        # Connect item right-clicked signal
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        self.highlighted_rows = set()  # Store the indices of highlighted rows

        self.sniff()

    def display_packet(self, packet):
        if not self.sniffing_paused:
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                msg_len = len(packet)
                
                row_position = self.table.rowCount()
                self.table.insertRow(row_position)
                
                src_item = QTableWidgetItem(src)
                dst_item = QTableWidgetItem(dst)
                proto_item = QTableWidgetItem(str(proto))
                len_item = QTableWidgetItem(str(msg_len))

                len_item.setTextAlignment(Qt.AlignCenter)
                
                self.table.setItem(row_position, 0, src_item)
                self.table.setItem(row_position, 1, dst_item)
                self.table.setItem(row_position, 2, proto_item)
                self.table.setItem(row_position, 3, len_item)

    def sniff(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.capture_packets)
        self.timer.start(750)

    def capture_packets(self):
        sniff(prn=self.display_packet, count=1)

    def toggle_sniffing(self):
        if self.sniffing_paused:
            self.sniffing_paused = False
            self.pause_button.setText("Pause")
        else:
            self.sniffing_paused = True
            self.pause_button.setText("Resume")

    def save_packets(self):
        # Implement saving packets functionality here
        QMessageBox.information(self, "Save Packets", "Functionality under development!")

    def create_menu_bar(self):
        menu_bar = self.menuBar()

        # File menu
        file_menu = menu_bar.addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close_application)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menu_bar.addMenu("Edit")

        # Network Interface menu
        ni_menu = menu_bar.addMenu("Network Interface")
        ni_action = QAction("Select Interface", self)
        ni_action.triggered.connect(self.select_interface)
        ni_menu.addAction(ni_action)

        # Dashboard menu
        dashboard_menu = menu_bar.addMenu("Dashboard")
        dashboard_action = QAction("Dashboard", self)
        dashboard_action.triggered.connect(self.open_dashboard)
        dashboard_menu.addAction(dashboard_action)

    def close_application(self):
        choice = QMessageBox.question(self, "Exit", "Are you sure you want to exit?", QMessageBox.Yes | QMessageBox.No)
        if choice == QMessageBox.Yes:
            sys.exit()
        
    def select_interface(self):
        QMessageBox.information(self, "Select Network Interface", "Feature under development!")
        
    def highlight_row(self, item):
        row = item.row()
        if row in self.highlighted_rows:
            self.highlighted_rows.remove(row)
            for col in range(self.table.columnCount()):
                self.table.item(row, col).setBackground(QColor("#ffffff"))  # White color
        else:
            self.highlighted_rows.add(row)
            for col in range(self.table.columnCount()):
                self.table.item(row, col).setBackground(QColor("#f0f0f0"))  # Lighter color

    def open_dashboard(self):
        self.dashboard = Dashboard()
        self.dashboard.show()


    def show_context_menu(self, pos):
        menu = QMenu()
        block_action = menu.addAction("Block")
        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == block_action:
            # Perform blocking action here
            selected_row = self.table.rowAt(pos.y())
            src_ip_item = self.table.item(selected_row, 0)
            if src_ip_item:
                src_ip = src_ip_item.text()
                block_successful = self.block_ip(src_ip)
                if block_successful:
                    QMessageBox.information(self, "Block IP", f"IP {src_ip} has been blocked.")
                else:
                    QMessageBox.warning(self, "Block IP", f"Failed to block IP {src_ip}.")

    def block_ip(self, ip):
        unreach_pkt = IP(dst=ip)/ICMP(type=3, code=1)
        
        # Send the crafted packet to the target IP
        send(unreach_pkt)
        
        return True


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.setLayout(layout)

        label = QLabel("Dashboard")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        # Create and embed a Matplotlib figure
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        # Example chart or list widgets can be added here
        self.plot_chart()

    def plot_chart(self):
        # Example chart using Seaborn
        data = sns.load_dataset("iris")
        sns.scatterplot(x="sepal_length", y="sepal_width", hue="species", data=data, ax=self.figure.add_subplot(111))
        plt.title("Sepal Length vs Sepal Width")
        plt.xlabel("Sepal Length")
        plt.ylabel("Sepal Width")
        plt.tight_layout()
        self.canvas.draw()


def main():
    app = QApplication(sys.argv)
    landing_page = LandingPage()
    landing_page.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
