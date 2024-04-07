import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QMessageBox, QLabel, QVBoxLayout, QWidget, QPushButton, QTextEdit, QFileDialog
from PyQt5.QtCore import Qt, QTimer

from scapy.all import *

class LandingPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NIDPS")
        layout = QVBoxLayout()
        self.setLayout(layout)

        label = QLabel("Welcome to NIDPS (Network Intrusion Detection and Prevention System)")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        
        I_label=QLabel("Select Interface")
    

        btn_start = QPushButton("Start Network Scan ")
        btn_start.clicked.connect(self.start_nidps)
        layout.addWidget(btn_start)

    def start_nidps(self):
        self.main_window = MainWindow()
        self.main_window.show()
        self.close()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("NIDPS")
        self.setGeometry(100, 100, 800, 600)

        self.create_menu_bar()

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()
        self.central_widget.setLayout(layout)

        label = QLabel("Main Window Content")
        label.setAlignment(Qt.AlignTop)
        layout.addWidget(label)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

        self.sniff()

    def display_packet(self, packet):
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            self.text_edit.append(f"Source IP: {src}, Destination IP: {dst}")
            def save(packet):
                pass

    def sniff(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.capture_packets)
        self.timer.start(750)

    def capture_packets(self):
        sniff(prn=self.display_packet, count=1)
    
    def create_menu_bar(self):
        menu_bar = self.menuBar()

        
        file_menu = menu_bar.addMenu("File")
        save_opt= QAction("&Save", self)
        save_opt.setShortcut('Ctrl+S')

        exit_action = QAction("&Exit", self)
        exit_action.triggered.connect(self.close_application)
        file_menu.addAction(exit_action)

        edit_menu = menu_bar.addMenu("Edit")

        ni_menu = menu_bar.addMenu("Network Interface")
        ni_action = QAction("Select Interface", self)
        ni_action.triggered.connect(self.select_interface)
        ni_menu.addAction(ni_action)

    def close_application(self):
        choice = QMessageBox.question(self, "Exit", "Are you sure you want to exit?", QMessageBox.Yes | QMessageBox.No)
        if choice == QMessageBox.Yes:
            sys.exit()
    
    def select_interface(self):
        QMessageBox.information(self, "Select Network Interface")

def main():
    app = QApplication(sys.argv)
    landing_page = LandingPage()
    landing_page.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 