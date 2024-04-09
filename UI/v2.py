import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QMessageBox, QLabel, QVBoxLayout, QWidget, QPushButton, QRadioButton, QScrollArea
from PyQt5.QtCore import Qt, QTimer
from scapy.all import *
import socket
from PyQt5.QtWidgets import QApplication, QMainWindow, QAction, QMessageBox, QLabel, QVBoxLayout, QWidget, QPushButton, QTextEdit,QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QHBoxLayout,QAbstractScrollArea,QSizePolicy
class LandingPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NIDPS")
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.setGeometry(100, 100, 400, 300)

        label = QLabel("Welcome to NIDPS")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)  # Allows the widget inside the scroll area to resize itself
        layout.addWidget(scroll_area)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_area.setWidget(scroll_content)

        self.interface_buttons = []

        active_interfaces = self.get_active_network_interfaces()

        for interface in active_interfaces:
            button = QRadioButton(interface)
            scroll_layout.addWidget(button)
            self.interface_buttons.append(button)

        btn_start = QPushButton("Start Network Scan ")
        btn_start.clicked.connect(self.start_nidps)
        scroll_layout.addWidget(btn_start)

    def get_active_network_interfaces(self):
        interfaces = []
        for interface in socket.if_nameindex():
            interfaces.append(interface[1])
        return interfaces

    def start_nidps(self):
        selected_interface = None
        for button in self.interface_buttons:
            if button.isChecked():
                selected_interface = button.text()
                break
        
        if selected_interface:
            self.main_window = MainWindow(selected_interface)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.warning(self, "Interface not selected", "Please select a network interface.")

class MainWindow(QMainWindow):
    def __init__(self, interface):
        super().__init__()

        self.interface = interface

        self.setWindowTitle("NIDPS")
        self.setGeometry(100, 100, 800, 600)

        self.create_menu_bar()

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()
        self.central_widget.setLayout(layout)

        self.label = QLabel(f"Scanning the Network on Interface: {self.interface}")
        self.label.setAlignment(Qt.AlignTop)
        layout.addWidget(self.label)

        # Table setup
        self.table = QTableWidget()
        self.table.setColumnCount(4)  # 4 columns: Source IP, Destination IP, Message Length, Message Content
        self.table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Message Length", "Message Content"])
        layout.addWidget(self.table)

        # Set table properties
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.sniff()

    def display_packet(self, packet):
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            msg_len = len(packet)
            msg_content = str(packet)

            row_position = self.table.rowCount()
            self.table.insertRow(row_position)

            src_item = QTableWidgetItem(src)
            dst_item = QTableWidgetItem(dst)
            len_item = QTableWidgetItem(str(msg_len))
            content_item = QTableWidgetItem(msg_content)

            len_item.setTextAlignment(Qt.AlignCenter)

            self.table.setItem(row_position, 0, src_item)
            self.table.setItem(row_position, 1, dst_item)
            self.table.setItem(row_position, 2, len_item)
            self.table.setItem(row_position, 3, content_item)

    def sniff(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.capture_packets)
        self.timer.start(750)

    def capture_packets(self):
        sniff(prn=self.display_packet, count=1, iface=self.interface)

    def create_menu_bar(self):
        menu_bar = self.menuBar()

        # File menu
        file_menu = menu_bar.addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close_application)
        file_menu.addAction(exit_action)

    def close_application(self):
        choice = QMessageBox.question(self, "Exit", "Are you sure you want to exit?", QMessageBox.Yes | QMessageBox.No)
        if choice == QMessageBox.Yes:
            sys.exit()

def main():
    app = QApplication(sys.argv)
    landing_page = LandingPage()
    landing_page.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
