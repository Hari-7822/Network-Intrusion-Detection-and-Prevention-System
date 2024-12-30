# main_window.py

from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QLabel, QPushButton, QHBoxLayout, QTableWidget, QTableWidgetItem, QAbstractScrollArea, QSizePolicy, QMessageBox, QAction, QMenu
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, QTimer
from scapy.all import *
from dashboard import Dashboard

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

        # Create a horizontal layout for the label and buttons
        top_layout = QHBoxLayout()
        layout.addLayout(top_layout)

        self.label = QLabel("Scanning the Network...")
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
                proto = packet.proto
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
