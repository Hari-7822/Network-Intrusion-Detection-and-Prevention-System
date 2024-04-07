from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QLabel, QWidget, QTextEdit, QAction, QMessageBox
from PyQt5.QtGui import QFont, QColor
from PyQt5 import QtCore
from PyQt5.QtCore import QTimer
from PyQt5.QtNetwork import QNetworkInterface
import sys
from scapy.all import *

def packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        return (f"Source IP: {ip_src}, Destination IP: {ip_dst}")

class NetworkTrafficWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Traffic Monitor")
        self.setGeometry(100, 100, 800, 600)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

        self.display_network_traffic()

    def display_network_traffic(self):
        interfaces = QNetworkInterface.allInterfaces()
        for interface in interfaces:
            self.text_edit.append(f"Interface: {interface.name()}")
            self.text_edit.append(f"  Hardware Address: {interface.hardwareAddress()}")
            self.text_edit.append("  IP Addresses:")
            for entry in interface.addressEntries():
                self.text_edit.append(f"    {entry.ip().toString()}")

class NIDPS(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def openinterface(self):
            self.nidps_window = Monitor()
            self.nidps_window.show()

    def initUI(self):
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')

        savepkt = QAction('&Save Packets', self)
        savepkt.setShortcut('Ctrl+S')
        savepkt.setStatusTip('Save captured packets')
        savepkt.triggered.connect(self.savePackets)

        exitmenu = QAction('&Exit', self)
        exitmenu.setShortcut('Ctrl+Q')
        exitmenu.setStatusTip('Exit application')
        exitmenu.triggered.connect(self.close)
        
        # interface = menubar.addMenu('&Network Interfaces', self)
        # interface.setShortcut('Ctrl+N')
        # interface.setStatusTip('View Network Interfaces')
        # interface.triggered.connect(self.openinterface)



        fileMenu.addAction(savepkt)
        fileMenu.addAction(exitmenu)

        # .append(sniff(prn=packet, store=0))
        self.safePackets = QTextEdit(self)
        self.safePackets.setReadOnly(True)
        self.safePackets.setStyleSheet("color: lightgreen;")

        self.suspiciousPackets = QTextEdit(self)
        self.suspiciousPackets.setReadOnly(True)
        self.suspiciousPackets.setStyleSheet("color: yellow;")

        self.blockedPackets = QTextEdit(self)
        self.blockedPackets.setText("Hello")
        self.blockedPackets.setReadOnly(True)
        self.blockedPackets.setStyleSheet("color: red;")

        # titleLabel = QLabel('Network Intrusion Detection and Prevention System', self)
        # titleLabel.setFont(QFont('Arial', 16))

        mainLayout = QVBoxLayout()
        # mainLayout.addWidget(titleLabel)

        textLayout = QHBoxLayout()
        textLayout.addWidget(self.safePackets)
        textLayout.addWidget(self.suspiciousPackets)
        textLayout.addWidget(self.blockedPackets)

        mainLayout.addLayout(textLayout)

        centralWidget = QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

        self.setGeometry(300, 300, 800, 600)
        self.setWindowTitle('NIDPS')

    def savePackets(self):
        packets = "Capturing packets:\n\n"
        try:
            with open('captured_packets.txt', 'w') as file:
                file.write(packets)
            QMessageBox.information(self, 'Saved', 'Captured packets saved successfully.')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error occurred while saving packets:\n{str(e)}')

class LandingPage(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def close_window(self):
        QtCore.QCoreApplication.isntance().quit()

    def initUI(self):
        self.setWindowTitle('NIDPS')
        self.label=QLabel()
        self.label.setText("Welcome")
        self.label.setAlignment(QtCore.Qt.AlignCenter)

        nidps_btn = QPushButton('Open NIDPS', self)
        nidps_btn.clicked.connect(self.openNIDPSWindow)
        nidps_btn.clicked.connect(self.close)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(nidps_btn)

        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)
        self.setGeometry(300, 300, 400, 100)

    def openNIDPSWindow(self):
        self.nidps_window = NIDPS()
        self.nidps_window.show()

class Monitor():
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Network Traffic Monitor")
        self.setGeometry(100, 100, 800, 600)

        self.text_edit = QTextEdit(self)
        self.setCentralWidget(self.text_edit)

        self.start_sniffing()

    def display_packet(self, packet):
        self.text_edit.append(f"Source IP: {packet[0][1].src}, Destination IP: {packet[0][1].dst}")

    def start_sniffing(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.capture_packets)
        self.timer.start(1000)  # Capture packets every 1 second

    def capture_packets(self):
        sniff(prn=self.display_packet, count=1)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    landingPage = LandingPage()
    landingPage.show()
    sys.exit(app.exec_())


