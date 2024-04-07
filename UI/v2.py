import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QComboBox, QPushButton
import pyshark

class NIDPSApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Intrusion Detection and Prevention System")
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        welcome_label = QLabel("Welcome to NIDPS!")
        layout.addWidget(welcome_label)

        self.interface_dropdown = QComboBox()
        self.populate_interfaces()
        layout.addWidget(self.interface_dropdown)

        capture_button = QPushButton("Capture Network Traffic")
        capture_button.clicked.connect(self.capture_traffic)
        layout.addWidget(capture_button)

        self.setLayout(layout)

    def populate_interfaces(self):
        interfaces = pyshark.get_interface_names()
        self.interface_dropdown.addItems(interfaces)

    def capture_traffic(self):
        selected_interface = self.interface_dropdown.currentText()
        # Capture traffic on the selected interface using Snort, PyCap, or other modules
        # Implement your network capture logic here
        print(f"Capturing network traffic on interface: {selected_interface}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    nidps_app = NIDPSApp()
    nidps_app.show()
    sys.exit(app.exec_())
