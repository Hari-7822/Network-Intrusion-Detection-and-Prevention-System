# dashboard.py

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import seaborn as sns
from PyQt5.QtWidgets import QVBoxLayout, QWidget, QLabel
from PyQt5.QtCore import Qt

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
