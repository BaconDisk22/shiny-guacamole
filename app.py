import csv
import random
import sys
import threading
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)


def packet_row(packet):
    decoded = packet.get("decoded") or {}
    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "from": str(packet.get("fromId") or packet.get("from") or ""),
        "type": str(decoded.get("portnum") or ""),
        "rssi": str(packet.get("rxRssi") if packet.get("rxRssi") is not None else ""),
        "snr": str(packet.get("rxSnr") if packet.get("rxSnr") is not None else ""),
    }


class RadioThread(QThread):
    packet = Signal(dict)
    status = Signal(str)

    def __init__(self, host, parent=None):
        super().__init__(parent)
        self.host = host
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def on_packet(self, packet, interface=None):
        if not self._stop.is_set():
            self.packet.emit(packet_row(packet))

    def run(self):
        interface = None
        subscribed = False
        try:
            from pubsub import pub
            from meshtastic.tcp_interface import TCPInterface
            if self._stop.is_set():
                return
            pub.subscribe(self.on_packet, "meshtastic.receive")
            subscribed = True
            interface = TCPInterface(hostname=self.host)
            if not self._stop.is_set():
                self.status.emit("Connected to " + self.host)
            while not self._stop.wait(0.25):
                pass
        except Exception as exc:
            if not self._stop.is_set():
                self.status.emit("Connection failed: " + str(exc))
        finally:
            if subscribed:
                try:
                    pub.unsubscribe(self.on_packet, "meshtastic.receive")
                except Exception:
                    pass
            if interface is not None:
                try:
                    interface.close()
                except Exception:
                    pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Meshtastic Sniffer TCP — Intel Mac")
        self.resize(900, 520)
        self.rows = []
        self.radio = None
        self.demo = QTimer(self)
        self.demo.timeout.connect(self.demo_packet)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        controls = QHBoxLayout()
        self.host = QLineEdit()
        self.host.setPlaceholderText("Radio IP address (e.g. 192.168.1.50)")
        self.connect_btn = QPushButton("Connect TCP")
        self.connect_btn.clicked.connect(self.connect_radio)
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect_radio)
        self.demo_btn = QPushButton("Demo Mode")
        self.demo_btn.clicked.connect(self.toggle_demo)
        export_btn = QPushButton("Export CSV")
        export_btn.clicked.connect(self.export_csv)
        for item in (self.host, self.connect_btn, self.disconnect_btn, self.demo_btn, export_btn):
            controls.addWidget(item)
        layout.addLayout(controls)
        self.status = QLabel("Disconnected")
        layout.addWidget(self.status)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "From", "Port", "RSSI", "SNR"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def add_packet(self, data):
        self.rows.append(data)
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, key in enumerate(("time", "from", "type", "rssi", "snr")):
            self.table.setItem(row, col, QTableWidgetItem(data.get(key, "")))
        self.table.scrollToBottom()

    def _radio_finished(self):
        radio = self.sender()
        if radio is self.radio:
            self.radio = None
            self.connect_btn.setEnabled(True)
            if not self.demo.isActive():
                self.status.setText("Disconnected")
        radio.deleteLater()

    def connect_radio(self):
        host = self.host.text().strip()
        if not host:
            QMessageBox.warning(self, "Missing address", "Enter your radio IP address.")
            return
        if self.radio is not None:
            self.status.setText("Disconnect the current radio before connecting again.")
            return
        self.demo.stop()
        self.radio = RadioThread(host, self)
        self.radio.packet.connect(self.add_packet)
        self.radio.status.connect(self.status.setText)
        self.radio.finished.connect(self._radio_finished)
        self.connect_btn.setEnabled(False)
        self.status.setText("Connecting...")
        self.radio.start()

    def disconnect_radio(self):
        if self.radio is not None:
            self.radio.stop()
            self.status.setText("Disconnecting...")
        elif not self.demo.isActive():
            self.status.setText("Disconnected")

    def toggle_demo(self):
        if self.demo.isActive():
            self.demo.stop()
            self.status.setText("Disconnected")
            return
        if self.radio is not None:
            self.status.setText("Disconnect the radio before starting demo mode.")
            return
        self.demo.start(1200)
        self.status.setText("Demo mode — simulated packets")

    def demo_packet(self):
        self.add_packet({
            "time": datetime.now().strftime("%H:%M:%S"),
            "from": "!%08x" % random.getrandbits(32),
            "type": random.choice(["TEXT_MESSAGE_APP", "POSITION_APP", "NODEINFO_APP"]),
            "rssi": str(random.randint(-120, -45)),
            "snr": str(round(random.uniform(-15, 12), 1)),
        })

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export packet log",
            str(Path.home() / "meshtastic-packets.csv"), "CSV files (*.csv)"
        )
        if path:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=["time", "from", "type", "rssi", "snr"])
                writer.writeheader()
                writer.writerows(self.rows)

    def closeEvent(self, event):
        self.demo.stop()
        if self.radio is not None:
            self.radio.stop()
            if not self.radio.wait(5000):
                event.ignore()
                self.status.setText("Waiting for TCP connection to close; please try again.")
                return
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
