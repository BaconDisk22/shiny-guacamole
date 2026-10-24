import csv
import random
import sys
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import QObject, QThread, Signal, Slot, QTimer
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox)

class RadioWorker(QObject):
    packet = Signal(dict)
    status = Signal(str)
    finished = Signal()

    def __init__(self, host):
        super().__init__()
        self.host = host
        self.interface = None

    @Slot()
    def run(self):
        try:
            from pubsub import pub
            from meshtastic.tcp_interface import TCPInterface
            pub.subscribe(self.on_packet, 'meshtastic.receive')
            self.interface = TCPInterface(hostname=self.host)
            self.status.emit('Connected to ' + self.host)
        except Exception as exc:
            self.status.emit('Connection failed: ' + str(exc))
            self.close()

    def on_packet(self, packet, interface=None):
        decoded = packet.get('decoded') or {}
        self.packet.emit({
            'time': datetime.now().strftime('%H:%M:%S'),
            'from': str(packet.get('fromId') or packet.get('from') or ''),
            'type': str(decoded.get('portnum') or ''),
            'rssi': str(packet.get('rxRssi') or ''),
            'snr': str(packet.get('rxSnr') or ''),
        })

    @Slot()
    def close(self):
        try:
            from pubsub import pub
            pub.unsubscribe(self.on_packet, 'meshtastic.receive')
        except Exception:
            pass
        if self.interface:
            try:
                self.interface.close()
            except Exception:
                pass
            self.interface = None
        self.finished.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Meshtastic Sniffer TCP — Intel Mac')
        self.resize(900, 520)
        self.rows = []
        self.thread = None
        self.worker = None
        self.demo = QTimer(self)
        self.demo.timeout.connect(self.demo_packet)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        controls = QHBoxLayout()
        self.host = QLineEdit()
        self.host.setPlaceholderText('Radio IP address (e.g. 192.168.1.50)')
        self.connect_btn = QPushButton('Connect TCP')
        self.connect_btn.clicked.connect(self.connect_radio)
        self.disconnect_btn = QPushButton('Disconnect')
        self.disconnect_btn.clicked.connect(self.disconnect_radio)
        self.demo_btn = QPushButton('Demo Mode')
        self.demo_btn.clicked.connect(self.toggle_demo)
        export_btn = QPushButton('Export CSV')
        export_btn.clicked.connect(self.export_csv)
        for item in (self.host, self.connect_btn, self.disconnect_btn, self.demo_btn, export_btn):
            controls.addWidget(item)
        layout.addLayout(controls)
        self.status = QLabel('Disconnected')
        layout.addWidget(self.status)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['Time', 'From', 'Port', 'RSSI', 'SNR'])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def add_packet(self, data):
        self.rows.append(data)
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, key in enumerate(('time', 'from', 'type', 'rssi', 'snr')):
            self.table.setItem(row, col, QTableWidgetItem(data.get(key, '')))
        self.table.scrollToBottom()

    def connect_radio(self):
        host = self.host.text().strip()
        if not host:
            QMessageBox.warning(self, 'Missing address', 'Enter your radio IP address.')
            return
        self.disconnect_radio()
        self.demo.stop()
        self.thread = QThread(self)
        self.worker = RadioWorker(host)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.packet.connect(self.add_packet)
        self.worker.status.connect(self.status.setText)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()
        self.status.setText('Connecting...')

    def disconnect_radio(self):
        if self.worker:
            self.worker.close()
            self.worker = None
        self.status.setText('Disconnected')

    def toggle_demo(self):
        self.disconnect_radio()
        if self.demo.isActive():
            self.demo.stop()
            self.status.setText('Disconnected')
        else:
            self.demo.start(1200)
            self.status.setText('Demo mode — simulated packets')

    def demo_packet(self):
        self.add_packet({'time': datetime.now().strftime('%H:%M:%S'), 'from': '!%08x' % random.getrandbits(32), 'type': random.choice(['TEXT_MESSAGE_APP', 'POSITION_APP', 'NODEINFO_APP']), 'rssi': str(random.randint(-120, -45)), 'snr': str(round(random.uniform(-15, 12), 1))})

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export packet log', str(Path.home() / 'meshtastic-packets.csv'), 'CSV files (*.csv)')
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=['time', 'from', 'type', 'rssi', 'snr'])
                writer.writeheader()
                writer.writerows(self.rows)

    def closeEvent(self, event):
        self.demo.stop()
        self.disconnect_radio()
        super().closeEvent(event)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
