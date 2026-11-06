import csv
import random
import sys
import threading
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Signal, QTimer, QSettings
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QAbstractItemView, QSplitter, QTextEdit,
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
        self.settings = QSettings('BaconDisk22', 'MeshtasticSnifferTCP')
        self.max_packets = 5000
        self.display_paused = False
        self.rows = []
        self.seen_nodes = set()
        self.port_counts = {}
        self.radio = None
        self.retry_count = 0
        self.retry_timer = QTimer(self)
        self.retry_timer.setSingleShot(True)
        self.retry_timer.timeout.connect(self.connect_radio)
        self.reconnect_enabled = False
        self.demo_nodes = ["!a1b2c3d4", "!b2c3d4e5", "!c3d4e5f6", "!d4e5f6a7"]
        self.demo = QTimer(self)
        self.demo.timeout.connect(self.demo_packet)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        controls = QHBoxLayout()
        self.host = QLineEdit()
        self.host.setPlaceholderText("Radio IP address (e.g. 192.168.1.50)")
        self.host.setText(self.settings.value("radio_host", "", type=str))
        self.connect_btn = QPushButton("Connect TCP")
        self.connect_btn.clicked.connect(self.connect_radio)
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect_radio)
        self.demo_btn = QPushButton("Demo Mode")
        self.demo_btn.clicked.connect(self.toggle_demo)
        self.pause_btn = QPushButton("Pause Display")
        self.pause_btn.clicked.connect(self.toggle_pause)
        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self.clear_log)
        export_btn = QPushButton("Export CSV")
        export_btn.clicked.connect(self.export_csv)
        for item in (self.host, self.connect_btn, self.disconnect_btn, self.demo_btn, self.pause_btn, clear_btn, export_btn):
            controls.addWidget(item)
        layout.addLayout(controls)
        self.status = QLabel("● Disconnected")
        layout.addWidget(self.status)
        self.stats = QLabel("Packets: 0  |  Nodes: 0  |  Message types: 0")
        layout.addWidget(self.stats)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter packets by node ID or message type...")
        self.filter_input.textChanged.connect(self.apply_filter)
        layout.addWidget(self.filter_input)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "From", "Port", "RSSI", "SNR"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setPlaceholderText("Select a packet to inspect its available metadata")
        self.packet_details.setMaximumHeight(110)
        self.table.itemSelectionChanged.connect(self.show_packet_details)
        self.node_table = QTableWidget(0, 2)
        self.node_table.setHorizontalHeaderLabels(["Node ID", "Packets"])
        self.node_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.node_table.horizontalHeader().setStretchLastSection(True)
        self.node_table.cellDoubleClicked.connect(self.filter_by_node)
        splitter = QSplitter()
        splitter.addWidget(self.table)
        splitter.addWidget(self.node_table)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)
        layout.addWidget(self.packet_details)

    def add_packet(self, data):
        self.rows.append(data)
        if len(self.rows) > self.max_packets:
            self.rows.pop(0)
            self.table.removeRow(0)
            self.seen_nodes = {row["from"] for row in self.rows if row.get("from")}
            self.port_counts = {}
            for row in self.rows[:-1]:
                kind = row.get("type") or "UNKNOWN"
                self.port_counts[kind] = self.port_counts.get(kind, 0) + 1
        if data.get("from"):
            self.seen_nodes.add(data["from"])
        kind = data.get("type") or "UNKNOWN"
        self.port_counts[kind] = self.port_counts.get(kind, 0) + 1
        self.stats.setText(f"Packets: {len(self.rows)}  |  Nodes: {len(self.seen_nodes)}  |  Message types: {len(self.port_counts)}")
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, key in enumerate(("time", "from", "type", "rssi", "snr")):
            self.table.setItem(row, col, QTableWidgetItem(data.get(key, "")))
        self.refresh_nodes()
        self.apply_filter()
        if not self.display_paused:
            self.table.scrollToBottom()

    def on_radio_status(self, message):
        self.status.setText(message)
        if message.startswith("Connected to "):
            self.retry_count = 0
        elif message.startswith("Connection failed:") and self.reconnect_enabled:
            self.retry_count += 1
            if self.retry_count <= 5:
                self.retry_timer.start(min(30000, 2000 * (2 ** (self.retry_count - 1))))

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
        self.retry_timer.stop()
        self.reconnect_enabled = True
        self.settings.setValue("radio_host", host)
        self.radio = RadioThread(host, self)
        self.radio.packet.connect(self.add_packet)
        self.radio.status.connect(self.on_radio_status)
        self.radio.finished.connect(self._radio_finished)
        self.connect_btn.setEnabled(False)
        self.status.setText("◌ Connecting to radio...")
        self.radio.start()

    def disconnect_radio(self):
        self.reconnect_enabled = False
        self.retry_timer.stop()
        self.retry_count = 0
        if self.radio is not None:
            self.radio.stop()
            self.status.setText("◌ Disconnecting...")
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
        self.reconnect_enabled = False
        self.retry_timer.stop()
        self.demo.start(1200)
        self.status.setText("● Demo mode — simulated packets")

    def demo_packet(self):
        self.add_packet({
            "time": datetime.now().strftime("%H:%M:%S"),
            "from": random.choice(self.demo_nodes),
            "type": random.choice(["TEXT_MESSAGE_APP", "POSITION_APP", "NODEINFO_APP"]),
            "rssi": str(random.randint(-120, -45)),
            "snr": str(round(random.uniform(-15, 12), 1)),
        })

    def show_packet_details(self):
        index = self.table.currentRow()
        if 0 <= index < len(self.rows):
            packet = self.rows[index]
            self.packet_details.setPlainText("\\n".join(f"{key}: {packet.get(key, '')}" for key in ("time", "from", "type", "rssi", "snr")))
        else:
            self.packet_details.clear()

    def filter_by_node(self, row, column):
        item = self.node_table.item(row, 0)
        if item is not None:
            self.filter_input.setText(item.text())

    def refresh_nodes(self):
        counts = {}
        for packet in self.rows:
            node = packet.get("from")
            if node:
                counts[node] = counts.get(node, 0) + 1
        self.node_table.setRowCount(len(counts))
        for row, (node, count) in enumerate(sorted(counts.items(), key=lambda item: -item[1])):
            self.node_table.setItem(row, 0, QTableWidgetItem(node))
            self.node_table.setItem(row, 1, QTableWidgetItem(str(count)))

    def apply_filter(self):
        query = self.filter_input.text().strip().casefold()
        for index, packet in enumerate(self.rows):
            searchable = " ".join(str(packet.get(key, "")) for key in ("from", "type")).casefold()
            self.table.setRowHidden(index, bool(query) and query not in searchable)

    def toggle_pause(self):
        self.display_paused = not self.display_paused
        self.pause_btn.setText("Resume Auto-scroll" if self.display_paused else "Pause Display")
        if not self.display_paused:
            self.table.scrollToBottom()

    def clear_log(self):
        self.rows.clear()
        self.seen_nodes.clear()
        self.port_counts.clear()
        self.table.setRowCount(0)
        self.packet_details.clear()
        self.node_table.setRowCount(0)
        self.stats.setText("Packets: 0  |  Nodes: 0  |  Message types: 0")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export packet log",
            str(Path.home() / "meshtastic-packets.csv"), "CSV files (*.csv)"
        )
        if path:
            try:
                with open(path, "w", newline="", encoding="utf-8") as file:
                    writer = csv.DictWriter(file, fieldnames=["time", "from", "type", "rssi", "snr"])
                    writer.writeheader()
                    writer.writerows(self.rows)
            except OSError as exc:
                QMessageBox.critical(self, "Export failed", str(exc))
            else:
                self.status.setText(f"Exported {len(self.rows)} packets to CSV")

    def closeEvent(self, event):
        self.reconnect_enabled = False
        self.retry_timer.stop()
        self.settings.setValue("radio_host", self.host.text().strip())
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
    theme_path = Path(__file__).resolve().parent / "dashboard.qss"
    if theme_path.is_file():
        app.setStyleSheet(theme_path.read_text(encoding="utf-8"))
    window = MainWindow()
    window.table.setAlternatingRowColors(True)
    window.show()
    sys.exit(app.exec())
