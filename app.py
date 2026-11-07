import csv
import random
import socket
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


RECEIVE_TOPIC = "meshtastic.receive"
LOST_TOPIC = "meshtastic.connection.lost"
MAX_RECONNECT_ATTEMPTS = 5


def reconnect_delay_ms(attempt):
    """Bounded exponential backoff: 2s, 4s, 8s, 16s, then capped at 30s."""
    return min(30000, 2000 * (2 ** (max(1, attempt) - 1)))


def enable_tcp_keepalive(sock, idle=15, interval=5, count=4):
    """Ask the OS to probe an idle TCP link so a vanished radio is noticed.

    Without keepalive a radio that loses power or Wi-Fi leaves recv() blocked
    indefinitely. With these values a dead link errors out after roughly
    idle + interval * count seconds (about 35s). Returns False when the socket
    or platform does not support the options.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        idle_option = getattr(socket, "TCP_KEEPIDLE", None) or getattr(socket, "TCP_KEEPALIVE", None)
        if idle_option is not None:
            sock.setsockopt(socket.IPPROTO_TCP, idle_option, idle)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
        return True
    except (OSError, AttributeError, TypeError):
        return False


def _default_interface_factory(host):
    from meshtastic.tcp_interface import TCPInterface
    return TCPInterface(hostname=host)


class RadioThread(QThread):
    """Owns one TCP session from connect to close.

    When run() returns, ``end_reason`` is one of ``"stopped"`` (user asked),
    ``"failed"`` (never connected) or ``"lost"`` (connected, then dropped),
    and ``end_detail`` explains why. Subscriptions are always removed and the
    interface closed before the thread finishes, so a reconnect never stacks
    duplicate packet callbacks.
    """

    packet = Signal(dict)
    status = Signal(str)
    connected = Signal(str)

    def __init__(self, host, parent=None, interface_factory=None, pubsub=None, poll_interval=0.25):
        super().__init__(parent)
        self.host = host
        self._interface_factory = interface_factory or _default_interface_factory
        self._pubsub = pubsub
        self._poll_interval = poll_interval
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._interface = None
        self.end_reason = "stopped"
        self.end_detail = ""

    def stop(self):
        self._stop.set()

    def on_packet(self, packet, interface=None):
        if self._stop.is_set():
            return
        if self._interface is not None and interface is not None and interface is not self._interface:
            return
        self.packet.emit(packet_row(packet))

    def on_connection_lost(self, interface=None):
        # Only trust loss events for the interface this thread owns; a late
        # event from a previous session must not tear down a new one.
        if self._interface is not None and interface is self._interface:
            self._lost.set()

    def link_problem(self, interface):
        """Return why the established link is dead, or None while it is healthy."""
        if self._lost.is_set():
            return "radio closed the connection"
        reader = getattr(interface, "_rxThread", None)
        if reader is not None and getattr(reader, "ident", None) is not None and not reader.is_alive():
            return "radio stopped responding"
        return None

    def run(self):
        interface = None
        subscribed = []
        reason, detail = "stopped", ""
        try:
            pub = self._pubsub
            if pub is None:
                from pubsub import pub
            if self._stop.is_set():
                return
            for topic, listener in ((RECEIVE_TOPIC, self.on_packet), (LOST_TOPIC, self.on_connection_lost)):
                pub.subscribe(listener, topic)
                subscribed.append((topic, listener))
            interface = self._interface_factory(self.host)
            self._interface = interface
            if self._stop.is_set():
                return
            self.connected.emit(self.host)
            self.status.emit("● Connected to " + self.host)
            keepalive_socket = None
            while not self._stop.wait(self._poll_interval):
                sock = getattr(interface, "socket", None)
                if sock is not None and sock is not keepalive_socket:
                    # The library may silently swap sockets when it reconnects
                    # internally, so re-arm keepalive on every new socket.
                    enable_tcp_keepalive(sock)
                    keepalive_socket = sock
                problem = self.link_problem(interface)
                if problem:
                    reason, detail = "lost", problem
                    break
        except Exception as exc:
            reason, detail = "failed", str(exc) or exc.__class__.__name__
        finally:
            for topic, listener in subscribed:
                try:
                    pub.unsubscribe(listener, topic)
                except Exception:
                    pass
            if interface is not None:
                try:
                    interface.close()
                except Exception:
                    pass
            if self._stop.is_set():
                reason, detail = "stopped", ""
            self.end_reason, self.end_detail = reason, detail


class MainWindow(QMainWindow):
    def __init__(self, radio_factory=None):
        super().__init__()
        self.radio_factory = radio_factory or RadioThread
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
        self.max_retries = MAX_RECONNECT_ATTEMPTS
        self.reconnect_host = ""
        self.retry_timer = QTimer(self)
        self.retry_timer.setSingleShot(True)
        self.retry_timer.timeout.connect(self._retry_connect)
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
        visible_export_btn = QPushButton("Export Filtered CSV")
        visible_export_btn.clicked.connect(self.export_filtered_csv)
        export_btn = QPushButton("Export CSV")
        export_btn.clicked.connect(self.export_csv)
        for item in (self.host, self.connect_btn, self.disconnect_btn, self.demo_btn, self.pause_btn, clear_btn, export_btn, visible_export_btn):
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
        self.node_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.copy_node_btn = QPushButton("Copy Selected Node ID")
        self.copy_node_btn.clicked.connect(self.copy_selected_node)
        self.node_table.cellDoubleClicked.connect(self.filter_by_node)
        splitter = QSplitter()
        splitter.addWidget(self.table)
        splitter.addWidget(self.node_table)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)
        layout.addWidget(self.packet_details)
        layout.addWidget(self.copy_node_btn)

    def add_packet(self, data):
        self.rows.append(data)
        if len(self.rows) > self.max_packets:
            self.rows.pop(0)
            self.table.removeRow(0)
            if hasattr(self, "packet_details"):
                self.packet_details.clear()
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
        if hasattr(self, "packet_details") and self.table.currentRow() >= 0:
            self.show_packet_details()
        if not self.display_paused:
            self.table.scrollToBottom()

    def on_radio_status(self, message):
        self.status.setText(message)

    def _on_radio_connected(self, host):
        self.retry_count = 0

    def _radio_finished(self):
        radio = self.sender()
        if radio is self.radio:
            self.radio = None
            self.connect_btn.setEnabled(True)
            reason = getattr(radio, "end_reason", "stopped")
            detail = getattr(radio, "end_detail", "")
            if reason in ("failed", "lost") and self.reconnect_enabled:
                self._schedule_reconnect(reason, detail)
            elif reason == "failed":
                self.status.setText("✕ Connection failed: " + detail)
            elif not self.demo.isActive():
                self.status.setText("● Disconnected")
        radio.deleteLater()

    def _schedule_reconnect(self, reason, detail):
        # Called only once the previous worker has fully finished, so the old
        # interface is closed and its subscriptions are gone before retrying.
        label = "Connection lost" if reason == "lost" else "Connection failed"
        self.retry_count += 1
        if self.retry_count > self.max_retries:
            self.reconnect_enabled = False
            self.status.setText(
                f"✕ {label}: {detail} — gave up after {self.max_retries} attempts. "
                "Select Connect TCP to try again."
            )
            return
        delay = reconnect_delay_ms(self.retry_count)
        self.retry_timer.start(delay)
        self.status.setText(
            f"◌ {label}: {detail} — reconnecting in {delay // 1000}s "
            f"(attempt {self.retry_count}/{self.max_retries})"
        )

    def _retry_connect(self):
        if self.reconnect_enabled and self.radio is None and self.reconnect_host:
            self._start_radio(self.reconnect_host)
            self.status.setText(
                f"◌ Reconnecting to {self.reconnect_host} "
                f"(attempt {self.retry_count}/{self.max_retries})..."
            )

    def connect_radio(self):
        host = self.host.text().strip()
        if not host:
            QMessageBox.warning(self, "Missing address", "Enter your radio IP address.")
            return
        if self.radio is not None:
            self.status.setText("Disconnect the current radio before connecting again.")
            return
        self.retry_count = 0
        self._start_radio(host)

    def _start_radio(self, host):
        self.demo.stop()
        self.retry_timer.stop()
        self.reconnect_enabled = True
        self.reconnect_host = host
        self.settings.setValue("radio_host", host)
        self.radio = self.radio_factory(host, self)
        self.radio.packet.connect(self.add_packet)
        self.radio.status.connect(self.on_radio_status)
        self.radio.connected.connect(self._on_radio_connected)
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
            self.status.setText("● Disconnected")

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

    def copy_selected_node(self):
        row = self.node_table.currentRow()
        item = self.node_table.item(row, 0) if row >= 0 else None
        if item is not None:
            QApplication.clipboard().setText(item.text())
            self.status.setText("Copied node ID: " + item.text())

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

    def export_filtered_csv(self):
        visible = [packet for index, packet in enumerate(self.rows) if not self.table.isRowHidden(index)]
        path, _ = QFileDialog.getSaveFileName(self, "Export filtered packet log", str(Path.home() / "meshtastic-filtered-packets.csv"), "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=["time", "from", "type", "rssi", "snr"])
                writer.writeheader()
                writer.writerows(visible)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
        else:
            self.status.setText(f"Exported {len(visible)} filtered packets")

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
