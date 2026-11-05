"""Capture a genuine offscreen rendering of the app in demo mode."""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from app import MainWindow

app = QApplication(sys.argv)
theme = Path(__file__).resolve().parents[1] / "dashboard.qss"
if theme.exists():
    app.setStyleSheet(theme.read_text(encoding="utf-8"))
window = MainWindow()
window.resize(1200, 720)
window.show()
window.toggle_demo()
for _ in range(12):
    window.demo_packet()
app.processEvents()
output = Path(__file__).resolve().parents[1] / "docs" / "screenshots" / "dashboard-demo.png"
output.parent.mkdir(parents=True, exist_ok=True)
if not window.grab().save(str(output), "PNG"):
    raise RuntimeError("Failed to save dashboard screenshot")
window.demo.stop()
window.close()
print(output)
