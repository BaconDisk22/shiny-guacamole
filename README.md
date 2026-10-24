# Meshtastic Sniffer TCP

A standalone, receive-focused Meshtastic monitoring desktop application for Intel macOS. This is an independent project, not an SDR sniffer and not affiliated with the Meshtastic project.

## Features (initial prototype)
- Meshtastic Wi-Fi/TCP connection using the official Python library
- Live packet event log, node IDs, timestamps, and available RSSI/SNR
- Demo mode without radio hardware
- CSV export
- Desktop GUI built with PySide6

## Development
Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Enter the radio's LAN IP address and select Connect, or use Demo Mode. Meshtastic TCP typically uses port 4403. The app does not transmit messages. Monitor only traffic your radio can receive and expose; it cannot decrypt traffic without appropriate keys.

## Intel Mac builds
GitHub Actions builds an x86_64 macOS .app and DMG on an Intel runner when available. See Actions artifacts. Builds are unsigned; macOS may require Control-click > Open. Test on actual Intel hardware before release.
