# Architecture and operational boundaries

## Data path
Meshtastic radio (LAN Wi-Fi/TCP) → official Meshtastic Python TCPInterface → pubsub packet callback → Qt worker signal → desktop packet table and node summary.

The monitor sees only packets surfaced by the connected radio and its configured firmware, channel, and keys. It does not independently decode arbitrary LoRa RF traffic.

## Current behavior
- Radio I/O uses a QThread, separate from the GUI thread.
- Incoming packets are normalized to timestamp, source ID, port, RSSI, and SNR.
- The GUI retains at most 5,000 rows in memory; CSV export is user-initiated.
- Demo mode generates synthetic traffic and must not be mistaken for live RF evidence.
- Explicit TCP connection failures receive bounded retry attempts.

## Known limitations and risks
- A connection that silently drops after a successful TCP connection may not be detected reliably.
- Radio firmware/library versions may expose different metadata.
- Node identifiers and packet metadata can be sensitive; exports should be handled responsibly.
- GitHub Actions packaging and headless UI tests are not substitutes for Intel Mac and live-radio tests.

## Next reliability work
Add an explicit disconnect signal/health monitor based on supported Meshtastic library APIs, verify event cleanup, and test network loss/recovery on a physical radio before advertising automatic recovery from established-session disconnects.
