# TCP connection troubleshooting

1. Connect your Meshtastic radio and Mac to the same reachable network.
2. Enable the radio's Wi-Fi networking and obtain its IP address.
3. In Meshtastic Sniffer TCP, enter the radio IP and select **Connect TCP**.
4. Verify the radio is reachable on TCP port 4403 (for example: `nc -vz RADIO_IP 4403`).
5. Confirm no firewall, client isolation or VPN blocks the local connection.
6. If the app shows **Connection failed**, check the address, network and radio firmware before retrying.
7. If the radio drops off the network after connecting, the app shows **Connection lost** and retries automatically up to 5 times (2s, 4s, 8s, 16s, 30s). A radio that loses power can take about 35 seconds to be noticed. After the last attempt it stops; select **Connect TCP** to start again. **Disconnect** cancels any pending retry.

A green GitHub Actions build does not verify connectivity to a physical radio. The app is receive-focused and cannot capture arbitrary RF traffic outside the connected radio's capabilities.
