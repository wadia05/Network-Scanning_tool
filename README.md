# Network-Scanning_tool

## Network Device Scanner with Visual Dashboard
Build your own lightweight network scanner (not just using Nmap directly), including device fingerprinting with MAC vendor lookup and a visual dashboard.

### Core Features
- Discover hosts on local network.
- Scan common ports and basic service info.
- Identify manufacturer via MAC OUI lookup.
- Show results in a dashboard.

### Suggested Stack
- Python + Scapy (packet crafting and discovery)
- Flask (web interface)
- Optional Raspberry Pi deployment

### Cybersecurity Focus
- Secure the dashboard (authentication, input validation, rate limiting).
- Secure scanner execution and stored scan data.