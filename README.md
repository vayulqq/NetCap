# NetCap

## Description

NetCap is a powerful Python-based network protocol capture and analysis tool designed to capture and analyze TLS ClientHello and QUIC Initial packets from a specified target domain. It provides detailed insights into network protocol interactions, making it an essential tool for network engineers, security researchers, and developers working with modern web protocols.

### Key Features
- **TLS ClientHello Capture**: Captures and analyzes TLS handshake initiation packets.
- **QUIC Initial Packet Capture**: Captures and verifies QUIC protocol initial packets.
- **Flexible Tool Support**: Supports both `curl` and `gocurl` for HTTP client operations.
- **Rich Output**: Presents capture results in formatted tables using the `rich` library for enhanced readability.
- **Packet Verification**: Performs basic validation of captured packets to ensure data integrity.
- **Configurable**: Allows customization of output directories and protocol selection (TLS, QUIC, or both).
- **Error Handling**: Robust error management with detailed logging for debugging.
- **Dependency Checking**: Includes a test mode to verify dependencies and system permissions.

### Use Cases
- Debugging network protocol issues in web applications.
- Analyzing TLS and QUIC implementations for compliance or performance.
- Security research to inspect handshake packets for vulnerabilities.
- Educational purposes for learning about modern network protocols.

### Requirements
- Python 3.6+
- Required Python packages: `scapy`, `rich`
- System tools: `curl` (or `gocurl` for QUIC support)
- Root/admin privileges for packet capture (depending on the system)

### Installation
```bash
pip install scapy rich
```

Ensure `curl` or `gocurl` is installed and available in your system's PATH.

### Usage
```bash
python capture.py [options] <domain>
```

#### Options
- `-t, --tls`: Capture only TLS ClientHello packets.
- `-q, --quic`: Capture only QUIC Initial packets.
- `-a, --all`: Capture both TLS and QUIC packets.
- `--tool [curl|gocurl]`: Specify the HTTP client tool (default: `curl`).
- `--output <dir>`: Specify the output directory for capture files (default: `captures`).
- `--test`: Run in test mode to check dependencies and permissions.
- `domain`: Target domain name (e.g., `example.com`).

#### Example
Capture TLS and QUIC packets for `example.com`:
```bash
python capture.py -a example.com
```

Run in test mode:
```bash
python capture.py --test
```

### Output
Captured packets are saved as binary files in the specified output directory (default: `captures`). Results are displayed in a rich table format, including:
- Domain name
- Protocol type
- Output file path
- File size
- Capture timestamp
- Hex dump of the first 32 bytes

### Logging
Logs are written to `protocol_capture.log` and also displayed in the console, providing detailed information about the capture process and any errors encountered.

### Contributing
Contributions are welcome! Please submit issues or pull requests for bug fixes, feature enhancements, or documentation improvements.

### License
MIT License
