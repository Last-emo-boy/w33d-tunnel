# w33d-tunnel

**w33d-tunnel** is a secure, censorship-resistant, and reliable UDP tunnel designed to bypass Deep Packet Inspection (DPI) and provide stable connectivity over unreliable networks.

It encapsulates TCP/UDP traffic within a custom encrypted UDP protocol, featuring built-in reliability mechanisms (ARQ) and traffic obfuscation to masquerade as random noise.

## Features

*   **🛡️ Strong Encryption**: End-to-end authenticated encryption using **X25519** (Key Exchange) and **ChaCha20-Poly1305** (Data).
*   **👻 Stealth & Obfuscation**: Header masking and random padding to eliminate protocol signatures and resist traffic analysis/probing.
*   **🔁 Reliability Layer**: Custom ARQ (Automatic Repeat Request) implementation provides reliable ordered delivery over UDP, similar to TCP but optimized for tunneling.
*   **⚡ UDP Support**: Full SOCKS5 **UDP Associate** support, enabling QUIC (HTTP/3), WebRTC, and online gaming.
*   **🌍 Global Proxy (Windows)**: One-click system-wide proxy configuration (`--global`).
*   **💻 Cross-Platform**: Compatible with Windows, Linux, and macOS (Intel/Apple Silicon).

## Installation & Build

### Prerequisites
*   [Go 1.22+](https://go.dev/dl/)

### Build from Source

**Windows (PowerShell):**
```powershell
.\build_all.ps1
```

**Linux / macOS:**
```bash
go build -o client ./cmd/client
go build -o server ./cmd/server
```

## Usage

### 1. Server Setup
Run the server on your remote VPS. It will automatically detect your public IP.

```bash
./server -port 8080
```

**Output:**
```
--- Server Information ---
Public IP Address (Fetching...):
  203.0.113.1
Static Public Key: <YOUR_SERVER_PUBLIC_KEY>
...
```
*Copy the `Static Public Key` for the client.*

### 2. Client Setup
Run the client on your local machine.

```bash
./client -server <SERVER_IP>:8080 -pubkey <SERVER_PUBLIC_KEY>
```

**Flags:**
*   `-socks string`: Local SOCKS5 listen address (default `":1080"`).
*   `-global`: (Windows Only) Enable global system proxy automatically.
*   `-v`: Enable verbose debug logging.

### 3. Configure Applications
Point your browser, Telegram, or other apps to the SOCKS5 proxy:
*   **IP**: `127.0.0.1`
*   **Port**: `1080` (or whatever you set with `-socks`)

## Protocol Details

The protocol is designed to look like high-entropy random UDP packets.

1.  **Handshake**: 0-RTT ephemeral key exchange (Noise-inspired).
2.  **Data Transport**:
    *   **Header**: Masked with a rolling key derived from the session key to hide sequence numbers and flags.
    *   **Payload**: Encrypted with ChaCha20-Poly1305.
    *   **Padding**: Variable length random padding to obscure packet size characteristics.
3.  **Reliability**:
    *   Implements Selective Repeat ARQ.
    *   Supports "Unreliable" mode for UDP-over-UDP to avoid Head-of-Line blocking.

## Roadmap

See [TODO.md](TODO.md) for planned features like Tun/Tap VPN mode and multi-user support.

## Disclaimer

This project is for educational and research purposes only. Please use it responsibly and in accordance with your local laws and regulations.
