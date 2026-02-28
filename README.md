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

## Local Stack (Manager + Server + Web)

Start everything locally with one command:

```powershell
./tools/local_stack.ps1 up
```

or

```bash
./tools/local_stack.sh up
```

Useful actions: `up`, `down`, `logs`, `status`.

After stack startup, run a smoke check:

```powershell
./tools/e2e_smoke.ps1
```

or

```bash
./tools/e2e_smoke.sh
```

## Usage

### 1. Server Setup
Run the server on your remote VPS. It will automatically detect your public IP.

```bash
./server -port 8080 -admin-secret <ADMIN_SECRET>
```

If you use the manager service, the default manager endpoint is:

```text
http://127.0.0.1:2933
```

Override it with `-manager` when needed.

To protect server-to-manager node APIs, enable a shared secret:

```bash
# manager
MANAGER_NODE_SECRET=<secret> ./manager

# server
./server -manager http://127.0.0.1:2933 -manager-secret <secret>
```

For `/admin/kick`, send `X-Admin-Secret: <ADMIN_SECRET>`; if `-admin-secret` is not set, the endpoint is disabled.

Runtime metrics are exposed at `GET /metrics` on the same admin port (default `:8090`).

Strict mode (recommended for production) enforces secrets at startup:

```bash
# manager
MANAGER_STRICT_AUTH=1 MANAGER_NODE_SECRET=<secret> ./manager

# server
./server -strict-auth -manager-secret <secret> -admin-secret <admin_secret>
```

Secret rotation window is supported with comma-separated values:

```bash
# manager accepts old + new during rollout
MANAGER_NODE_SECRET=old-secret,new-secret ./manager

# server admin endpoint accepts old + new during rollout
./server -admin-secret old-admin,new-admin
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

## Kernel Roadmap

Clash-like kernel evolution notes and milestones are tracked in:

- `spec/clash-like-kernel.md`
- `spec/tasks.md` (`Clash-like Kernel Evolution` section)
- `spec/native-desktop-ui.md` (native UI priority, non-web primary)
- `spec/secret-rotation.md` (control-plane secret rotation procedure)

Current kernel baseline now includes config hot reload and rule provider expansion (`routing.rule_providers` + `type: provider`).
Kernel DNS/FakeIP policy baseline is available (`DNSPolicy` + `FakeIPPool` with runtime DNS decision hook).
Kernel TUN ingress skeleton is available with lifecycle + metadata dispatch baseline.
Kernel local controller skeleton is also available with read-only runtime/config endpoints.

## Core Test Profile

Use the stable core test profile locally and in CI:

```bash
./tools/test_core.sh
```

or

```powershell
./tools/test_core.ps1
```

## Formatting

Check formatting:

```powershell
./tools/fmt.ps1 --check
```

or

```bash
bash ./tools/fmt.sh --check
```

Apply formatting:

```powershell
./tools/fmt.ps1
```

## Build All CLI Binaries

Build all CLI binaries (`client`, `server`, `manager`, `bench`, `http_bench`, `fetch_page`) for current platform:

```powershell
./tools/build_binaries.ps1 dist
```

or

```bash
bash ./tools/build_binaries.sh dist
```

GitHub Release workflow uploads only files generated under `dist/` (binary artifacts + checksums), not `TODO`/`task`/`spec` docs.

## Native Desktop UI

The primary operator UI direction is native desktop (Wails), not a browser dashboard.
Current desktop baseline includes tunnel controls, kernel config editing, kernel profile management (create/switch/delete), route probing diagnostics, and live runtime counters/adapter health.
Desktop route probe also includes rule trace chain visibility for first-match diagnostics.
Desktop kernel workspace now supports profile revision history and rollback.

## Roadmap

See [TODO.md](TODO.md) for planned features like Tun/Tap VPN mode and multi-user support.

## Disclaimer

This project is for educational and research purposes only. Please use it responsibly and in accordance with your local laws and regulations.
