# mynet

Minimal, ultra-fast CLI network auditor and LAN device discoverer written in Rust.

## Features

- 󰖟 **`myip`**: Shows public IP, Geo location, ISP/Provider, gateway, DNS, internet ping (1.1.1.1), and local interfaces (LAN, Wi-Fi, VPN) in a clean 2-column layout.
- 󰛳 **`mynet`**: Discovers all active devices in the local network in under **0.25 seconds** without `sudo` / root privileges.
- 󰓅 **Device Latency (RTT)**: Real-time network latency measurement for every host.
- 󰒋 **Quick Port Scanning (`-p` / `--ports`)**: Probes key services (SSH, DNS, Web, SMB, etc.) in parallel.
- 󰘦 **JSON Output (`-j` / `--json`)**: Machine-readable format perfect for scripting, Waybar, Polybar, or status bars.
- 󰞀 **VPN Bypassing**: Automatically binds discovery probes to the physical interface (`SO_BINDTODEVICE`), bypassing WireGuard/Amnezia routing tables.

## Usage

```bash
# Show public IP, location, gateway, DNS, ping & active interfaces
myip

# Discover active LAN devices with real-time latency
mynet

# Scan and display open ports (22, 53, 80, 443, etc.)
mynet -p

# Machine-readable JSON output (for Waybar, scripts, jq)
mynet --json
myip --json

# Safe fallback for standard fonts or Linux TTY console (no Nerd Font required)
mynet --ni
myip --ni
# Or via env: NO_ICONS=1 mynet
```

## Install

Via Cargo:
```bash
cargo install mynet
```

Or build from source:
```bash
git clone https://github.com/laguser/mynet.git
cd mynet
cargo build --release
cp target/release/mynet ~/.local/bin/
cp target/release/myip ~/.local/bin/
```

## License

MIT
