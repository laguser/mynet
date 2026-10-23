# mynet

Minimal CLI network auditor and LAN device discoverer written in Rust.

## Usage

```bash
# Show public IP, location, gateway, DNS & active interfaces
myip

# Discover active devices in the local network
mynet
```

## Install

Via Cargo:
```bash
cargo install mynet
```

Or build from source:
```bash
cargo build --release
```

## License

MIT
