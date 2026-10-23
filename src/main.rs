use mynet::*;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
struct Device {
    ip: String,
    mac: String,
    vendor: String,
    hostname: String,
    interface: String,
    is_local: bool,
}

struct LocalSubnet {
    local_ip: Ipv4Addr,
    network: Ipv4Addr,
    mask: Ipv4Addr,
}

fn get_local_subnets() -> Vec<LocalSubnet> {
    let mut subnets = Vec::new();
    let interfaces = pnet_datalink::interfaces();

    for iface in interfaces {
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        if iface.name.starts_with("vpn") || iface.name.starts_with("wg") || iface.name.starts_with("tun") {
            continue;
        }

        for ip in iface.ips {
            if let ipnetwork::IpNetwork::V4(net4) = ip {
                let ip4 = net4.ip();
                if !ip4.is_loopback() && !ip4.is_link_local() {
                    subnets.push(LocalSubnet {
                        local_ip: ip4,
                        network: net4.network(),
                        mask: net4.mask(),
                    });
                }
            }
        }
    }
    subnets
}

// Instantaneous non-blocking UDP sweep to awaken ARP table
fn trigger_arp_sweep(subnets: &[LocalSubnet]) {
    for sn in subnets {
        let net_u32 = u32::from(sn.network);
        let mask_u32 = u32::from(sn.mask);
        let host_count = (!mask_u32).saturating_sub(1);

        if host_count > 1024 {
            continue;
        }

        if let Ok(socket) = UdpSocket::bind(SocketAddrV4::new(sn.local_ip, 0)) {
            let _ = socket.set_broadcast(true);
            let bcast = Ipv4Addr::from(net_u32 | !mask_u32);
            let _ = socket.send_to(b"ping", SocketAddrV4::new(bcast, 55555));

            for i in 1..host_count {
                let target_ip = Ipv4Addr::from(net_u32 + i);
                let _ = socket.send_to(b"", SocketAddrV4::new(target_ip, 55555));
            }
        }
    }
}

fn get_neighbor_devices() -> HashMap<String, Device> {
    let mut devices = HashMap::new();

    // 1. /proc/net/arp
    if let Ok(content) = fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 6 {
                let ip = fields[0];
                let mac = fields[3];
                let dev = fields[5];
                if mac != "00:00:00:00:00:00" && mac != "—" && !mac.contains("incomplete") {
                    devices.insert(
                        ip.to_string(),
                        Device {
                            ip: ip.to_string(),
                            mac: mac.to_string(),
                            vendor: String::new(),
                            hostname: String::new(),
                            interface: dev.to_string(),
                            is_local: false,
                        },
                    );
                }
            }
        }
    }

    // 2. ip neigh
    if let Ok(output) = Command::new("ip").arg("neigh").output() {
        if let Ok(text) = String::from_utf8(output.stdout) {
            for line in text.lines() {
                if line.contains("FAILED") || line.contains("INCOMPLETE") {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 4 {
                    let ip = fields[0];
                    let mut mac = "";
                    let mut iface = "";
                    for i in 0..fields.len() - 1 {
                        if fields[i] == "dev" {
                            iface = fields[i + 1];
                        }
                        if fields[i] == "lladdr" {
                            mac = fields[i + 1];
                        }
                    }
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        devices.insert(
                            ip.to_string(),
                            Device {
                                ip: ip.to_string(),
                                mac: mac.to_string(),
                                vendor: String::new(),
                                hostname: String::new(),
                                interface: iface.to_string(),
                                is_local: false,
                            },
                        );
                    }
                }
            }
        }
    }

    // 3. Local machine IPs
    for iface in pnet_datalink::interfaces() {
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        let mac = iface.mac.map(|m| m.to_string()).unwrap_or_else(|| "—".to_string());
        for ip in iface.ips {
            if let ipnetwork::IpNetwork::V4(net4) = ip {
                let ip4 = net4.ip();
                if !ip4.is_loopback() {
                    devices.insert(
                        ip4.to_string(),
                        Device {
                            ip: ip4.to_string(),
                            mac: mac.clone(),
                            vendor: String::new(),
                            hostname: String::new(),
                            interface: iface.name.clone(),
                            is_local: true,
                        },
                    );
                }
            }
        }
    }

    devices
}

// Fast DNS lookup with strict 250ms deadline per host
fn lookup_hostname_fast(ip_str: &str) -> String {
    if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
        let (tx, rx) = mpsc::channel();
        let _ = thread::spawn(move || {
            let res = dns_lookup::lookup_addr(&ip_addr).unwrap_or_else(|_| "—".to_string());
            let _ = tx.send(res);
        });

        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(name) => name,
            Err(_) => "—".to_string(),
        }
    } else {
        "—".to_string()
    }
}

fn main() {
    let stop_spinner = Arc::new(AtomicBool::new(false));
    let stop_spinner_clone = stop_spinner.clone();

    print!("\x1b[?25l");
    let spinner_handle = thread::spawn(move || {
        let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut idx = 0;
        while !stop_spinner_clone.load(Ordering::Relaxed) {
            let f = frames[idx % frames.len()];
            print!("\r  {C_ACCENT}{f}{C_RESET} {C_MUTED}Discovering active topology...{C_RESET} ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            idx += 1;
            thread::sleep(Duration::from_millis(80));
        }
        print!("\r\x1b[2K\x1b[?25h");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    });

    let subnets = get_local_subnets();
    trigger_arp_sweep(&subnets);

    thread::sleep(Duration::from_millis(150));

    let dev_map = get_neighbor_devices();

    stop_spinner.store(true, Ordering::Relaxed);
    let _ = spinner_handle.join();

    if dev_map.is_empty() {
        println!("  {C_MUTED}No devices found on local network.{C_RESET}\n");
        return;
    }

    let (_, gw_full) = get_dns_and_gateway();
    let gw_ip = gw_full.split_whitespace().next().unwrap_or("").to_string();

    let mut dev_list: Vec<Device> = dev_map.into_values().collect();

    // Parallel vendor and timeout-bounded DNS resolution
    dev_list.par_iter_mut().for_each(|d| {
        d.vendor = lookup_vendor(&d.mac);

        if d.is_local {
            let host = fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "localhost".to_string());
            d.hostname = format!("{host} ●");
        } else if d.ip == gw_ip {
            d.hostname = "gateway / router".to_string();
        } else {
            d.hostname = lookup_hostname_fast(&d.ip);
        }
    });

    dev_list.sort_by_key(|d| d.ip.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED));

    let badge = get_session_badge();

    println!();
    println!("  {C_ACCENT}󰛳{C_RESET}  {C_BOLD}LOCAL TOPOLOGY{C_RESET}  {C_SUB}[{badge}]{C_RESET}");
    println!("  {C_DIM}{}{C_RESET}\n", "─".repeat(74));

    println!(
        "    {C_SUB}{:<16} {:<18} {:<10} {:<24} {}{C_RESET}",
        "IP ADDRESS", "MAC ADDRESS", "INTERFACE", "DEVICE / VENDOR", "HOSTNAME"
    );
    println!(
        "    {C_DIM}{:<16} {:<18} {:<10} {:<24} {}{C_RESET}",
        "─".repeat(15),
        "─".repeat(17),
        "─".repeat(9),
        "─".repeat(23),
        "─".repeat(16)
    );

    for d in &dev_list {
        let is_gw = d.ip == gw_ip;
        let icon = get_device_icon(&d.vendor, &d.hostname, d.is_local, is_gw);

        let icon_color = if is_gw {
            C_GREEN
        } else if d.is_local {
            C_SUB
        } else {
            C_ACCENT
        };

        let ip_col = format!("{C_TEXT}{:<16}{C_RESET}", d.ip);
        let mac_col = format!("{C_MUTED}{:<18}{C_RESET}", d.mac);
        let iface_col = format!("{C_SUB}{:<10}{C_RESET}", d.interface);

        let vendor_str = if d.vendor.len() > 23 {
            format!("{}...", &d.vendor[..20])
        } else {
            d.vendor.clone()
        };
        let vendor_col = format!("{C_ACCENT}{:<24}{C_RESET}", vendor_str);

        let host_col = if d.is_local {
            format!("{C_GREEN}{}{C_RESET}", d.hostname)
        } else if is_gw {
            format!("{C_SUB}{} 󰒋{C_RESET}", d.hostname)
        } else {
            format!("{C_TEXT}{}{C_RESET}", d.hostname)
        };

        println!("  {icon_color}{icon}{C_RESET} {ip_col} {mac_col} {iface_col} {vendor_col} {host_col}");
    }

    println!(
        "\n  {C_MUTED}Active nodes found:{C_RESET} {C_BOLD}{} devices{C_RESET}\n",
        dev_list.len()
    );
}
