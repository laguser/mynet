use mynet::*;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, serde::Serialize)]
struct Device {
    ip: String,
    mac: String,
    vendor: String,
    hostname: String,
    interface: String,
    latency_ms: Option<f64>,
    open_ports: Vec<u16>,
    is_local: bool,
    is_gateway: bool,
}

struct CliArgs {
    json: bool,
    ports: bool,
    no_icons: bool,
    help: bool,
}

fn parse_args() -> CliArgs {
    let mut json = false;
    let mut ports = false;
    let mut no_icons = false;
    let mut help = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-j" | "--json" => json = true,
            "-p" | "--ports" => ports = true,
            "--no-icons" | "--ni" | "-n" => no_icons = true,
            "-h" | "--help" => help = true,
            _ => {}
        }
    }

    no_icons = should_disable_icons(no_icons);

    CliArgs {
        json,
        ports,
        no_icons,
        help,
    }
}

fn print_help() {
    println!(
        "{C_BOLD}{C_ACCENT}mynet{C_RESET} {C_MUTED}v{} - Minimal CLI LAN device discoverer{C_RESET}\n",
        env!("CARGO_PKG_VERSION")
    );
    println!("{C_SUB}USAGE:{C_RESET}");
    println!("  mynet [options]\n");
    println!("{C_SUB}OPTIONS:{C_RESET}");
    println!("  {C_TEXT}-p, --ports{C_RESET}         Scan and display common open ports (22, 53, 80, 443, etc.)");
    println!("  {C_TEXT}--no-icons, --ni{C_RESET}    Disable Nerd Font icons (safe fallback for standard fonts / TTY)");
    println!("  {C_TEXT}-j, --json{C_RESET}          Output results as JSON (ideal for scripts, Waybar, Polybar)");
    println!("  {C_TEXT}-h, --help{C_RESET}          Print this help message\n");
}

struct LocalSubnet {
    iface_name: String,
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
                        iface_name: iface.name.clone(),
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

fn bind_socket_to_interface(socket: &UdpSocket, iface_name: &str) {
    let fd = socket.as_raw_fd();
    let mut bytes = iface_name.as_bytes().to_vec();
    bytes.push(0);
    let sndbuf: libc::c_int = 1024 * 1024;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sndbuf) as libc::socklen_t,
        );
    }
}

fn trigger_arp_sweep(subnets: &[LocalSubnet]) {
    for sn in subnets {
        let net_u32 = u32::from(sn.network);
        let mask_u32 = u32::from(sn.mask);
        let host_count = (!mask_u32).saturating_sub(1);

        if host_count > 1024 {
            continue;
        }

        let mut iface_bytes = sn.iface_name.as_bytes().to_vec();
        iface_bytes.push(0);

        // Open unprivileged ICMP ping socket (supported on Linux kernel without root)
        let icmp_fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
                libc::IPPROTO_ICMP,
            )
        };
        if icmp_fd >= 0 {
            let sndbuf: libc::c_int = 1024 * 1024;
            unsafe {
                libc::setsockopt(
                    icmp_fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_bytes.as_ptr() as *const libc::c_void,
                    iface_bytes.len() as libc::socklen_t,
                );
                libc::setsockopt(
                    icmp_fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &sndbuf as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&sndbuf) as libc::socklen_t,
                );
            }
        }

        if let Ok(socket) = UdpSocket::bind(SocketAddrV4::new(sn.local_ip, 0)) {
            let _ = socket.set_nonblocking(true);
            bind_socket_to_interface(&socket, &sn.iface_name);
            let _ = socket.set_broadcast(true);

            // Multicast & Broadcast discovery signals (mDNS + NetBIOS + UDP echo)
            let bcast = Ipv4Addr::from(net_u32 | !mask_u32);
            let _ = socket.send_to(b"\0", SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
            let _ = socket.send_to(b"\0", SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 55555));
            let _ = socket.send_to(b"\0", SocketAddrV4::new(bcast, 137));
            let _ = socket.send_to(b"\0", SocketAddrV4::new(bcast, 55555));

            // Standard ICMP Echo Request payload: type=8, code=0, id=1337, seq=1
            let icmp_packet: [u8; 8] = [8, 0, 0, 0, 0x05, 0x39, 0x00, 0x01];

            // Multi-vector sweep: ICMP Echo + mDNS/NetBIOS unicast probes
            for i in 1..host_count {
                let target_ip = Ipv4Addr::from(net_u32 + i);

                // 1. Send ICMP Echo Request if available
                if icmp_fd >= 0 {
                    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                    sin.sin_family = libc::AF_INET as libc::sa_family_t;
                    sin.sin_addr.s_addr = u32::from(target_ip).to_be();

                    for _ in 0..3 {
                        let res = unsafe {
                            libc::sendto(
                                icmp_fd,
                                icmp_packet.as_ptr() as *const libc::c_void,
                                icmp_packet.len(),
                                0,
                                &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                            )
                        };
                        if res >= 0 {
                            break;
                        }
                        let err = unsafe { *libc::__errno_location() };
                        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                            thread::sleep(Duration::from_micros(150));
                        } else {
                            break;
                        }
                    }
                }

                // 2. Send UDP probe (mDNS port 5353) with retry on WouldBlock
                for _ in 0..3 {
                    match socket.send_to(b"\0", SocketAddrV4::new(target_ip, 5353)) {
                        Ok(_) => break,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_micros(150));
                        }
                        Err(_) => break,
                    }
                }

                // Smooth pacing to prevent kernel ARP queue drops
                if i % 32 == 0 {
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }

        if icmp_fd >= 0 {
            unsafe {
                libc::close(icmp_fd);
            }
        }
    }
}

fn get_neighbor_devices() -> HashMap<String, Device> {
    let mut devices = HashMap::new();

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
                            latency_ms: None,
                            open_ports: Vec::new(),
                            is_local: false,
                            is_gateway: false,
                        },
                    );
                }
            }
        }
    }

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
                                latency_ms: None,
                                open_ports: Vec::new(),
                                is_local: false,
                                is_gateway: false,
                            },
                        );
                    }
                }
            }
        }
    }

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
                            latency_ms: None,
                            open_ports: Vec::new(),
                            is_local: true,
                            is_gateway: false,
                        },
                    );
                }
            }
        }
    }

    devices
}

fn lookup_hostname_fast(ip_str: &str) -> String {
    if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
        let (tx, rx) = mpsc::channel();
        let _ = thread::spawn(move || {
            let res = dns_lookup::lookup_addr(&ip_addr).unwrap_or_else(|_| "—".to_string());
            let _ = tx.send(res);
        });

        match rx.recv_timeout(Duration::from_millis(80)) {
            Ok(name) => name,
            Err(_) => "—".to_string(),
        }
    } else {
        "—".to_string()
    }
}

fn main() {
    let args = parse_args();
    if args.help {
        print_help();
        return;
    }

    let stop_spinner = Arc::new(AtomicBool::new(false));
    let stop_spinner_clone = stop_spinner.clone();

    let spinner_handle = if !args.json {
        print!("\x1b[?25l");
        Some(thread::spawn(move || {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut idx = 0;
            while !stop_spinner_clone.load(Ordering::Relaxed) {
                let f = frames[idx % frames.len()];
                print!("\r  {C_ACCENT}{f}{C_RESET} {C_MUTED}scanning network...{C_RESET} ");
                use std::io::Write;
                let _ = std::io::stdout().flush();
                idx += 1;
                thread::sleep(Duration::from_millis(50));
            }
            print!("\r\x1b[2K\x1b[?25h");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }))
    } else {
        None
    };

    let subnets = get_local_subnets();
    trigger_arp_sweep(&subnets);

    // 120ms wait ensures even sleeping Wi-Fi / power-saving mobile devices reply
    thread::sleep(Duration::from_millis(120));

    let dev_map = get_neighbor_devices();

    if dev_map.is_empty() {
        if let Some(handle) = spinner_handle {
            stop_spinner.store(true, Ordering::Relaxed);
            let _ = handle.join();
        }
        if args.json {
            println!("[]");
        } else {
            println!("  {C_MUTED}no devices found{C_RESET}\n");
        }
        return;
    }

    let (_, gw_full) = get_dns_and_gateway();
    let gw_ip = gw_full.split_whitespace().next().unwrap_or("").to_string();

    let mut dev_list: Vec<Device> = dev_map.into_values().collect();
    let all_macs: Vec<String> = dev_list.iter().map(|d| d.mac.clone()).collect();

    // Batch resolve all vendors in <2ms + parallel hostnames and latency/ports
    let vendor_map = lookup_vendors_batch(&all_macs);

    dev_list.par_iter_mut().for_each(|d| {
        let is_vpn = d.interface.starts_with("vpn") || d.interface.starts_with("wg") || d.interface.starts_with("tun");
        let raw_vendor = vendor_map
            .get(&d.mac)
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        d.vendor = if is_vpn && (raw_vendor == "—" || raw_vendor == "Unknown") {
            "VPN Tunnel".to_string()
        } else {
            raw_vendor
        };

        let is_gw = d.ip == gw_ip;
        d.is_gateway = is_gw;

        if d.is_local {
            d.hostname = "this machine".to_string();
        } else if is_gw {
            d.hostname = "router".to_string();
        } else {
            d.hostname = lookup_hostname_fast(&d.ip);
        }

        if let Ok(ip4) = d.ip.parse::<Ipv4Addr>() {
            let (lat, ports) = probe_ports_and_latency(ip4, &d.interface, d.is_local, args.ports || args.json);
            d.latency_ms = lat;
            d.open_ports = ports;
        }
    });

    if let Some(handle) = spinner_handle {
        stop_spinner.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    dev_list.sort_by_key(|d| d.ip.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED));

    if args.json {
        if let Ok(json_str) = serde_json::to_string_pretty(&dev_list) {
            println!("{json_str}");
        }
        return;
    }

    println!();
    if args.ports {
        println!(
            "    {C_MUTED}{:<16} {:<18} {:<10} {:<10} {:<24} {:<26} {}{C_RESET}",
            "IP ADDRESS", "MAC ADDRESS", "INTERFACE", "LATENCY", "DEVICE / VENDOR", "HOSTNAME", "OPEN PORTS"
        );
    } else {
        println!(
            "    {C_MUTED}{:<16} {:<18} {:<10} {:<10} {:<24} {}{C_RESET}",
            "IP ADDRESS", "MAC ADDRESS", "INTERFACE", "LATENCY", "DEVICE / VENDOR", "HOSTNAME"
        );
    }

    for d in &dev_list {
        let is_gw = d.is_gateway;
        let is_vpn = d.interface.starts_with("vpn") || d.interface.starts_with("wg") || d.interface.starts_with("tun");
        let icon = if args.no_icons {
            "●"
        } else if is_vpn {
            "󰞀"
        } else {
            get_device_icon(&d.vendor, &d.hostname, d.is_local, is_gw, false)
        };

        let icon_color = if is_gw {
            C_GREEN
        } else if d.is_local {
            C_SUB
        } else {
            C_ACCENT
        };

        let ip_col = if d.is_local || is_gw {
            format!("{C_BOLD}{C_TEXT}{:<16}{C_RESET}", d.ip)
        } else {
            format!("{C_TEXT}{:<16}{C_RESET}", d.ip)
        };
        let mac_col = format!("{C_MUTED}{:<18}{C_RESET}", d.mac);
        let iface_col = format!("{C_SUB}{:<10}{C_RESET}", d.interface);

        let lat_str = format_latency(d.latency_ms);
        let lat_pad = " ".repeat(10usize.saturating_sub(vlen(&lat_str)));
        let lat_col = format!("{lat_str}{lat_pad}");

        let vendor_str = if is_vpn && d.vendor == "—" {
            "VPN Tunnel".to_string()
        } else if d.vendor.len() > 23 {
            format!("{}...", &d.vendor[..20])
        } else {
            d.vendor.clone()
        };
        let vendor_col = if vendor_str == "—" {
            format!("{C_MUTED}{:<24}{C_RESET}", vendor_str)
        } else {
            format!("{C_ACCENT}{:<24}{C_RESET}", vendor_str)
        };

        let host_str = if d.is_local && is_vpn {
            format!("{C_GREEN}● this pc (vpn){C_RESET}")
        } else if d.is_local {
            format!("{C_GREEN}● this pc (lan){C_RESET}")
        } else if is_gw {
            if args.no_icons {
                format!("{C_SUB}[GW] router / gateway{C_RESET}")
            } else {
                format!("{C_SUB}󰒋 router / gateway{C_RESET}")
            }
        } else if d.hostname == "—" {
            format!("{C_MUTED}—{C_RESET}")
        } else {
            format!("{C_TEXT}{}{C_RESET}", d.hostname)
        };

        if args.ports {
            let host_pad = " ".repeat(26usize.saturating_sub(vlen(&host_str)));
            let host_col = format!("{host_str}{host_pad}");

            let ports_col = if d.open_ports.is_empty() {
                format!("{C_MUTED}—{C_RESET}")
            } else {
                let parts: Vec<String> = d
                    .open_ports
                    .iter()
                    .map(|p| {
                        let svc = port_service_name(*p);
                        format!("{C_SUB}{p}{C_MUTED}({svc}){C_RESET}")
                    })
                    .collect();
                parts.join(", ")
            };
            println!("  {icon_color}{icon}{C_RESET} {ip_col} {mac_col} {iface_col} {lat_col} {vendor_col} {host_col} {ports_col}");
        } else {
            println!("  {icon_color}{icon}{C_RESET} {ip_col} {mac_col} {iface_col} {lat_col} {vendor_col} {host_str}");
        }
    }

    println!();
}
