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
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len() as libc::socklen_t,
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

        if let Ok(socket) = UdpSocket::bind(SocketAddrV4::new(sn.local_ip, 0)) {
            let _ = socket.set_nonblocking(true);
            bind_socket_to_interface(&socket, &sn.iface_name);
            let _ = socket.set_broadcast(true);

            // Multicast & Broadcast discovery signals (mDNS + NetBIOS + UDP echo)
            let bcast = Ipv4Addr::from(net_u32 | !mask_u32);
            let _ = socket.send_to(b"", SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
            let _ = socket.send_to(b"", SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 55555));
            let _ = socket.send_to(b"", SocketAddrV4::new(bcast, 137));
            let _ = socket.send_to(b"", SocketAddrV4::new(bcast, 55555));

            // Multi-vector probes (mDNS + NetBIOS + high UDP) to awaken all types of devices
            for i in 1..host_count {
                let target_ip = Ipv4Addr::from(net_u32 + i);
                let _ = socket.send_to(b"", SocketAddrV4::new(target_ip, 5353));
                let _ = socket.send_to(b"", SocketAddrV4::new(target_ip, 137));
                let _ = socket.send_to(b"", SocketAddrV4::new(target_ip, 55555));
                if i % 32 == 0 {
                    thread::sleep(Duration::from_millis(4));
                }
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
                            is_local: false,
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
                                is_local: false,
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
                            is_local: true,
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
    let stop_spinner = Arc::new(AtomicBool::new(false));
    let stop_spinner_clone = stop_spinner.clone();

    print!("\x1b[?25l");
    let spinner_handle = thread::spawn(move || {
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
    });

    let subnets = get_local_subnets();
    trigger_arp_sweep(&subnets);

    // 100ms wait ensures even sleeping Wi-Fi / power-saving mobile devices reply
    thread::sleep(Duration::from_millis(100));

    let dev_map = get_neighbor_devices();

    if dev_map.is_empty() {
        stop_spinner.store(true, Ordering::Relaxed);
        let _ = spinner_handle.join();
        println!("  {C_MUTED}no devices found{C_RESET}\n");
        return;
    }

    let (_, gw_full) = get_dns_and_gateway();
    let gw_ip = gw_full.split_whitespace().next().unwrap_or("").to_string();

    let mut dev_list: Vec<Device> = dev_map.into_values().collect();
    let all_macs: Vec<String> = dev_list.iter().map(|d| d.mac.clone()).collect();

    // Batch resolve all vendors in <2ms + parallel hostnames in <=80ms
    let vendor_map = lookup_vendors_batch(&all_macs);

    dev_list.par_iter_mut().for_each(|d| {
        d.vendor = vendor_map
            .get(&d.mac)
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        if d.is_local {
            d.hostname = "this machine".to_string();
        } else if d.ip == gw_ip {
            d.hostname = "router".to_string();
        } else {
            d.hostname = lookup_hostname_fast(&d.ip);
        }
    });

    stop_spinner.store(true, Ordering::Relaxed);
    let _ = spinner_handle.join();

    dev_list.sort_by_key(|d| d.ip.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED));

    println!();
    println!(
        "    {C_MUTED}{:<16} {:<18} {:<10} {:<24} {}{C_RESET}",
        "ɪᴘ ᴀᴅᴅʀᴇss", "ᴍᴀᴄ ᴀᴅᴅʀᴇss", "ɪɴᴛᴇʀꜰᴀᴄᴇ", "ᴅᴇᴠɪᴄᴇ / ᴠᴇɴᴅᴏʀ", "ʜᴏsᴛɴᴀᴍᴇ"
    );

    for d in &dev_list {
        let is_gw = d.ip == gw_ip;
        let is_vpn = d.interface.starts_with("vpn") || d.interface.starts_with("wg") || d.interface.starts_with("tun");
        let icon = if is_vpn {
            "󰞀"
        } else {
            get_device_icon(&d.vendor, &d.hostname, d.is_local, is_gw)
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

        let host_col = if d.is_local && is_vpn {
            format!("{C_GREEN}● ᴛʜɪs ᴘᴄ (ᴠᴘɴ){C_RESET}")
        } else if d.is_local {
            format!("{C_GREEN}● ᴛʜɪs ᴘᴄ (ʟᴀɴ){C_RESET}")
        } else if is_gw {
            format!("{C_SUB}󰒋 ʀᴏᴜᴛᴇʀ / ɢᴀᴛᴇᴡᴀʏ{C_RESET}")
        } else if d.hostname == "—" {
            format!("{C_MUTED}—{C_RESET}")
        } else {
            format!("{C_TEXT}{}{C_RESET}", d.hostname)
        };

        println!("  {icon_color}{icon}{C_RESET} {ip_col} {mac_col} {iface_col} {vendor_col} {host_col}");
    }

    println!();
}
