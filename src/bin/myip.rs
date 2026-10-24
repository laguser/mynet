use mynet::*;
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Deserialize, Default)]
struct IpApiResponse {
    ip: Option<String>,
    city: Option<String>,
    country_name: Option<String>,
    org: Option<String>,
}

#[derive(Deserialize, Default)]
struct IpWhoisResponse {
    ip: Option<String>,
    city: Option<String>,
    country: Option<String>,
    connection: Option<IpWhoisConn>,
}

#[derive(Deserialize, Default)]
struct IpWhoisConn {
    isp: Option<String>,
}

// Returns (ip, location, isp)
fn fetch_public_ip() -> (String, String, String) {
    let (tx, rx) = mpsc::channel();

    let tx1 = tx.clone();
    thread::spawn(move || {
        if let Ok(resp) = ureq::get("https://ipwho.is/")
            .timeout(Duration::from_millis(900))
            .call()
        {
            if let Ok(info) = resp.into_json::<IpWhoisResponse>() {
                if let Some(ip) = info.ip {
                    let mut locs = Vec::new();
                    if let Some(city) = info.city {
                        locs.push(city);
                    }
                    if let Some(country) = info.country {
                        locs.push(country);
                    }
                    let isp = info
                        .connection
                        .and_then(|c| c.isp)
                        .unwrap_or_default();
                    let _ = tx1.send((ip, locs.join(", "), isp));
                }
            }
        }
    });

    let tx2 = tx.clone();
    thread::spawn(move || {
        if let Ok(resp) = ureq::get("https://ipapi.co/json/")
            .set("User-Agent", "curl/8.0")
            .timeout(Duration::from_millis(900))
            .call()
        {
            if let Ok(info) = resp.into_json::<IpApiResponse>() {
                if let Some(ip) = info.ip {
                    let mut locs = Vec::new();
                    if let Some(city) = info.city {
                        locs.push(city);
                    }
                    if let Some(country) = info.country_name {
                        locs.push(country);
                    }
                    let isp = info.org.unwrap_or_default();
                    let _ = tx2.send((ip, locs.join(", "), isp));
                }
            }
        }
    });

    drop(tx);

    if let Ok(res) = rx.recv_timeout(Duration::from_millis(950)) {
        return res;
    }

    ("Unavailable".to_string(), String::new(), String::new())
}

struct IfaceDetail {
    name: String,
    kind: &'static str,
    mac: String,
    ipv4: String,
    ipv6: String,
    status: String,
}

fn get_interfaces() -> Vec<IfaceDetail> {
    let mut results = Vec::new();
    let interfaces = pnet_datalink::interfaces();

    for iface in interfaces {
        if iface.is_loopback() {
            continue;
        }

        let mut ipv4s = Vec::new();
        let mut ipv6s = Vec::new();

        for ip in &iface.ips {
            match ip.ip() {
                std::net::IpAddr::V4(v4) => ipv4s.push(v4.to_string()),
                std::net::IpAddr::V6(v6) => {
                    if !v6.is_loopback() {
                        ipv6s.push(v6.to_string());
                    }
                }
            }
        }

        let status = if iface.is_up() { "UP" } else { "DOWN" };
        let mac = iface.mac.map(|m| m.to_string()).unwrap_or_else(|| "—".to_string());

        let ipv4_str = if ipv4s.is_empty() { "—".to_string() } else { ipv4s.join(", ") };
        let ipv6_str = if ipv6s.is_empty() {
            "—".to_string()
        } else if ipv6s.len() > 1 {
            format!("{} (+{})", ipv6s[0], ipv6s.len() - 1)
        } else {
            ipv6s[0].clone()
        };

        let kind = if iface.name.starts_with("wl") {
            "Wi-Fi"
        } else if iface.name.starts_with("vpn") || iface.name.starts_with("wg") || iface.name.starts_with("tun") {
            "VPN"
        } else if iface.name.starts_with("en") || iface.name.starts_with("eth") {
            "LAN"
        } else {
            "Net"
        };

        results.push(IfaceDetail {
            name: iface.name,
            kind,
            mac,
            ipv4: ipv4_str,
            ipv6: ipv6_str,
            status: status.to_string(),
        });
    }

    results
}

struct KeyVal {
    icon: &'static str,
    key: String,
    value: String,
}

fn render_row(k: &KeyVal, key_width: usize) -> String {
    let k_len = k.key.chars().count();
    let pad = key_width.saturating_sub(k_len);
    let padding = " ".repeat(pad);
    let icon = k.icon;
    let key = &k.key;
    let val = &k.value;
    if icon.is_empty() {
        format!("  {C_MUTED}{key}{padding}{C_RESET}  {C_TEXT}{val}{C_RESET}")
    } else {
        format!("{C_ACCENT}{icon}{C_RESET} {C_MUTED}{key}{padding}{C_RESET}  {C_TEXT}{val}{C_RESET}")
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
            print!("\r  {C_ACCENT}{f}{C_RESET} {C_MUTED}querying network...{C_RESET} ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            idx += 1;
            thread::sleep(Duration::from_millis(50));
        }
        print!("\r\x1b[2K\x1b[?25h");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    });

    let ifaces_handle = thread::spawn(get_interfaces);
    let route_handle = thread::spawn(get_dns_and_gateway);
    let (pub_ip, pub_loc, pub_isp) = fetch_public_ip();

    let ifaces = ifaces_handle.join().unwrap_or_default();
    let (dns, gateway) = route_handle.join().unwrap_or_else(|_| ("—".to_string(), "—".to_string()));

    stop_spinner.store(true, Ordering::Relaxed);
    let _ = spinner_handle.join();

    let mut left_items = vec![
        KeyVal {
            icon: "󰩠",
            key: "ᴘᴜʙʟɪᴄ ɪᴘ".to_string(),
            value: format!("{C_BOLD}{pub_ip}{C_RESET}"),
        },
    ];

    if !pub_loc.is_empty() {
        left_items.push(KeyVal {
            icon: "󰍹",
            key: "ʟᴏᴄᴀᴛɪᴏɴ".to_string(),
            value: pub_loc,
        });
    }

    if !pub_isp.is_empty() {
        let isp_short = if pub_isp.len() > 28 {
            format!("{}...", &pub_isp[..25])
        } else {
            pub_isp
        };
        left_items.push(KeyVal {
            icon: "󰒋",
            key: "ᴘʀᴏᴠɪᴅᴇʀ".to_string(),
            value: isp_short,
        });
    }

    let gw_clean = if let Some((ip, dev)) = gateway.split_once(' ') {
        format!("{ip} {C_MUTED}{dev}{C_RESET}")
    } else {
        gateway
    };

    left_items.push(KeyVal {
        icon: "󰌘",
        key: "ɢᴀᴛᴇᴡᴀʏ".to_string(),
        value: gw_clean,
    });
    left_items.push(KeyVal {
        icon: "󰒍",
        key: "ᴅɴs".to_string(),
        value: dns,
    });

    let mut right_items = Vec::new();
    for iface in ifaces {
        let icon = if iface.kind == "Wi-Fi" {
            "󰖩"
        } else if iface.kind == "VPN" {
            "󰞀"
        } else {
            "󰈀"
        };

        let status_badge = if iface.status == "UP" {
            format!("{C_GREEN}● ᴜᴘ{C_RESET}")
        } else {
            format!("{C_MUTED}○ ᴅᴏᴡɴ{C_RESET}")
        };

        let label = format!("{} ({})", iface.name, iface.kind);
        let lan_val = format!("{C_BOLD}{}{C_RESET}  {status_badge}", iface.ipv4);
        right_items.push(KeyVal {
            icon,
            key: label,
            value: lan_val,
        });

        let has_mac = iface.mac != "—";
        let has_ipv6 = iface.ipv6 != "—";

        if has_mac {
            let branch = if has_ipv6 { "├─" } else { "╰─" };
            right_items.push(KeyVal {
                icon: "",
                key: format!("{branch} ᴍᴀᴄ"),
                value: format!("{C_MUTED}{}{C_RESET}", iface.mac),
            });
        }
        if has_ipv6 {
            right_items.push(KeyVal {
                icon: "",
                key: "╰─ ɪᴘᴠ6".to_string(),
                value: format!("{C_MUTED}{}{C_RESET}", iface.ipv6),
            });
        }
    }

    let left_lines: Vec<String> = left_items.iter().map(|it| render_row(it, 10)).collect();
    let right_lines: Vec<String> = right_items.iter().map(|it| render_row(it, 13)).collect();

    let left_max_w = left_lines.iter().map(|l| vlen(l)).max().unwrap_or(28);
    let max_rows = left_lines.len().max(right_lines.len());

    println!();
    let gap = "   │   ";
    let left_hdr = format!("  {C_SUB}󰖟 ɪɴᴛᴇʀɴᴇᴛ & ʀᴏᴜᴛɪɴɢ{C_RESET}");
    let left_hdr_pad = " ".repeat(left_max_w.saturating_sub(vlen(&left_hdr) - 2));
    let right_hdr = format!("{C_SUB}󰛳 ʟᴏᴄᴀʟ ɪɴᴛᴇʀꜰᴀᴄᴇs{C_RESET}");
    println!("{left_hdr}{left_hdr_pad}{C_MUTED}{gap}{C_RESET}{right_hdr}");

    for r in 0..max_rows {
        let l_str = left_lines.get(r).map(|s| s.as_str()).unwrap_or("");
        let l_pad = " ".repeat(left_max_w.saturating_sub(vlen(l_str)));
        let r_str = right_lines.get(r).map(|s| s.as_str()).unwrap_or("");
        println!("  {l_str}{l_pad}{C_MUTED}{gap}{C_RESET}{r_str}");
    }
    println!();
}
