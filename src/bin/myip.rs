use mynet::*;
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Deserialize, Default)]
struct PublicIPInfo {
    ip: Option<String>,
    city: Option<String>,
    country_name: Option<String>,
    org: Option<String>,
}

fn fetch_public_ip() -> (String, String) {
    if let Ok(resp) = ureq::get("https://ipapi.co/json/")
        .set("User-Agent", "curl/8.0")
        .timeout(Duration::from_millis(2000))
        .call()
    {
        if let Ok(info) = resp.into_json::<PublicIPInfo>() {
            if let Some(ip) = info.ip {
                let mut locs = Vec::new();
                if let Some(city) = info.city {
                    locs.push(city);
                }
                if let Some(country) = info.country_name {
                    locs.push(country);
                }
                if let Some(org) = info.org {
                    locs.push(org);
                }
                return (ip, locs.join(", "));
            }
        }
    }

    if let Ok(resp) = ureq::get("https://api.ipify.org")
        .timeout(Duration::from_millis(1500))
        .call()
    {
        if let Ok(text) = resp.into_string() {
            let ip = text.trim().to_string();
            if !ip.is_empty() {
                return (ip, String::new());
            }
        }
    }

    ("Unavailable".to_string(), String::new())
}

struct IfaceDetail {
    name: String,
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

        results.push(IfaceDetail {
            name: iface.name,
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
    key: &'static str,
    value: String,
}

fn render_row(k: &KeyVal, key_width: usize) -> String {
    let pad = key_width.saturating_sub(k.key.len());
    let padding = " ".repeat(pad);
    format!(
        "{}{}{} {}{}{}{} {}{}{}",
        C_ACCENT, k.icon, C_RESET,
        C_MUTED, k.key, padding, C_RESET,
        C_TEXT, k.value, C_RESET
    )
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
            print!("\r  {C_ACCENT}{f}{C_RESET} {C_MUTED}Gathering network telemetry...{C_RESET} ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            idx += 1;
            thread::sleep(Duration::from_millis(80));
        }
        print!("\r\x1b[2K\x1b[?25h");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    });

    let (pub_ip, pub_extra) = fetch_public_ip();
    let ifaces = get_interfaces();
    let (dns, gateway) = get_dns_and_gateway();

    stop_spinner.store(true, Ordering::Relaxed);
    let _ = spinner_handle.join();

    let badge = get_session_badge();

    let mut left_items = vec![
        KeyVal { icon: "󰩠", key: "wan ip", value: pub_ip },
    ];

    if !pub_extra.is_empty() {
        let loc = if pub_extra.len() > 34 {
            format!("{}...", &pub_extra[..31])
        } else {
            pub_extra
        };
        left_items.push(KeyVal { icon: "󰍹", key: "location", value: loc });
    }

    left_items.push(KeyVal { icon: "󰌘", key: "gateway", value: gateway });
    left_items.push(KeyVal { icon: "󰒍", key: "dns", value: dns });
    left_items.push(KeyVal { icon: "", key: "session", value: format!("{C_SUB}{badge}{C_RESET}") });

    let mut right_items = Vec::new();
    for iface in ifaces {
        let icon = if iface.name.starts_with("wl") {
            "󰖩"
        } else if iface.name.starts_with("vpn") || iface.name.starts_with("wg") || iface.name.starts_with("tun") {
            "󰞀"
        } else {
            "󰈀"
        };

        let status_badge = if iface.status == "UP" {
            format!("{C_GREEN}● UP{C_RESET}")
        } else {
            format!("{C_MUTED}○ DOWN{C_RESET}")
        };

        let lan_val = format!("{} {}", iface.ipv4, status_badge);
        right_items.push(KeyVal { icon, key: Box::leak(iface.name.into_boxed_str()), value: lan_val });
        if iface.mac != "—" {
            right_items.push(KeyVal { icon: "󰇄", key: "  mac", value: iface.mac });
        }
        if iface.ipv6 != "—" {
            right_items.push(KeyVal { icon: "󰩠", key: "  ipv6", value: iface.ipv6 });
        }
    }

    let left_lines: Vec<String> = left_items.iter().map(|it| render_row(it, 9)).collect();
    let right_lines: Vec<String> = right_items.iter().map(|it| render_row(it, 9)).collect();

    let left_max_w = left_lines.iter().map(|l| vlen(l)).max().unwrap_or(30);
    let max_rows = left_lines.len().max(right_lines.len());
    let total_w = left_max_w + 6 + 40;

    println!();
    println!("  {C_ACCENT}󰛳{C_RESET}  {C_BOLD}NETWORK{C_RESET}  {C_SUB}[{badge}]{C_RESET}");
    println!("  {C_DIM}{}{C_RESET}", "─".repeat(total_w));

    let gap = "      ";
    for r in 0..max_rows {
        let l_str = left_lines.get(r).map(|s| s.as_str()).unwrap_or("");
        let l_pad = " ".repeat(left_max_w.saturating_sub(vlen(l_str)));
        let r_str = right_lines.get(r).map(|s| s.as_str()).unwrap_or("");
        println!("  {l_str}{l_pad}{gap}{r_str}");
    }
    println!();
}
