use std::collections::{HashMap, HashSet};
use std::fs;

pub const C_ACCENT: &str = "\x1b[35m";   // Magenta / Purple (Primary accent)
pub const C_SUB: &str = "\x1b[36m";      // Cyan / Blue (Secondary accent)
pub const C_TEXT: &str = "\x1b[97m";     // Bright White (High contrast primary text)
pub const C_MUTED: &str = "\x1b[90m";    // Slate Gray (Keys, MAC)
pub const C_GREEN: &str = "\x1b[32m";    // Green (UP, Gateway, Local)
pub const C_DIM: &str = "\x1b[2;37m";    // Dim (Borders, separators)
pub const C_RESET: &str = "\x1b[0m";     // Reset
pub const C_BOLD: &str = "\x1b[1m";      // Bold

pub fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut in_esc = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_esc = true;
        } else if in_esc {
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn vlen(s: &str) -> usize {
    strip_ansi(s).chars().count()
}

pub fn clean_vendor_name(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("routerboard") || lower.contains("mikrotik") {
        "MikroTik Router".to_string()
    } else if lower.contains("tp-link") {
        "TP-Link Router".to_string()
    } else if lower.contains("keenetic") {
        "Keenetic Router".to_string()
    } else if lower.contains("asus") {
        "ASUS Device".to_string()
    } else if lower.contains("netgear") {
        "Netgear Router".to_string()
    } else if lower.contains("d-link") {
        "D-Link Device".to_string()
    } else if lower.contains("ubiquiti") {
        "Ubiquiti UniFi".to_string()
    } else if lower.contains("cisco") {
        "Cisco Device".to_string()
    } else if lower.contains("huawei") {
        "Huawei Device".to_string()
    } else if lower.contains("zte") {
        "ZTE Device".to_string()
    } else if lower.contains("sagemcom") {
        "Sagemcom Router".to_string()
    } else if lower.contains("raspberry") {
        "Raspberry Pi".to_string()
    } else if lower.contains("micro-star") {
        "MSI PC".to_string()
    } else if lower.contains("apple") {
        "Apple Device".to_string()
    } else if lower.contains("intel") {
        "Intel Device".to_string()
    } else if lower.contains("samsung") {
        "Samsung Device".to_string()
    } else if lower.contains("xiaomi") {
        "Xiaomi Device".to_string()
    } else {
        raw.to_string()
    }
}

// Ultra-fast targeted OUI lookup that scans only for active MAC prefixes (<2ms)
pub fn lookup_vendors_batch(macs: &[String]) -> HashMap<String, String> {
    let mut results = HashMap::new();
    let mut needed_prefixes = HashSet::new();

    for mac in macs {
        if mac.is_empty() || mac == "—" {
            results.insert(mac.clone(), "—".to_string());
            continue;
        }
        let clean = mac.trim().to_uppercase();
        let parts: Vec<&str> = clean.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(b0) = u8::from_str_radix(parts[0], 16) {
                if (b0 & 2) != 0 {
                    results.insert(mac.clone(), "Randomized / Private".to_string());
                    continue;
                }
            }
            let dash_prefix = format!("{}-{}-{}", parts[0], parts[1], parts[2]);
            needed_prefixes.insert(dash_prefix);
        } else {
            results.insert(mac.clone(), "Unknown".to_string());
        }
    }

    if !needed_prefixes.is_empty() {
        let paths = [
            "/usr/share/hwdata/oui.txt",
            "/var/lib/ieee-data/oui.txt",
            "/usr/share/nmap/nmap-mac-prefixes",
        ];

        let mut prefix_to_vendor = HashMap::new();
        for path in paths {
            if let Ok(bytes) = fs::read(path) {
                for line in bytes.split(|&b| b == b'\n') {
                    if line.len() > 18 && line[2] == b'-' && line[5] == b'-' {
                        if let Ok(prefix_str) = std::str::from_utf8(&line[0..8]) {
                            let p_upper = prefix_str.to_uppercase();
                            if needed_prefixes.contains(&p_upper) {
                                if let Ok(full_line) = std::str::from_utf8(line) {
                                    if let Some(idx) = full_line.find("(hex)") {
                                        let vendor = full_line[idx + 5..].trim();
                                        prefix_to_vendor.insert(p_upper, clean_vendor_name(vendor));
                                        if prefix_to_vendor.len() == needed_prefixes.len() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if !prefix_to_vendor.is_empty() {
                    break;
                }
            }
        }

        for mac in macs {
            if results.contains_key(mac) {
                continue;
            }
            let clean = mac.trim().to_uppercase();
            let parts: Vec<&str> = clean.split(':').collect();
            if parts.len() >= 3 {
                let dash_prefix = format!("{}-{}-{}", parts[0], parts[1], parts[2]);
                if let Some(v) = prefix_to_vendor.get(&dash_prefix) {
                    results.insert(mac.clone(), v.clone());
                } else {
                    results.insert(mac.clone(), "Unknown".to_string());
                }
            }
        }
    }

    results
}

pub fn get_device_icon(vendor: &str, hostname: &str, is_local: bool, is_gateway: bool) -> &'static str {
    let v_lower = vendor.to_lowercase();
    let h_lower = hostname.to_lowercase();

    if is_gateway || v_lower.contains("router") {
        "󱂇"
    } else if v_lower.contains("raspberry") || h_lower.contains("pi") {
        "󰐿"
    } else if v_lower.contains("apple") || h_lower.contains("macbook") || h_lower.contains("iphone") {
        "󰀵"
    } else if is_local || v_lower.contains("pc") || v_lower.contains("msi") {
        "󰌢"
    } else if v_lower.contains("private") || v_lower.contains("randomized") {
        "󰤨"
    } else {
        "󰒋"
    }
}

pub fn get_session_badge() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());
    let host = fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string());
    format!("@{user}::{host}")
}

pub fn get_dns_and_gateway() -> (String, String) {
    let mut dns_str = "—".to_string();
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        let mut servers = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    servers.push(parts[1]);
                }
            }
        }
        if !servers.is_empty() {
            dns_str = servers.join(", ");
        }
    }

    let mut gw_str = "—".to_string();
    if let Ok(content) = fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "00000000" {
                let gw_hex = fields[2];
                if gw_hex.len() == 8 {
                    let b0 = u8::from_str_radix(&gw_hex[0..2], 16).unwrap_or(0);
                    let b1 = u8::from_str_radix(&gw_hex[2..4], 16).unwrap_or(0);
                    let b2 = u8::from_str_radix(&gw_hex[4..6], 16).unwrap_or(0);
                    let b3 = u8::from_str_radix(&gw_hex[6..8], 16).unwrap_or(0);
                    gw_str = format!("{b3}.{b2}.{b1}.{b0} ({})", fields[0]);
                }
                break;
            }
        }
    }

    (dns_str, gw_str)
}
