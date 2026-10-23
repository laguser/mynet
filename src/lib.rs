use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::sync::OnceLock;

pub const C_ACCENT: &str = "\x1b[35m";   // Magenta / Purple (Primary accent)
pub const C_SUB: &str = "\x1b[36m";      // Cyan / Blue (Secondary accent)
pub const C_TEXT: &str = "\x1b[97m";     // Bright White (High contrast primary text)
pub const C_MUTED: &str = "\x1b[90m";    // Slate Gray (Keys, MAC)
pub const C_GREEN: &str = "\x1b[32m";    // Green (UP, Gateway, Local)
pub const C_DIM: &str = "\x1b[2;37m";    // Dim (Borders, separators)
pub const C_RESET: &str = "\x1b[0m";     // Reset
pub const C_BOLD: &str = "\x1b[1m";      // Bold

static OUI_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

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

pub fn load_oui_map() -> &'static HashMap<String, String> {
    OUI_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        let paths = [
            "/usr/share/hwdata/oui.txt",
            "/var/lib/ieee-data/oui.txt",
            "/usr/share/nmap/nmap-mac-prefixes",
        ];

        for path in paths {
            if let Ok(file) = fs::File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    if line.contains("(hex)") {
                        let parts: Vec<&str> = line.split("(hex)").collect();
                        if parts.len() >= 2 {
                            let prefix = parts[0].trim().replace('-', ":").to_uppercase();
                            let vendor = parts[1].trim().to_string();
                            map.insert(prefix, vendor);
                        }
                    }
                }
                if !map.is_empty() {
                    break;
                }
            }
        }
        map
    })
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

pub fn lookup_vendor(mac: &str) -> String {
    if mac.is_empty() || mac == "—" {
        return "—".to_string();
    }

    let clean = mac.trim().to_uppercase();
    let parts: Vec<&str> = clean.split(':').collect();
    if parts.len() >= 3 {
        let oui_prefix = format!("{}:{}:{}", parts[0], parts[1], parts[2]);
        let map = load_oui_map();
        if let Some(v) = map.get(&oui_prefix) {
            return clean_vendor_name(v);
        }

        if let Ok(b0) = u8::from_str_radix(parts[0], 16) {
            if (b0 & 2) != 0 {
                return "Randomized / Private".to_string();
            }
        }
    }

    "Unknown".to_string()
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
