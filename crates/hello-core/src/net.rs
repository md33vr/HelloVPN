//! Выбор свободного адреса TUN.

use std::net::Ipv4Addr;

pub const TUN_CANDIDATES: [&str; 5] = [
    "172.19.0.1/30",
    "172.31.233.1/30",
    "10.254.233.1/30",
    "192.168.233.1/30",
    "172.27.111.1/30",
];

/// Адрес и маска существующего интерфейса.
#[derive(Debug, Clone, Copy)]
pub struct IfAddr {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

fn mask_from_prefix(bits: u32) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    }
}

/// Возвращает первый кандидат, не пересекающийся ни с одной существующей подсетью
/// (например, с TUN NekoBox 172.19.0.1/28).
pub fn pick_tun_address(used: &[IfAddr]) -> String {
    for cidr in TUN_CANDIDATES {
        let (ip, bits) = cidr.split_once('/').unwrap();
        let ip: Ipv4Addr = ip.parse().unwrap();
        let mask = mask_from_prefix(bits.parse().unwrap());
        let net = u32::from(ip) & mask;
        let clash = used.iter().any(|u| {
            let common = u32::from(u.mask) & mask; // более короткая маска
            (u32::from(u.ip) & common) == (net & common)
        });
        if !clash {
            return cidr.to_string();
        }
    }
    TUN_CANDIDATES[TUN_CANDIDATES.len() - 1].to_string()
}
