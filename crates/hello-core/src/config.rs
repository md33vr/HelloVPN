//! Сборка конфигов.
//!
//! sing-box ВСЕГДА поднимает TUN и маршрутизирует по процессам (process_name / process_path).
//! Ядро «sing-box»: прокси-outbound(ы) собираются прямо в sing-box (selector для автопереключения).
//! Ядро «xray»: Xray слушает локальный SOCKS5, sing-box отправляет в него трафик выбранных программ.

use crate::model::{AppRule, Profile, Settings};
use crate::parser::is_ip;
use serde_json::{json, Map, Value};

pub const CORE_EXE: [&str; 2] = ["sing-box.exe", "xray.exe"];
pub const DEFAULT_TUN: &str = "172.19.0.1/30";
pub const DEFAULT_TUN6: &str = "fdfe:dcba:9876::1/126";

/// Убирает null и пустые строки из объекта (аналог JSON.stringify с undefined).
fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        match &v {
            Value::Null => {}
            Value::String(s) if s.is_empty() => {}
            _ => {
                m.insert(k.to_string(), v);
            }
        }
    }
    Value::Object(m)
}

fn opt_str(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

/* ----------------------------- sing-box ----------------------------- */

fn sb_tls(p: &Profile) -> Value {
    if p.security.is_empty() || p.security == "none" {
        return Value::Null;
    }
    let sni = if !p.sni.is_empty() {
        p.sni.clone()
    } else if is_ip(&p.server) {
        String::new()
    } else {
        p.server.clone()
    };
    let fp = if !p.fp.is_empty() {
        p.fp.clone()
    } else if p.security == "reality" {
        "chrome".into()
    } else {
        String::new()
    };
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if !sni.is_empty() {
        tls.insert("server_name".into(), json!(sni));
    }
    if p.allow_insecure {
        tls.insert("insecure".into(), json!(true));
    }
    if !p.alpn.is_empty() {
        tls.insert("alpn".into(), json!(p.alpn));
    }
    if !fp.is_empty() {
        tls.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
    }
    if p.security == "reality" {
        tls.insert(
            "reality".into(),
            json!({ "enabled": true, "public_key": p.pbk, "short_id": p.sid }),
        );
    }
    Value::Object(tls)
}

fn sb_transport(p: &Profile) -> Result<Value, String> {
    Ok(match p.network.as_str() {
        "" | "tcp" | "udp" => Value::Null,
        "ws" => {
            let mut path = if p.path.is_empty() {
                "/".to_string()
            } else {
                p.path.clone()
            };
            let mut t = Map::new();
            t.insert("type".into(), json!("ws"));
            // ?ed=2048 в пути — early data через Sec-WebSocket-Protocol
            if let Some(i) = path.find("ed=") {
                let prev = path[..i].chars().last();
                if matches!(prev, Some('?') | Some('&')) {
                    let digits: String = path[i + 3..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if let Ok(n) = digits.parse::<u32>() {
                        t.insert("max_early_data".into(), json!(n));
                        t.insert(
                            "early_data_header_name".into(),
                            json!("Sec-WebSocket-Protocol"),
                        );
                        let end = i + 3 + digits.len();
                        path = format!("{}{}", &path[..i - 1], &path[end..]);
                        if path.ends_with('?') {
                            path.pop();
                        }
                        if path.is_empty() {
                            path = "/".into();
                        }
                    }
                }
            }
            t.insert("path".into(), json!(path));
            if !p.host.is_empty() {
                t.insert("headers".into(), json!({ "Host": p.host }));
            }
            Value::Object(t)
        }
        "grpc" => json!({ "type": "grpc", "service_name": p.service_name }),
        "http" => obj(vec![
            ("type", json!("http")),
            (
                "host",
                if p.host.is_empty() {
                    Value::Null
                } else {
                    json!([p.host])
                },
            ),
            ("path", json!(if p.path.is_empty() { "/" } else { &p.path })),
        ]),
        "httpupgrade" => obj(vec![
            ("type", json!("httpupgrade")),
            ("host", opt_str(&p.host)),
            ("path", json!(if p.path.is_empty() { "/" } else { &p.path })),
        ]),
        "xhttp" => {
            return Err(
                "Транспорт XHTTP поддерживает только Xray — переключите ядро в настройках.".into(),
            )
        }
        other => return Err(format!("Транспорт «{other}» не поддерживается sing-box.")),
    })
}

/// Outbound сервера для sing-box.
pub fn sb_proxy_outbound(p: &Profile, tag: &str) -> Result<Value, String> {
    let base = |typ: &str| -> Vec<(&str, Value)> {
        vec![
            ("type", json!(typ)),
            ("tag", json!(tag)),
            ("server", json!(p.server)),
            ("server_port", json!(p.port)),
        ]
    };
    Ok(match p.protocol.as_str() {
        "vless" => {
            let mut v = base("vless");
            v.push(("uuid", json!(p.uuid)));
            v.push(("packet_encoding", json!("xudp")));
            if !p.flow.is_empty() && p.network == "tcp" {
                v.push(("flow", json!(p.flow)));
            }
            v.push(("tls", sb_tls(p)));
            v.push(("transport", sb_transport(p)?));
            obj(v)
        }
        "vmess" => {
            let mut v = base("vmess");
            v.push(("uuid", json!(p.uuid)));
            v.push((
                "security",
                json!(if p.cipher.is_empty() {
                    "auto"
                } else {
                    &p.cipher
                }),
            ));
            v.push(("alter_id", json!(p.alter_id)));
            v.push(("tls", sb_tls(p)));
            v.push(("transport", sb_transport(p)?));
            obj(v)
        }
        "trojan" => {
            let mut v = base("trojan");
            v.push(("password", json!(p.password)));
            v.push(("tls", sb_tls(p)));
            v.push(("transport", sb_transport(p)?));
            obj(v)
        }
        "shadowsocks" => {
            let mut v = base("shadowsocks");
            v.push(("method", json!(p.method)));
            v.push(("password", json!(p.password)));
            obj(v)
        }
        "hysteria2" => {
            let mut tls = sb_tls(p);
            if tls.is_null() {
                tls = json!({ "enabled": true });
            }
            if tls.get("alpn").is_none() {
                tls["alpn"] = json!(["h3"]);
            }
            let mut v = base("hysteria2");
            if !p.hop_ports.is_empty() {
                v.retain(|(k, _)| *k != "server_port");
                v.push(("server_ports", json!(p.hop_ports)));
            }
            v.push(("password", json!(p.password)));
            v.push(("tls", tls));
            if !p.obfs.is_empty() {
                v.push((
                    "obfs",
                    json!({ "type": p.obfs, "password": p.obfs_password }),
                ));
            }
            obj(v)
        }
        other => return Err(format!("Протокол {other} не поддерживается sing-box")),
    })
}

/// Правила по выбранным приложениям (отдельно по имени и по пути).
fn app_matchers(apps: &[AppRule]) -> Vec<Value> {
    let mut by_name: Vec<String> = vec![];
    let mut by_path: Vec<String> = vec![];
    for a in apps.iter().filter(|a| a.enabled) {
        if a.match_by == "path" {
            if let Some(p) = a.path.as_ref().filter(|p| !p.is_empty()) {
                if !by_path.contains(p) {
                    by_path.push(p.clone());
                }
            }
        } else if !by_name.contains(&a.name) {
            by_name.push(a.name.clone());
        }
    }
    let mut out = vec![];
    if !by_name.is_empty() {
        out.push(json!({ "process_name": by_name }));
    }
    if !by_path.is_empty() {
        out.push(json!({ "process_path": by_path }));
    }
    out
}

fn with(mut v: Value, extra: Value) -> Value {
    if let (Some(m), Value::Object(e)) = (v.as_object_mut(), extra) {
        m.extend(e);
    }
    v
}

fn dns_direct_server(s: &Settings) -> Value {
    let v = s.dns_direct.trim();
    if v.is_empty() || v == "local" {
        json!({ "type": "local", "tag": "dns-direct" })
    } else {
        json!({ "type": "udp", "tag": "dns-direct", "server": v })
    }
}

/// Тег outbound'а сервера в группе автопереключения.
pub fn member_tag(p: &Profile) -> String {
    format!("srv-{}", p.id)
}

/// Серверы для автопереключения: выбранный — первым, затем остальные из той же подписки,
/// кроме исключённых и несовместимых с sing-box.
pub fn auto_group(profile: &Profile, all: &[Profile]) -> Vec<Profile> {
    let mut members = vec![profile.clone()];
    let Some(sub) = profile.sub_id.as_ref() else {
        return members;
    };
    for p in all {
        if p.id == profile.id || p.no_auto || p.sub_id.as_ref() != Some(sub) {
            continue;
        }
        if sb_proxy_outbound(p, "x").is_ok() {
            members.push(p.clone());
        }
    }
    members
}

#[derive(Debug, Clone, Default)]
pub struct ClashApi {
    pub port: u16,
    pub secret: String,
}

#[derive(Debug, Clone, Default)]
pub struct BuildOpts {
    /// Серверы группы автопереключения (если > 1 — собирается selector).
    pub group: Vec<Profile>,
    pub clash_api: Option<ClashApi>,
    pub tun_address: Option<String>,
}

/// Конфиг sing-box.
pub fn build_sing_box(profile: &Profile, s: &Settings, opts: &BuildOpts) -> Result<Value, String> {
    let include = s.mode == "include";
    let via_xray = s.core == "xray";
    let group: Option<&Vec<Profile>> = (!via_xray && opts.group.len() > 1).then_some(&opts.group);

    let mut proxy_outbounds: Vec<Value> = vec![];
    if via_xray {
        proxy_outbounds.push(json!({ "type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": s.socks_port, "version": "5" }));
    } else if let Some(g) = group {
        proxy_outbounds.push(json!({
            "type": "selector",
            "tag": "proxy",
            "outbounds": g.iter().map(member_tag).collect::<Vec<_>>(),
            "default": member_tag(profile),
            "interrupt_exist_connections": true,
        }));
        for p in g {
            proxy_outbounds.push(sb_proxy_outbound(p, &member_tag(p))?);
        }
    } else {
        proxy_outbounds.push(sb_proxy_outbound(profile, "proxy")?);
    }

    let servers: Vec<&Profile> = match group {
        Some(g) => g.iter().collect(),
        None => vec![profile],
    };
    let mut server_domains: Vec<String> = vec![];
    for p in servers {
        if !p.server.is_empty() && !is_ip(&p.server) && !server_domains.contains(&p.server) {
            server_domains.push(p.server.clone());
        }
    }

    let matchers = app_matchers(&s.apps);
    let app_target = if include { "proxy" } else { "direct" };
    let dns_for_apps = if include { "dns-remote" } else { "dns-direct" };
    let dns_final = if include {
        if s.dns_others_via_vpn {
            "dns-remote"
        } else {
            "dns-direct"
        }
    } else {
        "dns-remote"
    };

    let tun4 = opts
        .tun_address
        .clone()
        .unwrap_or_else(|| DEFAULT_TUN.into());
    let address = if s.ipv6 {
        json!([tun4, DEFAULT_TUN6])
    } else {
        json!([tun4])
    };

    let mut dns_rules =
        vec![json!({ "process_name": CORE_EXE, "action": "route", "server": "dns-direct" })];
    if !server_domains.is_empty() {
        dns_rules
            .push(json!({ "domain": server_domains, "action": "route", "server": "dns-direct" }));
    }
    for m in &matchers {
        dns_rules.push(with(
            m.clone(),
            json!({ "action": "route", "server": dns_for_apps }),
        ));
    }

    let mut route_rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        // Трафик самих ядер (подключение к VPN-серверу) — всегда напрямую
        json!({ "process_name": CORE_EXE, "action": "route", "outbound": "direct" }),
        json!({ "ip_is_private": true, "action": "route", "outbound": "direct" }),
    ];
    for m in &matchers {
        route_rules.push(with(
            m.clone(),
            json!({ "action": "route", "outbound": app_target }),
        ));
    }

    let mut outbounds = proxy_outbounds;
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));

    let mut config = json!({
        "log": { "level": if s.log_level.is_empty() { "info" } else { &s.log_level }, "timestamp": true },
        "dns": {
            "servers": [
                { "type": "https", "tag": "dns-remote", "server": if s.dns_remote.is_empty() { "1.1.1.1" } else { &s.dns_remote }, "detour": "proxy" },
                dns_direct_server(s),
            ],
            "rules": dns_rules,
            "final": dns_final,
            "strategy": if s.ipv6 { "prefer_ipv4" } else { "ipv4_only" },
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "Hello",
            "address": address,
            "mtu": 9000,
            "auto_route": true,
            "strict_route": s.strict_route,
            "stack": if s.tun_stack.is_empty() { "mixed" } else { &s.tun_stack },
        }],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": true,
            "find_process": true,
            "default_domain_resolver": "dns-direct",
            "rules": route_rules,
            // include: всё остальное напрямую; exclude: всё остальное через VPN
            "final": if include { "direct" } else { "proxy" },
        },
    });
    if let Some(api) = &opts.clash_api {
        config["experimental"] = json!({
            "clash_api": { "external_controller": format!("127.0.0.1:{}", api.port), "secret": api.secret }
        });
    }
    Ok(config)
}

/* ------------------------------- Xray ------------------------------- */

fn xray_stream(p: &Profile) -> Value {
    let mut network = match p.network.as_str() {
        "http" => "xhttp".to_string(),
        "" => "tcp".to_string(),
        n => n.to_string(),
    };
    if network == "tcp" {
        network = "raw".into();
    }
    let sni = if !p.sni.is_empty() {
        p.sni.clone()
    } else if is_ip(&p.server) {
        String::new()
    } else {
        p.server.clone()
    };
    let fp = if p.fp.is_empty() {
        "chrome".to_string()
    } else {
        p.fp.clone()
    };
    let mut s = Map::new();
    s.insert("network".into(), json!(network));
    match p.security.as_str() {
        "tls" => {
            let mut t = Map::new();
            if !sni.is_empty() {
                t.insert("serverName".into(), json!(sni));
            }
            t.insert("fingerprint".into(), json!(fp));
            if !p.alpn.is_empty() {
                t.insert("alpn".into(), json!(p.alpn));
            }
            if p.allow_insecure {
                t.insert("allowInsecure".into(), json!(true));
            }
            s.insert("security".into(), json!("tls"));
            s.insert("tlsSettings".into(), Value::Object(t));
        }
        "reality" => {
            s.insert("security".into(), json!("reality"));
            s.insert("realitySettings".into(), json!({
                "serverName": sni, "fingerprint": fp, "publicKey": p.pbk, "shortId": p.sid, "spiderX": p.spx,
            }));
        }
        _ => {
            s.insert("security".into(), json!("none"));
        }
    }
    let path = if p.path.is_empty() { "/" } else { &p.path };
    match network.as_str() {
        "ws" => {
            s.insert(
                "wsSettings".into(),
                obj(vec![("path", json!(path)), ("host", opt_str(&p.host))]),
            );
        }
        "grpc" => {
            s.insert(
                "grpcSettings".into(),
                json!({ "serviceName": p.service_name, "multiMode": p.mode == "multi" }),
            );
        }
        "httpupgrade" => {
            s.insert(
                "httpupgradeSettings".into(),
                obj(vec![("path", json!(path)), ("host", opt_str(&p.host))]),
            );
        }
        "xhttp" => {
            s.insert(
                "xhttpSettings".into(),
                obj(vec![
                    ("path", json!(path)),
                    ("host", opt_str(&p.host)),
                    (
                        "mode",
                        json!(if p.mode.is_empty() { "auto" } else { &p.mode }),
                    ),
                ]),
            );
        }
        "raw" if p.header_type == "http" => {
            let headers = if p.host.is_empty() {
                json!({})
            } else {
                json!({ "Host": [p.host] })
            };
            s.insert("rawSettings".into(), json!({ "header": { "type": "http", "request": { "path": [path], "headers": headers } } }));
        }
        _ => {}
    }
    Value::Object(s)
}

fn xray_outbound(p: &Profile) -> Result<Value, String> {
    Ok(match p.protocol.as_str() {
        "vless" => json!({
            "tag": "proxy", "protocol": "vless",
            "settings": { "vnext": [{ "address": p.server, "port": p.port,
                "users": [obj(vec![("id", json!(p.uuid)), ("encryption", json!("none")), ("flow", opt_str(&p.flow))])] }] },
            "streamSettings": xray_stream(p),
        }),
        "vmess" => json!({
            "tag": "proxy", "protocol": "vmess",
            "settings": { "vnext": [{ "address": p.server, "port": p.port,
                "users": [{ "id": p.uuid, "alterId": p.alter_id, "security": if p.cipher.is_empty() { "auto" } else { &p.cipher } }] }] },
            "streamSettings": xray_stream(p),
        }),
        "trojan" => json!({
            "tag": "proxy", "protocol": "trojan",
            "settings": { "servers": [{ "address": p.server, "port": p.port, "password": p.password }] },
            "streamSettings": xray_stream(p),
        }),
        "shadowsocks" => json!({
            "tag": "proxy", "protocol": "shadowsocks",
            "settings": { "servers": [{ "address": p.server, "port": p.port, "method": p.method, "password": p.password }] },
        }),
        "hysteria2" => return Err("Для Hysteria2 выберите ядро sing-box в настройках.".into()),
        other => return Err(format!("Протокол {other} не поддерживается Xray")),
    })
}

/// Конфиг Xray (SOCKS-вход для sing-box).
pub fn build_xray(profile: &Profile, s: &Settings) -> Result<Value, String> {
    Ok(json!({
        "log": { "loglevel": if s.log_level == "debug" { "debug" } else { "warning" } },
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": s.socks_port, "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
            // sing-box отдаёт IP; сниффинг возвращает домен, чтобы сервер резолвил его сам
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] },
        }],
        "outbounds": [xray_outbound(profile)?, { "tag": "direct", "protocol": "freedom" }],
    }))
}
