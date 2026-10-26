//! Разбор share-ссылок (vless/vmess/trojan/ss/hysteria2) и подписок.

use crate::model::{new_id, Profile, UserInfo};
use base64::Engine;
use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use url::Url;

/// Декодирует base64 в любом варианте: стандартный/URL-safe, с паддингом и без, с переносами.
pub fn b64decode(s: &str) -> Option<String> {
    let cleaned: String = s
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn strip_brackets(h: &str) -> String {
    h.trim_start_matches('[').trim_end_matches(']').to_string()
}

fn norm_network(t: &str) -> String {
    match t.to_ascii_lowercase().as_str() {
        "" | "raw" | "tcp" => "tcp".into(),
        "splithttp" => "xhttp".into(),
        "h2" => "http".into(),
        other => other.into(),
    }
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn truthy(v: Option<&String>) -> bool {
    matches!(v.map(|s| s.as_str()), Some("1") | Some("true"))
}

fn query(u: &Url) -> HashMap<String, String> {
    u.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn get(q: &HashMap<String, String>, k: &str) -> String {
    q.get(k).cloned().unwrap_or_default()
}

fn fragment_name(u: &Url) -> String {
    u.fragment().map(decode).unwrap_or_default()
}

/// vless://uuid@host:port?...#name и trojan://password@host:port?...#name
fn parse_vless_trojan(link: &str, protocol: &str) -> Result<Profile, String> {
    let u = Url::parse(link).map_err(|e| format!("неверная ссылка: {e}"))?;
    let q = query(&u);
    let network = norm_network(&get(&q, "type"));
    let host = strip_brackets(u.host_str().unwrap_or_default());
    let default_sec = if protocol == "trojan" { "tls" } else { "none" };
    let security = q
        .get("security")
        .cloned()
        .unwrap_or_else(|| default_sec.into())
        .to_ascii_lowercase();
    let mut p = Profile {
        protocol: protocol.into(),
        name: {
            let n = fragment_name(&u);
            if n.is_empty() {
                host.clone()
            } else {
                n
            }
        },
        server: host,
        port: u.port().unwrap_or(443),
        security,
        sni: q
            .get("sni")
            .or_else(|| q.get("peer"))
            .cloned()
            .unwrap_or_default(),
        fp: get(&q, "fp"),
        alpn: split_list(&get(&q, "alpn")),
        pbk: get(&q, "pbk"),
        sid: get(&q, "sid"),
        spx: get(&q, "spx"),
        allow_insecure: truthy(q.get("allowInsecure")) || truthy(q.get("insecure")),
        path: q.get("path").cloned().unwrap_or_else(|| {
            if network == "xhttp" {
                "/".into()
            } else {
                String::new()
            }
        }),
        host: get(&q, "host"),
        service_name: get(&q, "serviceName"),
        mode: get(&q, "mode"),
        header_type: get(&q, "headerType"),
        network,
        ..Default::default()
    };
    let user = decode(u.username());
    if protocol == "vless" {
        p.uuid = user;
        p.flow = get(&q, "flow");
    } else {
        p.password = user;
    }
    Ok(p)
}

/// vmess://base64(JSON)
fn parse_vmess(link: &str) -> Result<Profile, String> {
    let body = b64decode(&link["vmess://".len()..]).ok_or("vmess: не base64")?;
    let j: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("vmess: {e}"))?;
    let s = |k: &str| -> String {
        match &j[k] {
            serde_json::Value::String(v) => v.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    };
    let network = norm_network(&s("net"));
    let grpc = network == "grpc";
    Ok(Profile {
        protocol: "vmess".into(),
        name: if s("ps").is_empty() {
            s("add")
        } else {
            s("ps")
        },
        server: s("add"),
        port: s("port").parse().unwrap_or(0),
        uuid: s("id"),
        alter_id: s("aid").parse().unwrap_or(0),
        cipher: if s("scy").is_empty() {
            "auto".into()
        } else {
            s("scy")
        },
        security: if s("tls") == "tls" {
            "tls".into()
        } else {
            "none".into()
        },
        sni: s("sni"),
        fp: s("fp"),
        alpn: split_list(&s("alpn")),
        allow_insecure: matches!(s("allowInsecure").as_str(), "1" | "true"),
        path: if grpc { String::new() } else { s("path") },
        host: s("host"),
        service_name: if grpc { s("path") } else { String::new() },
        mode: if grpc { s("type") } else { String::new() },
        header_type: if network == "tcp" {
            s("type")
        } else {
            String::new()
        },
        network,
        ..Default::default()
    })
}

/// ss://base64(method:pass)@host:port#name | ss://base64(method:pass@host:port)#name | ss://method:pass@host:port
fn parse_shadowsocks(link: &str) -> Result<Profile, String> {
    let mut body = link["ss://".len()..].to_string();
    let mut name = String::new();
    if let Some(i) = body.find('#') {
        name = decode(&body[i + 1..]);
        body.truncate(i);
    }
    let body = body
        .split('?')
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();

    let (userinfo, hostport) = if let Some(at) = body.rfind('@') {
        let ui = &body[..at];
        let dec = decode(ui);
        let ui = if dec.contains(':') {
            dec
        } else {
            b64decode(ui).ok_or("ss: не base64")?
        };
        (ui, body[at + 1..].to_string())
    } else {
        let full = b64decode(&body).ok_or("ss: не base64")?;
        let at = full.rfind('@').ok_or("ss: нет адреса")?;
        (full[..at].to_string(), full[at + 1..].to_string())
    };
    let colon = userinfo.find(':').ok_or("ss: нет пароля")?;
    let (method, password) = (
        userinfo[..colon].to_string(),
        userinfo[colon + 1..].to_string(),
    );

    let (host, port) =
        split_host_port(&hostport).ok_or("Не удалось разобрать адрес Shadowsocks")?;
    Ok(Profile {
        protocol: "shadowsocks".into(),
        name: if name.is_empty() { host.clone() } else { name },
        server: host,
        port,
        method,
        password,
        security: "none".into(),
        network: "tcp".into(),
        ..Default::default()
    })
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    let i = s.rfind(':')?;
    let host = strip_brackets(&s[..i]);
    let port = s[i + 1..].parse().ok()?;
    if host.is_empty() {
        None
    } else {
        Some((host, port))
    }
}

/// hysteria2://auth@host:port[,port-range]/?sni=..&obfs=salamander&obfs-password=..&insecure=1#name
fn parse_hysteria2(link: &str) -> Result<Profile, String> {
    let mut normalized = link.to_string();
    if normalized.to_ascii_lowercase().starts_with("hy2://") {
        normalized = format!("hysteria2://{}", &normalized[6..]);
    }
    // Мультипорт (443,20000-30000) не разбирается URL — вытаскиваем вручную
    let mut ports = String::new();
    if let Some(at) = normalized.find('@') {
        let rest = &normalized[at + 1..];
        let host_end = if rest.starts_with('[') {
            rest.find(']').map(|i| i + 1).unwrap_or(0)
        } else {
            rest.find(':').unwrap_or(rest.len())
        };
        let after = &rest[host_end..];
        if let Some(stripped) = after.strip_prefix(':') {
            let end = stripped
                .find(|c: char| !(c.is_ascii_digit() || c == ',' || c == '-'))
                .unwrap_or(stripped.len());
            ports = stripped[..end].to_string();
            let first: String = ports.split([',', '-']).next().unwrap_or("").to_string();
            normalized = format!(
                "{}{}:{}{}",
                &normalized[..at + 1],
                &rest[..host_end],
                first,
                &stripped[end..]
            );
        }
    }
    let u = Url::parse(&normalized).map_err(|e| format!("неверная ссылка: {e}"))?;
    let q = query(&u);
    let hop_ports = if ports.contains(',') || ports.contains('-') {
        ports.split(',').map(|r| r.replace('-', ":")).collect()
    } else {
        vec![]
    };
    let host = strip_brackets(u.host_str().unwrap_or_default());
    Ok(Profile {
        protocol: "hysteria2".into(),
        name: {
            let n = fragment_name(&u);
            if n.is_empty() {
                host.clone()
            } else {
                n
            }
        },
        server: host,
        port: u.port().unwrap_or(443),
        hop_ports,
        password: decode(u.username()),
        security: "tls".into(),
        sni: get(&q, "sni"),
        alpn: split_list(&get(&q, "alpn")),
        allow_insecure: truthy(q.get("insecure")),
        obfs: get(&q, "obfs"),
        obfs_password: get(&q, "obfs-password"),
        network: "udp".into(),
        ..Default::default()
    })
}

/// Разбирает одну ссылку.
pub fn parse_link(raw: &str) -> Result<Profile, String> {
    let link = raw.trim();
    let scheme = link.split("://").next().unwrap_or("").to_ascii_lowercase();
    let mut p = match scheme.as_str() {
        "vless" => parse_vless_trojan(link, "vless")?,
        "trojan" => parse_vless_trojan(link, "trojan")?,
        "vmess" => parse_vmess(link)?,
        "ss" => parse_shadowsocks(link)?,
        "hysteria2" | "hy2" => parse_hysteria2(link)?,
        _ => return Err(format!("Неподдерживаемый протокол: {scheme}")),
    };
    if p.server.is_empty() || p.port == 0 {
        return Err("В ссылке нет адреса или порта сервера".into());
    }
    p.id = new_id();
    p.raw = link.to_string();
    Ok(p)
}

/// Результат разбора текста: серверы и ошибки по строкам.
#[derive(Debug, Default)]
pub struct ParseResult {
    pub profiles: Vec<Profile>,
    pub errors: Vec<String>,
}

/// Разбирает текст: одна ссылка, несколько ссылок или base64-подписка.
pub fn parse_many(text: &str) -> ParseResult {
    // JSON-конфиг Xray/sing-box (так панели часто отвечают Happ'у)
    if crate::jsonsub::looks_like_json(text) {
        return match crate::jsonsub::parse_json(text) {
            Ok((profiles, errors)) => ParseResult { profiles, errors },
            Err(e) => ParseResult {
                profiles: vec![],
                errors: vec![e],
            },
        };
    }
    let mut body = text.trim().to_string();
    if !body.contains("://") {
        if let Some(d) = b64decode(&body) {
            body = d;
        }
    }
    let mut res = ParseResult::default();
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || !l.contains("://") {
            continue;
        }
        match parse_link(l) {
            Ok(p) => res.profiles.push(p),
            Err(e) => {
                let short: String = l.chars().take(40).collect();
                res.errors.push(format!("{short}…: {e}"));
            }
        }
    }
    res
}

/// Заголовок subscription-userinfo: upload=..; download=..; total=..; expire=..
pub fn parse_user_info(header: &str) -> Option<UserInfo> {
    let mut info = UserInfo::default();
    let mut any = false;
    for part in header.split(';') {
        let mut kv = part.splitn(2, '=');
        let (Some(k), Some(v)) = (kv.next(), kv.next()) else {
            continue;
        };
        let Ok(n) = v.trim().parse::<f64>() else {
            continue;
        };
        let n = n as u64;
        match k.trim() {
            "upload" => info.upload = Some(n),
            "download" => info.download = Some(n),
            "total" => info.total = Some(n),
            "expire" => info.expire = Some(n),
            _ => continue,
        }
        any = true;
    }
    any.then_some(info)
}

/// Текстовый заголовок подписки (profile-title, announce): может быть «base64:…».
pub fn parse_profile_title(header: &str) -> String {
    let h = header.trim();
    match h.strip_prefix("base64:") {
        Some(b) => b64decode(b).unwrap_or_default(),
        None => percent_decode_str(h).decode_utf8_lossy().into_owned(),
    }
    .trim()
    .to_string()
}

pub fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}
