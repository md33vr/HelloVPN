//! Подписки в виде JSON-конфигов: Xray (один конфиг или массив, как отдают Happ'у
//! панели Remnawave/Marzban) и sing-box (`outbounds`). Из них достаём серверы.

use crate::model::{new_id, Profile};
use serde_json::Value;

fn s(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn port(v: &Value) -> u16 {
    match v {
        Value::Number(n) => n.as_u64().unwrap_or(0) as u16,
        Value::String(x) => x.parse().unwrap_or(0),
        _ => 0,
    }
}

fn list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(s).filter(|x| !x.is_empty()).collect(),
        Value::String(x) => x
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => vec![],
    }
}

fn truthy(v: &Value) -> bool {
    matches!(v, Value::Bool(true)) || matches!(s(v).as_str(), "1" | "true")
}

fn norm_network(t: &str) -> String {
    match t.to_ascii_lowercase().as_str() {
        "" | "raw" | "tcp" => "tcp".into(),
        "splithttp" => "xhttp".into(),
        "h2" => "http".into(),
        other => other.into(),
    }
}

/// Похоже ли на JSON-подписку.
pub fn looks_like_json(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// Серверы из JSON (Xray или sing-box). Ошибки — по отдельным outbound'ам.
pub fn parse_json(text: &str) -> Result<(Vec<Profile>, Vec<String>), String> {
    let v: Value = serde_json::from_str(text.trim()).map_err(|e| format!("JSON: {e}"))?;
    let configs: Vec<&Value> = match &v {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    let mut profiles = vec![];
    let mut errors = vec![];
    for cfg in configs {
        let remarks = s(&cfg["remarks"]);
        let Some(outs) = cfg["outbounds"].as_array() else {
            continue;
        };
        let mut found: Vec<Profile> = vec![];
        for o in outs {
            let r = if o.get("protocol").is_some() {
                xray_outbound(o)
            } else if o.get("type").is_some() {
                singbox_outbound(o)
            } else {
                continue;
            };
            match r {
                Some(Ok(p)) => found.push(p),
                Some(Err(e)) => errors.push(e),
                None => {}
            }
        }
        // У Xray-конфига имя сервера — remarks; если прокси внутри несколько, добавим тег.
        let many = found.len() > 1;
        for mut p in found {
            if !remarks.is_empty() {
                p.name = if many && !p.name.is_empty() {
                    format!("{remarks} · {}", p.name)
                } else {
                    remarks.clone()
                };
            }
            if p.name.is_empty() {
                p.name = p.server.clone();
            }
            p.id = new_id();
            p.raw = fingerprint(&p);
            profiles.push(p);
        }
    }
    Ok((profiles, errors))
}

/// Устойчивый идентификатор сервера из JSON (для сохранения выбора при обновлении подписки).
fn fingerprint(p: &Profile) -> String {
    let secret = if p.uuid.is_empty() {
        &p.password
    } else {
        &p.uuid
    };
    format!(
        "json:{}://{}@{}:{}/{}#{}",
        p.protocol, secret, p.server, p.port, p.network, p.name
    )
}

/* --------------------------------- Xray --------------------------------- */

fn xray_outbound(o: &Value) -> Option<Result<Profile, String>> {
    let proto = s(&o["protocol"]).to_ascii_lowercase();
    let tag = s(&o["tag"]);
    let mut p = Profile {
        name: tag.clone(),
        ..Default::default()
    };
    let st = &o["settings"];
    match proto.as_str() {
        "vless" | "vmess" => {
            let vn = &st["vnext"][0];
            let user = &vn["users"][0];
            p.protocol = proto.clone();
            p.server = s(&vn["address"]);
            p.port = port(&vn["port"]);
            p.uuid = s(&user["id"]);
            if proto == "vless" {
                p.flow = s(&user["flow"]);
            } else {
                p.alter_id = port(&user["alterId"]) as u32;
                let c = s(&user["security"]);
                p.cipher = if c.is_empty() { "auto".into() } else { c };
            }
            // Новый формат Xray: адрес прямо в settings
            if p.server.is_empty() {
                p.server = s(&st["address"]);
                p.port = port(&st["port"]);
                p.uuid = s(&st["id"]);
                p.flow = s(&st["flow"]);
            }
        }
        "trojan" | "shadowsocks" => {
            let sv = &st["servers"][0];
            p.protocol = proto.clone();
            p.server = s(&sv["address"]);
            p.port = port(&sv["port"]);
            p.password = s(&sv["password"]);
            p.method = s(&sv["method"]);
            if p.server.is_empty() {
                p.server = s(&st["address"]);
                p.port = port(&st["port"]);
                p.password = s(&st["password"]);
                p.method = s(&st["method"]);
            }
        }
        // freedom, blackhole, dns, loopback и т. п. — не серверы
        _ => return None,
    }
    if p.server.is_empty() || p.port == 0 {
        return Some(Err(format!("{tag}: нет адреса или порта")));
    }

    let ss = &o["streamSettings"];
    p.network = norm_network(&s(&ss["network"]));
    let sec = s(&ss["security"]).to_ascii_lowercase();
    p.security = match sec.as_str() {
        "" => {
            if proto == "trojan" {
                "tls".into()
            } else {
                "none".into()
            }
        }
        other => other.into(),
    };
    if p.security == "reality" {
        let r = &ss["realitySettings"];
        p.sni = s(&r["serverName"]);
        p.fp = s(&r["fingerprint"]);
        p.pbk = s(&r["publicKey"]);
        p.sid = s(&r["shortId"]);
        p.spx = s(&r["spiderX"]);
    } else if p.security == "tls" {
        let t = &ss["tlsSettings"];
        p.sni = s(&t["serverName"]);
        p.fp = s(&t["fingerprint"]);
        p.alpn = list(&t["alpn"]);
        p.allow_insecure = truthy(&t["allowInsecure"]);
    }
    match p.network.as_str() {
        "ws" => {
            let w = &ss["wsSettings"];
            p.path = s(&w["path"]);
            p.host = s(&w["host"]);
            if p.host.is_empty() {
                p.host = s(&w["headers"]["Host"]);
            }
        }
        "grpc" => {
            let g = &ss["grpcSettings"];
            p.service_name = s(&g["serviceName"]);
            if truthy(&g["multiMode"]) {
                p.mode = "multi".into();
            }
        }
        "httpupgrade" => {
            let h = &ss["httpupgradeSettings"];
            p.path = s(&h["path"]);
            p.host = s(&h["host"]);
        }
        "xhttp" => {
            let h = if ss["xhttpSettings"].is_object() {
                &ss["xhttpSettings"]
            } else {
                &ss["splithttpSettings"]
            };
            p.path = s(&h["path"]);
            if p.path.is_empty() {
                p.path = "/".into();
            }
            p.host = s(&h["host"]);
            p.mode = s(&h["mode"]);
        }
        "http" => {
            let h = &ss["httpSettings"];
            p.path = s(&h["path"]);
            p.host = list(&h["host"]).join(",");
        }
        "tcp" => {
            let t = &ss["tcpSettings"]["header"];
            let ht = s(&t["type"]);
            if ht == "http" {
                p.header_type = ht;
                p.path = list(&t["request"]["path"]).join(",");
                p.host = list(&t["request"]["headers"]["Host"]).join(",");
            }
        }
        _ => {}
    }
    Some(Ok(p))
}

/* -------------------------------- sing-box ------------------------------- */

fn singbox_outbound(o: &Value) -> Option<Result<Profile, String>> {
    let t = s(&o["type"]).to_ascii_lowercase();
    let tag = s(&o["tag"]);
    let mut p = Profile {
        name: tag.clone(),
        server: s(&o["server"]),
        port: port(&o["server_port"]),
        ..Default::default()
    };
    match t.as_str() {
        "vless" => {
            p.protocol = "vless".into();
            p.uuid = s(&o["uuid"]);
            p.flow = s(&o["flow"]);
        }
        "vmess" => {
            p.protocol = "vmess".into();
            p.uuid = s(&o["uuid"]);
            p.alter_id = port(&o["alter_id"]) as u32;
            let c = s(&o["security"]);
            p.cipher = if c.is_empty() { "auto".into() } else { c };
        }
        "trojan" => {
            p.protocol = "trojan".into();
            p.password = s(&o["password"]);
        }
        "shadowsocks" => {
            p.protocol = "shadowsocks".into();
            p.method = s(&o["method"]);
            p.password = s(&o["password"]);
        }
        "hysteria2" => {
            p.protocol = "hysteria2".into();
            p.password = s(&o["password"]);
            p.hop_ports = list(&o["server_ports"]);
            if s(&o["obfs"]["type"]) == "salamander" {
                p.obfs = "salamander".into();
                p.obfs_password = s(&o["obfs"]["password"]);
            }
        }
        // direct, block, dns, selector, urltest — не серверы
        _ => return None,
    }
    if p.server.is_empty() || p.port == 0 {
        return Some(Err(format!("{tag}: нет адреса или порта")));
    }
    let tls = &o["tls"];
    if truthy(&tls["enabled"]) {
        p.sni = s(&tls["server_name"]);
        p.alpn = list(&tls["alpn"]);
        p.allow_insecure = truthy(&tls["insecure"]);
        p.fp = s(&tls["utls"]["fingerprint"]);
        if truthy(&tls["reality"]["enabled"]) {
            p.security = "reality".into();
            p.pbk = s(&tls["reality"]["public_key"]);
            p.sid = s(&tls["reality"]["short_id"]);
        } else {
            p.security = "tls".into();
        }
    } else {
        p.security = if t == "hysteria2" { "tls" } else { "none" }.into();
    }
    let tr = &o["transport"];
    p.network = if t == "hysteria2" {
        "udp".into()
    } else {
        norm_network(&s(&tr["type"]))
    };
    match p.network.as_str() {
        "ws" | "httpupgrade" => {
            p.path = s(&tr["path"]);
            p.host = s(&tr["host"]);
            if p.host.is_empty() {
                p.host = s(&tr["headers"]["Host"]);
            }
        }
        "grpc" => p.service_name = s(&tr["service_name"]),
        "http" => {
            p.path = s(&tr["path"]);
            p.host = list(&tr["host"]).join(",");
        }
        _ => {}
    }
    Some(Ok(p))
}
