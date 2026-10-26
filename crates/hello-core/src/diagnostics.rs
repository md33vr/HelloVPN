//! «Собрать логи»: вырезание секретов и упаковка в zip.

use crate::model::{Profile, Subscription};
use serde_json::Value;
use std::io::{Cursor, Write};

/// Поля, значения которых всегда заменяются на `***`.
/// Адреса серверов (server/address) вычищаются по значению через [`Scrubber`],
/// чтобы не потерять полезное для отладки (адрес TUN, DNS 1.1.1.1, 127.0.0.1).
const SECRET_KEYS: [&str; 26] = [
    "uuid",
    "id",
    "password",
    "pass",
    "public_key",
    "publicKey",
    "publickey",
    "pbk",
    "short_id",
    "shortId",
    "sid",
    "private_key",
    "secret",
    "auth",
    "auth_str",
    "obfs-password",
    "obfsPassword",
    "raw",
    "url",
    "server_ports",
    "hopPorts",
    "users",
    "hwid",
    "announce",
    "supportUrl",
    "webPageUrl",
];
const EXTRA_KEYS: [&str; 1] = ["external_controller"];

/// Вычищает из текста известные секреты, share-ссылки и UUID.
pub struct Scrubber {
    secrets: Vec<String>,
}

impl Scrubber {
    pub fn new(mut secrets: Vec<String>) -> Self {
        secrets.retain(|s| s.chars().count() >= 4);
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Self { secrets }
    }

    pub fn from_store(profiles: &[Profile], subs: &[Subscription]) -> Self {
        let mut s = vec![];
        for p in profiles {
            for v in [
                &p.uuid,
                &p.password,
                &p.pbk,
                &p.sid,
                &p.obfs_password,
                &p.raw,
                &p.server,
            ] {
                if !v.is_empty() {
                    s.push(v.clone());
                }
            }
        }
        for sub in subs {
            s.push(sub.url.clone());
            for v in [&sub.announce, &sub.support_url, &sub.web_page_url] {
                if !v.is_empty() {
                    s.push(v.clone());
                }
            }
            if let Ok(u) = url::Url::parse(&sub.url) {
                if u.path().len() > 4 {
                    s.push(u.path().to_string());
                }
                if let Some(q) = u.query() {
                    s.push(q.to_string());
                }
            }
        }
        Self::new(s)
    }

    pub fn scrub(&self, text: &str) -> String {
        let mut t = text.to_string();
        for s in &self.secrets {
            if t.contains(s.as_str()) {
                t = t.replace(s.as_str(), "***");
            }
        }
        replace_links(&replace_uuids(&t))
    }
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// Заменяет UUID вида 8-4-4-4-12 на `***`.
fn replace_uuids(t: &str) -> String {
    let b = t.as_bytes();
    let groups = [8usize, 4, 4, 4, 12];
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    'outer: while i < b.len() {
        if i + 36 <= b.len() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let mut j = i;
            let mut ok = true;
            for (gi, g) in groups.iter().enumerate() {
                if !b[j..j + g].iter().all(|c| is_hex(*c)) {
                    ok = false;
                    break;
                }
                j += g;
                if gi < 4 {
                    if b[j] != b'-' {
                        ok = false;
                        break;
                    }
                    j += 1;
                }
            }
            if ok && (j == b.len() || !b[j].is_ascii_alphanumeric()) {
                out.push_str("***");
                i = j;
                continue 'outer;
            }
        }
        let ch = t[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Заменяет share-ссылки (vless://… и т.п.) на `<ссылка ***>`.
fn replace_links(t: &str) -> String {
    const SCHEMES: [&str; 8] = [
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "ssr://",
        "hysteria2://",
        "hy2://",
        "tuic://",
    ];
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    loop {
        let lower = rest.to_ascii_lowercase();
        let found = SCHEMES.iter().filter_map(|s| lower.find(s)).min();
        match found {
            Some(pos) => {
                out.push_str(&rest[..pos]);
                out.push_str("<ссылка ***>");
                let tail = &rest[pos..];
                let end = tail
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .unwrap_or(tail.len());
                rest = &tail[end..];
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    out
}

/// Глубокая копия JSON с замаскированными секретными полями.
pub fn redact(v: &Value, sc: &Scrubber) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(|x| redact(x, sc)).collect()),
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, val) in m {
                let secret = SECRET_KEYS.contains(&k.as_str()) || EXTRA_KEYS.contains(&k.as_str());
                let empty = matches!(val, Value::Null | Value::Bool(_)) || val.as_str() == Some("");
                if secret && !empty {
                    out.insert(k.clone(), Value::String("***".into()));
                } else {
                    out.insert(k.clone(), redact(val, sc));
                }
            }
            Value::Object(out)
        }
        Value::String(s) => Value::String(sc.scrub(s)),
        other => other.clone(),
    }
}

/// Файл для архива.
pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
}

impl Entry {
    pub fn text(name: &str, data: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data: data.into().into_bytes(),
        }
    }
}

/// Упаковывает файлы в zip (deflate, имена в UTF-8).
pub fn make_zip(entries: &[Entry]) -> Result<Vec<u8>, String> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for e in entries {
        w.start_file(e.name.as_str(), opts)
            .map_err(|e| e.to_string())?;
        w.write_all(&e.data).map_err(|e| e.to_string())?;
    }
    Ok(w.finish().map_err(|e| e.to_string())?.into_inner())
}
