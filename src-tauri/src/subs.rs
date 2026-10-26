//! Загрузка и обновление подписок.

use crate::store::Store;
use hello_core::model::{Subscription, UserInfo};
use hello_core::parser::{parse_many, parse_profile_title, parse_user_info};
use std::time::Duration;

pub struct Fetched {
    pub text: String,
    pub title: String,
    pub user_info: Option<UserInfo>,
    pub announce: String,
    pub support_url: String,
    pub web_page_url: String,
    /// С каким User-Agent удалось загрузить.
    pub ua: String,
}

/// Как представляться серверу подписки.
pub struct FetchOpts {
    /// Свой User-Agent из настроек (если задан — пробуется первым).
    pub custom_ua: String,
    /// User-Agent Hello! по умолчанию.
    pub default_ua: String,
    /// Идентификатор устройства для панелей с лимитом устройств.
    pub hwid: String,
    /// User-Agent, сработавший для этой подписки в прошлый раз.
    pub preferred_ua: String,
}

/// Версия Happ, под которую представляемся: многие провайдеры отдают серверы
/// только известным клиентам и отвечают ошибкой всем остальным.
const HAPP_UA: &str = "Happ/3.12.0";

struct Attempt {
    ua: String,
    device_headers: bool,
}

fn attempts(o: &FetchOpts) -> Vec<Attempt> {
    let mut v: Vec<Attempt> = vec![];
    if !o.custom_ua.trim().is_empty() {
        v.push(Attempt {
            ua: o.custom_ua.trim().into(),
            device_headers: true,
        });
    }
    v.push(Attempt {
        ua: o.default_ua.clone(),
        device_headers: false,
    });
    v.push(Attempt {
        ua: HAPP_UA.into(),
        device_headers: true,
    });
    v.push(Attempt {
        ua: "v2rayN/7.15.4".into(),
        device_headers: false,
    });
    v.push(Attempt {
        ua: "sing-box 1.12.0".into(),
        device_headers: false,
    });
    // Сначала — то, что сработало в прошлый раз, без повторов.
    if let Some(i) = v.iter().position(|a| a.ua == o.preferred_ua) {
        let a = v.remove(i);
        v.insert(0, a);
    }
    v
}

/// Скачивает подписку. Если сервер отказал или прислал не то (HTML-страницу,
/// пустой ответ), повторяет, представляясь распространёнными клиентами.
/// Возвращает результат и заметки для журнала (без секретов).
pub async fn fetch(url: &str, o: &FetchOpts) -> (Result<Fetched, String>, Vec<String>) {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let mut notes = vec![];
    let mut first_err: Option<String> = None;
    for a in attempts(o) {
        match fetch_once(url, &a, &o.hwid).await {
            Ok((mut f, status, ctype)) => {
                let parsed = parse_many(&f.text);
                notes.push(format!(
                    "подписка {host}: UA «{}» → HTTP {status}, {ctype}, {} байт, серверов: {}",
                    a.ua,
                    f.text.len(),
                    parsed.profiles.len()
                ));
                if !parsed.profiles.is_empty() {
                    f.ua = a.ua.clone();
                    return (Ok(f), notes);
                }
                first_err.get_or_insert_with(|| {
                    if f.text.trim_start().starts_with('<') {
                        "Сервер подписки прислал веб-страницу вместо списка серверов".into()
                    } else {
                        parsed
                            .errors
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "В подписке не найдено ни одного сервера".into())
                    }
                });
            }
            Err(e) => {
                notes.push(format!("подписка {host}: UA «{}» → {e}", a.ua));
                first_err.get_or_insert(e);
            }
        }
    }
    (
        Err(first_err.unwrap_or_else(|| "Не удалось загрузить подписку".into())),
        notes,
    )
}

async fn fetch_once(url: &str, a: &Attempt, hwid: &str) -> Result<(Fetched, u16, String), String> {
    let http = reqwest::Client::builder()
        .user_agent(a.ua.as_str())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = http.get(url).header("Accept", "*/*");
    if a.device_headers && !hwid.is_empty() {
        req = req
            .header("x-hwid", hwid)
            .header("x-device-os", "Windows")
            .header("x-ver-os", "10")
            .header("x-device-model", "Hello!");
    }
    let res = req.send().await.map_err(|e| {
        if e.is_timeout() {
            "сервер подписки не ответил за 15 с".to_string()
        } else if e.is_connect() {
            "не удалось подключиться к серверу подписки".to_string()
        } else {
            e.to_string()
        }
    })?;
    let status = res.status().as_u16();
    if !res.status().is_success() {
        return Err(format!("HTTP {status}"));
    }
    let h = |k: &str| {
        res.headers()
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap_or_default()
    };
    let text_header = |k: &str| {
        let v = h(k);
        if v.is_empty() {
            v
        } else {
            parse_profile_title(&v)
        }
    };
    let ctype = h("content-type");
    let title = text_header("profile-title");
    let announce = text_header("announce");
    let support_url = only_link(&h("support-url"));
    let web_page_url = only_link(&h("profile-web-page-url"));
    let user_info = parse_user_info(&h("subscription-userinfo"));
    let text = res.text().await.map_err(|e| e.to_string())?;
    Ok((
        Fetched {
            text,
            title,
            user_info,
            announce,
            support_url,
            web_page_url,
            ua: String::new(),
        },
        status,
        if ctype.is_empty() {
            "без типа".into()
        } else {
            ctype
        },
    ))
}

/// Пропускает только http(s) и t.me-ссылки: их потом открывает Проводник.
fn only_link(v: &str) -> String {
    let v = v.trim();
    let l = v.to_ascii_lowercase();
    if (l.starts_with("https://") || l.starts_with("http://")) && !v.contains(['"', ' ', '<', '>'])
    {
        v.to_string()
    } else {
        String::new()
    }
}

/// Подставляет свежие серверы подписки в хранилище, сохраняя выбранный сервер
/// и исключения из автовыбора (по совпадению ссылки, затем имени).
pub fn apply(store: &mut Store, sub_id: &str, f: Fetched) -> Result<(usize, Vec<String>), String> {
    let parsed = parse_many(&f.text);
    if parsed.profiles.is_empty() {
        return Err("В подписке не найдено ни одного сервера".into());
    }
    let d = &mut store.data;
    let prev: Vec<_> = d
        .profiles
        .iter()
        .filter(|p| p.sub_id.as_deref() == Some(sub_id))
        .cloned()
        .collect();
    let prev_active = d.active_profile().cloned();
    d.profiles.retain(|p| p.sub_id.as_deref() != Some(sub_id));
    let mut new = parsed.profiles;
    for p in &mut new {
        p.sub_id = Some(sub_id.to_string());
        let old = prev
            .iter()
            .find(|o| o.raw == p.raw)
            .or_else(|| prev.iter().find(|o| o.name == p.name));
        if let Some(o) = old {
            p.no_auto = o.no_auto;
            if prev_active.as_ref().is_some_and(|a| a.id == o.id) {
                d.settings.active_profile_id = Some(p.id.clone());
            }
        }
    }
    let first_id = new[0].id.clone();
    let count = new.len();
    d.profiles.extend(new);
    if prev_active
        .as_ref()
        .is_some_and(|a| a.sub_id.as_deref() == Some(sub_id))
        && d.active_profile().is_none()
    {
        d.settings.active_profile_id = Some(first_id);
    }
    if let Some(s) = d.subscriptions.iter_mut().find(|s| s.id == sub_id) {
        if !f.title.is_empty() {
            s.name = f.title;
        }
        s.user_info = f.user_info;
        s.announce = f.announce;
        s.support_url = f.support_url;
        s.web_page_url = f.web_page_url;
        s.client_ua = f.ua;
        s.updated_at = Some(crate::logs::now_ms() as u64);
    }
    store.save();
    Ok((count, parsed.errors))
}

pub fn new_subscription(url: &str) -> Subscription {
    let name = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string());
    Subscription {
        id: hello_core::model::new_id(),
        name,
        url: url.to_string(),
        ..Default::default()
    }
}
