//! «Собрать логи»: zip на рабочий стол, секреты вырезаны.

use crate::app::AppState;
use crate::platform::{interfaces_report, is_admin, run_text};
use hello_core::diagnostics::{make_zip, redact, Entry, Scrubber};
use serde_json::{json, Value};
use std::path::PathBuf;

pub async fn collect(st: &AppState) -> Result<PathBuf, String> {
    let (data, store_path) = {
        let s = st.store.lock().unwrap();
        (s.data.clone(), s.file().to_path_buf())
    };
    let sc = Scrubber::from_store(&data.profiles, &data.subscriptions);
    let mut files = vec![];

    // 1. Журнал
    let journal = st
        .logs
        .all()
        .iter()
        .map(|e| {
            let t = chrono::DateTime::from_timestamp_millis(e.ts)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            format!("[{t} {}] {}", e.source, e.line)
        })
        .collect::<Vec<_>>()
        .join("\n");
    files.push(Entry::text("journal.log", sc.scrub(&journal)));

    // 2. Сгенерированные конфиги
    for f in ["sing-box.json", "xray.json"] {
        if let Ok(raw) = std::fs::read_to_string(st.core.work_dir.join(f)) {
            let body = match serde_json::from_str::<Value>(&raw) {
                Ok(v) => serde_json::to_string_pretty(&redact(&v, &sc)).unwrap(),
                Err(_) => sc.scrub(&raw),
            };
            files.push(Entry::text(&format!("configs/{f}"), body));
        }
    }

    // 3. Настройки и серверы без реквизитов
    let settings = serde_json::to_value(&data.settings).unwrap();
    files.push(Entry::text(
        "settings.json",
        serde_json::to_string_pretty(&redact(&settings, &sc)).unwrap(),
    ));
    let active = data.settings.active_profile_id.clone();
    let servers: Vec<Value> = data
        .profiles
        .iter()
        .map(|p| {
            json!({
                "name": sc.scrub(&p.name), "protocol": p.protocol, "network": p.network, "security": p.security,
                "port": p.port, "flow": p.flow, "fp": p.fp, "alpn": p.alpn,
                "fromSubscription": p.sub_id.is_some(), "excludedFromAuto": p.no_auto,
                "active": active.as_deref() == Some(p.id.as_str()),
            })
        })
        .collect();
    files.push(Entry::text(
        "servers.json",
        serde_json::to_string_pretty(&servers).unwrap(),
    ));
    let subs: Vec<Value> = data
        .subscriptions
        .iter()
        .map(|s| {
            json!({
                "name": sc.scrub(&s.name),
                "servers": data.profiles.iter().filter(|p| p.sub_id.as_deref() == Some(s.id.as_str())).count(),
                "updatedAt": s.updated_at, "userInfo": s.user_info,
            })
        })
        .collect();
    files.push(Entry::text(
        "subscriptions.json",
        serde_json::to_string_pretty(&subs).unwrap(),
    ));

    // 4. История автопереключений
    let history = st.core.history.lock().unwrap().clone();
    files.push(Entry::text(
        "autoswitch-history.json",
        sc.scrub(&serde_json::to_string_pretty(&history).unwrap()),
    ));

    // 5. Система
    let sb_ver = match st.core.find_bin("sing-box.exe") {
        Some(p) => run_text(&p.to_string_lossy(), &["version"]).await,
        None => "нет".into(),
    };
    let xr_ver = match st.core.find_bin("xray.exe") {
        Some(p) => run_text(&p.to_string_lossy(), &["version"]).await,
        None => "не скачан".into(),
    };
    let (os, routes) = if cfg!(windows) {
        (
            run_text("cmd", &["/c", "ver"]).await,
            run_text("route", &["print", "-4"]).await,
        )
    } else {
        (std::env::consts::OS.to_string(), String::new())
    };
    let system = [
        format!(
            "Приложение: Hello! {} (Tauri {})",
            crate::app::display_version(),
            tauri::VERSION
        ),
        format!("ОС: {os} {}", std::env::consts::ARCH),
        format!(
            "Права администратора: {}",
            if is_admin().await { "да" } else { "нет" }
        ),
        format!("Состояние VPN: {:?}", st.core.state()),
        format!("Настройки: {}", store_path.display()),
        format!("Собрано: {}", chrono::Local::now().to_rfc2822()),
        String::new(),
        "== sing-box version ==".into(),
        sb_ver,
        String::new(),
        "== xray version ==".into(),
        xr_ver,
        String::new(),
        "== Сетевые интерфейсы ==".into(),
        interfaces_report(),
        String::new(),
        "== Таблица маршрутов IPv4 ==".into(),
        routes,
    ]
    .join("\n");
    files.push(Entry::text("system.txt", sc.scrub(&system)));
    files.push(Entry::text(
        "README.txt",
        "Архив диагностики Hello!.\r\nUUID, пароли, ключи, адреса серверов и ссылки подписок заменены на ***.\r\nЕго можно спокойно отправить для разбора проблемы.\r\n",
    ));

    let zip = make_zip(&files)?;
    let dir = dirs::desktop_dir().unwrap_or_else(std::env::temp_dir);
    let name = format!(
        "Hello-logs-{}.zip",
        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
    );
    let out = dir.join(name);
    std::fs::write(&out, zip).map_err(|e| e.to_string())?;
    Ok(out)
}
