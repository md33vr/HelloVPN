//! Состояние приложения, команды интерфейса, трей и окно.

use crate::core::{tcp_ping, Core, SwitchEntry, VpnState};
use crate::logs::Logs;
use crate::platform;
use crate::store::{data_dir, Store};
use hello_core::model::{AppRule, Profile};
use hello_core::parser::parse_many;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_notification::NotificationExt;

const VERSION_JSON: &str = include_str!("../../version.json");

/// «0.2a-b1»
pub fn display_version() -> String {
    let v: Value = serde_json::from_str(VERSION_JSON).unwrap_or_default();
    let d = v["displayVersion"].as_str().unwrap_or("0.2a");
    match v["buildNumber"].as_u64() {
        Some(b) => format!("{d}-b{b}"),
        None => d.to_string(),
    }
}

pub struct AppState {
    pub store: Mutex<Store>,
    pub logs: Arc<Logs>,
    pub core: Arc<Core>,
    tray: Mutex<Option<TrayIcon>>,
}

type Res<T> = Result<T, String>;

impl AppState {
    fn public(&self, admin: Option<bool>) -> Value {
        let s = self.store.lock().unwrap();
        let mut v = json!({
            "app": { "name": "Hello!", "version": display_version() },
            "settings": s.data.settings,
            "profiles": s.data.profiles,
            "subscriptions": s.data.subscriptions,
            "core": { "state": self.core.state(), "auto": self.core.is_auto() },
            "cores": { "singbox": self.core.find_bin("sing-box.exe").is_some(), "xray": true },
        });
        if let Some(a) = admin {
            v["admin"] = json!(a);
        }
        v
    }

    fn snapshot(&self) -> (Option<Profile>, hello_core::model::Settings, Vec<Profile>) {
        let s = self.store.lock().unwrap();
        (
            s.active_profile(),
            s.data.settings.clone(),
            s.data.profiles.clone(),
        )
    }
}

/* ------------------------------ окно и трей ------------------------------ */

/// Показывает окно, создавая его заново, если оно было закрыто (в трее окна нет вовсе — экономия памяти).
pub fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    if let Err(e) = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Hello!")
        .inner_size(1100.0, 760.0)
        .min_inner_size(900.0, 640.0)
        .background_color(tauri::window::Color(11, 16, 34, 255))
        .build()
    {
        crate::logs::write_file(&format!("окно: {e}"));
    }
}

fn tray_menu(app: &AppHandle, connected: bool) -> tauri::Result<Menu<tauri::Wry>> {
    Menu::with_items(
        app,
        &[
            &MenuItem::with_id(
                app,
                "toggle",
                if connected {
                    "Отключить"
                } else {
                    "Подключить"
                },
                true,
                None::<&str>,
            )?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open", "Открыть", true, None::<&str>)?,
            &MenuItem::with_id(app, "logs", "Собрать логи", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?,
        ],
    )
}

pub fn update_tray(app: &AppHandle) {
    let st = app.state::<AppState>();
    let connected = st.core.state() == VpnState::Connected;
    let name = st
        .store
        .lock()
        .unwrap()
        .active_profile()
        .map(|p| p.name)
        .unwrap_or_default();
    let tray = st.tray.lock().unwrap().clone();
    if let Some(tray) = tray {
        let tip = if connected {
            format!("Hello! — подключено: {name}")
        } else {
            "Hello! — отключено".into()
        };
        let _ = tray.set_tooltip(Some(tip));
        if let Ok(m) = tray_menu(app, connected) {
            let _ = tray.set_menu(Some(m));
        }
    }
}

pub fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?;
    let tray = TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("Hello!")
        .menu(&tray_menu(app, false)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| match e.id().as_ref() {
            "toggle" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let st = app.state::<AppState>();
                    let _ = toggle(&st).await;
                });
            }
            "open" => show_window(app),
            "logs" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let st = app.state::<AppState>();
                    match crate::diag::collect(&st).await {
                        Ok(f) => {
                            st.logs
                                .push("launcher", &format!("Логи собраны: {}", f.display()));
                            platform::reveal(&f);
                        }
                        Err(e) => notify(&app, &format!("Не удалось собрать логи: {e}")),
                    }
                });
            }
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    app.state::<AppState>().core.stop().await;
                    app.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = e
            {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;
    *app.state::<AppState>().tray.lock().unwrap() = Some(tray);
    Ok(())
}

fn notify(app: &AppHandle, body: &str) {
    let _ = app
        .notification()
        .builder()
        .title("Hello!")
        .body(body)
        .show();
}

/// Сторож переключил сервер: запоминаем его как выбранный.
pub fn on_switch(app: &AppHandle, entry: SwitchEntry) {
    let st = app.state::<AppState>();
    {
        let mut s = st.store.lock().unwrap();
        if s.data.profiles.iter().any(|p| p.id == entry.to_id) {
            s.data.settings.active_profile_id = Some(entry.to_id.clone());
            s.save();
        }
    }
    let mut payload = serde_json::to_value(&entry).unwrap();
    payload["state"] = st.public(None);
    let _ = app.emit("vpn:switch", payload);
    update_tray(app);
    notify(
        app,
        &format!(
            "Сервер не отвечал — переключились на «{}» ({} мс)",
            entry.to, entry.delay
        ),
    );
}

pub fn on_all_down(app: &AppHandle) {
    let _ = app.emit("vpn:allDown", ());
    notify(
        app,
        "Все серверы подписки сейчас недоступны. Продолжаю проверять.",
    );
}

async fn toggle(st: &AppState) -> Res<()> {
    match st.core.state() {
        VpnState::Connected | VpnState::Connecting => {
            st.core.stop().await;
            Ok(())
        }
        _ => connect_inner(st).await,
    }
}

async fn connect_inner(st: &AppState) -> Res<()> {
    let (p, s, all) = st.snapshot();
    let p = p.ok_or("Не выбран сервер")?;
    st.core.start(p, s, all).await
}

/* ------------------------------ пути ------------------------------ */

pub fn bin_dirs(app: &AppHandle) -> Vec<PathBuf> {
    let mut v = vec![];
    if let Ok(r) = app.path().resource_dir() {
        v.push(r.join("bin"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            v.push(d.join("bin"));
        }
    }
    if cfg!(debug_assertions) {
        v.push(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("bin"),
        );
    }
    v
}

pub fn init_state(app: &AppHandle) -> AppState {
    let logs = Arc::new(Logs::new(app.clone()));
    let core = Arc::new(Core::new(
        app.clone(),
        logs.clone(),
        bin_dirs(app),
        data_dir().join("cores"),
        data_dir().join("run"),
    ));
    AppState {
        store: Mutex::new(Store::load()),
        logs,
        core,
        tray: Mutex::new(None),
    }
}

/* ------------------------------ команды ------------------------------ */

#[tauri::command]
pub async fn get_state(st: State<'_, AppState>) -> Res<Value> {
    let admin = platform::is_admin().await;
    Ok(st.public(Some(admin)))
}

#[tauri::command]
pub fn get_logs(st: State<'_, AppState>) -> Value {
    json!(st.logs.all())
}

#[tauri::command]
pub fn clear_logs(st: State<'_, AppState>) -> bool {
    st.logs.clear();
    true
}

#[tauri::command]
pub async fn collect_logs(st: State<'_, AppState>) -> Res<String> {
    let f = crate::diag::collect(&st).await?;
    st.logs
        .push("launcher", &format!("Логи собраны: {}", f.display()));
    platform::reveal(&f);
    Ok(f.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn relaunch_admin(app: AppHandle) {
    platform::relaunch_as_admin();
    app.exit(0);
}

#[tauri::command]
pub fn open_bin_dir(st: State<'_, AppState>) {
    let dir = st
        .core
        .bin_dirs
        .first()
        .cloned()
        .unwrap_or_else(|| st.core.cores_dir.clone());
    let _ = std::fs::create_dir_all(&dir);
    platform::open_dir(&dir);
}

#[tauri::command]
pub fn update_settings(app: AppHandle, st: State<'_, AppState>, patch: Value) -> Res<Value> {
    let mut s = st.store.lock().unwrap();
    let mut cur = serde_json::to_value(&s.data.settings).map_err(|e| e.to_string())?;
    if let (Some(c), Value::Object(p)) = (cur.as_object_mut(), patch) {
        c.extend(p);
    }
    s.data.settings = serde_json::from_value(cur).map_err(|e| e.to_string())?;
    s.save();
    let out = serde_json::to_value(&s.data.settings).unwrap();
    drop(s);
    update_tray(&app);
    Ok(out)
}

/// Параметры загрузки подписок; при первом вызове создаёт идентификатор устройства.
fn fetch_opts(st: &AppState) -> crate::subs::FetchOpts {
    let mut s = st.store.lock().unwrap();
    if s.data.settings.hwid.is_empty() {
        s.data.settings.hwid = format!("{:016x}", rand::random::<u64>());
        s.save();
    }
    crate::subs::FetchOpts {
        custom_ua: s.data.settings.sub_user_agent.clone(),
        default_ua: format!("Hello/{}", display_version()),
        hwid: s.data.settings.hwid.clone(),
        preferred_ua: String::new(),
    }
}

async fn refresh_one(st: &AppState, id: &str) -> Res<(usize, Vec<String>)> {
    let (url, preferred_ua) = {
        let s = st.store.lock().unwrap();
        s.data
            .subscriptions
            .iter()
            .find(|x| x.id == id)
            .map(|x| (x.url.clone(), x.client_ua.clone()))
            .ok_or("Подписка не найдена")?
    };
    let mut opts = fetch_opts(st);
    opts.preferred_ua = preferred_ua;
    let (fetched, notes) = crate::subs::fetch(&url, &opts).await;
    for n in &notes {
        st.logs.push("launcher", n);
    }
    let fetched = fetched?;
    let mut s = st.store.lock().unwrap();
    crate::subs::apply(&mut s, id, fetched)
}

#[tauri::command]
pub async fn import_profiles(st: State<'_, AppState>, text: String) -> Res<Value> {
    let input = text.trim().to_string();
    let lower = input.to_lowercase();
    if (lower.starts_with("http://") || lower.starts_with("https://")) && !input.contains('\n') {
        let sub = crate::subs::new_subscription(&input);
        let id = sub.id.clone();
        st.store.lock().unwrap().data.subscriptions.push(sub);
        match refresh_one(&st, &id).await {
            Ok((added, errors)) => {
                let mut s = st.store.lock().unwrap();
                if s.active_profile().is_none() {
                    s.data.settings.active_profile_id = s
                        .data
                        .profiles
                        .iter()
                        .find(|p| p.sub_id.as_deref() == Some(id.as_str()))
                        .map(|p| p.id.clone());
                    s.save();
                }
                drop(s);
                return Ok(json!({ "added": added, "errors": errors, "state": st.public(None) }));
            }
            Err(e) => {
                let mut s = st.store.lock().unwrap();
                s.data.subscriptions.retain(|x| x.id != id);
                s.save();
                return Err(e);
            }
        }
    }
    let r = parse_many(&input);
    if r.profiles.is_empty() {
        return Err(r
            .errors
            .first()
            .cloned()
            .unwrap_or_else(|| "Не найдено ни одной ссылки".into()));
    }
    let added = r.profiles.len();
    let mut s = st.store.lock().unwrap();
    let first = r.profiles[0].id.clone();
    s.data.profiles.extend(r.profiles);
    if s.active_profile().is_none() {
        s.data.settings.active_profile_id = Some(first);
    }
    s.save();
    drop(s);
    Ok(json!({ "added": added, "errors": r.errors, "state": st.public(None) }))
}

#[tauri::command]
pub async fn refresh_subs(st: State<'_, AppState>, id: Option<String>) -> Res<Value> {
    let ids: Vec<(String, String)> = {
        let s = st.store.lock().unwrap();
        s.data
            .subscriptions
            .iter()
            .filter(|x| id.as_deref().map_or(true, |i| i == x.id))
            .map(|x| (x.id.clone(), x.name.clone()))
            .collect()
    };
    let mut errors = vec![];
    for (sid, name) in ids {
        if let Err(e) = refresh_one(&st, &sid).await {
            errors.push(format!("{name}: {e}"));
        }
    }
    Ok(json!({ "errors": errors, "state": st.public(None) }))
}

/// Открывает в браузере ссылку провайдера из подписки (поддержка или личный кабинет).
/// Открываются только ссылки, пришедшие в заголовках подписки, — не произвольные.
#[tauri::command]
pub fn open_sub_link(st: State<'_, AppState>, id: String, kind: String) -> Res<()> {
    let link = {
        let s = st.store.lock().unwrap();
        let sub = s
            .data
            .subscriptions
            .iter()
            .find(|x| x.id == id)
            .ok_or("Подписка не найдена")?;
        if kind == "support" {
            sub.support_url.clone()
        } else {
            sub.web_page_url.clone()
        }
    };
    if link.is_empty() {
        return Err("Провайдер не указал ссылку".into());
    }
    crate::platform::open_url(&link);
    Ok(())
}

#[tauri::command]
pub fn remove_sub(st: State<'_, AppState>, id: String) -> Value {
    {
        let mut s = st.store.lock().unwrap();
        s.data.subscriptions.retain(|x| x.id != id);
        s.data
            .profiles
            .retain(|p| p.sub_id.as_deref() != Some(id.as_str()));
        if s.active_profile().is_none() {
            s.data.settings.active_profile_id = s.data.profiles.first().map(|p| p.id.clone());
        }
        s.save();
    }
    st.public(None)
}

#[tauri::command]
pub fn remove_profile(st: State<'_, AppState>, id: String) -> Value {
    {
        let mut s = st.store.lock().unwrap();
        s.data.profiles.retain(|p| p.id != id);
        if s.active_profile().is_none() {
            s.data.settings.active_profile_id = s.data.profiles.first().map(|p| p.id.clone());
        }
        s.save();
    }
    st.public(None)
}

#[tauri::command]
pub fn set_profile_auto(st: State<'_, AppState>, id: String, included: bool) -> Value {
    {
        let mut s = st.store.lock().unwrap();
        if let Some(p) = s.data.profiles.iter_mut().find(|p| p.id == id) {
            p.no_auto = !included;
        }
        s.save();
    }
    st.public(None)
}

#[tauri::command]
pub async fn select_profile(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<Value> {
    {
        let mut s = st.store.lock().unwrap();
        s.data.settings.active_profile_id = Some(id.clone());
        s.save();
    }
    update_tray(&app);
    if st.core.state() == VpnState::Connected && !st.core.select_in_group(&id).await {
        // Внутри группы автопереключения — мгновенно, иначе переподключение
        connect_inner(&st).await?;
    }
    Ok(st.public(None))
}

#[tauri::command]
pub async fn ping_profiles(st: State<'_, AppState>) -> Res<HashMap<String, i64>> {
    let list: Vec<Profile> = st.store.lock().unwrap().data.profiles.clone();
    let results = futures_util::future::join_all(list.into_iter().map(|p| async move {
        // Hysteria2 работает по UDP — TCP-пинг для него бессмыслен
        let v = if p.protocol == "hysteria2" {
            -2
        } else {
            tcp_ping(&p.server, p.port)
                .await
                .map(|d| d as i64)
                .unwrap_or(-1)
        };
        (p.id, v)
    }))
    .await;
    Ok(results.into_iter().collect())
}

#[tauri::command]
pub async fn list_processes() -> Res<Value> {
    Ok(json!(crate::procs::list().await?))
}

#[tauri::command]
pub async fn pick_exe(app: AppHandle) -> Res<Value> {
    use tauri_plugin_dialog::DialogExt;
    let files = app
        .dialog()
        .file()
        .set_title("Выберите программу")
        .add_filter("Программы", &["exe"])
        .blocking_pick_files();
    let paths: Vec<String> = files
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| f.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let icons = crate::procs::icons_for(&paths).await;
    Ok(json!(paths
        .iter()
        .map(|p| json!({
            "name": std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default(),
            "path": p,
            "icon": icons.get(p).cloned().unwrap_or_default(),
        }))
        .collect::<Vec<_>>()))
}

#[tauri::command]
pub fn set_apps(st: State<'_, AppState>, apps: Vec<AppRule>) -> Value {
    let mut s = st.store.lock().unwrap();
    s.data.settings.apps = apps;
    s.save();
    serde_json::to_value(&s.data.settings).unwrap()
}

#[tauri::command]
pub async fn app_icons(st: State<'_, AppState>) -> Res<HashMap<String, String>> {
    let paths: Vec<String> = st
        .store
        .lock()
        .unwrap()
        .data
        .settings
        .apps
        .iter()
        .filter_map(|a| a.path.clone())
        .filter(|p| !p.is_empty())
        .collect();
    Ok(crate::procs::icons_for(&paths).await)
}

#[tauri::command]
pub async fn connect(st: State<'_, AppState>) -> Res<VpnState> {
    connect_inner(&st).await?;
    Ok(st.core.state())
}

#[tauri::command]
pub async fn disconnect(st: State<'_, AppState>) -> Res<VpnState> {
    st.core.stop().await;
    Ok(st.core.state())
}

#[tauri::command]
pub async fn restart(st: State<'_, AppState>) -> Res<VpnState> {
    if st.core.state() == VpnState::Connected {
        connect_inner(&st).await?;
    }
    Ok(st.core.state())
}
