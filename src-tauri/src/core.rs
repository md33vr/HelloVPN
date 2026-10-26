//! Запуск и остановка ядер, автоперезапуск sing-box при падении,
//! сторож автопереключения серверов через Clash API.

use crate::logs::{now_ms, Logs};
use crate::platform::{hidden, ipv4_interfaces};
use futures_util::{stream, StreamExt};
use hello_core::config::{auto_group, build_sing_box, build_xray, member_tag, BuildOpts, ClashApi};
use hello_core::model::{Profile, Settings};
use hello_core::net::pick_tun_address;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

const TEST_URL: &str = "https://www.gstatic.com/generate_204";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnState {
    Disconnected,
    Connecting,
    Connected,
    Stopping,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchEntry {
    pub ts: i64,
    pub from: String,
    pub to: String,
    pub to_id: String,
    pub delay: u32,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct Member {
    id: String,
    name: String,
    tag: String,
}

/// Процесс ядра: сигнал на остановку и ожидание её завершения.
struct Proc {
    kill: Option<oneshot::Sender<()>>,
    done: Option<oneshot::Receiver<()>>,
}

#[derive(Default)]
struct Inner {
    singbox: Option<Proc>,
    xray: Option<Proc>,
    watchdog: Option<JoinHandle<()>>,
    /// Растёт при каждом запуске/остановке — старые события процессов игнорируются.
    generation: u64,
    /// Последние автоперезапуски (для ограничения частоты).
    restarts: Vec<Instant>,
    /// Что запускали — для автоперезапуска.
    last: Option<(Profile, Settings, Vec<Profile>)>,
}

pub struct Core {
    app: AppHandle,
    logs: Arc<Logs>,
    pub bin_dirs: Vec<PathBuf>,
    pub cores_dir: PathBuf,
    pub work_dir: PathBuf,
    inner: AsyncMutex<Inner>,
    state: Mutex<VpnState>,
    api: Mutex<Option<Clash>>,
    group: Mutex<Option<Vec<Member>>>,
    pub history: Mutex<Vec<SwitchEntry>>,
    since: Mutex<Option<i64>>,
}

/* ------------------------------ Clash API ------------------------------ */

#[derive(Clone)]
pub struct Clash {
    base: String,
    secret: String,
    http: reqwest::Client,
}

impl Clash {
    fn new(port: u16, secret: String) -> Self {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        Self {
            base: format!("http://127.0.0.1:{port}"),
            secret,
            http,
        }
    }

    fn enc(s: &str) -> String {
        url_encode(s)
    }

    async fn current(&self, group: &str) -> Result<String, String> {
        let v: Value = self
            .http
            .get(format!("{}/proxies/{}", self.base, Self::enc(group)))
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        v["now"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "нет поля now".into())
    }

    async fn select(&self, group: &str, name: &str) -> Result<(), String> {
        let r = self
            .http
            .put(format!("{}/proxies/{}", self.base, Self::enc(group)))
            .bearer_auth(&self.secret)
            .json(&json!({ "name": name }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", r.status()))
        }
    }

    /// Задержка через сервер (мс) или None.
    async fn delay(&self, name: &str, timeout_ms: u64) -> Option<u32> {
        let url = format!(
            "{}/proxies/{}/delay?timeout={}&url={}",
            self.base,
            Self::enc(name),
            timeout_ms,
            Self::enc(TEST_URL)
        );
        let r = self
            .http
            .get(url)
            .bearer_auth(&self.secret)
            .timeout(Duration::from_millis(timeout_ms + 3000))
            .send()
            .await
            .ok()?;
        let v: Value = r.json().await.ok()?;
        v["delay"].as_u64().filter(|d| *d > 0).map(|d| d as u32)
    }
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/* ------------------------------ сеть ------------------------------ */

async fn free_port() -> Result<u16, String> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

async fn wait_port(port: u16, timeout: Duration) -> bool {
    let until = Instant::now() + timeout;
    while Instant::now() < until {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    false
}

/// TCP-«пинг»: время установки соединения (мс).
pub async fn tcp_ping(host: &str, port: u16) -> Option<u32> {
    let start = Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u32),
        _ => None,
    }
}

/* ------------------------------ менеджер ------------------------------ */

impl Core {
    pub fn new(
        app: AppHandle,
        logs: Arc<Logs>,
        bin_dirs: Vec<PathBuf>,
        cores_dir: PathBuf,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            app,
            logs,
            bin_dirs,
            cores_dir,
            work_dir,
            inner: AsyncMutex::new(Inner::default()),
            state: Mutex::new(VpnState::Disconnected),
            api: Mutex::new(None),
            group: Mutex::new(None),
            history: Mutex::new(vec![]),
            since: Mutex::new(None),
        }
    }

    pub fn state(&self) -> VpnState {
        *self.state.lock().unwrap()
    }

    pub fn is_auto(&self) -> bool {
        self.group.lock().unwrap().is_some()
    }

    fn log(&self, source: &str, line: &str) {
        self.logs.push(source, line);
    }

    fn set_state(&self, st: VpnState, extra: Value) {
        *self.state.lock().unwrap() = st;
        if st == VpnState::Connected {
            let mut since = self.since.lock().unwrap();
            if since.is_none() {
                *since = Some(now_ms());
            }
        } else if st == VpnState::Disconnected {
            *self.since.lock().unwrap() = None;
        }
        let mut payload =
            json!({ "state": st, "auto": self.is_auto(), "since": *self.since.lock().unwrap() });
        if let (Some(m), Value::Object(e)) = (payload.as_object_mut(), extra) {
            m.extend(e);
        }
        let _ = self.app.emit("vpn:state", payload);
    }

    /// Путь к ядру: рядом с программой, в %APPDATA%\Hello\cores или (в разработке) в bin репозитория.
    pub fn find_bin(&self, name: &str) -> Option<PathBuf> {
        self.bin_dirs
            .iter()
            .chain(std::iter::once(&self.cores_dir))
            .map(|d| d.join(name))
            .find(|p| p.exists())
    }

    fn bin(&self, name: &str) -> Result<PathBuf, String> {
        self.find_bin(name).ok_or_else(|| {
            format!("Не найден {name}. Переустановите Hello! или положите файл в папку ядер.")
        })
    }

    fn write_config(&self, name: &str, v: &Value) -> Result<PathBuf, String> {
        std::fs::create_dir_all(&self.work_dir).map_err(|e| e.to_string())?;
        let f = self.work_dir.join(name);
        std::fs::write(&f, serde_json::to_string_pretty(v).unwrap()).map_err(|e| e.to_string())?;
        Ok(f)
    }

    /// `sing-box check` — понятная ошибка до запуска.
    async fn check_sing_box(&self, file: &Path) -> Result<(), String> {
        let out = hidden(self.bin("sing-box.exe")?)
            .arg("check")
            .arg("-c")
            .arg(file)
            .arg("-D")
            .arg(&self.work_dir)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            return Ok(());
        }
        let msg = crate::logs::strip_ansi(&format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        ));
        for l in msg.lines() {
            self.log("singbox", l);
        }
        Err(format!(
            "Конфиг sing-box не прошёл проверку: {}",
            msg.trim().lines().last().unwrap_or("")
        ))
    }

    /// Запускает процесс ядра: вывод — в журнал, неожиданное завершение — в on_exit.
    fn spawn_core(
        self: &Arc<Self>,
        key: &'static str,
        exe: PathBuf,
        args: Vec<String>,
        generation: u64,
    ) -> Result<Proc, String> {
        let mut child = hidden(&exe)
            .args(&args)
            .current_dir(&self.work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Не удалось запустить {}: {e}", exe.display()))?;
        for pipe in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let me = self.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(pipe).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    me.log(key, &l);
                }
            });
        }
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel::<()>();
        let me = self.clone();
        tokio::spawn(async move {
            tokio::select! {
                status = child.wait() => {
                    let code = status.ok().and_then(|s| s.code()).map(|c| c.to_string()).unwrap_or_else(|| "?".into());
                    me.log(key, &format!("процесс завершён (код {code})"));
                    let _ = done_tx.send(());
                    me.on_unexpected_exit(key, code, generation).await;
                }
                _ = kill_rx => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    let _ = done_tx.send(());
                }
            }
        });
        Ok(Proc {
            kill: Some(kill_tx),
            done: Some(done_rx),
        })
    }

    /// Ядро упало само: перезапускаем (не чаще 3 раз в минуту), иначе отключаемся.
    async fn on_unexpected_exit(self: &Arc<Self>, key: &str, code: String, generation: u64) {
        let (restart, last) = {
            let mut inner = self.inner.lock().await;
            if inner.generation != generation
                || self.state() == VpnState::Stopping
                || self.state() == VpnState::Disconnected
            {
                return;
            }
            let now = Instant::now();
            inner
                .restarts
                .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
            let ok = self.state() == VpnState::Connected && inner.restarts.len() < 3;
            if ok {
                inner.restarts.push(now);
            }
            (ok, inner.last.clone())
        };
        if let (true, Some((p, s, all))) = (restart, last) {
            self.log(
                "launcher",
                &format!("⟳ {key} неожиданно завершился (код {code}) — перезапускаю"),
            );
            if let Err(e) = self.start(p, s, all).await {
                self.log("launcher", &format!("✗ Перезапуск не удался: {e}"));
            }
        } else {
            self.stop().await;
            self.set_state(VpnState::Disconnected, json!({ "error": format!("{key} неожиданно завершился (код {code}). Смотрите журнал.") }));
        }
    }

    /// Подключение.
    pub async fn start(
        self: &Arc<Self>,
        profile: Profile,
        settings: Settings,
        all: Vec<Profile>,
    ) -> Result<(), String> {
        if self.state() != VpnState::Disconnected {
            self.stop_inner(false).await;
        }
        self.set_state(VpnState::Connecting, json!({}));
        let res = self.start_inner(&profile, &settings, &all).await;
        match res {
            Ok(()) => {
                self.inner.lock().await.last = Some((profile.clone(), settings.clone(), all));
                self.set_state(VpnState::Connected, json!({ "profileId": profile.id }));
                if self.is_auto() {
                    self.start_watchdog(settings.check_interval).await;
                }
                Ok(())
            }
            Err(e) => {
                self.stop_inner(true).await;
                self.set_state(VpnState::Disconnected, json!({ "error": e }));
                Err(e)
            }
        }
    }

    async fn start_inner(
        self: &Arc<Self>,
        profile: &Profile,
        settings: &Settings,
        all: &[Profile],
    ) -> Result<(), String> {
        let auto = settings.auto_switch && settings.core != "xray";
        let mut members = if auto {
            auto_group(profile, all)
        } else {
            vec![profile.clone()]
        };
        let mut clash = Some(ClashApi {
            port: free_port().await?,
            secret: random_hex(12),
        });
        let tun = pick_tun_address(&ipv4_interfaces());
        self.log(
            "launcher",
            &format!(
                "TUN: адрес {tun}{}",
                if members.len() > 1 {
                    format!(", автопереключение среди {} серверов", members.len())
                } else {
                    String::new()
                }
            ),
        );

        let opts = BuildOpts {
            group: members.clone(),
            clash_api: clash.clone(),
            tun_address: Some(tun.clone()),
        };
        let mut sb_file =
            self.write_config("sing-box.json", &build_sing_box(profile, settings, &opts)?)?;
        if let Err(e) = self.check_sing_box(&sb_file).await {
            // Сборка sing-box без Clash API — подключаемся без автопереключения, а не падаем
            if !e.to_lowercase().contains("clash") {
                return Err(e);
            }
            self.log("launcher", "⚠ Эта сборка sing-box без Clash API — автопереключение отключено для этого подключения");
            members = vec![profile.clone()];
            clash = None;
            let opts = BuildOpts {
                tun_address: Some(tun),
                ..Default::default()
            };
            sb_file =
                self.write_config("sing-box.json", &build_sing_box(profile, settings, &opts)?)?;
            self.check_sing_box(&sb_file).await?;
        }

        let generation = {
            let mut inner = self.inner.lock().await;
            inner.generation += 1;
            inner.generation
        };

        if settings.core == "xray" {
            let xr_file = self.write_config("xray.json", &build_xray(profile, settings)?)?;
            let exe = match self.find_bin("xray.exe") {
                Some(p) => p,
                None => crate::cores::download_xray(&self.cores_dir, &self.logs).await?,
            };
            let proc = self.spawn_core(
                "xray",
                exe,
                vec!["run".into(), "-c".into(), xr_file.to_string_lossy().into()],
                generation,
            )?;
            self.inner.lock().await.xray = Some(proc);
            if !wait_port(settings.socks_port, Duration::from_secs(5)).await {
                return Err(format!("Xray не открыл порт {}", settings.socks_port));
            }
        }

        let args = vec![
            "run".into(),
            "-c".into(),
            sb_file.to_string_lossy().into(),
            "-D".into(),
            self.work_dir.to_string_lossy().into(),
        ];
        let proc = self.spawn_core("singbox", self.bin("sing-box.exe")?, args, generation)?;
        self.inner.lock().await.singbox = Some(proc);

        if let Some(c) = &clash {
            wait_port(c.port, Duration::from_secs(8)).await;
            tokio::time::sleep(Duration::from_millis(400)).await;
        } else {
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }
        if self.inner.lock().await.generation != generation || self.state() != VpnState::Connecting
        {
            return Err("sing-box не запустился — подробности в журнале".into());
        }

        *self.api.lock().unwrap() = clash.map(|c| Clash::new(c.port, c.secret));
        *self.group.lock().unwrap() = if self.api.lock().unwrap().is_some() && members.len() > 1 {
            Some(
                members
                    .iter()
                    .map(|p| Member {
                        id: p.id.clone(),
                        name: p.name.clone(),
                        tag: member_tag(p),
                    })
                    .collect(),
            )
        } else {
            None
        };
        Ok(())
    }

    /// Отключение.
    pub async fn stop(self: &Arc<Self>) {
        self.stop_inner(true).await;
    }

    async fn stop_inner(self: &Arc<Self>, emit: bool) {
        let (sb, xr, wd) = {
            let mut inner = self.inner.lock().await;
            inner.generation += 1;
            (
                inner.singbox.take(),
                inner.xray.take(),
                inner.watchdog.take(),
            )
        };
        if let Some(w) = wd {
            w.abort();
        }
        *self.api.lock().unwrap() = None;
        *self.group.lock().unwrap() = None;
        let had = sb.is_some() || xr.is_some();
        if had && emit {
            self.set_state(VpnState::Stopping, json!({}));
        }
        // Сначала sing-box (снимает маршруты TUN), затем Xray
        for p in [sb, xr].into_iter().flatten() {
            let Proc { kill, done } = p;
            if let Some(k) = kill {
                let _ = k.send(());
            }
            if let Some(d) = done {
                let _ = tokio::time::timeout(Duration::from_secs(5), d).await;
            }
        }
        if emit && self.state() != VpnState::Disconnected {
            self.set_state(VpnState::Disconnected, json!({}));
        }
    }

    /* ----------------------- автопереключение ----------------------- */

    async fn start_watchdog(self: &Arc<Self>, interval_s: u32) {
        let me = self.clone();
        let interval = Duration::from_secs(interval_s.max(10) as u64);
        let h = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let mut fails = 0u32;
            loop {
                if me.state() != VpnState::Connected {
                    break;
                }
                let api = me.api.lock().unwrap().clone();
                if let Some(api) = api {
                    match api.current("proxy").await {
                        Ok(now) => match api.delay(&now, 5000).await {
                            Some(ms) => {
                                if fails > 0 {
                                    me.log(
                                        "launcher",
                                        &format!("✓ {} снова отвечает ({ms} мс)", me.name_of(&now)),
                                    );
                                }
                                fails = 0;
                                let _ = me
                                    .app
                                    .emit("vpn:health", json!({ "tag": now, "delay": ms }));
                            }
                            None => {
                                fails += 1;
                                me.log(
                                    "launcher",
                                    &format!(
                                        "✗ {} не ответил на проверку ({fails}/2)",
                                        me.name_of(&now)
                                    ),
                                );
                                let _ = me
                                    .app
                                    .emit("vpn:health", json!({ "tag": now, "delay": -1 }));
                                if fails >= 2 {
                                    fails = 0;
                                    me.failover(&api, &now, "нет ответа").await;
                                }
                            }
                        },
                        Err(e) => me.log("launcher", &format!("проверка соединения: {e}")),
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
        self.inner.lock().await.watchdog = Some(h);
    }

    fn name_of(&self, tag: &str) -> String {
        self.group
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|g| g.iter().find(|m| m.tag == tag).map(|m| m.name.clone()))
            .unwrap_or_else(|| tag.to_string())
    }

    /// Меряет серверы группы и переключается на самый быстрый рабочий, проверяя каждый.
    async fn failover(self: &Arc<Self>, api: &Clash, from: &str, reason: &str) -> bool {
        let Some(group) = self.group.lock().unwrap().clone() else {
            return false;
        };
        self.log(
            "launcher",
            &format!(
                "⇄ Ищу замену для «{}»: замеряю серверы подписки…",
                self.name_of(from)
            ),
        );
        // Не все разом: в подписке могут быть сотни серверов
        let mut alive: Vec<(Member, u32)> =
            stream::iter(group.into_iter().filter(|m| m.tag != from))
                .map(|m| async move {
                    let d = api.delay(&m.tag, 4000).await;
                    (m, d)
                })
                .buffer_unordered(24)
                .filter_map(|(m, d)| async move { d.map(|d| (m, d)) })
                .collect()
                .await;
        alive.sort_by_key(|(_, d)| *d);
        for (cand, _) in alive {
            if api.select("proxy", &cand.tag).await.is_err() {
                continue;
            }
            if let Some(check) = api.delay("proxy", 5000).await {
                let entry = SwitchEntry {
                    ts: now_ms(),
                    from: self.name_of(from),
                    to: cand.name.clone(),
                    to_id: cand.id.clone(),
                    delay: check,
                    reason: reason.into(),
                };
                self.log(
                    "launcher",
                    &format!(
                        "⇄ Переключено: {} → {} ({check} мс, причина: {reason})",
                        entry.from, entry.to
                    ),
                );
                {
                    let mut h = self.history.lock().unwrap();
                    h.push(entry.clone());
                    if h.len() > 100 {
                        h.remove(0);
                    }
                }
                crate::app::on_switch(&self.app, entry);
                return true;
            }
            self.log(
                "launcher",
                &format!(
                    "✗ {} не прошёл проверку после переключения, пробую следующий",
                    cand.name
                ),
            );
        }
        // Ничего не работает — возвращаемся на исходный, сторож попробует снова
        let _ = api.select("proxy", from).await;
        self.log(
            "launcher",
            "⚠ Все серверы подписки сейчас недоступны — повторю проверку позже",
        );
        crate::app::on_all_down(&self.app);
        false
    }

    /// Ручной выбор сервера без перезапуска, если он в текущей группе.
    pub async fn select_in_group(&self, profile_id: &str) -> bool {
        if self.state() != VpnState::Connected {
            return false;
        }
        let member = self
            .group
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|g| g.iter().find(|m| m.id == profile_id).cloned());
        let api = self.api.lock().unwrap().clone();
        match (member, api) {
            (Some(m), Some(api)) => {
                let ok = api.select("proxy", &m.tag).await.is_ok();
                if ok {
                    self.log("launcher", &format!("Сервер выбран вручную: {}", m.name));
                }
                ok
            }
            _ => false,
        }
    }
}

pub fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
