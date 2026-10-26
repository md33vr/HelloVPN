//! Журнал: кольцевой буфер + событие `log` в интерфейс.

use serde::Serialize;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter};

const MAX: usize = 3000;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub source: String,
    pub line: String,
    pub ts: i64,
}

pub struct Logs {
    buf: Mutex<VecDeque<LogEntry>>,
    app: AppHandle,
}

/// Убирает ANSI-коды цвета (sing-box раскрашивает вывод).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for n in chars.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Logs {
    pub fn new(app: AppHandle) -> Self {
        Self {
            buf: Mutex::new(VecDeque::with_capacity(MAX)),
            app,
        }
    }

    pub fn push(&self, source: &str, line: &str) {
        let clean = strip_ansi(line);
        let clean = clean.trim_end();
        if clean.is_empty() {
            return;
        }
        let e = LogEntry {
            source: source.into(),
            line: clean.into(),
            ts: now_ms(),
        };
        {
            let mut b = self.buf.lock().unwrap();
            if b.len() >= MAX {
                b.pop_front();
            }
            b.push_back(e.clone());
        }
        write_file(&format!(
            "[{} {}] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            e.source,
            e.line
        ));
        let _ = self.app.emit("log", e);
    }

    pub fn all(&self) -> Vec<LogEntry> {
        self.buf.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.buf.lock().unwrap().clear();
    }
}

/// Журнал на диске: `%APPDATA%\Hello\hello.log` (при 2 МБ старый уходит в hello.old.log).
/// Нужен, когда окно не открывается или программа падает.
pub fn write_file(line: &str) {
    let dir = crate::store::data_dir();
    let file = dir.join("hello.log");
    let _ = std::fs::create_dir_all(&dir);
    if std::fs::metadata(&file)
        .map(|m| m.len() > 2 * 1024 * 1024)
        .unwrap_or(false)
    {
        let _ = std::fs::rename(&file, dir.join("hello.old.log"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
    {
        let _ = writeln!(f, "{line}");
    }
}
