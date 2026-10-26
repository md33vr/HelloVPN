//! Мелочи, зависящие от Windows.

use std::path::Path;
use tokio::process::Command;

#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Команда без мигающего окна консоли.
pub fn hidden(program: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(program);
    #[cfg(windows)]
    c.creation_flags(CREATE_NO_WINDOW);
    c.kill_on_drop(true);
    c
}

/// Есть ли права администратора.
pub async fn is_admin() -> bool {
    #[cfg(windows)]
    {
        hidden("net")
            .arg("session")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Перезапуск текущего exe с правами администратора.
pub fn relaunch_as_admin() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let q = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let cmd = format!(
        "Start-Process -FilePath {} -Verb RunAs",
        q(&exe.to_string_lossy())
    );
    if cfg!(windows) {
        let _ = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &cmd])
            .spawn();
    }
}

/// Показать файл в Проводнике.
pub fn reveal(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer.exe")
            .arg(format!("/select,{}", path.display()))
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
}

/// Открыть ссылку в браузере по умолчанию. Через Проводник — чтобы браузер
/// запустился от имени пользователя, а не с правами администратора, как Hello!.
pub fn open_url(url: &str) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer.exe").arg(url).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = url;
    }
}

/// Открыть папку.
pub fn open_dir(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer.exe").arg(path).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
}

/// IPv4-адреса интерфейсов (для выбора свободного адреса TUN).
pub fn ipv4_interfaces() -> Vec<hello_core::net::IfAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(hello_core::net::IfAddr {
                ip: v4.ip,
                mask: v4.netmask,
            }),
            _ => None,
        })
        .collect()
}

/// Интерфейсы для отчёта: «имя: адрес/маска».
pub fn interfaces_report() -> String {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| match i.addr {
            if_addrs::IfAddr::V4(v) => format!("{}: {}/{}", i.name, v.ip, v.netmask),
            if_addrs::IfAddr::V6(v) => format!("{}: {}/{}", i.name, v.ip, v.netmask),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Вывод команды целиком (для отчёта).
pub async fn run_text(program: &str, args: &[&str]) -> String {
    match hidden(program).args(args).output().await {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            if s.trim().is_empty() {
                s = String::from_utf8_lossy(&o.stderr).into_owned();
            }
            s.trim().to_string()
        }
        Err(e) => e.to_string(),
    }
}
