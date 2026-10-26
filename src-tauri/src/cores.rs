//! Xray не входит в установщик (нужен редко — для XHTTP): скачивается при первом выборе этого ядра.

use crate::logs::Logs;
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};

const XRAY_ASSET: &str = "Xray-windows-64.zip";

pub async fn download_xray(dir: &Path, logs: &Logs) -> Result<PathBuf, String> {
    let http = reqwest::Client::builder()
        .user_agent("Hello-VPN")
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?;
    logs.push(
        "launcher",
        "Xray ещё не скачан — загружаю последнюю версию с GitHub…",
    );
    let rel: Value = http
        .get("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("GitHub недоступен: {e}"))?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let tag = rel["tag_name"].as_str().unwrap_or("?").to_string();
    let url = rel["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"] == XRAY_ASSET))
        .and_then(|x| x["browser_download_url"].as_str())
        .ok_or_else(|| format!("В релизе Xray {tag} нет {XRAY_ASSET}"))?
        .to_string();
    let bytes = http
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bytes()
        .await
        .map_err(|e| e.to_string())?;
    let mut zip =
        zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).map_err(|e| e.to_string())?;
    let mut exe = Vec::new();
    zip.by_name("xray.exe")
        .map_err(|_| "В архиве нет xray.exe".to_string())?
        .read_to_end(&mut exe)
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let out = dir.join("xray.exe");
    std::fs::write(&out, exe).map_err(|e| e.to_string())?;
    logs.push("launcher", &format!("✓ Xray {tag} скачан"));
    Ok(out)
}
