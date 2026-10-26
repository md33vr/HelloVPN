//! Настройки, серверы и подписки в `%APPDATA%\Hello\launcher.json` —
//! тот же файл, что у Electron-версии, поэтому всё переезжает само.

use hello_core::model::{Profile, StoreData};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Store {
    file: PathBuf,
    pub data: StoreData,
}

/// `%APPDATA%\Hello`
pub fn data_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Hello")
}

impl Store {
    pub fn load() -> Self {
        let dir = data_dir();
        let file = dir.join("launcher.json");
        if !file.exists() {
            // Ещё более старые версии («VPN Launcher»)
            if let Some(base) = dirs::config_dir() {
                for legacy in ["VPN Launcher", "vpn-launcher"] {
                    let old = base.join(legacy).join("launcher.json");
                    if old.exists() {
                        let _ = fs::create_dir_all(&dir);
                        let _ = fs::copy(&old, &file);
                        break;
                    }
                }
            }
        }
        let data = fs::read_to_string(&file)
            .ok()
            .and_then(|s| serde_json::from_str::<StoreData>(&s).ok())
            .unwrap_or_default();
        Self { file, data }
    }

    pub fn save(&self) {
        if let Some(dir) = self.file.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let tmp = self.file.with_extension("json.tmp");
        if let Ok(s) = serde_json::to_string_pretty(&self.data) {
            if fs::write(&tmp, s).is_ok() {
                let _ = fs::rename(&tmp, &self.file);
            }
        }
    }

    pub fn active_profile(&self) -> Option<Profile> {
        self.data.active_profile().cloned()
    }

    pub fn file(&self) -> &Path {
        &self.file
    }
}
