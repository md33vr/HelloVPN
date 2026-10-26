//! Список запущенных программ с иконками (Windows).

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcItem {
    pub name: String,
    pub path: String,
    pub title: String,
    pub pids: Vec<u32>,
    pub has_window: bool,
    pub icon: String,
}

const SYSTEM_SKIP: [&str; 23] = [
    "system",
    "idle",
    "registry",
    "smss",
    "csrss",
    "wininit",
    "services",
    "lsass",
    "svchost",
    "fontdrvhost",
    "dwm",
    "winlogon",
    "conhost",
    "dllhost",
    "sihost",
    "ctfmon",
    "runtimebroker",
    "searchindexer",
    "spoolsv",
    "wudfhost",
    "taskhostw",
    "sing-box",
    "xray",
];

static ICONS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

async fn powershell(script: &str) -> Result<String, String> {
    let out = crate::platform::hidden("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Иконки exe как data:image/png;base64 (с кэшем).
pub async fn icons_for(paths: &[String]) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut missing = vec![];
    {
        let cache = ICONS.lock().unwrap();
        for p in paths {
            match cache.as_ref().and_then(|c| c.get(p)) {
                Some(i) => {
                    result.insert(p.clone(), i.clone());
                }
                None => missing.push(p.clone()),
            }
        }
    }
    if missing.is_empty() || !cfg!(windows) {
        return result;
    }
    let list = missing
        .iter()
        .map(|p| ps_quote(p))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Add-Type -AssemblyName System.Drawing; $r=@{{}}; foreach($p in @({list})){{ try {{ $i=[System.Drawing.Icon]::ExtractAssociatedIcon($p); $b=$i.ToBitmap(); $m=New-Object IO.MemoryStream; $b.Save($m,[System.Drawing.Imaging.ImageFormat]::Png); $r[$p]='data:image/png;base64,'+[Convert]::ToBase64String($m.ToArray()) }} catch {{ $r[$p]='' }} }}; $r | ConvertTo-Json -Compress"
    );
    if let Ok(out) = powershell(&script).await {
        if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(out.trim()) {
            let mut cache = ICONS.lock().unwrap();
            let c = cache.get_or_insert_with(HashMap::new);
            for (k, v) in map {
                c.insert(k.clone(), v.clone());
                result.insert(k, v);
            }
        }
    }
    result
}

/// Уникальные по пути процессы: сначала оконные, затем по имени.
pub async fn list() -> Result<Vec<ProcItem>, String> {
    if !cfg!(windows) {
        return Ok(vec![]);
    }
    let out = powershell(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Process | Where-Object { $_.Path } | Select-Object Name, Id, Path, @{n='Title';e={$_.MainWindowTitle}} | ConvertTo-Json -Compress",
    )
    .await?;
    let v: serde_json::Value =
        serde_json::from_str(out.trim()).map_err(|e| format!("список процессов: {e}"))?;
    let arr = match v {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    };
    let mut by_path: Vec<ProcItem> = vec![];
    for p in arr {
        let name = p["Name"].as_str().unwrap_or("").to_string();
        let path = p["Path"].as_str().unwrap_or("").to_string();
        if path.is_empty() || SYSTEM_SKIP.contains(&name.to_lowercase().as_str()) {
            continue;
        }
        let pid = p["Id"].as_u64().unwrap_or(0) as u32;
        let title = p["Title"].as_str().unwrap_or("").to_string();
        match by_path
            .iter_mut()
            .find(|x| x.path.eq_ignore_ascii_case(&path))
        {
            Some(x) => {
                x.pids.push(pid);
                if !title.is_empty() {
                    x.title = title;
                    x.has_window = true;
                }
            }
            None => by_path.push(ProcItem {
                name: std::path::Path::new(&path)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or(name),
                has_window: !title.is_empty(),
                title,
                pids: vec![pid],
                icon: String::new(),
                path,
            }),
        }
    }
    let icons = icons_for(&by_path.iter().map(|p| p.path.clone()).collect::<Vec<_>>()).await;
    for p in &mut by_path {
        p.icon = icons.get(&p.path).cloned().unwrap_or_default();
    }
    by_path.sort_by(|a, b| {
        b.has_window
            .cmp(&a.has_window)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(by_path)
}
