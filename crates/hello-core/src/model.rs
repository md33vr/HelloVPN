//! Модель данных. Имена полей совпадают с `launcher.json` Electron-версии,
//! поэтому настройки, серверы и подписки переезжают без конвертации.

use serde::{Deserialize, Serialize};

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Сервер (из ссылки или подписки).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Profile {
    pub id: String,
    pub name: String,
    /// vless | vmess | trojan | shadowsocks | hysteria2
    pub protocol: String,
    pub server: String,
    pub port: u16,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub flow: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub alter_id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cipher: String,

    /// none | tls | reality
    pub security: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fp: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pbk: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub spx: String,
    #[serde(skip_serializing_if = "is_false")]
    pub allow_insecure: bool,

    /// tcp | udp | ws | grpc | http | httpupgrade | xhttp
    pub network: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub service_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub header_type: String,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hop_ports: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub obfs: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub obfs_password: String,

    /// Исходная ссылка.
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_id: Option<String>,
    /// Исключён из автопереключения.
    #[serde(skip_serializing_if = "is_false")]
    pub no_auto: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct UserInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_info: Option<UserInfo>,
    /// Объявление провайдера (заголовок `announce`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub announce: String,
    /// Поддержка провайдера (`support-url`), например ссылка на Telegram.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub support_url: String,
    /// Сайт/личный кабинет (`profile-web-page-url`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub web_page_url: String,
    /// User-Agent, с которым подписка загрузилась в прошлый раз.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_ua: String,
}

/// Приложение в списке раздельного туннелирования.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct AppRule {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// name | path
    pub match_by: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// sing-box | xray
    pub core: String,
    /// include — только выбранные через VPN; exclude — всё, кроме выбранных
    pub mode: String,
    pub apps: Vec<AppRule>,
    pub active_profile_id: Option<String>,
    pub socks_port: u16,
    pub dns_remote: String,
    pub dns_direct: String,
    pub dns_others_via_vpn: bool,
    pub tun_stack: String,
    pub strict_route: bool,
    pub ipv6: bool,
    pub log_level: String,
    pub auto_switch: bool,
    pub check_interval: u32,
    pub sub_user_agent: String,
    /// Идентификатор устройства для подписок с ограничением по устройствам (x-hwid).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hwid: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            core: "sing-box".into(),
            mode: "include".into(),
            apps: vec![],
            active_profile_id: None,
            socks_port: 10808,
            dns_remote: "1.1.1.1".into(),
            dns_direct: "local".into(),
            dns_others_via_vpn: true,
            tun_stack: "mixed".into(),
            strict_route: true,
            ipv6: false,
            log_level: "info".into(),
            auto_switch: true,
            check_interval: 30,
            sub_user_agent: String::new(),
            hwid: String::new(),
        }
    }
}

/// Содержимое `launcher.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct StoreData {
    pub settings: Settings,
    pub profiles: Vec<Profile>,
    pub subscriptions: Vec<Subscription>,
}

impl StoreData {
    pub fn active_profile(&self) -> Option<&Profile> {
        let id = self.settings.active_profile_id.as_deref()?;
        self.profiles.iter().find(|p| p.id == id)
    }
}

/// Случайный короткий идентификатор (12 hex-символов).
pub fn new_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
