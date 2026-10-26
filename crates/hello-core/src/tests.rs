//! Те же проверки, что были в scripts/selftest.js Electron-версии.

use crate::config::*;
use crate::diagnostics::*;
use crate::model::*;
use crate::net::*;
use crate::parser::*;
use base64::Engine;
use serde_json::Value;

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

const REALITY: &str = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY123&sid=abcd&flow=xtls-rprx-vision#%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B";
const VLESS_WS: &str = "vless://uuid-ws@cdn.example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com#WS";
const XHTTP: &str =
    "vless://uuid-x@x.example.com:443?type=xhttp&security=tls&path=%2Fxh&mode=packet-up#XHTTP";
const TROJAN: &str = "trojan://p%40ss@tr.example.com:8443?sni=tr.example.com#Trojan";
const SS2022: &str =
    "ss://2022-blake3-aes-128-gcm:a2V5MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@9.9.9.9:443#SS2022";
const HY2: &str = "hysteria2://authpass@hy.example.com:443,20000-30000/?sni=hy.example.com&obfs=salamander&obfs-password=obfspw&insecure=1#HY2";

fn vmess() -> String {
    format!(
        "vmess://{}",
        b64(
            r#"{"v":"2","ps":"VMess gRPC","add":"vm.example.com","port":"443","id":"uuid-vm","aid":"0","net":"grpc","path":"grpcsvc","tls":"tls","sni":"vm.example.com"}"#
        )
    )
}
fn ss() -> String {
    format!(
        "ss://{}@5.6.7.8:8388#SS",
        b64("chacha20-ietf-poly1305:secret")
    )
}
fn all_links() -> Vec<String> {
    vec![
        REALITY.into(),
        VLESS_WS.into(),
        XHTTP.into(),
        vmess(),
        TROJAN.into(),
        ss(),
        SS2022.into(),
        HY2.into(),
    ]
}

fn settings() -> Settings {
    Settings {
        apps: vec![
            AppRule {
                name: "chrome.exe".into(),
                path: Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe".into()),
                match_by: "name".into(),
                enabled: true,
            },
            AppRule {
                name: "Telegram.exe".into(),
                path: Some(r"C:\Users\me\AppData\Roaming\Telegram Desktop\Telegram.exe".into()),
                match_by: "path".into(),
                enabled: true,
            },
            AppRule {
                name: "off.exe".into(),
                path: None,
                match_by: "name".into(),
                enabled: false,
            },
        ],
        ..Default::default()
    }
}

#[test]
fn parses_all_links() {
    let r = parse_link(REALITY).unwrap();
    assert_eq!(r.name, "Нидерланды");
    assert_eq!(r.security, "reality");
    assert_eq!(r.flow, "xtls-rprx-vision");
    assert_eq!(r.uuid, "11111111-2222-3333-4444-555555555555");
    assert_eq!(parse_link(&vmess()).unwrap().service_name, "grpcsvc");
    assert_eq!(parse_link(TROJAN).unwrap().password, "p@ss");
    assert_eq!(parse_link(&ss()).unwrap().method, "chacha20-ietf-poly1305");
    assert_eq!(
        parse_link(SS2022).unwrap().password,
        "a2V5MTIzNDU2Nzg5MDEyMzQ1Ng=="
    );
    let hy = parse_link(HY2).unwrap();
    assert_eq!(hy.hop_ports, vec!["443", "20000:30000"]);
    assert_eq!(hy.port, 443);
    assert_eq!(hy.obfs_password, "obfspw");
    assert!(hy.allow_insecure);
    assert!(parse_link("tuic://x@y:1").is_err());
}

#[test]
fn parses_base64_subscription() {
    let sub = b64(&all_links().join("\n"));
    let r = parse_many(&sub);
    assert_eq!(r.profiles.len(), 8, "{:?}", r.errors);
    // URL-safe base64 без паддинга тоже
    let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(all_links().join("\n"));
    assert_eq!(parse_many(&url_safe).profiles.len(), 8);
}

#[test]
fn user_info_and_title() {
    let u = parse_user_info("upload=1000; download=2000; total=10737418240; expire=1798000000")
        .unwrap();
    assert_eq!(u.total, Some(10737418240));
    assert_eq!(u.expire, Some(1798000000));
    assert_eq!(
        parse_profile_title(&format!("base64:{}", b64("Мой провайдер"))),
        "Мой провайдер"
    );
}

fn rules(cfg: &Value) -> &Vec<Value> {
    cfg["route"]["rules"].as_array().unwrap()
}

#[test]
fn sing_box_include_and_exclude() {
    let p = parse_link(REALITY).unwrap();
    let s = Settings {
        mode: "include".into(),
        ..settings()
    };
    let cfg = build_sing_box(&p, &s, &BuildOpts::default()).unwrap();
    assert_eq!(cfg["route"]["final"], "direct");
    assert_eq!(
        cfg["outbounds"][0]["tls"]["reality"]["public_key"],
        "PUBKEY123"
    );
    let app_rules: Vec<&Value> = rules(&cfg)
        .iter()
        .filter(|r| {
            r.get("process_path").is_some()
                || r["process_name"]
                    .as_array()
                    .is_some_and(|a| a.contains(&"chrome.exe".into()))
        })
        .collect();
    assert_eq!(app_rules.len(), 2);
    assert!(app_rules.iter().all(|r| r["outbound"] == "proxy"));
    assert!(!cfg.to_string().contains("off.exe"));
    assert!(
        cfg["log"].get("disable_color").is_none(),
        "в sing-box нет поля log.disable_color"
    );

    let s = Settings {
        mode: "exclude".into(),
        ..settings()
    };
    let cfg = build_sing_box(&p, &s, &BuildOpts::default()).unwrap();
    assert_eq!(cfg["route"]["final"], "proxy");
    assert!(rules(&cfg).iter().any(|r| r["process_name"]
        .as_array()
        .is_some_and(|a| a.contains(&"chrome.exe".into()))
        && r["outbound"] == "direct"));
    assert!(rules(&cfg).iter().any(|r| r["process_name"]
        .as_array()
        .is_some_and(|a| a.contains(&"xray.exe".into()))
        && r["outbound"] == "direct"));
}

#[test]
fn transports() {
    let ws = build_sing_box(
        &parse_link(VLESS_WS).unwrap(),
        &settings(),
        &BuildOpts::default(),
    )
    .unwrap();
    assert_eq!(ws["outbounds"][0]["transport"]["path"], "/ws");
    assert_eq!(ws["outbounds"][0]["transport"]["max_early_data"], 2048);

    let hy = build_sing_box(
        &parse_link(HY2).unwrap(),
        &settings(),
        &BuildOpts::default(),
    )
    .unwrap();
    assert_eq!(
        hy["outbounds"][0]["server_ports"],
        serde_json::json!(["443", "20000:30000"])
    );
    assert!(hy["outbounds"][0].get("server_port").is_none());
    assert_eq!(hy["outbounds"][0]["obfs"]["type"], "salamander");
    assert_eq!(hy["outbounds"][0]["tls"]["alpn"], serde_json::json!(["h3"]));

    let vm = build_sing_box(
        &parse_link(&vmess()).unwrap(),
        &settings(),
        &BuildOpts::default(),
    )
    .unwrap();
    assert_eq!(vm["outbounds"][0]["transport"]["service_name"], "grpcsvc");

    // XHTTP — только Xray
    let x = parse_link(XHTTP).unwrap();
    assert!(build_sing_box(&x, &settings(), &BuildOpts::default())
        .unwrap_err()
        .contains("XHTTP"));
    let xs = Settings {
        core: "xray".into(),
        ..settings()
    };
    assert_eq!(
        build_xray(&x, &xs).unwrap()["outbounds"][0]["streamSettings"]["network"],
        "xhttp"
    );
    assert_eq!(
        build_sing_box(&x, &xs, &BuildOpts::default()).unwrap()["outbounds"][0]["type"],
        "socks"
    );
}

#[test]
fn xray_outbounds() {
    let s = settings();
    assert_eq!(
        build_xray(&parse_link(REALITY).unwrap(), &s).unwrap()["outbounds"][0]["streamSettings"]
            ["realitySettings"]["publicKey"],
        "PUBKEY123"
    );
    assert_eq!(
        build_xray(&parse_link(&ss()).unwrap(), &s).unwrap()["outbounds"][0]["settings"]["servers"]
            [0]["port"],
        8388
    );
    assert_eq!(
        build_xray(&parse_link(TROJAN).unwrap(), &s).unwrap()["outbounds"][0]["streamSettings"]
            ["security"],
        "tls"
    );
    assert!(build_xray(&parse_link(HY2).unwrap(), &s)
        .unwrap_err()
        .contains("sing-box"));
}

#[test]
fn tun_address() {
    let ip = |a: &str, m: &str| IfAddr {
        ip: a.parse().unwrap(),
        mask: m.parse().unwrap(),
    };
    assert_eq!(pick_tun_address(&[]), "172.19.0.1/30");
    assert_eq!(
        pick_tun_address(&[ip("172.19.0.1", "255.255.255.240")]),
        "172.31.233.1/30"
    );
    assert_eq!(
        pick_tun_address(&[
            ip("172.19.0.1", "255.255.255.252"),
            ip("172.31.0.5", "255.255.0.0")
        ]),
        "10.254.233.1/30"
    );
}

fn sub_profiles() -> Vec<Profile> {
    let mut v: Vec<Profile> = parse_many(&b64(&all_links().join("\n"))).profiles;
    for p in &mut v {
        p.sub_id = Some("S1".into());
    }
    v.iter_mut()
        .find(|p| p.protocol == "trojan")
        .unwrap()
        .no_auto = true;
    v
}

#[test]
fn auto_switch_group() {
    let all = sub_profiles();
    let sel = all
        .iter()
        .find(|p| p.security == "reality")
        .unwrap()
        .clone();
    let grp = auto_group(&sel, &all);
    assert_eq!(grp[0].id, sel.id);
    assert!(
        !grp.iter().any(|p| p.protocol == "trojan"),
        "исключённый сервер не в группе"
    );
    assert!(
        !grp.iter().any(|p| p.network == "xhttp"),
        "XHTTP не поддерживается sing-box"
    );
    let opts = BuildOpts {
        group: grp.clone(),
        clash_api: Some(ClashApi {
            port: 9999,
            secret: "s".into(),
        }),
        tun_address: Some("10.254.233.1/30".into()),
    };
    let cfg = build_sing_box(&sel, &settings(), &opts).unwrap();
    let selector = cfg["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "selector")
        .unwrap();
    assert_eq!(selector["tag"], "proxy");
    assert_eq!(selector["default"], member_tag(&sel));
    assert_eq!(selector["outbounds"].as_array().unwrap().len(), grp.len());
    assert_eq!(cfg["inbounds"][0]["address"][0], "10.254.233.1/30");
    assert_eq!(cfg["inbounds"][0]["interface_name"], "Hello");
    assert_eq!(
        cfg["experimental"]["clash_api"]["external_controller"],
        "127.0.0.1:9999"
    );
    assert!(cfg["dns"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["domain"]
            .as_array()
            .is_some_and(|d| d.contains(&"hy.example.com".into()))));
    // без группы — одиночный outbound «proxy»
    assert_eq!(
        build_sing_box(
            &sel,
            &settings(),
            &BuildOpts {
                group: vec![sel.clone()],
                ..Default::default()
            }
        )
        .unwrap()["outbounds"][0]["tag"],
        "proxy"
    );
}

#[test]
fn diagnostics_scrub_and_zip() {
    let all = sub_profiles();
    let sel = all
        .iter()
        .find(|p| p.security == "reality")
        .unwrap()
        .clone();
    let opts = BuildOpts {
        group: auto_group(&sel, &all),
        clash_api: Some(ClashApi {
            port: 9999,
            secret: "topsecret".into(),
        }),
        tun_address: Some("10.254.233.1/30".into()),
    };
    let cfg = build_sing_box(&sel, &settings(), &opts).unwrap();
    let sc = Scrubber::from_store(
        &all,
        &[Subscription {
            url: "https://sub.example.com/abcDEF123secret".into(),
            ..Default::default()
        }],
    );
    let red = redact(&cfg, &sc).to_string();
    for secret in [
        "11111111-2222-3333-4444-555555555555",
        "PUBKEY123",
        "authpass",
        "obfspw",
        "cdn.example.com",
        "1.2.3.4",
        "topsecret",
    ] {
        assert!(!red.contains(secret), "секрет просочился: {secret}");
    }
    assert!(
        red.contains("10.254.233.1/30"),
        "адрес TUN должен остаться для отладки"
    );
    assert!(!sc
        .scrub("sub https://sub.example.com/abcDEF123secret ok")
        .contains("abcDEF123secret"));
    assert!(!sc.scrub(REALITY).contains("PUBKEY123"));
    assert_eq!(
        Scrubber::new(vec![]).scrub("id 123e4567-e89b-12d3-a456-426614174000 end"),
        "id *** end"
    );
    assert_eq!(
        Scrubber::new(vec![]).scrub("x vless://abc@h:1?y=1 z"),
        "x <ссылка ***> z"
    );

    let z = make_zip(&[
        Entry::text("a.txt", "привет"),
        Entry::text("dir/b.json", "{\"x\":1}"),
    ])
    .unwrap();
    let mut ar = zip::ZipArchive::new(std::io::Cursor::new(z)).unwrap();
    let mut s = String::new();
    std::io::Read::read_to_string(&mut ar.by_name("a.txt").unwrap(), &mut s).unwrap();
    assert_eq!(s, "привет");
    assert_eq!(ar.len(), 2);
}

#[test]
fn reads_electron_launcher_json() {
    let json = r#"{
      "settings": {"core":"sing-box","mode":"include","apps":[{"name":"chrome.exe","path":"C:\\x\\chrome.exe","matchBy":"name","enabled":true},{"name":"Discord.exe","path":"","matchBy":"name","enabled":false}],
        "activeProfileId":"abc","socksPort":10808,"dnsRemote":"1.1.1.1","dnsDirect":"local","dnsOthersViaVpn":true,"tunStack":"mixed","strictRoute":true,
        "ipv6":false,"logLevel":"info","autoSwitch":true,"checkInterval":30,"subUserAgent":"VPNLauncher/1.0"},
      "profiles":[{"protocol":"vless","name":"NL","server":"nl.example.com","port":443,"security":"reality","sni":"a","fp":"chrome","alpn":[],"pbk":"K","sid":"","spx":"",
        "allowInsecure":false,"network":"tcp","path":"","host":"","serviceName":"","mode":"","headerType":"","uuid":"u","flow":"xtls-rprx-vision","id":"abc","raw":"vless://...","subId":"s1","noAuto":true}],
      "subscriptions":[{"id":"s1","name":"Мой провайдер","url":"https://x","updatedAt":1792900000000,"userInfo":{"upload":1,"download":2,"total":3,"expire":4}}]
    }"#;
    let d: StoreData = serde_json::from_str(json).unwrap();
    assert_eq!(d.settings.apps.len(), 2);
    assert_eq!(d.active_profile().unwrap().name, "NL");
    assert!(d.profiles[0].no_auto);
    assert_eq!(
        d.subscriptions[0].user_info.as_ref().unwrap().total,
        Some(3)
    );
    assert_eq!(d.settings.sub_user_agent, "VPNLauncher/1.0");
    // и обратно — те же имена полей
    let back = serde_json::to_value(&d).unwrap();
    assert_eq!(back["settings"]["activeProfileId"], "abc");
    assert_eq!(back["profiles"][0]["subId"], "s1");
    assert_eq!(back["profiles"][0]["noAuto"], true);
}

#[test]
fn json_xray_subscription() {
    let text = r#"[
      {"remarks":"🇳🇱 Нидерланды","outbounds":[
        {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"nl.example.com","port":443,
          "users":[{"id":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision","encryption":"none"}]}]},
         "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.org",
          "fingerprint":"chrome","publicKey":"PBK","shortId":"ab12","spiderX":"/"}}},
        {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]},
      {"remarks":"🇩🇪 Германия XHTTP","outbounds":[
        {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"de.example.com","port":8443,
          "users":[{"id":"aaaaaaaa-2222-3333-4444-555555555555","encryption":"none"}]}]},
         "streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"de.example.com","alpn":["h2"]},
          "xhttpSettings":{"path":"/x","mode":"auto"}}},
        {"tag":"direct","protocol":"freedom"}]}
    ]"#;
    let r = crate::parser::parse_many(text);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.profiles.len(), 2);
    let a = &r.profiles[0];
    assert_eq!(a.name, "🇳🇱 Нидерланды");
    assert_eq!(
        (a.protocol.as_str(), a.server.as_str(), a.port),
        ("vless", "nl.example.com", 443)
    );
    assert_eq!(
        (a.security.as_str(), a.pbk.as_str(), a.sid.as_str()),
        ("reality", "PBK", "ab12")
    );
    assert_eq!(a.flow, "xtls-rprx-vision");
    assert_eq!(a.network, "tcp");
    let b = &r.profiles[1];
    assert_eq!(
        (b.network.as_str(), b.path.as_str(), b.security.as_str()),
        ("xhttp", "/x", "tls")
    );
    assert_eq!(b.alpn, vec!["h2".to_string()]);
    // Повторный разбор даёт тот же raw — выбор сервера переживает обновление подписки
    assert_eq!(crate::parser::parse_many(text).profiles[0].raw, a.raw);
    // И из него строится рабочий конфиг sing-box
    let cfg = build_sing_box(a, &Settings::default(), &BuildOpts::default());
    assert!(cfg.is_ok(), "{:?}", cfg.err());
}

#[test]
fn json_singbox_subscription() {
    let text = r#"{"outbounds":[
      {"type":"selector","tag":"select","outbounds":["a","b"]},
      {"type":"trojan","tag":"a","server":"t.example.com","server_port":443,"password":"pw",
       "tls":{"enabled":true,"server_name":"t.example.com"},"transport":{"type":"ws","path":"/ws","headers":{"Host":"cdn.example.com"}}},
      {"type":"hysteria2","tag":"b","server":"h.example.com","server_port":443,"password":"pw2",
       "obfs":{"type":"salamander","password":"ob"},"tls":{"enabled":true,"server_name":"h.example.com"}},
      {"type":"direct","tag":"direct"}]}"#;
    let r = crate::parser::parse_many(text);
    assert_eq!(r.profiles.len(), 2, "{:?}", r.errors);
    let t = &r.profiles[0];
    assert_eq!(
        (t.protocol.as_str(), t.network.as_str(), t.host.as_str()),
        ("trojan", "ws", "cdn.example.com")
    );
    let h = &r.profiles[1];
    assert_eq!(
        (h.protocol.as_str(), h.obfs.as_str(), h.network.as_str()),
        ("hysteria2", "salamander", "udp")
    );
}

#[test]
fn announce_header() {
    use crate::parser::parse_profile_title;
    assert_eq!(parse_profile_title("base64:0J/RgNC40LLQtdGC"), "Привет");
    assert_eq!(parse_profile_title("Hello%20world"), "Hello world");
}
