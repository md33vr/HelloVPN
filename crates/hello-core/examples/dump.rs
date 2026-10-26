//! Печатает конфиги для профилей из JSON (stdin) — для сверки с Electron-версией.
use hello_core::{config::*, model::*};
fn main() {
    let input: serde_json::Value = serde_json::from_reader(std::io::stdin()).unwrap();
    let profiles: Vec<Profile> = serde_json::from_value(input["profiles"].clone()).unwrap();
    let settings: Settings = serde_json::from_value(input["settings"].clone()).unwrap();
    let mut out = vec![];
    for p in &profiles {
        let sb = build_sing_box(
            p,
            &settings,
            &BuildOpts {
                tun_address: Some("10.254.233.1/30".into()),
                ..Default::default()
            },
        )
        .map_err(|e| e)
        .ok();
        let grp = auto_group(p, &profiles);
        let sbg = build_sing_box(
            p,
            &settings,
            &BuildOpts {
                group: grp,
                clash_api: Some(ClashApi {
                    port: 9999,
                    secret: "s".into(),
                }),
                tun_address: Some("10.254.233.1/30".into()),
            },
        )
        .ok();
        let xr = build_xray(
            p,
            &Settings {
                core: "xray".into(),
                ..settings.clone()
            },
        )
        .ok();
        out.push(serde_json::json!({ "name": p.name, "sb": sb, "sbg": sbg, "xr": xr }));
    }
    println!("{}", serde_json::to_string(&out).unwrap());
}
