//! Hello! — VPN-клиент для Windows на Tauri.

mod app;
mod core;
mod cores;
mod diag;
mod logs;
mod platform;
mod procs;
mod store;
mod subs;

use tauri::{Manager, RunEvent};

pub fn run() {
    // Падения — в файл журнала, чтобы их можно было разобрать
    std::panic::set_hook(Box::new(|info| {
        logs::write_file(&format!(
            "[{}] PANIC: {info}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
    }));
    logs::write_file(&format!("==== Hello! {} старт", app::display_version()));
    let app = tauri::Builder::default()
        // Второй запуск просто показывает окно уже работающего Hello!
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            app::show_window(app)
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let handle = app.handle().clone();
            app.manage(app::init_state(&handle));
            if let Err(e) = app::create_tray(&handle) {
                logs::write_file(&format!("трей: {e}"));
            }
            app::show_window(&handle);
            handle.state::<app::AppState>().logs.push(
                "launcher",
                &format!("Hello! {} запущен", app::display_version()),
            );

            // Обновление подписок раз в 6 часов
            let h = handle.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(6 * 60 * 60)).await;
                    let st = h.state::<app::AppState>();
                    let _ = app::refresh_subs(st, None).await;
                }
            });
            // Подключение/отключение → подсказка и меню трея
            let h = handle.clone();
            use tauri::Listener;
            handle.listen("vpn:state", move |_| app::update_tray(&h));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app::get_state,
            app::get_logs,
            app::clear_logs,
            app::collect_logs,
            app::relaunch_admin,
            app::open_bin_dir,
            app::update_settings,
            app::import_profiles,
            app::refresh_subs,
            app::remove_sub,
            app::open_sub_link,
            app::remove_profile,
            app::set_profile_auto,
            app::select_profile,
            app::ping_profiles,
            app::list_processes,
            app::pick_exe,
            app::set_apps,
            app::app_icons,
            app::connect,
            app::disconnect,
            app::restart,
        ])
        .build(tauri::generate_context!());
    let app = match app {
        Ok(a) => a,
        Err(e) => {
            logs::write_file(&format!("Не удалось запустить: {e}"));
            return;
        }
    };
    app.run(|app, event| {
        // Закрытие окна не завершает программу: VPN продолжает работать из трея,
        // а само окно (WebView2) выгружается из памяти.
        match event {
            RunEvent::ExitRequested {
                api, code: None, ..
            } => api.prevent_exit(),
            RunEvent::Exit => {
                let core = app.state::<app::AppState>().core.clone();
                tauri::async_runtime::block_on(async move { core.stop().await });
            }
            _ => {}
        }
    });
}
