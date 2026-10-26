fn main() {
    // Hello! всегда работает с правами администратора: они нужны sing-box для TUN.
    // В манифесте НЕ должно быть строки <?xml ...?>: tauri-build вставляет его в ресурсы
    // с пробелом в начале строки, XML становится некорректным, и Windows отказывается
    // запускать exe («параллельная конфигурация неправильна»).
    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows-app-manifest.xml"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("tauri-build");
}
