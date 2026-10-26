// Без окна консоли в релизной сборке
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    hello_lib::run()
}
