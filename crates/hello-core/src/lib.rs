//! Логика Hello!, не зависящая от Windows и Tauri: разбор ссылок, конфиги ядер,
//! адрес TUN, вырезание секретов. Покрыта тестами (`cargo test -p hello-core`).

pub mod config;
pub mod diagnostics;
pub mod jsonsub;
pub mod model;
pub mod net;
pub mod parser;

#[cfg(test)]
mod tests;
