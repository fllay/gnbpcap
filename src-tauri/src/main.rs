#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use gnbpcap_core::{get_packet_details_blocking, parse_pcap_blocking, ParseResult, TreeNode};
use tauri::async_runtime::spawn_blocking;

#[tauri::command]
async fn parse_pcap(file_path: String) -> Result<ParseResult, String> {
    spawn_blocking(move || parse_pcap_blocking(&file_path))
        .await
        .map_err(|e| format!("parse worker failed: {e}"))?
}

#[tauri::command]
async fn get_packet_details(
    file_path: String,
    frame_num: u32,
    selected_decode_opts: Vec<String>,
) -> Result<Vec<TreeNode>, String> {
    spawn_blocking(move || {
        get_packet_details_blocking(&file_path, frame_num, &selected_decode_opts)
    })
    .await
    .map_err(|e| format!("details worker failed: {e}"))?
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![parse_pcap, get_packet_details])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
