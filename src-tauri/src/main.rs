#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use gnbpcap_core::{get_packet_details_blocking, parse_pcap_blocking, ParseResult, TreeNode};
use serde::Serialize;
use std::sync::Mutex;
use tauri::async_runtime::spawn_blocking;
use tauri::{Manager, RunEvent, State};
use tokio::task::JoinHandle;

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

/// Holds the running embedded MCP server task, if the toggle is currently
/// on, plus the port it's listening on. This runs entirely in-process
/// (no subprocess, no Python) via gnbpcap-mcp, so it works in a downloaded
/// release build the same as it does when built from source.
#[derive(Default)]
struct McpServerState(Mutex<Option<(JoinHandle<()>, u16)>>);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct McpStatus {
    running: bool,
    port: Option<u16>,
}

#[tauri::command]
async fn start_mcp_server(
    state: State<'_, McpServerState>,
    port: Option<u16>,
) -> Result<u16, String> {
    {
        let guard = state.0.lock().map_err(|e| e.to_string())?;
        if let Some((handle, existing_port)) = guard.as_ref() {
            if !handle.is_finished() {
                return Ok(*existing_port);
            }
        }
    }

    let port = port.unwrap_or(8765);
    let handle = gnbpcap_mcp::spawn("127.0.0.1", port)
        .await
        .map_err(|e| format!("failed to start MCP server on port {port}: {e}"))?;

    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    *guard = Some((handle, port));
    Ok(port)
}

#[tauri::command]
fn stop_mcp_server(state: State<McpServerState>) -> Result<(), String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    if let Some((handle, _)) = guard.take() {
        handle.abort();
    }
    Ok(())
}

#[tauri::command]
fn mcp_server_status(state: State<McpServerState>) -> Result<McpStatus, String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;

    let still_running = match guard.as_ref() {
        Some((handle, _)) => !handle.is_finished(),
        None => false,
    };

    if !still_running {
        *guard = None;
        return Ok(McpStatus {
            running: false,
            port: None,
        });
    }

    let port = guard.as_ref().unwrap().1;
    Ok(McpStatus {
        running: true,
        port: Some(port),
    })
}

fn main() {
    tauri::Builder::default()
        .manage(McpServerState::default())
        .invoke_handler(tauri::generate_handler![
            parse_pcap,
            get_packet_details,
            start_mcp_server,
            stop_mcp_server,
            mcp_server_status
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app_handle.try_state::<McpServerState>() {
                    if let Ok(mut guard) = state.0.lock() {
                        if let Some((handle, _)) = guard.take() {
                            handle.abort();
                        }
                    }
                }
            }
        });
}
