#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use gnbpcap_core::{get_packet_details_blocking, parse_pcap_blocking, ParseResult, TreeNode};
use serde::Serialize;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::async_runtime::spawn_blocking;
use tauri::{Manager, RunEvent, State};

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

/// Holds the spawned `mcp-server/server.py --transport http` child process,
/// if the MCP toggle is currently on, plus the port it's listening on.
#[derive(Default)]
struct McpServerState(Mutex<Option<(Child, u16)>>);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct McpStatus {
    running: bool,
    port: Option<u16>,
}

fn mcp_server_script_path() -> String {
    std::env::var("GNBPCAP_MCP_SERVER").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../mcp-server/server.py").to_string()
    })
}

fn mcp_python_bin() -> String {
    std::env::var("GNBPCAP_MCP_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

fn port_is_listening(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[tauri::command]
fn start_mcp_server(state: State<McpServerState>, port: Option<u16>) -> Result<u16, String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;

    if let Some((child, existing_port)) = guard.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return Ok(*existing_port);
        }
    }

    let port = port.unwrap_or(8765);
    let script = mcp_server_script_path();
    if !std::path::Path::new(&script).exists() {
        return Err(format!(
            "MCP server script not found: {script}. Set GNBPCAP_MCP_SERVER if it's not at the default location."
        ));
    }

    let mut child = Command::new(mcp_python_bin())
        .arg(&script)
        .arg("--transport")
        .arg("http")
        .arg("--port")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start MCP server ({}): {e}", mcp_python_bin()))?;

    if !port_is_listening(port, Duration::from_secs(5)) {
        kill_child(&mut child);
        return Err(format!(
            "MCP server did not start listening on port {port} within 5s — check that `pip install -r mcp-server/requirements.txt` has been run."
        ));
    }

    *guard = Some((child, port));
    Ok(port)
}

#[tauri::command]
fn stop_mcp_server(state: State<McpServerState>) -> Result<(), String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;
    if let Some((mut child, _)) = guard.take() {
        kill_child(&mut child);
    }
    Ok(())
}

#[tauri::command]
fn mcp_server_status(state: State<McpServerState>) -> Result<McpStatus, String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;

    let still_running = match guard.as_mut() {
        Some((child, _)) => matches!(child.try_wait(), Ok(None)),
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
                        if let Some((mut child, _)) = guard.take() {
                            kill_child(&mut child);
                        }
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the actual spawn/poll/kill sequence start_mcp_server and
    /// stop_mcp_server use, against the real mcp-server/server.py, without
    /// needing a running Tauri app to extract State from.
    #[test]
    fn spawns_http_server_and_it_becomes_reachable_then_stops() {
        let script = mcp_server_script_path();
        assert!(
            std::path::Path::new(&script).exists(),
            "expected mcp-server/server.py at {script}"
        );

        let port = 18765u16;
        let mut child = Command::new(mcp_python_bin())
            .arg(&script)
            .arg("--transport")
            .arg("http")
            .arg("--port")
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn python3 mcp-server/server.py");

        assert!(
            port_is_listening(port, Duration::from_secs(5)),
            "server did not start listening in time"
        );

        // Not accepting connections proves nothing about correctness on its
        // own — confirm it's actually speaking MCP over HTTP, not just any
        // listener on that port.
        let body = ureq_post_initialize(port);
        assert!(
            body.contains("\"serverInfo\""),
            "expected an MCP initialize response, got: {body}"
        );

        kill_child(&mut child);
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "port should be free again after kill_child"
        );
    }

    /// Minimal hand-rolled HTTP POST — avoids pulling in an HTTP client
    /// dependency just for this one test.
    fn ureq_post_initialize(port: u16) -> String {
        use std::io::{Read, Write};
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );

        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).expect("connect for initialize request");
        stream.write_all(request.as_bytes()).expect("write request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read response");
        response
    }
}
