//! Runs the embedded MCP server standalone, without the Tauri app — for
//! manual verification. Usage: `cargo run --example serve -p gnbpcap-mcp
//! [port]` (default port 8765, same as the Tauri app's toggle default).

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8765);
    let handle = gnbpcap_mcp::spawn("127.0.0.1", port)
        .await
        .expect("failed to bind/start server");
    println!("gnbpcap MCP server listening on http://127.0.0.1:{port}/mcp");
    let _ = handle.await;
}
