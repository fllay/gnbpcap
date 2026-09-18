//! Real end-to-end test: spawns the actual embedded server (the same
//! `gnbpcap_mcp::spawn` the Tauri toggle calls), sends genuine MCP
//! requests over HTTP, and cross-checks results against the ground truth
//! already established manually against these same capture files.
//!
//! Ignored by default since it needs real .pcap fixtures and `tshark`
//! installed — not something a fresh CI runner has. Run locally with
//! `cargo test -p gnbpcap-mcp -- --ignored`.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const GNB_MAC_SMALL: &str = "/Users/fa/Desktop/Projects/5g/pcap/gnb_mac.pcap";
const GNB_MAC_BIG: &str = "/Users/fa/Desktop/Projects/5g/pcap/A33_ocudu/gnb_mac.pcap";

/// rmcp's Streamable HTTP transport keeps the connection open as a
/// persistent event stream rather than closing after one response (unlike
/// the old Python/FastMCP server), so `read_to_string` (which waits for
/// EOF) hangs forever. Read incrementally instead and stop as soon as a
/// complete `data: {...}` JSON-RPC event has arrived, with a timeout as a
/// safety net rather than depending on the server ever closing the socket.
fn read_until_json_event(stream: &mut TcpStream, timeout: Duration) -> String {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set_read_timeout");
    let start = Instant::now();
    let mut buf = [0u8; 8192];
    let mut acc = String::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                if extract_sse_json_opt(&acc).is_some() {
                    return acc;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read error: {e}"),
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for a JSON-RPC event; got so far: {acc}");
        }
    }
    acc
}

fn extract_sse_json_opt(response: &str) -> Option<Value> {
    for line in response.lines() {
        if let Some(rest) = line.strip_prefix("data: ") {
            if let Ok(v) = serde_json::from_str::<Value>(rest) {
                return Some(v);
            }
        }
    }
    None
}

fn extract_sse_json(response: &str) -> Value {
    extract_sse_json_opt(response)
        .unwrap_or_else(|| panic!("no JSON-RPC data line found in response: {response}"))
}

fn split_headers_body(raw: &str) -> (&str, &str) {
    raw.split_once("\r\n\r\n").unwrap_or((raw, ""))
}

fn initialize(port: u16) -> String {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#;
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let response = read_until_json_event(&mut stream, Duration::from_secs(10));

    let (headers, _) = split_headers_body(&response);
    headers
        .lines()
        .find_map(|l| {
            l.to_lowercase()
                .starts_with("mcp-session-id:")
                .then(|| l.split_once(':').unwrap().1.trim().to_string())
        })
        .expect("mcp-session-id header")
}

fn call_tool(port: u16, session: &str, name: &str, arguments: Value) -> Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
    .to_string();
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMcp-Session-Id: {session}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let response = read_until_json_event(&mut stream, Duration::from_secs(30));

    let (_, resp_body) = split_headers_body(&response);
    let envelope = extract_sse_json(resp_body);
    let text = envelope["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content in response: {envelope}"));
    serde_json::from_str(text).unwrap_or_else(|_| panic!("tool result wasn't JSON: {text}"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn full_tool_suite_against_real_captures() {
    let port = 18901u16;
    let _handle = gnbpcap_mcp::spawn("127.0.0.1", port)
        .await
        .expect("spawn server");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // parse_pcap: small capture returns everything in one window.
    let session = initialize(port);
    let result = call_tool(
        port,
        &session,
        "parse_pcap",
        serde_json::json!({ "file_path": GNB_MAC_SMALL }),
    );
    assert_eq!(result["totalPackets"], 197);
    assert_eq!(result["returned"], 197);
    assert_eq!(result["hasMore"], false);

    // parse_pcap: big capture paginates and byte-caps automatically.
    let session = initialize(port);
    let result = call_tool(
        port,
        &session,
        "parse_pcap",
        serde_json::json!({ "file_path": GNB_MAC_BIG }),
    );
    assert_eq!(result["totalPackets"], 2156);
    assert!(result["returned"].as_u64().unwrap() < 2156);
    assert_eq!(result["hasMore"], true);
    let response_bytes = serde_json::to_string(&result).unwrap().len();
    assert!(response_bytes < 210_000, "response too large: {response_bytes}");

    // parse_pcap: protocol_filter narrows before pagination.
    let session = initialize(port);
    let result = call_tool(
        port,
        &session,
        "parse_pcap",
        serde_json::json!({ "file_path": GNB_MAC_BIG, "protocol_filter": ["RRC", "NAS-5GS"] }),
    );
    assert_eq!(result["totalPackets"], 1042);

    // get_packet_details: field_filter for a term known NOT present (ground truth from
    // earlier manual grep against the raw decoded tree: zero "redcap" matches in frame 30).
    let session = initialize(port);
    let result = call_tool(
        port,
        &session,
        "get_packet_details",
        serde_json::json!({ "file_path": GNB_MAC_BIG, "frame_num": 30, "field_filter": ["redcap"] }),
    );
    assert_eq!(result["matches"], 0);

    // get_packet_details: field_filter for a term known present.
    let session = initialize(port);
    let result = call_tool(
        port,
        &session,
        "get_packet_details",
        serde_json::json!({ "file_path": GNB_MAC_BIG, "frame_num": 30, "field_filter": ["accessstratumrelease"] }),
    );
    let text = serde_json::to_string(&result).unwrap();
    assert!(text.contains("rel15"), "expected rel15 in filtered result: {text}");

    // check_redcap_status: known ground truth for this capture (rel15, not RedCap capable).
    let session = initialize(port);
    let result = call_tool(
        port,
        &session,
        "check_redcap_status",
        serde_json::json!({ "file_path": GNB_MAC_BIG }),
    );
    assert_eq!(result["found"], true);
    assert_eq!(result["redcap_capable"], false);
    assert!(
        result["access_stratum_release"]
            .as_str()
            .unwrap()
            .contains("rel15")
    );

    let _ = session; // silence unused warning on the last iteration
}
