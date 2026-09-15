//! Thin CLI wrapper around gnbpcap-core, so an out-of-process caller
//! (the Python MCP server in ../mcp-server) can get the exact same
//! parsing logic the Tauri GUI uses, as JSON on stdout.
//!
//! Usage:
//!   gnbpcap-cli parse-pcap <file_path>
//!   gnbpcap-cli packet-details <file_path> <frame_num> [decode_opt ...]
//!
//! On success: JSON result printed to stdout, exit code 0.
//! On failure: JSON {"error": "..."} printed to stdout, exit code 1.
//! (Errors go to stdout, not stderr, so the MCP server can always just
//! read + json-parse stdout regardless of outcome.)

use std::env;
use std::process::ExitCode;

fn print_ok<T: serde::Serialize>(value: &T) -> ExitCode {
    match serde_json::to_string(value) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{{\"error\": \"failed to serialize result: {e}\"}}");
            ExitCode::FAILURE
        }
    }
}

fn print_err(msg: &str) -> ExitCode {
    // Escape naively for JSON string safety.
    let escaped = msg.replace('\\', "\\\\").replace('"', "\\\"");
    println!("{{\"error\": \"{escaped}\"}}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        return print_err(
            "usage: gnbpcap-cli <parse-pcap <file>|packet-details <file> <frame_num> [decode_opt...]>",
        );
    }

    match args[1].as_str() {
        "parse-pcap" => {
            let file_path = &args[2];
            match gnbpcap_core::parse_pcap_blocking(file_path) {
                Ok(result) => print_ok(&result),
                Err(e) => print_err(&e),
            }
        }
        "packet-details" => {
            if args.len() < 4 {
                return print_err("packet-details requires <file> <frame_num> [decode_opt...]");
            }
            let file_path = &args[2];
            let frame_num: u32 = match args[3].parse() {
                Ok(n) => n,
                Err(_) => return print_err("frame_num must be an integer"),
            };
            let decode_opts: Vec<String> = args[4..].to_vec();
            match gnbpcap_core::get_packet_details_blocking(file_path, frame_num, &decode_opts) {
                Ok(nodes) => print_ok(&nodes),
                Err(e) => print_err(&e),
            }
        }
        other => print_err(&format!("unknown subcommand: {other}")),
    }
}
