# Dev Context for AI Coding Assistants

This file is read by Claude Code and opencode to provide project context.

## Project

**5G NR Ladder Diagram Viewer** — a Tauri desktop app that reads PCAP files and renders 5G NR protocol traces as an interactive ladder diagram.

## Stack

- **Core parsing logic**: Rust (`gnbpcap-core/src/lib.rs`) — pure functions, no Tauri types. Invokes `tshark`, auto-selects a decode profile, parses PDML XML. Shared by all consumers below.
- **Desktop app**: Rust (`src-tauri/src/main.rs`) — thin Tauri command wrappers around `gnbpcap-core`, plus commands (`start_mcp_server`/`stop_mcp_server`/`mcp_server_status`) that start/stop the embedded MCP server for the UI's MCP on/off toggle
- **Embedded MCP server (Option B)**: Rust (`gnbpcap-mcp/src/lib.rs`) — native MCP server (via the `rmcp` SDK) that the Tauri app runs in-process (no subprocess) when the toggle is on. Calls `gnbpcap-core` directly, so it works identically in a downloaded release build or built from source — nothing is looked up by file path at runtime.
- **Frontend**: Plain HTML/CSS/JS (`ui/`) — canvas-based ladder diagram, no framework
- **Standalone MCP server (Option A)**: Python (`mcp-server/server.py`) — exposes the same tools to Claude Desktop via a small Rust CLI shim (`gnbpcap-cli`), for people who'd rather have Claude Desktop spawn a process itself over stdio than use the Tauri app's toggle. See `mcp-server/SETUP.md`.
- **Build tool**: Cargo workspace (root `Cargo.toml`) for the four Rust crates; Tauri CLI via npm (`package.json`) for the desktop app specifically

## Running in Dev Mode

```bash
PATH="/opt/homebrew/bin:$HOME/.cargo/bin:$PATH" npm run tauri:dev
```

- Node is at `/opt/homebrew/bin/node`
- Cargo/rustc is at `~/.cargo/bin/`
- Do NOT use `conda run` or `python` — this is not a Python project

## Key Files

| File | Purpose |
|------|---------|
| `gnbpcap-core/src/lib.rs` | All parsing logic: tshark invocation, decode-profile scoring, packet classification, PDML tree building. No Tauri deps — edit here, not in src-tauri or gnbpcap-mcp, for anything that should apply to the GUI and both MCP servers |
| `gnbpcap-mcp/src/lib.rs` | Native embedded MCP server (Option B) — calls gnbpcap-core directly (no subprocess). `spawn(host, port)` binds and returns an abortable `JoinHandle`. Tool logic (pagination/byte-cap/field_filter/node_id/max_depth/check_redcap_status) mirrors `mcp-server/server.py`'s — keep both in sync if you change one |
| `gnbpcap-cli/src/main.rs` | Thin CLI shim over gnbpcap-core (`parse-pcap`, `packet-details` subcommands), prints JSON to stdout. Only consumer is `mcp-server/server.py` (Option A) |
| `src-tauri/src/main.rs` | Tauri command wrappers for gnbpcap-core, plus `start_mcp_server`/`stop_mcp_server`/`mcp_server_status` — start/abort the `gnbpcap-mcp` server task in-process for the MCP toggle in the header |
| `mcp-server/server.py` | Standalone MCP server (Option A), runnable over stdio (default, spawned by an MCP client like Claude Desktop) or `--transport http --port N` (for manual testing — the Tauri toggle no longer uses this). `parse_pcap` paginates/byte-caps its output (with optional `protocol_filter`); `get_packet_details` supports `field_filter`/`node_id`/`max_depth` to scope into oversized decoded trees; `check_redcap_status` is a higher-level RedCap capability check |
| `ui/main.js` | All frontend logic: canvas rendering, Tauri invoke calls, state management |
| `ui/index.html` | App shell and layout |
| `ui/styles.css` | Styles |
| `Cargo.toml` (workspace root) | Cargo workspace members: gnbpcap-core, gnbpcap-cli, gnbpcap-mcp, src-tauri |
| `src-tauri/Cargo.toml` | Tauri-specific deps (tauri) + path deps on gnbpcap-core and gnbpcap-mcp |
| `src-tauri/tauri.conf.json` | Tauri window/app configuration |
| `package.json` | npm scripts: `tauri:dev`, `tauri:build` |

## Architecture Notes

- The Rust backend exposes two Tauri commands: `parse_pcap` and `get_packet_details`
- `parse_pcap` tries four decode profiles and picks the one with the highest score (most meaningful 5G packets)
- `get_packet_details` returns a PDML-derived recursive tree for a single frame
- All tshark calls are run via `spawn_blocking` to avoid blocking the async runtime
- Frontend holds all session state (loaded path, selected decode opts, packets, pagination)
- Both MCP servers (`gnbpcap-mcp` and `mcp-server/server.py`) cap every tool-call response well under typical LLM client size limits, since a full capture's packet list or a capability message's decoded tree can otherwise run into the hundreds of KB
- The MCP toggle in the UI runs `gnbpcap-mcp::spawn(...)` as a `tokio::spawn`'d task the Tauri app owns directly (`.abort()` on toggle-off or `RunEvent::Exit`) — no subprocess, no Python, nothing looked up by file path at runtime. This is why it works in a downloaded release build, unlike the old subprocess-based approach it replaced (which baked in `CARGO_MANIFEST_DIR` at compile time — broken the moment the app was built on a different machine than it runs on)
- Claude Desktop doesn't accept a bare `"url"` entry in `claude_desktop_config.json` (silently skipped as invalid) — point it at the toggle-controlled instance via the `mcp-remote` npm package as a stdio↔HTTP bridge instead (see `mcp-server/SETUP.md`, Option B). This is unaffected by the toggle's backend being native Rust now vs. Python before — `mcp-remote` just proxies to whatever's listening on the port
- `#[tokio::test]` defaults to a single-threaded runtime — a test that does blocking `std::net::TcpStream` I/O against a `tokio::spawn`'d server on the *same* runtime deadlocks (the blocking read never yields, so the server task never gets polled). Use `#[tokio::test(flavor = "multi_thread")]` for any test that spawns a server and talks to it in the same test function (see `gnbpcap-mcp/tests/integration.rs`)

## Do Not

- Do not add a Python/NiceGUI layer — the project was migrated away from `app.py`
- Do not introduce a JS framework unless explicitly requested
- Do not modify `Cargo.lock` or `package-lock.json` manually
