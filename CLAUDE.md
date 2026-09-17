# Dev Context for AI Coding Assistants

This file is read by Claude Code and opencode to provide project context.

## Project

**5G NR Ladder Diagram Viewer** — a Tauri desktop app that reads PCAP files and renders 5G NR protocol traces as an interactive ladder diagram.

## Stack

- **Core parsing logic**: Rust (`gnbpcap-core/src/lib.rs`) — pure functions, no Tauri types. Invokes `tshark`, auto-selects a decode profile, parses PDML XML. Shared by both consumers below.
- **Desktop app**: Rust (`src-tauri/src/main.rs`) — thin Tauri command wrappers around `gnbpcap-core`, plus process-lifecycle commands (`start_mcp_server`/`stop_mcp_server`/`mcp_server_status`) for the UI's MCP on/off toggle
- **Frontend**: Plain HTML/CSS/JS (`ui/`) — canvas-based ladder diagram, no framework
- **MCP server**: Python (`mcp-server/server.py`) — exposes the same `gnbpcap-core` logic to Claude Desktop via a small Rust CLI shim (`gnbpcap-cli`), so Claude can call `parse_pcap`/`get_packet_details`/`check_redcap_status` directly. See `mcp-server/SETUP.md`.
- **Build tool**: Cargo workspace (root `Cargo.toml`) for the three Rust crates; Tauri CLI via npm (`package.json`) for the desktop app specifically

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
| `gnbpcap-core/src/lib.rs` | All parsing logic: tshark invocation, decode-profile scoring, packet classification, PDML tree building. No Tauri deps — edit here, not in src-tauri, for anything that should apply to both the GUI and the MCP server |
| `gnbpcap-cli/src/main.rs` | Thin CLI shim over gnbpcap-core (`parse-pcap`, `packet-details` subcommands), prints JSON to stdout. Only consumer is `mcp-server/server.py` |
| `src-tauri/src/main.rs` | Tauri command wrappers for gnbpcap-core, plus `start_mcp_server`/`stop_mcp_server`/`mcp_server_status` — spawns/kills `mcp-server/server.py --transport http` as a child process for the MCP toggle in the header |
| `mcp-server/server.py` | MCP server, runnable over stdio (default, spawned by an MCP client like Claude Desktop) or `--transport http --port N` (spawned/killed by the Tauri app's MCP toggle instead). `parse_pcap` paginates/byte-caps its output (with optional `protocol_filter`); `get_packet_details` supports `field_filter`/`node_id`/`max_depth` to scope into oversized decoded trees; `check_redcap_status` is a higher-level RedCap capability check |
| `ui/main.js` | All frontend logic: canvas rendering, Tauri invoke calls, state management |
| `ui/index.html` | App shell and layout |
| `ui/styles.css` | Styles |
| `Cargo.toml` (workspace root) | Cargo workspace members: gnbpcap-core, gnbpcap-cli, src-tauri |
| `src-tauri/Cargo.toml` | Tauri-specific deps only (tauri) + path dep on gnbpcap-core |
| `src-tauri/tauri.conf.json` | Tauri window/app configuration |
| `package.json` | npm scripts: `tauri:dev`, `tauri:build` |

## Architecture Notes

- The Rust backend exposes two Tauri commands: `parse_pcap` and `get_packet_details`
- `parse_pcap` tries four decode profiles and picks the one with the highest score (most meaningful 5G packets)
- `get_packet_details` returns a PDML-derived recursive tree for a single frame
- All tshark calls are run via `spawn_blocking` to avoid blocking the async runtime
- Frontend holds all session state (loaded path, selected decode opts, packets, pagination)
- The MCP server (`mcp-server/server.py`) is a separate, stateless consumer of the same core logic via `gnbpcap-cli` — any single tool-call response is capped well under typical LLM client size limits, since a full capture's packet list or a capability message's decoded tree can otherwise run into the hundreds of KB
- The MCP toggle in the UI runs the server as an HTTP process the Tauri app owns (`RunEvent::Exit` kills it if the app quits while it's on) — this is a separate mode from a client (e.g. Claude Desktop) spawning it over stdio. Claude Desktop doesn't accept a bare `"url"` entry in `claude_desktop_config.json` (silently skipped as invalid) — point it at the toggle-controlled instance via the `mcp-remote` npm package as a stdio↔HTTP bridge instead (see `mcp-server/SETUP.md`, Option B)

## Do Not

- Do not add a Python/NiceGUI layer — the project was migrated away from `app.py`
- Do not introduce a JS framework unless explicitly requested
- Do not modify `Cargo.lock` or `package-lock.json` manually
