# Dev Context for AI Coding Assistants

This file is read by Claude Code and opencode to provide project context.

## Project

**5G NR Ladder Diagram Viewer** — a Tauri desktop app that reads PCAP files and renders 5G NR protocol traces as an interactive ladder diagram.

## Stack

- **Backend**: Rust (`src-tauri/src/main.rs`) — Tauri commands that invoke `tshark` and parse PDML XML
- **Frontend**: Plain HTML/CSS/JS (`ui/`) — canvas-based ladder diagram, no framework
- **Build tool**: Tauri CLI via npm (`package.json`)

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
| `src-tauri/src/main.rs` | All backend logic: tshark invocation, packet parsing, PDML tree building |
| `ui/main.js` | All frontend logic: canvas rendering, Tauri invoke calls, state management |
| `ui/index.html` | App shell and layout |
| `ui/styles.css` | Styles |
| `src-tauri/Cargo.toml` | Rust dependencies (tauri 1.6, serde, xmltree) |
| `src-tauri/tauri.conf.json` | Tauri window/app configuration |
| `package.json` | npm scripts: `tauri:dev`, `tauri:build` |

## Architecture Notes

- The Rust backend exposes two Tauri commands: `parse_pcap` and `get_packet_details`
- `parse_pcap` tries four decode profiles and picks the one with the highest score (most meaningful 5G packets)
- `get_packet_details` returns a PDML-derived recursive tree for a single frame
- All tshark calls are run via `spawn_blocking` to avoid blocking the async runtime
- Frontend holds all session state (loaded path, selected decode opts, packets, pagination)

## Do Not

- Do not add a Python/NiceGUI layer — the project was migrated away from `app.py`
- Do not introduce a JS framework unless explicitly requested
- Do not modify `Cargo.lock` or `package-lock.json` manually
