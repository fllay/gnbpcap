# 5G NR Ladder Diagram Viewer

A desktop application for visualizing 5G NR (New Radio) protocol traces as an interactive ladder diagram. Built with [Tauri](https://tauri.app/) (Rust backend + HTML/JS frontend) and uses Wireshark's `tshark` for deep protocol decoding.

![5G NR Ladder Diagram Viewer](docs/screenshot.png)

## Features

- **Load PCAP files** — Browse or enter a file path directly
- **Ladder Diagram** — Visualizes UE ↔ gNB message exchanges over time
- **Protocol Layers** — Color-coded by layer: MAC, RLC, RRC, NGAP, NAS-5GS
- **Filtering** — Filter by protocol layer or UE/IP address
- **Click for Details** — Click any message to see the full Wireshark-like protocol tree
- **Packet Details Search** — Search fields in the protocol tree with autocomplete and match navigation
- **Pagination** — Navigate through large captures with page controls

## Requirements

- **Wireshark** (provides `tshark`)
- **Rust toolchain** — install via [rustup](https://rustup.rs/)
- **Node.js + npm**

`tshark` is discovered automatically in this order:
1. `TSHARK_BIN` environment variable
2. `/Applications/Wireshark.app/Contents/MacOS/tshark` (macOS)
3. `/opt/homebrew/bin/tshark`
4. `/usr/local/bin/tshark`
5. `/usr/bin/tshark` (default location on Ubuntu/Debian)
6. Any `tshark` in `PATH`

macOS is the primary, actively-used platform. [CI](#ci--releases) verifies
the Rust workspace (including the Tauri app crate, which needs the Ubuntu
system libraries below) actually compiles on Ubuntu and Windows runners
for every push — but the full local setup steps (installers, `npm run
tauri:dev`, actually running the built app) haven't been tried end-to-end
by a person on those platforms. If something's off, please open an issue.

## Setup

### macOS

```bash
brew install node wireshark
git clone <repo>
cd gnbpcap
npm install
```

### Ubuntu / Debian Linux

Tauri needs a handful of system libraries beyond Rust/Node — install them
along with `tshark`:

```bash
sudo apt update
sudo apt install -y tshark libwebkit2gtk-4.0-dev build-essential curl wget \
  file libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install Node.js (Ubuntu's default `apt` package is often outdated — either
use [nvm](https://github.com/nvm-sh/nvm) for a current version, or the
distro package if it's new enough):

```bash
sudo apt install -y nodejs npm
```

Then clone and install as usual:

```bash
git clone <repo>
cd gnbpcap
npm install
```

The `tshark` install prompts about allowing non-root packet capture —
answer either way, since gnbpcap only ever reads existing `.pcap` files,
never captures live traffic.

### Windows

1. Install Rust via [rustup](https://rustup.rs/) (`rustup-init.exe`), plus
   the **Microsoft C++ Build Tools** (Visual Studio Build Tools, with the
   "Desktop development with C++" workload) — Tauri needs the MSVC linker.
2. Install [Node.js](https://nodejs.org/) (official Windows installer).
3. Install [Wireshark](https://www.wireshark.org/) (official Windows
   installer). Auto-discovery doesn't cover Windows paths yet, so set
   `TSHARK_BIN` explicitly, typically:
   ```
   C:\Program Files\Wireshark\tshark.exe
   ```
   (forward slashes also work: `C:/Program Files/Wireshark/tshark.exe`)
4. WebView2 (Tauri's Windows renderer) ships with Windows 10/11 by
   default; if missing, install the
   [Evergreen Bootstrapper](https://developer.microsoft.com/microsoft-edge/webview2/).

```powershell
git clone <repo>
cd gnbpcap
npm install
```

## Development

macOS (Homebrew's paths aren't on `PATH` by default for GUI-launched
processes, so they're prefixed explicitly):

```bash
PATH="/opt/homebrew/bin:$HOME/.cargo/bin:$PATH" npm run tauri:dev
```

Ubuntu/Linux and Windows (rustup/Node installers already put both on
`PATH`):

```bash
npm run tauri:dev
```

The desktop window opens directly via Tauri WebView.

## Build

macOS:

```bash
PATH="/opt/homebrew/bin:$HOME/.cargo/bin:$PATH" npm run tauri:build
```

Ubuntu/Linux and Windows:

```bash
npm run tauri:build
```

## Claude Desktop Integration (MCP)

Besides the Tauri GUI, gnbpcap's PCAP parsing is also available directly in
[Claude Desktop](https://claude.ai/download) chat via an MCP (Model Context
Protocol) server — no need to open the desktop app to ask questions about a
capture. There are two ways to run it; both expose the same three tools.

### Option B: the app's MCP toggle (recommended — nothing extra to install)

The Tauri app has an **MCP toggle** in its header. Flip it on and the app
runs a native Rust MCP server in-process (the `gnbpcap-mcp` crate — no
Python, no `pip install`, nothing to build separately) on
`http://127.0.0.1:8765/mcp`. Flip it off (or quit the app) and it stops.

Claude Desktop's config doesn't accept a bare `url` entry, so point it at
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) as a tiny
stdio↔HTTP bridge instead — add this to `claude_desktop_config.json`'s
`mcpServers` object (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`;
Windows: `%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "gnbpcap": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:8765/mcp"]
    }
  }
}
```

**Startup order matters**: Claude Desktop connects once at launch and
doesn't retry, so turn the toggle on *before* opening Claude Desktop, not
after. If you open Claude Desktop first (or with the toggle off), you'll
see a **"MCP gnbpcap: Server disconnected"** warning — this is expected
and harmless (`mcp-remote` had nothing to connect to yet), not a bug.
Turn the toggle on and fully restart Claude Desktop to clear it.

### Option A: stdio (Claude Desktop spawns a Python process)

Requires building `gnbpcap-cli` and installing `mcp-server/server.py`'s
Python dependencies first:

```bash
cargo build --release -p gnbpcap-cli
pip install -r mcp-server/requirements.txt
```

Then use this `mcpServers` entry instead:

```json
{
  "mcpServers": {
    "gnbpcap": {
      "command": "python3",
      "args": ["/absolute/path/to/gnbpcap/mcp-server/server.py"],
      "env": {
        "GNBPCAP_CLI_BIN": "/absolute/path/to/gnbpcap/target/release/gnbpcap-cli"
      }
    }
  }
}
```

`GNBPCAP_CLI_BIN` is optional — if unset, the server looks for
`target/{release,debug}/gnbpcap-cli` relative to the workspace root
automatically. This option runs the whole time Claude Desktop is open,
regardless of whether the Tauri app is running.

(Claude Desktop doesn't have an official Linux release; on Ubuntu, use
either server with Claude Code or another MCP-capable client instead.)

---

**Fully quit and reopen Claude Desktop** after changing the config either
way (it's only read at startup). This exposes three tools in chat:

- **`parse_pcap`** — decode a capture into its packet list, paginated and
  size-capped (with an optional `protocol_filter`) so large captures never
  exceed a single response's size budget
- **`get_packet_details`** — the full decoded protocol tree for one frame,
  with `field_filter`/`node_id`/`max_depth` options to scope into huge
  messages (e.g. RRC UE Capability Information) instead of hitting a
  response-size limit
- **`check_redcap_status`** — automatically finds the UE capability
  exchange and reports 3GPP Release 17 RedCap capability

See [`mcp-server/SETUP.md`](mcp-server/SETUP.md) for full details and
manual verification steps.

## Project Structure

```
gnbpcap/
├── gnbpcap-core/           # Shared Rust parsing logic (no Tauri deps)
│   └── src/lib.rs          # tshark invocation, decode-profile scoring, PDML tree building
├── gnbpcap-mcp/            # Native embedded MCP server (Option B), used by the app's toggle
│   ├── src/lib.rs          # Calls gnbpcap-core directly, no subprocess — spawn(host, port)
│   ├── examples/serve.rs   # Run it standalone for manual testing
│   └── tests/integration.rs
├── gnbpcap-cli/            # Thin CLI shim over gnbpcap-core, JSON on stdout
│   └── src/main.rs         # Only consumer is mcp-server/server.py (Option A)
├── src-tauri/              # Rust backend (Tauri app)
│   ├── src/main.rs         # Tauri commands: parse_pcap, get_packet_details, start/stop_mcp_server
│   ├── Cargo.toml
│   └── tauri.conf.json
├── mcp-server/             # Standalone MCP server for Claude Desktop (Option A)
│   ├── server.py           # parse_pcap, get_packet_details, check_redcap_status tools
│   ├── requirements.txt
│   └── SETUP.md            # Claude Desktop configuration instructions
├── ui/                     # Frontend (plain HTML/CSS/JS)
│   ├── index.html
│   ├── main.js             # Ladder diagram, canvas rendering, Tauri invoke calls
│   └── styles.css
├── Cargo.toml              # Workspace root (gnbpcap-core, gnbpcap-cli, gnbpcap-mcp, src-tauri)
├── SPEC.md                 # Original specification
├── CLAUDE.md               # AI coding assistant context (Claude Code / opencode)
├── package.json
└── README.md
```

## Supported Protocols

| Layer | Color | Description |
|-------|-------|-------------|
| MAC | Teal `#4ecca3` | MAC-NR scheduling, BSR, PHR |
| RLC | Amber `#ffc857` | RLC-NR ACK/SRBs/DRBs |
| RRC | Red `#ff6b6b` | Radio Resource Control |
| NGAP | Purple `#7b68ee` | NG Application Protocol (gNB ↔ AMF) |
| NAS | Pink `#e94560` | NAS-5GS (Registration, PDU Session) |

## Technical Details

- **Frontend**: Plain HTML/CSS/JS rendered by Tauri's WebView
- **Backend**: Rust — spawns `tshark` via `std::process::Command`, parses PDML XML with `xmltree`
- **Packet list**: `tshark -T fields` with score-based decode profile auto-selection
- **Detail tree**: `tshark -T pdml` parsed into a recursive `TreeNode` structure
- **Rendering**: HTML5 Canvas for the ladder diagram

## CI / Releases

Two GitHub Actions workflows build the desktop app across all three
platforms:

- **`.github/workflows/ci.yml`** — runs on every push to `main` and every
  PR; `cargo build`/`cargo test` on macOS, Ubuntu, and Windows runners to
  catch breakage early (this is what actually verifies the Ubuntu/Windows
  build steps above, unlike the manual setup instructions which aren't
  independently tested).
- **`.github/workflows/release.yml`** — triggered by pushing a tag
  matching `v*` (e.g. `v0.1.0`); builds a macOS universal binary, a Linux
  `.deb`/`.AppImage`, and a Windows `.msi`/`.exe` via
  [`tauri-apps/tauri-action`](https://github.com/tauri-apps/tauri-action),
  and creates a **draft** GitHub Release with all three attached. Review
  and publish the draft manually from the repo's Releases page.

To cut a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Troubleshooting

### Window is blank / canvas not showing
Hard-refresh the WebView: open the developer tools and force reload.

### No packets decoded
- Confirm the PCAP contains 5G NR traffic
- Test manually: `tshark -r yourfile.pcap -c 10`
- The app tries four decode profiles automatically and picks the one with the most meaningful packets

### tshark not found
Install Wireshark from [wireshark.org](https://www.wireshark.org/) or set `TSHARK_BIN=/path/to/tshark` before running.
