# gnbpcap MCP server setup

Exposes 5G NR PCAP parsing (`parse_pcap`, `get_packet_details`,
`check_redcap_status`) as MCP tools, backed by the `gnbpcap-cli` Rust
binary (a thin shim over the `gnbpcap-core` crate — the same logic the
Tauri GUI uses).

## 1. Build the CLI binary

From the repo root:

```bash
cargo build --release -p gnbpcap-cli
```

This produces `target/release/gnbpcap-cli`. It shells out to `tshark`
exactly like the Tauri app does, so Wireshark (or a standalone `tshark`)
must already be installed — set `TSHARK_BIN` if it's not on `PATH` or in
one of the usual install locations.

## 2. Install the Python MCP server's dependencies

```bash
pip install -r mcp-server/requirements.txt
```

## 3. Register the server with Claude Desktop

There are two ways to run this server — pick one. They're mutually
exclusive for the `gnbpcap` entry in `claude_desktop_config.json`.

### Option A: stdio (Claude Desktop spawns it)

The simplest option — Claude Desktop starts and stops the Python process
itself alongside the app. Add this entry to `claude_desktop_config.json`'s
`mcpServers` object (on macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`).
Replace `/absolute/path/to/gnbpcap` with the path to your checkout of this
repo:

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
automatically.

### Option B: HTTP, controlled by the Tauri app's MCP toggle

The Tauri GUI has an "MCP" toggle in the header that starts/stops
`server.py --transport http` itself, so the server only runs while you
choose to have it on (and while the Tauri app itself is open) — instead of
Claude Desktop always spawning it in the background. Point
`claude_desktop_config.json` at the URL instead of a command:

```json
{
  "mcpServers": {
    "gnbpcap": {
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

With this option, tool calls fail if the toggle is off — that's the
point. `GNBPCAP_CLI_BIN`/`GNBPCAP_MCP_PYTHON`/`GNBPCAP_MCP_SERVER` can be
set as environment variables for the Tauri app's own process if the
defaults (`python3` on `PATH`, `target/{release,debug}/gnbpcap-cli`, and
`mcp-server/server.py` next to the workspace root) don't apply on your
machine.

---

Restart Claude Desktop after changing the config either way. The
`gnbpcap` server should then offer three tools:

- `parse_pcap(file_path, offset?, limit?, protocol_filter?)` — decode a
  capture and list its 5G NR packets, paginated and byte-capped so large
  captures never exceed a single response's size budget. Pass
  `protocol_filter=["RRC", "NAS-5GS"]` to narrow to just the layers you
  care about, or follow `nextOffset` to page through everything.
- `get_packet_details(file_path, frame_num, selected_decode_opts?, field_filter?, node_id?, max_depth?)` —
  the decoded protocol tree for one frame (like Wireshark's packet detail
  pane). Pass back the `selectedDecodeOpts` from `parse_pcap` as
  `selected_decode_opts` to keep the same decode profile. Use
  `field_filter`/`node_id`/`max_depth` to scope into huge trees (e.g. RRC
  UE Capability Information) instead of hitting a response-size limit.
- `check_redcap_status(file_path)` — finds the UE capability exchange
  automatically and reports whether the UE is 3GPP Release 17 RedCap
  capable, without needing to manually locate or read the capability
  frame.

## Verifying manually

```bash
target/release/gnbpcap-cli parse-pcap /path/to/capture.pcap
target/release/gnbpcap-cli packet-details /path/to/capture.pcap 42
```

Both print JSON to stdout matching the shapes the Tauri UI already uses
(`ParseResult` and the `TreeNode` array respectively) on success, or
`{"error": "..."}` with a non-zero exit code on failure.

To verify the HTTP mode (Option B) without the Tauri app, run the server
directly and send it a real MCP request:

```bash
python3 mcp-server/server.py --transport http --port 8765 &
curl -s -X POST http://127.0.0.1:8765/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}'
```

A successful response includes `"serverInfo":{"name":"gnbpcap", ...}`.
