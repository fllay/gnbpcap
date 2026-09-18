# gnbpcap MCP server setup

Exposes 5G NR PCAP parsing (`parse_pcap`, `get_packet_details`,
`check_redcap_status`) as MCP tools. Two independent implementations
exist — pick whichever matches the setup option you want below:

- **Option A** (stdio): the Python server (`mcp-server/server.py`),
  backed by the `gnbpcap-cli` Rust binary (a thin shim over the
  `gnbpcap-core` crate — the same logic the Tauri GUI uses).
- **Option B** (HTTP, the app's MCP toggle): the native Rust server
  (`gnbpcap-mcp` crate), embedded directly in the Tauri app — calls
  `gnbpcap-core` in-process, no Python or `gnbpcap-cli` involved.

## 1. Build the CLI binary

Only needed for Option A — skip this if you're only using the toggle
(Option B). From the repo root:

```bash
cargo build --release -p gnbpcap-cli
```

This produces `target/release/gnbpcap-cli`. It shells out to `tshark`
exactly like the Tauri app does, so Wireshark (or a standalone `tshark`)
must already be installed — set `TSHARK_BIN` if it's not on `PATH` or in
one of the usual install locations.

## 2. Install the Python MCP server's dependencies

Also only needed for Option A:

```bash
pip install -r mcp-server/requirements.txt
```

Option B needs nothing extra — `gnbpcap-mcp` builds as part of the normal
`cargo build`/`npm run tauri:build` for the Tauri app.

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

The Tauri GUI has an "MCP" toggle in the header that starts/stops a
**native Rust MCP server, embedded directly in the app** (the `gnbpcap-mcp`
crate — no subprocess, no Python, no `pip install` needed at all for this
path). It calls `gnbpcap-core`'s parsing functions directly in-process,
so it works the same whether you built from source or just downloaded a
release — nothing needs to be found at a particular file path at runtime.

Claude Desktop's `mcpServers` config doesn't accept a bare `"url"` entry
(at least as of this writing — it silently skips it with "not a valid MCP
server configuration"). Use [`mcp-remote`](https://www.npmjs.com/package/mcp-remote)
as a tiny stdio↔HTTP bridge instead — Claude Desktop spawns it like any
other `command`-based server, and it proxies through to whatever's
listening on the toggle's port:

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

With this option, tool calls fail if the toggle is off (`mcp-remote` has
nothing to connect to) — that's the point. Also note the **startup
order**: Claude Desktop connects at launch and doesn't retry, so the
toggle needs to be on *before* you open Claude Desktop, not after.

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

To verify the native Rust server (Option B) without the Tauri app, run it
standalone and send it a real MCP request:

```bash
cargo run --example serve -p gnbpcap-mcp &
curl -s -X POST http://127.0.0.1:8765/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}'
```

A successful response includes `"serverInfo":{"name":"rmcp", ...}`.
