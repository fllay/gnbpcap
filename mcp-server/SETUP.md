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

Add this entry to `claude_desktop_config.json`'s `mcpServers` object
(on macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`).
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

Restart Claude Desktop after saving. The `gnbpcap` server should then offer
three tools:

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
