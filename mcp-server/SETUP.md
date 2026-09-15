# gnbpcap MCP server setup

Exposes 5G NR PCAP parsing (`parse_pcap`, `get_packet_details`) as MCP tools,
backed by the `gnbpcap-cli` Rust binary.

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
        "GNBPCAP_CLI": "/absolute/path/to/gnbpcap/target/release/gnbpcap-cli"
      }
    }
  }
}
```

Restart Claude Desktop after saving. The `gnbpcap` server should then offer
two tools:

- `parse_pcap(file_path)` — decode a capture and list its 5G NR packets
- `get_packet_details(file_path, frame_num, decode_opts?)` — full PDML
  protocol tree for one frame (pass back the `selectedDecodeOpts` from
  `parse_pcap` as `decode_opts` to keep the same decode profile)

## Verifying manually

```bash
target/release/gnbpcap-cli parse /path/to/capture.pcap
target/release/gnbpcap-cli details /path/to/capture.pcap 42
```

Both print JSON to stdout matching the shapes the Tauri UI already uses
(`ParseResult` and the `TreeNode` array respectively).
