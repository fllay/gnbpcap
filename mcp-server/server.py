#!/usr/bin/env python3
"""
MCP server exposing gnbpcap's pcap-parsing logic to Claude Desktop.

Shells out to the `gnbpcap-cli` Rust binary (built from the shared
gnbpcap-core crate — the same logic the Tauri GUI uses) and exposes
it as MCP tools, plus a couple of higher-level tools that encode
common 5G NR analysis workflows directly.

Requires: pip install "mcp[cli]"
Requires: gnbpcap-cli built — from the workspace root:
    cargo build --release -p gnbpcap-cli

Configure the binary location with GNBPCAP_CLI_BIN if it's not at
the default ../target/{release,debug}/gnbpcap-cli relative to this file.

Response sizes are kept under any client's per-call limit: parse_pcap
paginates and byte-caps its output (with an optional protocol_filter),
and get_packet_details supports field_filter/node_id/max_depth to scope
into oversized decoded trees (e.g. RRC UE Capability Information) instead
of failing outright.

By default this runs over stdio, for an MCP client (e.g. Claude Desktop)
that spawns it directly. Pass --transport http to instead serve over
Streamable HTTP on a fixed local port — this is the mode the Tauri app's
MCP toggle uses, since a client can connect to (and disconnect from) an
already-running HTTP server, which isn't possible with stdio:

    python3 server.py --transport http --port 8765
"""

import argparse
import json
import os
import subprocess
from typing import Any, Optional

try:
    from mcp.server.fastmcp import FastMCP  # mcp 1.x

    _MCP_V2 = False
except ModuleNotFoundError:
    from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x

    _MCP_V2 = True

mcp = FastMCP("gnbpcap")

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_ROOT = os.path.dirname(HERE)

# Keep a single tool response comfortably under any client's per-call size
# limit, regardless of how much was requested or how big a decoded tree is.
MAX_RESPONSE_BYTES = 200_000


def _find_cli_bin() -> str:
    env_bin = os.environ.get("GNBPCAP_CLI_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    for profile in ("release", "debug"):
        candidate = os.path.join(WORKSPACE_ROOT, "target", profile, "gnbpcap-cli")
        if os.path.exists(candidate):
            return candidate

    raise FileNotFoundError(
        "gnbpcap-cli binary not found. Build it with:\n"
        "  cargo build --release -p gnbpcap-cli\n"
        "from the gnbpcap workspace root, or set GNBPCAP_CLI_BIN."
    )


def _run_cli(*args: str) -> Any:
    cli_bin = _find_cli_bin()
    proc = subprocess.run(
        [cli_bin, *args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError(
            f"gnbpcap-cli produced no output (exit={proc.returncode}): {proc.stderr.strip()}"
        )
    result = json.loads(stdout)
    if isinstance(result, dict) and "error" in result:
        raise RuntimeError(result["error"])
    return result


def _flatten_tree_labels(nodes: list, out: list) -> None:
    for node in nodes:
        out.append(node.get("label", ""))
        children = node.get("children")
        if children:
            _flatten_tree_labels(children, out)


def _prune_tree(nodes: list, terms: list[str]) -> list:
    """Keep only nodes whose label matches one of `terms` (case-insensitive
    substring) — along with that node's full subtree — plus the ancestor
    chain needed to show where each match sits. Non-matching siblings and
    their subtrees are dropped, which is what keeps this small even for a
    huge ASN.1 capability tree.
    """
    lowered_terms = [t.lower() for t in terms]

    def matches(label: str) -> bool:
        low = label.lower()
        return any(t in low for t in lowered_terms)

    def walk(node: dict) -> Optional[dict]:
        label = node.get("label", "")
        if matches(label):
            return node
        children = node.get("children") or []
        kept_children = [c for c in (walk(ch) for ch in children) if c is not None]
        if not kept_children:
            return None
        pruned = dict(node)
        pruned["children"] = kept_children
        return pruned

    return [n for n in (walk(node) for node in nodes) if n is not None]


def _outline_tree(nodes: list, depth: int) -> list:
    """Shallow id/label/childCount view of a tree, for when it's too big to
    return in full and the caller hasn't narrowed it with field_filter."""
    if depth <= 0:
        return []
    out = []
    for node in nodes:
        entry = {"id": node.get("id"), "label": node.get("label")}
        children = node.get("children") or []
        if children:
            entry["childCount"] = len(children)
            if depth > 1:
                entry["children"] = _outline_tree(children, depth - 1)
        out.append(entry)
    return out


def _find_node_by_id(nodes: list, target_id: str) -> Optional[dict]:
    """Depth-first search for a node with this id anywhere in the tree.
    Ids come from a previous outline/result, so the caller can drill down
    into one branch without re-fetching everything."""
    for node in nodes:
        if node.get("id") == target_id:
            return node
        found = _find_node_by_id(node.get("children") or [], target_id)
        if found is not None:
            return found
    return None


def _cap_depth(nodes: list, depth: int) -> list:
    """Like _outline_tree, but keeps full node shape (id/label/children) at
    every level within the cap instead of collapsing to childCount — only
    the children *past* the cap are dropped, and marked so the caller knows
    there's more to fetch (via node_id) rather than assuming the tree just
    ends there."""
    out = []
    for node in nodes:
        entry = {"id": node.get("id"), "label": node.get("label")}
        children = node.get("children") or []
        if children:
            if depth > 0:
                entry["children"] = _cap_depth(children, depth - 1)
            else:
                entry["childrenTruncatedAtDepth"] = True
                entry["childCount"] = len(children)
        out.append(entry)
    return out


@mcp.tool()
def parse_pcap(
    file_path: str,
    offset: int = 0,
    limit: int = 500,
    protocol_filter: Optional[list[str]] = None,
) -> dict:
    """Parse a 5G NR pcap file (MAC-NR/RLC-NR/NGAP/NAS-5GS) and return a
    window of its decoded packets: frame number, relative time, protocol
    layer, direction (ul/dl), a short message-type summary, and the raw
    tshark info column for each frame. Use this first to see the overall
    session flow (RRC Setup, Registration, Security Mode, RRC
    Reconfiguration, PDU Session, etc.) before drilling into any specific
    frame with get_packet_details.

    Results are paginated and size-capped so a single call never returns
    more than a client can safely consume, even for large captures.

    Args:
        file_path: Absolute path to the .pcap/.pcapng file to parse.
        offset: Index of the first matching packet to return (0-based).
        limit: Maximum number of packets to return in this call.
        protocol_filter: Optional list of protocol layers to keep (e.g.
            `["RRC", "NAS-5GS"]`); matches the `protocol` field
            case-insensitively. Filtering narrows the result before
            pagination, so it's usually the fastest way to get a call flow
            without paging.

    Returns:
        Object with `packets` (this window), `totalPackets` (matching the
        filter, before windowing), `offset`, `returned` (count actually
        included — may be less than `limit` if the size cap was hit),
        `hasMore` and `nextOffset` (call again with this offset to continue),
        `selectedDecodeOpts`, and `tsharkBin`.
    """
    full = _run_cli("parse-pcap", file_path)
    packets = full["packets"]

    if protocol_filter:
        wanted = {p.upper() for p in protocol_filter}
        packets = [p for p in packets if p["protocol"].upper() in wanted]

    total = len(packets)
    window = packets[offset : offset + max(limit, 0)]

    trimmed = []
    size = 0
    for pkt in window:
        pkt_size = len(json.dumps(pkt))
        if trimmed and size + pkt_size > MAX_RESPONSE_BYTES:
            break
        trimmed.append(pkt)
        size += pkt_size

    returned = len(trimmed)
    next_offset = offset + returned if offset + returned < total else None

    return {
        "packets": trimmed,
        "totalPackets": total,
        "offset": offset,
        "returned": returned,
        "hasMore": next_offset is not None,
        "nextOffset": next_offset,
        "selectedDecodeOpts": full["selectedDecodeOpts"],
        "tsharkBin": full["tsharkBin"],
    }


@mcp.tool()
def get_packet_details(
    file_path: str,
    frame_num: int,
    selected_decode_opts: Optional[list[str]] = None,
    field_filter: Optional[list[str]] = None,
    node_id: Optional[str] = None,
    max_depth: Optional[int] = None,
) -> Any:
    """Get the decoded protocol tree (like Wireshark's packet detail pane)
    for one frame — or a scoped slice of it, for exploratory analysis
    without ever hitting the response-size limit.

    Some messages (RRC UE Capability Information especially) decode into a
    tree with hundreds of thousands of characters of JSON — too big for a
    single tool response. Three ways to keep any call small, usable
    together or alone:

    - `field_filter`: prune to only branches whose label contains one of
      the given case-insensitive substrings (e.g.
      `field_filter=["redcap", "accessStratumRelease"]`), plus the
      ancestor path to each match. Best when you know roughly what you're
      looking for.
    - `node_id`: scope the whole call to one subtree, by an id you got
      from a previous call's `outline`, a `childrenTruncatedAtDepth` node,
      or any node in a prior result. Best for drilling down after a first
      exploratory call showed you where the interesting content is.
    - `max_depth`: cap how many levels deep to expand; nodes beyond the
      cap come back with `childrenTruncatedAtDepth: true` and `childCount`
      instead of their children, so you can decide whether to drill into
      them with `node_id`. Best for a first look at an unfamiliar message
      when you don't yet know what field names to filter for.

    If you call this with none of the three and the frame is small, you
    just get the whole tree — that's fine and is the common case for most
    non-capability messages (RRC Setup, Security Mode Command, etc.).

    Args:
        file_path: Absolute path to the .pcap/.pcapng file.
        frame_num: 1-based tshark frame number to inspect.
        selected_decode_opts: Optional tshark decode options, normally the
            `selectedDecodeOpts` returned by `parse_pcap` for this same
            file, so the same decode profile is used.
        field_filter: Optional list of case-insensitive substrings to match
            against node labels. Only matching branches (and their full
            subtrees) are returned, which keeps the response small even for
            huge capability messages.
        node_id: Optional node id to scope to before anything else is
            applied — e.g. get an outline first, spot an interesting
            branch, then call again with that branch's id.
        max_depth: Optional depth cap (0 = just the requested node's own
            label, no children) applied after field_filter/node_id.

    Returns:
        Normally a list of tree nodes (each with `id`, `label`, and
        optional `children`), or a single such node if `node_id` was given
        without other params. If field_filter matched nothing, or the
        (possibly filtered/scoped) tree still exceeds the response budget,
        returns a dict instead of erroring — `matches: 0` with a hint, or
        `truncated: True` with either `matchedTopLevelLabels` or a shallow
        `outline` — so you always get something back and know what to try
        next instead of a bare failure.
    """
    args = ["packet-details", file_path, str(frame_num)]
    if selected_decode_opts:
        args.extend(selected_decode_opts)
    tree = _run_cli(*args)

    scope_label = None
    if node_id:
        found = _find_node_by_id(tree, node_id)
        if found is None:
            return {
                "matches": 0,
                "reason": f"No node with id '{node_id}' found in this frame's tree.",
            }
        tree = [found]
        scope_label = found.get("label")

    if field_filter:
        pruned = _prune_tree(tree, field_filter)
        if not pruned:
            return {
                "matches": 0,
                "reason": (
                    f"No labels matched {field_filter!r}"
                    + (f" within '{scope_label}'" if scope_label else "")
                    + ". Call again without field_filter (optionally with "
                    "max_depth) to see what's actually in this frame."
                ),
            }
        if max_depth is not None:
            pruned = _cap_depth(pruned, max_depth)
        text = json.dumps(pruned)
        if len(text) <= MAX_RESPONSE_BYTES:
            return pruned
        return {
            "truncated": True,
            "reason": (
                f"Filtered tree is still {len(text)} bytes, over the "
                f"{MAX_RESPONSE_BYTES}-byte response budget — narrow "
                "field_filter further, or add max_depth."
            ),
            "matchedTopLevelLabels": [n.get("label") for n in pruned][:50],
        }

    if max_depth is not None:
        capped = _cap_depth(tree, max_depth)
        text = json.dumps(capped)
        if len(text) <= MAX_RESPONSE_BYTES:
            return capped
        return {
            "truncated": True,
            "reason": (
                f"Tree capped at max_depth={max_depth} is still {len(text)} "
                f"bytes, over the {MAX_RESPONSE_BYTES}-byte response budget "
                "— lower max_depth, or add field_filter."
            ),
            "outline": _outline_tree(tree, depth=2),
        }

    full_text = json.dumps(tree)
    if len(full_text) <= MAX_RESPONSE_BYTES:
        return tree

    return {
        "truncated": True,
        "reason": (
            f"{'This branch' if scope_label else 'Full packet tree'} is "
            f"{len(full_text)} bytes, over the {MAX_RESPONSE_BYTES}-byte "
            "response budget. Showing a shallow outline instead — call "
            "again with field_filter=[\"...\"] or max_depth=N to pull just "
            "what you need, or node_id to drill into one branch."
        ),
        "outline": _outline_tree(tree, depth=3),
    }


@mcp.tool()
def check_redcap_status(file_path: str) -> dict:
    """Check whether the UE in a 5G NR pcap capture is RedCap-capable
    (3GPP Release 17 Reduced Capability). Automatically finds the UE
    capability exchange (RRC UECapabilityInformation, or the NGAP
    InitialContextSetupRequest if the RRC exchange was skipped because the
    AMF already cached the UE's radio capability), then checks the decoded
    tree for RedCap-related fields. Returns a small structured summary
    instead of requiring you to manually locate and read the (huge)
    capability frame.
    """
    full = _run_cli("parse-pcap", file_path)
    packets = full.get("packets", [])
    decode_opts = full.get("selectedDecodeOpts", [])

    candidates = [
        p for p in packets
        if "ue capability information" in p.get("messageType", "").lower()
    ]
    source = "rrc_ue_capability_information"
    if not candidates:
        candidates = [
            p for p in packets
            if p.get("protocol", "").upper() == "NGAP"
            and "initialcontextsetuprequest" in p.get("messageType", "").lower().replace(" ", "")
        ]
        source = "ngap_initial_context_setup_request"

    if not candidates:
        return {
            "found": False,
            "reason": (
                "No UECapabilityInformation or InitialContextSetupRequest frame "
                "found. This usually means the UE's NAS 'NG-RAN Radio Capability "
                "Update' flag was 'Not Needed' (GUTI-based reattach, AMF already "
                "has it cached) and this session genuinely never exchanged "
                "capability info. Try a fresh SIM/IMSI or restart the AMF to "
                "force a real exchange."
            ),
        }

    frame_num = candidates[0]["index"]
    args = ["packet-details", file_path, str(frame_num)]
    args.extend(decode_opts)
    tree = _run_cli(*args)

    labels: list = []
    _flatten_tree_labels(tree, labels)

    access_stratum_release = None
    redcap_capable = False
    matched_lines = []
    for label in labels:
        lower = label.lower()
        if "accessstratumrelease" in lower:
            access_stratum_release = label
            matched_lines.append(label)
        if "redcap" in lower:
            redcap_capable = True
            matched_lines.append(label)
        if "reducedmaxbw" in lower or "reducedmaxmimo" in lower:
            matched_lines.append(label)

    return {
        "found": True,
        "source": source,
        "frame_number": frame_num,
        "access_stratum_release": access_stratum_release,
        "redcap_capable": redcap_capable,
        "matched_fields": matched_lines,
        "note": (
            "redcap_capable=False with a rel15/rel16 accessStratumRelease is "
            "conclusive (RedCap requires rel17+). redcap_capable=False with "
            "rel17+ means the UE supports Rel-17 features but did not declare "
            "RedCap specifically."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="stdio (default): spawned directly by an MCP client. "
        "http: serve Streamable HTTP on --host:--port for a client to "
        "connect to independently (used by the Tauri app's MCP toggle).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
        return

    if _MCP_V2:
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
