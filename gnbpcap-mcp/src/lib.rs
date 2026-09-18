//! Native Rust MCP server for gnbpcap, embedded directly in the Tauri app
//! (no subprocess, no Python) so the MCP toggle works in a downloaded
//! release build — not just when building from source.
//!
//! Calls gnbpcap-core's parsing functions directly in-process (no
//! gnbpcap-cli shell-out needed here, unlike the Python server). Response
//! sizes are kept under any client's per-call limit the same way the
//! Python server did: parse_pcap paginates/byte-caps its output (with an
//! optional protocol_filter), and get_packet_details supports
//! field_filter/node_id/max_depth to scope into oversized decoded trees.

use gnbpcap_core::{get_packet_details_blocking, parse_pcap_blocking, TreeNode};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Keep a single tool response comfortably under any client's per-call size
/// limit, regardless of how many packets are requested.
const MAX_RESPONSE_BYTES: usize = 200_000;

fn default_limit() -> usize {
    500
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ParsePcapParams {
    /// Absolute path to the .pcap/.pcapng file to parse.
    pub file_path: String,
    /// Index of the first matching packet to return (0-based).
    #[serde(default)]
    pub offset: usize,
    /// Maximum number of packets to return in this call.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Optional list of protocol layers to keep (e.g. ["RRC", "NAS-5GS"]);
    /// matches the `protocol` field case-insensitively.
    #[serde(default)]
    pub protocol_filter: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetPacketDetailsParams {
    /// Absolute path to the .pcap/.pcapng file.
    pub file_path: String,
    /// 1-based tshark frame number to inspect.
    pub frame_num: u32,
    /// Optional tshark decode options, normally the `selectedDecodeOpts`
    /// returned by `parse_pcap` for this same file.
    #[serde(default)]
    pub selected_decode_opts: Option<Vec<String>>,
    /// Optional list of case-insensitive substrings to match against node
    /// labels; only matching branches (and their subtrees) are returned.
    #[serde(default)]
    pub field_filter: Option<Vec<String>>,
    /// Optional node id to scope to before anything else is applied.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Optional depth cap (0 = just the requested node's own label, no
    /// children) applied after field_filter/node_id.
    #[serde(default)]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckRedcapStatusParams {
    /// Absolute path to the .pcap/.pcapng file.
    pub file_path: String,
}

fn tree_to_value(nodes: &[TreeNode]) -> Value {
    serde_json::to_value(nodes).unwrap_or(Value::Null)
}

fn node_label(v: &Value) -> String {
    v.get("label")
        .and_then(|l| l.as_str())
        .unwrap_or("")
        .to_string()
}

fn node_id_str(v: &Value) -> String {
    v.get("id").and_then(|l| l.as_str()).unwrap_or("").to_string()
}

fn node_children(v: &Value) -> Vec<Value> {
    v.get("children")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default()
}

fn flatten_tree_labels(nodes: &[Value], out: &mut Vec<String>) {
    for node in nodes {
        out.push(node_label(node));
        let children = node_children(node);
        if !children.is_empty() {
            flatten_tree_labels(&children, out);
        }
    }
}

/// Keep only nodes whose label matches one of `terms` (case-insensitive
/// substring) — along with that node's full subtree — plus the ancestor
/// chain needed to show where each match sits.
fn prune_tree(nodes: &[Value], terms: &[String]) -> Vec<Value> {
    let lowered: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();
    let matches = |label: &str| {
        let low = label.to_lowercase();
        lowered.iter().any(|t| low.contains(t.as_str()))
    };

    fn walk(node: &Value, matches: &impl Fn(&str) -> bool) -> Option<Value> {
        let label = node_label(node);
        if matches(&label) {
            return Some(node.clone());
        }
        let children = node_children(node);
        let kept: Vec<Value> = children
            .iter()
            .filter_map(|c| walk(c, matches))
            .collect();
        if kept.is_empty() {
            return None;
        }
        let mut pruned = node.clone();
        pruned["children"] = Value::Array(kept);
        Some(pruned)
    }

    nodes.iter().filter_map(|n| walk(n, &matches)).collect()
}

/// Shallow id/label/childCount view of a tree, for when it's too big to
/// return in full and the caller hasn't narrowed it with field_filter.
fn outline_tree(nodes: &[Value], depth: usize) -> Vec<Value> {
    if depth == 0 {
        return Vec::new();
    }
    nodes
        .iter()
        .map(|node| {
            let mut entry = json!({
                "id": node_id_str(node),
                "label": node_label(node),
            });
            let children = node_children(node);
            if !children.is_empty() {
                entry["childCount"] = json!(children.len());
                if depth > 1 {
                    entry["children"] = json!(outline_tree(&children, depth - 1));
                }
            }
            entry
        })
        .collect()
}

/// Depth-first search for a node with this id anywhere in the tree.
fn find_node_by_id(nodes: &[Value], target_id: &str) -> Option<Value> {
    for node in nodes {
        if node_id_str(node) == target_id {
            return Some(node.clone());
        }
        let children = node_children(node);
        if let Some(found) = find_node_by_id(&children, target_id) {
            return Some(found);
        }
    }
    None
}

/// Like outline_tree, but keeps full node shape (id/label/children) at
/// every level within the cap instead of collapsing to childCount — only
/// the children *past* the cap are dropped, and marked so the caller
/// knows there's more to fetch (via node_id) rather than assuming the
/// tree just ends there.
fn cap_depth(nodes: &[Value], depth: usize) -> Vec<Value> {
    nodes
        .iter()
        .map(|node| {
            let mut entry = json!({
                "id": node_id_str(node),
                "label": node_label(node),
            });
            let children = node_children(node);
            if !children.is_empty() {
                if depth > 0 {
                    entry["children"] = json!(cap_depth(&children, depth - 1));
                } else {
                    entry["childrenTruncatedAtDepth"] = json!(true);
                    entry["childCount"] = json!(children.len());
                }
            }
            entry
        })
        .collect()
}

fn json_byte_len(v: &Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(usize::MAX)
}

#[derive(Clone, Default)]
pub struct GnbpcapServer {
    tool_router: ToolRouter<GnbpcapServer>,
}

#[tool_router]
impl GnbpcapServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Parse a 5G NR pcap file (MAC-NR/RLC-NR/NGAP/NAS-5GS) and return a
    /// window of its decoded packets: frame number, relative time,
    /// protocol layer, direction (ul/dl), a short message-type summary,
    /// and the raw tshark info column for each frame. Use this first to
    /// see the overall session flow (RRC Setup, Registration, Security
    /// Mode, RRC Reconfiguration, PDU Session, etc.) before drilling into
    /// any specific frame with get_packet_details.
    ///
    /// Results are paginated and size-capped so a single call never
    /// returns more than a client can safely consume, even for large
    /// captures.
    #[tool(description = "Parse a 5G NR pcap file and return a window of its decoded packets, paginated and size-capped. Use this first to see the overall session flow before drilling into a frame with get_packet_details.")]
    async fn parse_pcap(
        &self,
        params: Parameters<ParsePcapParams>,
    ) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let full = parse_pcap_blocking(&p.file_path)
            .map_err(|e| McpError::internal_error(e, None))?;

        let mut packets = full.packets;
        if let Some(filter) = &p.protocol_filter {
            let wanted: Vec<String> = filter.iter().map(|f| f.to_uppercase()).collect();
            packets.retain(|pkt| wanted.contains(&pkt.protocol.to_uppercase()));
        }

        let total = packets.len();
        let window: Vec<_> = packets
            .into_iter()
            .skip(p.offset)
            .take(p.limit)
            .collect();

        let mut trimmed = Vec::new();
        let mut size = 0usize;
        for pkt in window {
            let pkt_value = serde_json::to_value(&pkt).unwrap_or(Value::Null);
            let pkt_size = json_byte_len(&pkt_value);
            if !trimmed.is_empty() && size + pkt_size > MAX_RESPONSE_BYTES {
                break;
            }
            trimmed.push(pkt_value);
            size += pkt_size;
        }

        let returned = trimmed.len();
        let next_offset = if p.offset + returned < total {
            Some(p.offset + returned)
        } else {
            None
        };

        let result = json!({
            "packets": trimmed,
            "totalPackets": total,
            "offset": p.offset,
            "returned": returned,
            "hasMore": next_offset.is_some(),
            "nextOffset": next_offset,
            "selectedDecodeOpts": full.selected_decode_opts,
            "tsharkBin": full.tshark_bin,
        });

        let content = ContentBlock::json(result).map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![content]))
    }

    /// Get the decoded protocol tree (like Wireshark's packet detail
    /// pane) for one frame — or a scoped slice of it, for exploratory
    /// analysis without ever hitting the response-size limit.
    ///
    /// Some messages (RRC UE Capability Information especially) decode
    /// into a tree with hundreds of thousands of characters of JSON — too
    /// big for a single tool response. Three ways to keep any call small:
    /// field_filter (prune to matching branches + their ancestor path),
    /// node_id (scope to one subtree by id from a previous result), and
    /// max_depth (cap expansion depth, with childCount on truncated
    /// nodes). If none are given and the frame is small, the whole tree
    /// comes back — the common case for non-capability messages.
    #[tool(description = "Get the decoded protocol tree for one frame, or a scoped slice of it via field_filter/node_id/max_depth to stay under the response-size limit for huge messages like RRC UE Capability Information.")]
    async fn get_packet_details(
        &self,
        params: Parameters<GetPacketDetailsParams>,
    ) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let decode_opts = p.selected_decode_opts.unwrap_or_default();
        let tree_nodes = get_packet_details_blocking(&p.file_path, p.frame_num, &decode_opts)
            .map_err(|e| McpError::internal_error(e, None))?;
        let mut tree = tree_to_value(&tree_nodes);
        let mut tree_arr = tree.as_array().cloned().unwrap_or_default();

        let mut scope_label: Option<String> = None;
        if let Some(node_id) = &p.node_id {
            match find_node_by_id(&tree_arr, node_id) {
                None => {
                    let result = json!({
                        "matches": 0,
                        "reason": format!("No node with id '{node_id}' found in this frame's tree."),
                    });
                    let content = ContentBlock::json(result)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                    return Ok(CallToolResult::success(vec![content]));
                }
                Some(found) => {
                    scope_label = Some(node_label(&found));
                    tree_arr = vec![found];
                }
            }
        }
        tree = Value::Array(tree_arr.clone());

        if let Some(field_filter) = &p.field_filter {
            let pruned = prune_tree(&tree_arr, field_filter);
            if pruned.is_empty() {
                let scope_note = scope_label
                    .as_ref()
                    .map(|l| format!(" within '{l}'"))
                    .unwrap_or_default();
                let result = json!({
                    "matches": 0,
                    "reason": format!(
                        "No labels matched {:?}{scope_note}. Call again without field_filter (optionally with max_depth) to see what's actually in this frame.",
                        field_filter
                    ),
                });
                let content = ContentBlock::json(result)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                return Ok(CallToolResult::success(vec![content]));
            }

            let pruned = if let Some(depth) = p.max_depth {
                cap_depth(&pruned, depth)
            } else {
                pruned
            };
            let pruned_value = Value::Array(pruned.clone());
            let text_len = json_byte_len(&pruned_value);
            let result = if text_len <= MAX_RESPONSE_BYTES {
                pruned_value
            } else {
                let labels: Vec<String> = pruned.iter().take(50).map(|n| node_label(n)).collect();
                json!({
                    "truncated": true,
                    "reason": format!("Filtered tree is still {text_len} bytes, over the {MAX_RESPONSE_BYTES}-byte response budget — narrow field_filter further, or add max_depth."),
                    "matchedTopLevelLabels": labels,
                })
            };
            let content = ContentBlock::json(result)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(CallToolResult::success(vec![content]));
        }

        if let Some(depth) = p.max_depth {
            let capped = cap_depth(&tree_arr, depth);
            let capped_value = Value::Array(capped);
            let text_len = json_byte_len(&capped_value);
            let result = if text_len <= MAX_RESPONSE_BYTES {
                capped_value
            } else {
                json!({
                    "truncated": true,
                    "reason": format!("Tree capped at max_depth={depth} is still {text_len} bytes, over the {MAX_RESPONSE_BYTES}-byte response budget — lower max_depth, or add field_filter."),
                    "outline": outline_tree(&tree_arr, 2),
                })
            };
            let content = ContentBlock::json(result)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(CallToolResult::success(vec![content]));
        }

        let full_len = json_byte_len(&tree);
        let result = if full_len <= MAX_RESPONSE_BYTES {
            tree
        } else {
            let branch_or_full = if scope_label.is_some() { "This branch" } else { "Full packet tree" };
            json!({
                "truncated": true,
                "reason": format!("{branch_or_full} is {full_len} bytes, over the {MAX_RESPONSE_BYTES}-byte response budget. Showing a shallow outline instead — call again with field_filter=[\"...\"] or max_depth=N to pull just what you need, or node_id to drill into one branch."),
                "outline": outline_tree(&tree_arr, 3),
            })
        };

        let content = ContentBlock::json(result).map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![content]))
    }

    /// Check whether the UE in a 5G NR pcap capture is RedCap-capable
    /// (3GPP Release 17 Reduced Capability). Automatically finds the UE
    /// capability exchange (RRC UECapabilityInformation, or the NGAP
    /// InitialContextSetupRequest if the RRC exchange was skipped because
    /// the AMF already cached the UE's radio capability), then checks the
    /// decoded tree for RedCap-related fields.
    #[tool(description = "Check whether the UE in a 5G NR pcap capture is RedCap-capable (3GPP Release 17), automatically finding the UE capability exchange frame.")]
    async fn check_redcap_status(
        &self,
        params: Parameters<CheckRedcapStatusParams>,
    ) -> Result<CallToolResult, McpError> {
        let p = params.0;
        let full = parse_pcap_blocking(&p.file_path)
            .map_err(|e| McpError::internal_error(e, None))?;

        let mut candidates: Vec<_> = full
            .packets
            .iter()
            .filter(|pkt| pkt.message_type.to_lowercase().contains("ue capability information"))
            .collect();
        let mut source = "rrc_ue_capability_information";
        if candidates.is_empty() {
            candidates = full
                .packets
                .iter()
                .filter(|pkt| {
                    pkt.protocol.to_uppercase() == "NGAP"
                        && pkt
                            .message_type
                            .to_lowercase()
                            .replace(' ', "")
                            .contains("initialcontextsetuprequest")
                })
                .collect();
            source = "ngap_initial_context_setup_request";
        }

        let Some(candidate) = candidates.first() else {
            let result = json!({
                "found": false,
                "reason": "No UECapabilityInformation or InitialContextSetupRequest frame found. This usually means the UE's NAS 'NG-RAN Radio Capability Update' flag was 'Not Needed' (GUTI-based reattach, AMF already has it cached) and this session genuinely never exchanged capability info. Try a fresh SIM/IMSI or restart the AMF to force a real exchange.",
            });
            let content = ContentBlock::json(result)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(CallToolResult::success(vec![content]));
        };

        let frame_num = candidate.index;
        let tree_nodes = get_packet_details_blocking(&p.file_path, frame_num, &full.selected_decode_opts)
            .map_err(|e| McpError::internal_error(e, None))?;
        let tree_value = tree_to_value(&tree_nodes);
        let tree_arr = tree_value.as_array().cloned().unwrap_or_default();

        let mut labels = Vec::new();
        flatten_tree_labels(&tree_arr, &mut labels);

        let mut access_stratum_release: Option<String> = None;
        let mut redcap_capable = false;
        let mut matched_lines = Vec::new();
        for label in &labels {
            let lower = label.to_lowercase();
            if lower.contains("accessstratumrelease") {
                access_stratum_release = Some(label.clone());
                matched_lines.push(label.clone());
            }
            if lower.contains("redcap") {
                redcap_capable = true;
                matched_lines.push(label.clone());
            }
            if lower.contains("reducedmaxbw") || lower.contains("reducedmaxmimo") {
                matched_lines.push(label.clone());
            }
        }

        let result = json!({
            "found": true,
            "source": source,
            "frame_number": frame_num,
            "access_stratum_release": access_stratum_release,
            "redcap_capable": redcap_capable,
            "matched_fields": matched_lines,
            "note": "redcap_capable=False with a rel15/rel16 accessStratumRelease is conclusive (RedCap requires rel17+). redcap_capable=False with rel17+ means the UE supports Rel-17 features but did not declare RedCap specifically.",
        });

        let content = ContentBlock::json(result).map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![content]))
    }
}

#[tool_handler]
impl ServerHandler for GnbpcapServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// Binds a Streamable HTTP MCP server on `host:port` and spawns it on the
/// current Tokio runtime. Returns a handle that can be `.abort()`ed to
/// stop it. No subprocess, no Python — this runs directly in-process.
pub async fn spawn(host: &str, port: u16) -> std::io::Result<JoinHandle<()>> {
    let config = StreamableHttpServerConfig::default();
    let service = StreamableHttpService::new(
        || Ok(GnbpcapServer::new()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = TcpListener::bind((host, port)).await?;

    Ok(tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    }))
}
