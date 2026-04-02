#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::Command;
use tauri::async_runtime::spawn_blocking;
use xmltree::{Element, XMLNode};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Packet {
    index: u32,
    relative_time: f64,
    protocols: String,
    protocol: String,
    color_key: String,
    message_type: String,
    direction: String,
    info: String,
    src: String,
    dst: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseResult {
    packets: Vec<Packet>,
    selected_decode_opts: Vec<String>,
    tshark_bin: String,
}

#[derive(Debug, Clone, Serialize)]
struct TreeNode {
    id: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<TreeNode>>,
}

#[tauri::command]
async fn parse_pcap(file_path: String) -> Result<ParseResult, String> {
    spawn_blocking(move || parse_pcap_blocking(&file_path))
        .await
        .map_err(|e| format!("parse worker failed: {e}"))?
}

#[tauri::command]
async fn get_packet_details(
    file_path: String,
    frame_num: u32,
    selected_decode_opts: Vec<String>,
) -> Result<Vec<TreeNode>, String> {
    spawn_blocking(move || get_packet_details_blocking(&file_path, frame_num, &selected_decode_opts))
        .await
        .map_err(|e| format!("details worker failed: {e}"))?
}

fn find_tshark() -> Option<String> {
    if let Ok(bin) = env::var("TSHARK_BIN") {
        if Path::new(&bin).exists() {
            return Some(bin);
        }
    }

    let paths = [
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ];

    for path in paths {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    which("tshark")
}

fn which(bin: &str) -> Option<String> {
    let path = env::var("PATH").ok()?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn parse_pcap_blocking(file_path: &str) -> Result<ParseResult, String> {
    if !Path::new(file_path).exists() {
        return Err(format!("file not found: {file_path}"));
    }

    let tshark_bin = find_tshark().ok_or_else(|| {
        "tshark not found. Install Wireshark or set TSHARK_BIN environment variable.".to_string()
    })?;

    let base_opts = vec![
        "-o",
        "mac-nr.attempt_to_dissect_srb_sdus:TRUE",
        "-o",
        "mac-nr.attempt_rrc_decode:TRUE",
        "-o",
        "nas-5gs.null_decipher:TRUE",
        "--enable-heuristic",
        "mac_nr_udp",
        "--enable-heuristic",
        "rlc_nr_udp",
        "--enable-heuristic",
        "pdcp_nr_udp",
        "--enable-heuristic",
        "nas_5gs_udp",
    ];

    let decode_profiles: Vec<Vec<&str>> = vec![
        vec![],
        vec!["-o", "wtap_pktap.prefer_pktap:FALSE"],
        vec![
            "-d",
            "udp.port==0,udp",
            "-d",
            "user_dlt==149,udp",
            "-d",
            "user_dlt==157,mac-nr-framed",
        ],
        vec![
            "-o",
            "uat:user_dlts:\"User 2 (DLT=149)\",\"udp\",\"0\",\"\",\"0\",\"\"",
            "-o",
            "uat:user_dlts:\"User 10 (DLT=157)\",\"mac-nr-framed\",\"0\",\"\",\"0\",\"\"",
            "-o",
            "uat:user_dlts:\"User 5 (DLT=152)\",\"ngap\",\"0\",\"\",\"0\",\"\"",
            "-o",
            "uat:user_dlts:\"User 9 (DLT=156)\",\"gtp\",\"0\",\"\",\"0\",\"\"",
        ],
    ];

    let mut best_packets: Vec<Packet> = Vec::new();
    let mut best_profile: Vec<String> = Vec::new();
    let mut best_score: i64 = -1;
    let mut last_stderr = String::new();

    for profile in &decode_profiles {
        let mut cmd = Command::new(&tshark_bin);
        cmd.arg("-r").arg(file_path);
        cmd.args(&base_opts);
        cmd.args(profile);
        cmd.args([
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
            "-e",
            "frame.protocols",
            "-e",
            "_ws.col.info",
            "-e",
            "_ws.col.protocol",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-E",
            "header=y",
            "-E",
            "occurrence=l",
        ]);

        let output = cmd
            .output()
            .map_err(|e| format!("failed to run tshark: {e}"))?;

        if !output.status.success() {
            last_stderr = String::from_utf8_lossy(&output.stderr).to_string();
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let candidate_packets = parse_fields_output(&stdout);
        if candidate_packets.is_empty() {
            continue;
        }

        let non_pktap = candidate_packets
            .iter()
            .filter(|p| p.protocol.to_uppercase() != "PKTAP")
            .count() as i64;

        let meaningful = candidate_packets
            .iter()
            .filter(|p| {
                let upper = p.protocol.to_uppercase();
                matches!(
                    upper.as_str(),
                    "MAC" | "RLC" | "RRC" | "NR RRC" | "NGAP" | "NAS-5GS" | "GTP"
                )
            })
            .count() as i64;

        let score = meaningful * 1_000_000 + non_pktap * 100_000 + candidate_packets.len() as i64;
        if score > best_score {
            best_score = score;
            best_packets = candidate_packets;
            best_profile = profile.iter().map(|s| s.to_string()).collect();
        }
    }

    if best_packets.is_empty() {
        if last_stderr.is_empty() {
            return Err("no packets decoded by tshark".to_string());
        }
        return Err(format!("no packets decoded by tshark: {}", first_line(&last_stderr)));
    }

    Ok(ParseResult {
        packets: best_packets,
        selected_decode_opts: best_profile,
        tshark_bin,
    })
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or(text).to_string()
}

fn parse_fields_output(output: &str) -> Vec<Packet> {
    let mut lines = output.lines();
    let Some(header_line) = lines.next() else {
        return Vec::new();
    };

    let header: Vec<&str> = header_line.split('\t').collect();
    let mut col: HashMap<String, usize> = HashMap::new();
    for (idx, field_name) in header.iter().enumerate() {
        col.insert(field_name.trim().to_lowercase(), idx);
    }

    let mut packets = Vec::new();

    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < header.len() {
            continue;
        }

        let g = |name: &str| -> String {
            let idx = col.get(&name.to_lowercase()).copied().unwrap_or(usize::MAX);
            if idx < fields.len() {
                fields[idx].trim().to_string()
            } else {
                String::new()
            }
        };

        let frame_num = g("frame.number").parse::<u32>().unwrap_or(0);
        let rel_time = g("frame.time_relative").parse::<f64>().unwrap_or(0.0);
        let protocols = g("frame.protocols");
        let info = g("_ws.col.info");
        let proto_col = g("_ws.col.protocol");
        let ip_src = g("ip.src");
        let ip_dst = g("ip.dst");

        let (layer, direction, msg_name, color_key) =
            classify_packet(&protocols, &proto_col, &info, &ip_src, &ip_dst);

        packets.push(Packet {
            index: frame_num,
            relative_time: rel_time,
            protocols,
            protocol: layer,
            color_key,
            message_type: msg_name,
            direction,
            info,
            src: ip_src,
            dst: ip_dst,
        });
    }

    packets
}

fn classify_packet(
    protocols: &str,
    proto_col: &str,
    info: &str,
    _ip_src: &str,
    _ip_dst: &str,
) -> (String, String, String, String) {
    let proto_chain = protocols.to_lowercase();
    let info_str = info.trim();

    let mut direction = "ul".to_string();
    if info_str.contains("[DL]")
        || info_str.contains("DL Information Transfer")
        || info_str.contains("DL-DCCH")
    {
        direction = "dl".to_string();
    } else if info_str.contains("[UL]")
        || info_str.contains("UL Information Transfer")
        || info_str.contains("UL-DCCH")
    {
        direction = "ul".to_string();
    } else {
        let dl_msgs = [
            "RRC Setup ",
            "RRC Reconfiguration",
            "RRC Release",
            "Security Mode Command",
            "Identity request",
            "Authentication request",
            "Registration accept",
            "Paging",
            "MSG2",
            "MSG4",
        ];
        let ul_msgs = [
            "RRC Setup Request",
            "RRC Setup Complete",
            "RRC Reconfiguration Complete",
            "Security Mode Complete",
            "Identity response",
            "Authentication response",
            "Registration request",
            "Measurement Report",
            "MSG1",
            "MSG3",
        ];

        if ul_msgs.iter().any(|k| info_str.contains(k)) {
            direction = "ul".to_string();
        } else if dl_msgs.iter().any(|k| info_str.contains(k)) {
            direction = "dl".to_string();
        }
    }

    let mut layer = proto_col.to_string();
    let mut color_key = "other".to_string();
    let mut msg_name = truncate(extract_message_name(info_str), 70);

    if proto_chain.contains("nas-5gs") || proto_col.contains("NAS") {
        layer = "NAS-5GS".to_string();
        color_key = "nas".to_string();
        msg_name = truncate(extract_message_name(info_str), 70);
    } else if proto_chain.contains("ngap") || proto_col.contains("NGAP") {
        layer = "NGAP".to_string();
        color_key = "ngap".to_string();
        msg_name = truncate(extract_message_name(info_str), 70);
    } else if proto_chain.contains("nr-rrc") || proto_col.contains("RRC") {
        layer = "RRC".to_string();
        color_key = "rrc".to_string();
        msg_name = truncate(extract_message_name(info_str), 70);
    } else if proto_chain.contains("rlc-nr") || proto_col.contains("RLC") {
        layer = "RLC".to_string();
        color_key = "rlc".to_string();
        msg_name = truncate(extract_rlc_name(info_str), 70);
    } else if proto_chain.contains("mac-nr") || proto_col.contains("MAC") {
        layer = "MAC".to_string();
        color_key = "mac".to_string();
        msg_name = truncate(extract_message_name(info_str), 70);
    }

    (layer, direction, msg_name, color_key)
}

fn truncate(text: String, max_chars: usize) -> String {
    text.chars().take(max_chars).collect::<String>()
}

fn extract_message_name(info: &str) -> String {
    let mut s = info.trim().to_string();

    let noise_patterns = [
        "(Padding ",
        "(Short BSR",
        "(PHR",
        "UEId=",
        "[AM]",
    ];

    for pattern in noise_patterns {
        if let Some(pos) = s.find(pattern) {
            s = s[..pos].trim().trim_matches(',').trim().to_string();
        }
    }

    if s.is_empty() {
        "RLC ACK".to_string()
    } else {
        s
    }
}

fn extract_rlc_name(info: &str) -> String {
    if info.contains("[AM]") {
        let mut bearer = "RLC".to_string();
        if let Some(i) = info.find("SRB:") {
            let chunk = &info[i..];
            let token = chunk.split_whitespace().next().unwrap_or("SRB");
            bearer = format!("RLC {token}");
        } else if let Some(i) = info.find("DRB:") {
            let chunk = &info[i..];
            let token = chunk.split_whitespace().next().unwrap_or("DRB");
            bearer = format!("RLC {token}");
        }

        if let Some(i) = info.find("SN=") {
            let tail = &info[i..];
            let sn = tail.split_whitespace().next().unwrap_or("SN");
            return format!("{bearer} {sn}");
        }
        return bearer;
    }

    truncate(info.to_string(), 40)
}

fn get_packet_details_blocking(
    file_path: &str,
    frame_num: u32,
    selected_decode_opts: &[String],
) -> Result<Vec<TreeNode>, String> {
    if !Path::new(file_path).exists() {
        return Ok(vec![TreeNode {
            id: "missing".to_string(),
            label: "capture file not found".to_string(),
            children: None,
        }]);
    }

    let tshark_bin = find_tshark().ok_or_else(|| {
        "tshark not found. Install Wireshark or set TSHARK_BIN environment variable.".to_string()
    })?;

    let mut cmd = Command::new(tshark_bin);
    cmd.arg("-r").arg(file_path);
    cmd.args([
        "-o",
        "mac-nr.attempt_to_dissect_srb_sdus:TRUE",
        "-o",
        "mac-nr.attempt_rrc_decode:TRUE",
        "-o",
        "nas-5gs.null_decipher:TRUE",
        "--enable-heuristic",
        "mac_nr_udp",
        "--enable-heuristic",
        "rlc_nr_udp",
        "--enable-heuristic",
        "pdcp_nr_udp",
        "--enable-heuristic",
        "nas_5gs_udp",
    ]);
    cmd.args(selected_decode_opts);
    cmd.arg("-Y").arg(format!("frame.number == {frame_num}"));
    cmd.arg("-T").arg("pdml");

    let output = cmd
        .output()
        .map_err(|e| format!("failed to run tshark pdml: {e}"))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        return Ok(vec![TreeNode {
            id: "error".to_string(),
            label: format!("tshark PDML error: {}", first_line(&err)),
            children: None,
        }]);
    }

    let xml = String::from_utf8_lossy(&output.stdout).to_string();
    if xml.trim().is_empty() {
        return Ok(vec![TreeNode {
            id: "empty".to_string(),
            label: "no decoded data for this frame".to_string(),
            children: None,
        }]);
    }

    let root = Element::parse(xml.as_bytes()).map_err(|e| format!("PDML parse error: {e}"))?;
    let Some(packet) = root.get_child("packet") else {
        return Ok(vec![TreeNode {
            id: "missing_packet".to_string(),
            label: "PDML packet node missing".to_string(),
            children: None,
        }]);
    };

    let mut counter: usize = 0;
    let mut nodes = Vec::new();
    for child in &packet.children {
        if let XMLNode::Element(el) = child {
            if el.name == "proto" {
                if let Some(node) = parse_proto(el, &mut counter) {
                    nodes.push(node);
                }
            }
        }
    }

    if nodes.is_empty() {
        nodes.push(TreeNode {
            id: "none".to_string(),
            label: "no protocol nodes found".to_string(),
            children: None,
        });
    }

    Ok(nodes)
}

fn parse_proto(elem: &Element, counter: &mut usize) -> Option<TreeNode> {
    let showname = elem.attributes.get("showname").cloned().unwrap_or_default();
    let name = elem.attributes.get("name").cloned().unwrap_or_default();
    let label = if !showname.is_empty() { showname } else { name.clone() };
    if label.is_empty() {
        return None;
    }

    *counter += 1;
    let id = format!("p_{counter}");

    let mut children = Vec::new();
    for child in &elem.children {
        if let XMLNode::Element(el) = child {
            if el.name == "field" {
                if let Some(node) = parse_field(el, counter) {
                    children.push(node);
                }
            } else if el.name == "proto" {
                if let Some(node) = parse_proto(el, counter) {
                    children.push(node);
                }
            }
        }
    }

    Some(TreeNode {
        id,
        label: truncate(label, 200),
        children: if children.is_empty() { None } else { Some(children) },
    })
}

fn parse_field(elem: &Element, counter: &mut usize) -> Option<TreeNode> {
    let showname = elem.attributes.get("showname").cloned().unwrap_or_default();
    let show = elem.attributes.get("show").cloned().unwrap_or_default();
    let name = elem.attributes.get("name").cloned().unwrap_or_default();
    let label = if !showname.is_empty() {
        showname
    } else if !show.is_empty() {
        show
    } else {
        name
    };

    if label.is_empty() {
        return None;
    }

    *counter += 1;
    let id = format!("f_{counter}");

    let mut children = Vec::new();
    for child in &elem.children {
        if let XMLNode::Element(el) = child {
            if el.name == "field" {
                if let Some(node) = parse_field(el, counter) {
                    children.push(node);
                }
            }
        }
    }

    Some(TreeNode {
        id,
        label: truncate(label, 200),
        children: if children.is_empty() { None } else { Some(children) },
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![parse_pcap, get_packet_details])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
