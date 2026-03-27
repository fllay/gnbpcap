import json
import os
import subprocess
import re
import csv
import io
import shutil
import xml.etree.ElementTree as ET
from nicegui import app, ui

# ---------------------------------------------------------------------------
# tshark-based PCAP parser
# ---------------------------------------------------------------------------

def find_tshark() -> str:
    """Find tshark binary in common locations."""
    paths = [
        '/Applications/Wireshark.app/Contents/MacOS/tshark',
        '/Applications/Wireshark.app/Contents/MOS/extras/tshark',
        '/usr/local/bin/tshark',
        '/opt/homebrew/bin/tshark',
        '/usr/bin/tshark',
    ]
    
    for path in paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Try to find in PATH
    tshark_path = shutil.which('tshark')
    if tshark_path:
        return tshark_path
    
    # Default fallback
    return '/Applications/Wireshark.app/Contents/MacOS/tshark'

TSHARK_BIN = find_tshark()

packets_data: list[dict] = []
filtered_packets: list[dict] = []
loaded_pcap_path: str = ''
selected_decode_opts: list[str] = []

# Pagination
PAGE_SIZE = 200
current_page = 0

# UI references (set in create_ui)
detail_tree_ref = None


def parse_pcap_tshark(file_path: str) -> list[dict]:
    """Use tshark to decode the PCAP and extract protocol info."""
    global packets_data, filtered_packets, current_page, loaded_pcap_path, selected_decode_opts

    packets_data = []
    current_page = 0
    loaded_pcap_path = file_path

    if not os.path.exists(file_path):
        ui.notify(f'File not found: {file_path}', type='warning')
        return packets_data

    base_opts = [
        '-o', 'mac-nr.attempt_to_dissect_srb_sdus:TRUE',
        '-o', 'mac-nr.attempt_rrc_decode:TRUE',
        '-o', 'nas-5gs.null_decipher:TRUE',
    ]
    decode_profiles = [
        [],
        ['-o', 'wtap_pktap.prefer_pktap:FALSE'],
        ['-d', 'udp.port==0,udp', '-d', 'user_dlt==149,udp', '-d', 'user_dlt==157,mac-nr-framed'],
    ]

    def parse_lines(lines: list[str]) -> list[dict]:
        if len(lines) < 2:
            return []
        header = lines[0].split('\t')
        col = {h.strip().lower(): i for i, h in enumerate(header)}
        tmp_packets = []

        for line in lines[1:]:
            fields = line.split('\t')
            if len(fields) < len(header):
                continue

            def g(name):
                idx = col.get(name.lower(), -1)
                if 0 <= idx < len(fields):
                    return fields[idx].strip()
                return ''

            frame_num = g('frame.number')
            rel_time = g('frame.time_relative')
            protocols = g('frame.protocols')
            info = g('_ws.col.info')
            proto_col = g('_ws.col.protocol')
            ip_src = g('ip.src')
            ip_dst = g('ip.dst')

            layer, direction, msg_name, color_key = classify_packet(
                protocols, proto_col, info, ip_src, ip_dst
            )

            tmp_packets.append({
                'index': int(frame_num) if frame_num else 0,
                'relative_time': float(rel_time) if rel_time else 0.0,
                'protocols': protocols,
                'protocol': layer,
                'color_key': color_key,
                'message_type': msg_name,
                'direction': direction,
                'info': info,
                'src': ip_src,
                'dst': ip_dst,
            })
        return tmp_packets

    best_packets: list[dict] = []
    best_profile: list[str] = []
    best_score = -1
    last_error = ''

    print(f'Running tshark on {file_path} ...')
    for profile in decode_profiles:
        cmd = [
            TSHARK_BIN,
            '-r', file_path,
            *base_opts,
            *profile,
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', 'frame.protocols',
            '-e', '_ws.col.Info',
            '-e', '_ws.col.Protocol',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-E', 'header=y',
            '-E', 'occurrence=l',
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            ui.notify('tshark not found. Install Wireshark.', type='negative')
            return packets_data
        except subprocess.TimeoutExpired:
            continue

        lines = result.stdout.strip().split('\n') if result.stdout.strip() else []
        if result.returncode != 0:
            last_error = result.stderr[:500]
            continue

        candidate_packets = parse_lines(lines)
        if not candidate_packets:
            continue

        non_pktap = sum(1 for p in candidate_packets if p.get('protocol', '').upper() != 'PKTAP')
        score = non_pktap * 100000 + len(candidate_packets)
        if score > best_score:
            best_score = score
            best_packets = candidate_packets
            best_profile = profile

    packets_data = best_packets
    selected_decode_opts = best_profile

    if not packets_data:
        if last_error:
            print(f'tshark stderr: {last_error}')
        ui.notify('No packets decoded by tshark', type='warning')
        return packets_data

    print(f'Parsed {len(packets_data)} packets via tshark; profile={best_profile}')
    filtered_packets = packets_data[:]
    return packets_data


def classify_packet(protocols: str, proto_col: str, info: str,
                    ip_src: str, ip_dst: str):
    """Return (layer, direction, msg_name, color_key)."""
    proto_upper = proto_col.upper()
    proto_chain = protocols.lower()

    direction = 'ul'
    info_str = info.strip()

    if '[UL]' in info_str:
        direction = 'ul'
    elif '[DL]' in info_str:
        direction = 'dl'
    elif 'DL Information Transfer' in info_str or 'DL-DCCH' in info_str:
        direction = 'dl'
    elif 'UL Information Transfer' in info_str or 'UL-DCCH' in info_str:
        direction = 'ul'
    else:
        dl_msgs = [
            'RRC Setup ', 'RRC Reconfiguration', 'RRC Release',
            'RRC Reject', 'RRC Reestablishment ',
            'Security Mode Command', 'Security mode command',
            'Identity request', 'Authentication request',
            'Registration accept', 'Registration reject',
            'PDU session establishment accept',
            'PDU session modification command',
            'Service accept', 'Service reject',
            'De-registration accept',
            'Configuration update command',
            'UECapabilityEnquiry', 'Capability Enquiry',
            'Paging', 'MasterInformationBlock', 'SystemInformation',
            'RACH Response', 'MSG2', 'MSG4',
        ]
        ul_msgs = [
            'RRC Setup Request', 'RRC Setup Complete',
            'RRC Reconfiguration Complete', 'RRC Reestablishment Request',
            'RRC Reestablishment Complete',
            'Security Mode Complete', 'Security mode complete',
            'Identity response', 'Authentication response',
            'Registration request', 'Registration complete',
            'PDU session establishment request',
            'PDU session modification complete',
            'Service request',
            'UECapabilityInformation', 'Capability Information',
            'Measurement Report',
            'RACH Preamble', 'MSG1', 'MSG3',
            'De-registration request',
        ]

        for kw in ul_msgs:
            if kw in info_str:
                direction = 'ul'
                break
        else:
            for kw in dl_msgs:
                if kw in info_str:
                    direction = 'dl'
                    break

    msg_name = info_str[:80]
    layer = proto_col
    color_key = 'other'

    if 'nas-5gs' in proto_chain or 'NAS' in proto_col:
        layer = 'NAS-5GS'
        color_key = 'nas'
        msg_name = extract_message_name(info_str)
    elif 'ngap' in proto_chain or 'NGAP' in proto_col:
        layer = 'NGAP'
        color_key = 'ngap'
        msg_name = extract_message_name(info_str)
    elif 'nr-rrc' in proto_chain or 'RRC' in proto_col:
        layer = 'RRC'
        color_key = 'rrc'
        msg_name = extract_message_name(info_str)
    elif 'rlc-nr' in proto_chain or 'RLC' in proto_col:
        layer = 'RLC'
        color_key = 'rlc'
        msg_name = extract_rlc_name(info_str)
    elif 'mac-nr' in proto_chain or 'MAC' in proto_col:
        layer = 'MAC'
        color_key = 'mac'
        msg_name = extract_message_name(info_str)

    return layer, direction, msg_name, color_key


def extract_message_name(info: str) -> str:
    """Pull a clean message name from the tshark Info column."""
    info = info.strip()
    info = re.sub(r'\(Padding \d+ bytes?\)', '', info)
    info = re.sub(r'\(Short BSR[^)]*\)', '', info)
    info = re.sub(r'\(PHR[^)]*\)', '', info)
    info = re.sub(r'\[\d+-bytes?\.?\.\.\]', '', info)
    info = re.sub(r'\[\d+-bytes?\]', '', info)
    info = re.sub(r'UEId=\d+\s+\[(UL|DL)\]\s+\[AM\]\s+SRB:\d+\s+\[(?:CONTROL|DATA)\]\s+(?:ACK_)?SN=\d+\s*(?:\|\|)?\s*,?\s*', '', info)
    info = re.sub(r'\s{2,}', ' ', info).strip()
    info = info.strip(',').strip()
    if not info:
        return 'RLC ACK'
    return info[:70]


def extract_rlc_name(info: str) -> str:
    """Extract a short name for RLC-only packets."""
    info = info.strip()
    m = re.search(r'\[(UL|DL)\]\s+\[AM\]\s+(SRB|DRB):(\d+)\s+\[(CONTROL|DATA)\]', info)
    if m:
        bearer = f'{m.group(2)}:{m.group(3)}'
        pdu_type = m.group(4)
        sn_match = re.search(r'(?:ACK_)?SN=(\d+)', info)
        sn = sn_match.group(0) if sn_match else ''
        return f'RLC {bearer} {pdu_type} {sn}'.strip()
    return info[:40]


# ---------------------------------------------------------------------------
# Filter / draw helpers
# ---------------------------------------------------------------------------

def apply_filters(layer_filters: dict | None = None, ue_filter: str = ''):
    global filtered_packets, current_page
    current_page = 0
    filtered_packets = packets_data[:]

    # layer_filters is a dict like {'MAC': True, 'RLC': True, ...}
    if layer_filters:
        active_layers = [k for k, v in layer_filters.items() if v]
        if active_layers:
            filtered_packets = [
                p for p in filtered_packets
                if p['color_key'] in [l.lower() for l in active_layers]
                   or p['protocol'].upper() in [l.upper() for l in active_layers]
            ]

    if ue_filter:
        ue_lower = ue_filter.lower()
        filtered_packets = [
            p for p in filtered_packets
            if ue_lower in p['src'].lower()
            or ue_lower in p['dst'].lower()
            or ue_lower in p['info'].lower()
        ]

    draw_diagram()


def draw_diagram():
    try:
        start = current_page * PAGE_SIZE
        end = start + PAGE_SIZE
        page_data = filtered_packets[start:end]
        data = json.dumps(page_data)
        # Use a retry wrapper in case drawLadder isn't ready yet
        ui.run_javascript(f'''
            (function tryDraw(retries) {{
                if (window.drawLadder) {{
                    window.drawLadder({data});
                }} else if (retries > 0) {{
                    setTimeout(function() {{ tryDraw(retries - 1); }}, 200);
                }}
            }})(20);
        ''')
    except Exception as e:
        print(f'draw_diagram error: {e}')


def go_page(delta: int):
    global current_page
    total_pages = max(1, (len(filtered_packets) + PAGE_SIZE - 1) // PAGE_SIZE)
    current_page = max(0, min(current_page + delta, total_pages - 1))
    draw_diagram()


def go_to_page(page_num: int):
    global current_page
    total_pages = max(1, (len(filtered_packets) + PAGE_SIZE - 1) // PAGE_SIZE)
    current_page = max(0, min(page_num, total_pages - 1))
    draw_diagram()


# ---------------------------------------------------------------------------
# Wireshark-like protocol tree via tshark PDML
# ---------------------------------------------------------------------------

_id_counter = 0


def _next_id(prefix: str = 'n') -> str:
    """Generate a unique ID for each tree node."""
    global _id_counter
    _id_counter += 1
    return f'{prefix}_{_id_counter}'


def _parse_xml_field(elem) -> dict | None:
    """Recursively parse a PDML <field> element into a tree node."""
    showname = elem.get('showname', '')
    show = elem.get('show', '')
    name = elem.get('name', '')

    label = showname or show or name
    if not label:
        return None

    label = label[:200]

    children = []
    for child in elem:
        if child.tag == 'field':
            child_node = _parse_xml_field(child)
            if child_node:
                children.append(child_node)

    node = {'id': _next_id(name or 'f'), 'label': label}
    if children:
        node['children'] = children
    return node


def _parse_xml_proto(proto_elem) -> dict | None:
    """Parse a PDML <proto> element into a tree node with its direct <field> children."""
    showname = proto_elem.get('showname', '')
    name = proto_elem.get('name', '')
    label = showname or name
    if not label:
        return None

    children = []
    for child in proto_elem:
        if child.tag == 'field':
            node = _parse_xml_field(child)
            if node:
                children.append(node)
        elif child.tag == 'proto':
            # Nested protocol (e.g. NAS inside RRC)
            sub_proto = _parse_xml_proto(child)
            if sub_proto:
                children.append(sub_proto)

    result = {'id': _next_id(name or 'p'), 'label': label}
    if children:
        result['children'] = children
    return result


def tshark_get_pdml(frame_num: int) -> list[dict]:
    """Run tshark -T pdml for a single frame and return tree nodes for NiceGUI."""
    global _id_counter
    _id_counter = 0

    if not loaded_pcap_path or not os.path.exists(loaded_pcap_path):
        return []

    cmd = [
        TSHARK_BIN,
        '-r', loaded_pcap_path,
        '-o', 'mac-nr.attempt_to_dissect_srb_sdus:TRUE',
        '-o', 'mac-nr.attempt_rrc_decode:TRUE',
        '-o', 'nas-5gs.null_decipher:TRUE',
        *selected_decode_opts,
        '-Y', f'frame.number == {frame_num}',
        '-T', 'pdml',
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        print(f'tshark pdml error: {e}')
        return []

    if result.returncode != 0:
        print(f'tshark pdml stderr: {result.stderr[:300]}')
        return []

    xml_text = result.stdout.strip()
    if not xml_text:
        return []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f'PDML parse error: {e}')
        return []

    # Find the <packet> element
    packet = root.find('packet')
    if packet is None:
        return []

    tree_nodes = []
    for proto_elem in packet:
        if proto_elem.tag == 'proto':
            node = _parse_xml_proto(proto_elem)
            if node:
                tree_nodes.append(node)

    return tree_nodes


def get_packet_details(packet_index: int):
    """Get detailed packet info from tshark PDML for a specific packet."""
    global detail_tree_ref

    if not packets_data or detail_tree_ref is None:
        return

    # Run tshark PDML to get the full Wireshark-like protocol tree
    tree_nodes = tshark_get_pdml(packet_index)

    if not tree_nodes:
        tree_nodes = [{'id': 'empty', 'label': f'No decoded data for frame #{packet_index}'}]

    try:
        detail_tree_ref.props['nodes'] = tree_nodes
        detail_tree_ref.update()
    except Exception as e:
        print(f'Tree update error: {e}')


async def on_canvas_click(e):
    """Handle click on canvas - get packet index and show details."""
    try:
        # emitEvent sends {args: packetIndex}
        data = e.args
        if isinstance(data, dict):
            packet_index = int(data.get('args', 0))
        else:
            packet_index = int(data)
        print(f'on_canvas_click: frame #{packet_index}')
        get_packet_details(packet_index)
    except Exception as ex:
        print(f"Click error: {ex}")
        import traceback; traceback.print_exc()


# ---------------------------------------------------------------------------
# File load handlers
# ---------------------------------------------------------------------------

async def handle_file_upload(e):
    try:
        print(f"Upload event received: {e}")
        file_obj = getattr(e, 'file', None)
        if not file_obj:
            ui.notify('No file in upload event', type='warning')
            return
        temp_path = getattr(file_obj, '_path', None)
        if not temp_path:
            ui.notify('Cannot find temp file path', type='warning')
            return
        print(f"  temp file: {temp_path}")
        import shutil
        dest = f'/tmp/{file_obj.name}'
        shutil.copy(str(temp_path), dest)
        print(f"  copied to: {dest}")
        parse_pcap_tshark(dest)
        ui.notify(f'Loaded {len(packets_data)} packets', type='positive')
        draw_diagram()
    except Exception as ex:
        print(f"Upload error: {ex}")
        import traceback; traceback.print_exc()
        ui.notify(f'Error: {str(ex)[:50]}', type='negative')


async def handle_multi_upload(e):
    try:
        print(f"Multi-upload event: {e}")
        files = getattr(e, 'files', [])
        if not files:
            ui.notify('No files in upload', type='warning')
            return
        file_obj = files[-1]
        temp_path = getattr(file_obj, '_path', None)
        if temp_path:
            import shutil
            dest = f'/tmp/{file_obj.name}'
            shutil.copy(str(temp_path), dest)
            parse_pcap_tshark(dest)
            ui.notify(f'Loaded {len(packets_data)} packets', type='positive')
            draw_diagram()
    except Exception as ex:
        print(f"Multi-upload error: {ex}")
        import traceback; traceback.print_exc()


def load_pcap_from_path(path: str):
    path = path.strip()
    print(f'load_pcap_from_path called with: "{path}"')
    if not path or not os.path.exists(path):
        ui.notify(f'File not found: {path}', type='warning')
        return
    parse_pcap_tshark(path)
    ui.notify(f'Loaded {len(packets_data)} packets', type='positive')
    draw_diagram()


# ---------------------------------------------------------------------------
# JavaScript - vertical ladder diagram with clickable message labels
# ---------------------------------------------------------------------------

LADDER_INJECT_JS = r'''
<script>
(function injectCanvas() {
    const container = document.getElementById('ladder-container');
    if (!container) { setTimeout(injectCanvas, 100); return; }
    if (!document.getElementById('ladder-canvas')) {
        const c = document.createElement('canvas');
        c.id = 'ladder-canvas';
        c.width = 950;
        c.height = 600;
        c.style.background = '#1a1a2e';
        container.appendChild(c);
        console.log('Canvas injected');
    }
})();
</script>
'''

LADDER_JS = r'''
<script>
function initLadder() {
    const canvas = document.getElementById('ladder-canvas');
    if (!canvas) { setTimeout(initLadder, 200); return; }
    const ctx = canvas.getContext('2d');
    if (!ctx) { console.log('no 2d context'); return; }

    const dpr = window.devicePixelRatio || 1;

    const COLORS = {
        bg:       '#1a1a2e',
        lifeline: '#2a6a4a',
        lifelineGnb: '#3a5a8a',
        mac:  '#4ecca3',
        rlc:  '#ffc857',
        rrc:  '#ff6b6b',
        ngap: '#7b68ee',
        nas:  '#e94560',
        other:'#888888',
        text: '#eaeaea',
        ue:   '#ff6b6b',
        gnb:  '#4dabf7',
    };

    const CFG = {
        ueX:       250,
        gnbX:      700,
        topY:      90,
        rowH:      50,
        padBottom: 40,
        labelFontSize: 14,
    };

    // Store current packets and label hit regions for click detection
    let currentPackets = [];
    let labelHitRegions = [];
    let selectedRow = -1;

    window.drawLadder = function(data) {
        currentPackets = data || [];
        labelHitRegions = [];
        const packets = currentPackets;
        const totalH = CFG.topY + packets.length * CFG.rowH + CFG.padBottom;
        const W = 950;

        canvas.style.width  = W + 'px';
        canvas.style.height = totalH + 'px';
        canvas.width  = W * dpr;
        canvas.height = totalH * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        // Background
        ctx.fillStyle = COLORS.bg;
        ctx.fillRect(0, 0, W, totalH);

        // Column headers
        ctx.textAlign = 'center';
        ctx.font = 'bold 18px "JetBrains Mono", monospace';
        ctx.fillStyle = '#9aa0a6';
        ctx.fillText('Proto', 150, 30);
        ctx.fillStyle = COLORS.ue;
        ctx.fillText('UE', CFG.ueX, 30);
        ctx.fillStyle = COLORS.gnb;
        ctx.fillText('gNB', CFG.gnbX, 30);

        ctx.font = '28px serif';
        ctx.fillText('\uD83D\uDCF1', CFG.ueX, 64);
        ctx.fillText('\uD83D\uDCE1', CFG.gnbX, 64);

        // Lifelines
        ctx.save();
        ctx.setLineDash([6, 4]);
        ctx.strokeStyle = COLORS.lifeline;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(CFG.ueX, CFG.topY);
        ctx.lineTo(CFG.ueX, totalH - 10);
        ctx.stroke();
        ctx.strokeStyle = COLORS.lifelineGnb;
        ctx.beginPath();
        ctx.moveTo(CFG.gnbX, CFG.topY);
        ctx.lineTo(CFG.gnbX, totalH - 10);
        ctx.stroke();
        ctx.restore();

        if (packets.length === 0) {
            ctx.fillStyle = COLORS.text;
            ctx.font = 'italic 16px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('No packets loaded \u2013 enter a PCAP path above', W / 2, 200);
            return;
        }

        // Draw each message as an arrow
        packets.forEach((pkt, i) => {
            const y = CFG.topY + i * CFG.rowH + 25;
            const isUL = pkt.direction === 'ul';
            const fromX = isUL ? CFG.ueX : CFG.gnbX;
            const toX   = isUL ? CFG.gnbX : CFG.ueX;
            const color  = COLORS[pkt.color_key] || COLORS.other;

            // Highlight selected row
            if (i === selectedRow) {
                ctx.fillStyle = 'rgba(255,255,255,0.07)';
                ctx.fillRect(0, y - CFG.rowH / 2 + 2, W, CFG.rowH);
            }

            // Arrow line
            ctx.save();
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.setLineDash([4, 3]);
            ctx.beginPath();
            ctx.moveTo(fromX, y);
            ctx.lineTo(toX, y);
            ctx.stroke();
            ctx.restore();

            // Arrowhead
            const headLen = 10;
            const dir = isUL ? 1 : -1;
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.moveTo(toX, y);
            ctx.lineTo(toX - dir * headLen, y - 5);
            ctx.lineTo(toX - dir * headLen, y + 5);
            ctx.closePath();
            ctx.fill();

            // Dot at source
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(fromX, y, 4, 0, Math.PI * 2);
            ctx.fill();

            // Message label (clickable)
            const midX = (fromX + toX) / 2;
            ctx.fillStyle = color;
            ctx.font = 'italic ' + CFG.labelFontSize + 'px "JetBrains Mono", monospace';
            ctx.textAlign = 'center';
            const labelText = pkt.message_type;
            ctx.fillText(labelText, midX, y - 8);

            // Measure text to store hit region
            const metrics = ctx.measureText(labelText);
            const lx = midX - metrics.width / 2 - 4;
            const ly = y - 8 - CFG.labelFontSize;
            const lw = metrics.width + 8;
            const lh = CFG.labelFontSize + 6;
            labelHitRegions.push({ x: lx, y: ly, w: lw, h: lh, rowIndex: i, packetIndex: pkt.index });

            // Timestamp
            ctx.fillStyle = '#666';
            ctx.font = '10px monospace';
            ctx.textAlign = 'right';
            ctx.fillText(pkt.relative_time.toFixed(4) + 's', 55, y + 3);

            // Protocol type column between timestamp and ladder
            ctx.fillStyle = color;
            ctx.font = '11px "JetBrains Mono", monospace';
            ctx.textAlign = 'center';
            const protoText = (pkt.protocol || '').toString().toUpperCase();
            ctx.fillText(protoText, 150, y + 3);
        });
    };

    console.log('drawLadder ready');
    window.drawLadder([]);

    // Click handler - detect clicks on message labels
    canvas.addEventListener('click', function(e) {
        const rect = canvas.getBoundingClientRect();
        const scaleX = (canvas.width / dpr) / rect.width;
        const scaleY = (canvas.height / dpr) / rect.height;
        const mx = (e.clientX - rect.left) * scaleX;
        const my = (e.clientY - rect.top) * scaleY;

        // Check if click is on a label hit region
        for (let i = labelHitRegions.length - 1; i >= 0; i--) {
            const r = labelHitRegions[i];
            if (mx >= r.x && mx <= r.x + r.w && my >= r.y && my <= r.y + r.h) {
                selectedRow = r.rowIndex;
                console.log('Clicked message label:', r.packetIndex, currentPackets[r.rowIndex].message_type);
                // Redraw to show highlight
                window.drawLadder(currentPackets);
                // Emit to Python via NiceGUI custom event
                emitEvent('ladder-packet-click', { args: r.packetIndex });
                return;
            }
        }

        // Fallback: click on arrow row area
        const clickedIndex = Math.floor((my - CFG.topY - 25 + CFG.rowH / 2) / CFG.rowH);
        if (clickedIndex >= 0 && clickedIndex < currentPackets.length) {
            selectedRow = clickedIndex;
            const pkt = currentPackets[clickedIndex];
            console.log('Clicked row:', pkt.index, pkt.message_type);
            window.drawLadder(currentPackets);
            emitEvent('ladder-packet-click', { args: pkt.index });
        }
    });

    // Cursor change on hover over labels
    canvas.addEventListener('mousemove', function(e) {
        const rect = canvas.getBoundingClientRect();
        const scaleX = (canvas.width / dpr) / rect.width;
        const scaleY = (canvas.height / dpr) / rect.height;
        const mx = (e.clientX - rect.left) * scaleX;
        const my = (e.clientY - rect.top) * scaleY;

        let onLabel = false;
        for (let i = 0; i < labelHitRegions.length; i++) {
            const r = labelHitRegions[i];
            if (mx >= r.x && mx <= r.x + r.w && my >= r.y && my <= r.y + r.h) {
                onLabel = true;
                break;
            }
        }
        canvas.style.cursor = onLabel ? 'pointer' : 'default';
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initLadder);
} else {
    initLadder();
}
</script>
'''


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

COLORS_UI = {
    'primary': '#0f3460',
    'surface': '#16213e',
    'accent': '#e94560',
    'mac': '#4ecca3',
    'rlc': '#ffc857',
    'rrc': '#ff6b6b',
    'ngap': '#7b68ee',
    'nas': '#e94560',
}


def create_ui():
    global detail_tree_ref

    ui.colors(primary=COLORS_UI['primary'],
              secondary=COLORS_UI['surface'],
              accent=COLORS_UI['accent'])

    # --- Header ---
    with ui.header(elevated=True).classes('items-center justify-between'):
        ui.label('5G NR Ladder Diagram').classes('text-h5')
        with ui.row().classes('gap-2 items-center'):
            file_input = ui.input(label='PCAP path',
                                  placeholder='/path/to/capture.pcap') \
                           .classes('w-96')
            ui.button('Load',
                      on_click=lambda: load_pcap_from_path(file_input.value)) \
              .props('size=sm color=positive')
            ui.upload(on_upload=handle_file_upload,
                      on_multi_upload=handle_multi_upload,
                      multiple=False,
                      label='Upload',
                      max_file_size=200_000_000,
                      auto_upload=True) \
              .props('accept=".pcap,.pcapng"').classes('w-32')
            
    ui.add_head_html('''
        <style>
            .q-uploader__list { display: none !important; }
        </style>
    ''')

    # --- Body ---
    with ui.row().classes('w-full gap-4 p-4'):
        # Sidebar filters
        with ui.column().classes('w-48').style('background: #16213e;'):
            ui.label('Filters').classes('text-h6')
            
            # Layer filter checkboxes
            ui.label('Layers').classes('text-subtitle2')
            layer_checkboxes = {}
            for name, color in [('MAC', 'mac'), ('RLC', 'rlc'), ('RRC', 'rrc'), ('NGAP', 'ngap'), ('NAS', 'nas')]:
                with ui.row().classes('items-center gap-2'):
                    cb = ui.checkbox('', value=True, on_change=lambda e: apply_filters({k: v.value for k, v in layer_checkboxes.items()}, ue_input.value))
                    ui.element('div').style(
                        f'width: 12px; height: 12px; background: {COLORS_UI[color]}; border-radius: 2px;'
                    )
                    ui.label(name).style('color: #eaeaea')
                    layer_checkboxes[name] = cb
            
            ue_input = ui.input(label='UE / IP filter',
                                placeholder='e.g. 10.0.0.1',
                                on_change=lambda e: apply_filters(
                                    {k: v.value for k, v in layer_checkboxes.items()}, e.value))

            with ui.card().classes('w-full mt-4').style('background: #16213e; padding: 8px'):
                ui.label('Legend').classes('text-subtitle1').style('color: #eaeaea')
                ui.label('MAC: #4ecca3').style('color: #eaeaea; font-weight: bold')
                ui.label('RLC: #ffc857').style('color: #eaeaea; font-weight: bold')
                ui.label('RRC: #ff6b6b').style('color: #eaeaea; font-weight: bold')
                ui.label('NGAP: #7b68ee').style('color: #eaeaea; font-weight: bold')
                ui.label('NAS: #e94560').style('color: #eaeaea; font-weight: bold')
                for name, color in [('MAC', COLORS_UI['mac']),
                                    ('RLC', COLORS_UI['rlc']),
                                    ('RRC', COLORS_UI['rrc']),
                                    ('NGAP', COLORS_UI['ngap']),
                                    ('NAS-5GS', COLORS_UI['nas'])]:
                    with ui.row().classes('items-center gap-2'):
                        ui.element('div').style(
                            f'width: 14px; height: 14px; background: {color}; border-radius: 2px;'
                        )
                        ui.label(f'{name} ({color})').style('color: #eaeaea')

        # Main diagram area (scrollable)
        with ui.column().classes('flex-grow'):
            # Pagination controls
            with ui.row().classes('w-full items-center justify-center gap-2 mb-2'):
                ui.button('|<', on_click=lambda: go_to_page(0)) \
                    .props('flat dense size=sm').classes('text-white')
                ui.button('<< Prev', on_click=lambda: go_page(-1)) \
                    .props('outline size=sm')
                page_label = ui.label('Page 1 / 1').classes('mx-4 text-white')
                ui.button('Next >>', on_click=lambda: go_page(1)) \
                    .props('outline size=sm')
                ui.button('>|', on_click=lambda: go_to_page(99999)) \
                    .props('flat dense size=sm').classes('text-white')

            with ui.scroll_area().classes('w-full').style(
                    'height: calc(100vh - 210px); '
                    'background: #1a1a2e; border-radius: 8px;') as scroll:
                canvas_container = ui.element('div').classes('w-full')
                canvas_container.props(f'id="ladder-container"')
            ui.add_body_html(LADDER_INJECT_JS)
            ui.add_body_html(LADDER_JS)

        # Right panel: Packet details (Wireshark-like tree)
        with ui.column().classes('w-96'):
            ui.label('Packet Details').classes('text-h6')
            with ui.scroll_area().classes('w-full').style(
                    'height: calc(100vh - 210px); '
                    'background: #1e1e2e; border-radius: 8px; padding: 4px;'):
                detail_tree_ref = ui.tree(
                    [{'id': 'root', 'label': 'Click a message to see details'}],
                    label_key='label',
                    children_key='children',
                ).classes('w-full text-white')
                detail_tree_ref.props('dense')
                # Style the tree to look more like Wireshark
                detail_tree_ref.style(
                    'font-family: "JetBrains Mono", "Consolas", monospace; '
                    'font-size: 12px; '
                    'color: #eaeaea;'
                )
    # Force white text on all inner tree node labels (added to head, outside layout context)
    ui.add_head_html('''
        <style>
            .q-tree__node-header,
            .q-tree__node-header .q-tree__node-header-content,
            .q-tree .q-tree__node--child > .q-tree__node-header,
            .q-tree .q-tree__node-body,
            .q-tree__node-header-content span,
            .q-tree .q-icon {
                color: #eaeaea !important;
            }
        </style>
    ''')

    # Listen for custom event emitted from JS when user clicks a message
    ui.on('ladder-packet-click', on_canvas_click)

    # --- Footer ---
    with ui.footer().classes('items-center'):
        ui.label('Status:').classes('mr-2')
        status_label = ui.label('Ready')

        def update_status():
            n = len(filtered_packets)
            if n == 0:
                status_label.text = 'No packets loaded'
                page_label.text = 'Page 0 / 0'
            else:
                total_pages = (n + PAGE_SIZE - 1) // PAGE_SIZE
                start = current_page * PAGE_SIZE + 1
                end = min((current_page + 1) * PAGE_SIZE, n)
                status_label.text = f'{n} messages total'
                page_label.text = f'Page {current_page + 1} / {total_pages}  (#{start}\u2013#{end})'
        ui.timer(0.5, update_status)


create_ui()
ui.run(title='5G NR Ladder Diagram', port=8080, reload=False)
