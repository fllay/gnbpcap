# 5G NR Ladder Diagram Viewer

A desktop application for visualizing 5G NR (New Radio) protocol traces as an interactive ladder diagram. Built with [NiceGUI](https://nicegui.io/) and uses Wireshark's [tshark](https://www.wireshark.org/) for deep protocol decoding.

## Features

- **Load PCAP files** - Upload via drag-and-drop or specify file path
- **Ladder Diagram** - Visualizes UE ↔ gNB message exchanges over time
- **Protocol Layers** - Color-coded by layer: MAC, RLC, RRC, NGAP, NAS-5GS
- **Filtering** - Filter by protocol layer or UE/IP address
- **Click for Details** - Click any message to see the full Wireshark-like protocol tree
- **Pagination** - Navigate through large captures with page controls

## Requirements

- **macOS** (tested) - may work on Linux with path adjustments
- **Python 3.10+**
- **Wireshark** (includes tshark) - Must be installed at `/Applications/Wireshark.app/Contents/MacOS/tshark`

## Installation

```bash
cd /Users/cake/Desktop/Projects/5g/gnbpcap
pip install nicegui
```

## Usage

```bash
python app.py
```

The app opens at **http://localhost:8080**

### Loading a PCAP

1. Click **Upload** to select a `.pcap` or `.pcapng` file, OR
2. Enter a file path in the input field and click **Load**

### Viewing Details

1. Click on any message name in the ladder diagram
2. The right panel shows the full protocol tree (Frame → MAC-NR → RLC → PDCP → RRC → NAS, etc.)
3. Expand/collapse nodes to explore decoded fields

### Filtering

- Use the **Layer** dropdown to show only specific protocols (MAC, RLC, RRC, NGAP, NAS)
- Use the **UE / IP filter** to search by IP address or UE identifier

## Supported Protocols

| Layer | Color | Description |
|-------|-------|-------------|
| MAC | Teal (#4ecca3) | MAC-NR scheduling, BSR, PHR |
| RLC | Amber (#ffc857) | RLC-NR ACK/SRBs/DRBs |
| RRC | Red (#ff6b6b) | Radio Resource Control |
| NGAP | Purple (#7b68ee) | NG Application Protocol (gNB ↔ AMF) |
| NAS | Pink (#e94560) | NAS-5GS (Registration, PDU Session) |

## Project Structure

```
gnbpcap/
├── app.py          # Main application (NiceGUI + tshark integration)
├── SPEC.md         # Original specification document
└── README.md       # This file
```

## Technical Details

- **Frontend**: NiceGUI (Quasar/Vue components)
- **Backend**: Python with subprocess calls to tshark
- **Protocol Parsing**: Uses `tshark -T fields` for packet list, `tshark -T pdml` for detailed protocol trees
- **Rendering**: HTML5 Canvas for the ladder diagram
- **Protocol Decoding**: Full Wireshark dissector chain via tshark PDML output

## Keyboard Shortcuts

- **Cmd+Shift+R** (Mac) / **Ctrl+Shift+R** (Windows) - Hard refresh to reload

## Troubleshooting

### Canvas not showing
- Hard refresh the browser (Cmd+Shift+R)
- Check browser console for JavaScript errors
- Ensure Wireshark/tshark is installed

### No packets decoded
- Ensure the PCAP contains 5G NR traffic (MAC-NR, RLC-NR, NGAP, etc.)
- Check that tshark can read the file: `tshark -r yourfile.pcap -c 10`

### Port already in use
```bash
lsof -ti:8080 | xargs kill -9
```
