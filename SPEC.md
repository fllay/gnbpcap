# 5G RAN Ladder Diagram Viewer - Specification

## Project Overview
- **Project name**: gnbpcap
- **Type**: Desktop Application (NiceGUI)
- **Core functionality**: Parse 5G RAN PCAP files (MAC, RLC, NGAP layers) and display as interactive ladder diagram
- **Target users**: Telecom engineers analyzing 5G NR protocol traces

## UI/UX Specification

### Layout Structure
- **Header**: Application title, file upload button, layer filter controls
- **Sidebar**: Message type legend, filter controls, UE/flow selector
- **Main Area**: Scrollable ladder diagram canvas
- **Footer**: Status bar with packet count, selected packet info

### Visual Design
- **Color Palette**:
  - Background: #1a1a2e (dark navy)
  - Surface: #16213e (darker blue)
  - Primary: #0f3460 (deep blue)
  - Accent: #e94560 (coral red)
  - MAC layer: #4ecca3 (teal)
  - RLC layer: #ffc857 (amber)
  - NGAP layer: #7b68ee (medium slate blue)
  - Text: #eaeaea
  - Grid lines: #2a2a4a
- **Typography**:
  - Font: JetBrains Mono, monospace
  - Headers: 18px bold
  - Body: 14px
  - Labels: 12px
- **Spacing**: 8px base unit

### Components
- File uploader (drag & drop supported)
- Layer toggle buttons (MAC/RLC/NGAP)
- Timeline ruler with time markers
- Message boxes with protocol info
- Connection lines between messages
- Hover tooltips with packet details
- Click to expand packet info panel

## Functionality Specification

### Core Features
1. **PCAP Parsing**: Read DLT_USER packets with DLT 149 (MAC/RLC), DLT 157 (MAC-NR framed), DLT 152 (NGAP)
2. **Protocol Detection**: Identify MAC-NR, RLC-NR, NGAP messages
3. **Ladder Diagram Rendering**:
   - Horizontal axis: Time
   - Vertical axis: Protocol layers/channels
   - Message boxes with direction indicators (UE <-> gNB)
4. **Interactivity**:
   - Zoom in/out (mouse wheel)
   - Pan (drag)
   - Filter by UE, message type
   - Click message for details

### User Interactions
- Upload PCAP via button or drag-drop
- Toggle layers on/off
- Filter by UE ID (UE/C-RNTI)
- Click message to see full packet decoded content
- Export diagram as PNG (future)

### Data Handling
- Use scapy for PCAP parsing
- Extract timestamps, protocol types, message content
- Group messages by UE/flow context

## Acceptance Criteria
1. Application launches with NiceGUI
2. Can load a PCAP file
3. Displays ladder diagram with proper timing
4. Can filter by layer type
5. Shows packet details on click
6. Handles multiple UE contexts
