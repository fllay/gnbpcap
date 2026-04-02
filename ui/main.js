function getInvoke() {
  return window.__TAURI__?.tauri?.invoke;
}

function getOpenDialog() {
  return window.__TAURI__?.dialog?.open;
}

const state = {
  loadedPath: "",
  tsharkBin: "",
  selectedDecodeOpts: [],
  allPackets: [],
  filteredPackets: [],
  pageSize: 200,
  page: 0,
  selectedRow: -1,
  hitRegions: []
};

const el = {
  pcapPath: document.getElementById("pcapPath"),
  pickBtn: document.getElementById("pickBtn"),
  loadBtn: document.getElementById("loadBtn"),
  ueFilter: document.getElementById("ueFilter"),
  pageLabel: document.getElementById("pageLabel"),
  statusText: document.getElementById("statusText"),
  tsharkPath: document.getElementById("tsharkPath"),
  firstPage: document.getElementById("firstPage"),
  prevPage: document.getElementById("prevPage"),
  nextPage: document.getElementById("nextPage"),
  lastPage: document.getElementById("lastPage"),
  canvas: document.getElementById("ladderCanvas"),
  detailsTree: document.getElementById("detailsTree"),
  expandAllBtn: document.getElementById("expandAllBtn"),
  collapseAllBtn: document.getElementById("collapseAllBtn"),
  layerCbs: [...document.querySelectorAll("input[type=checkbox][data-layer]")]
};

const COLORS = {
  bg: "#111b30",
  lifeline: "#2f7a62",
  lifelineGnb: "#3d5d9a",
  mac: "#4ecca3",
  rlc: "#ffc857",
  rrc: "#ff6b6b",
  ngap: "#7b68ee",
  nas: "#e94560",
  other: "#8a95ad",
  text: "#e8edf7",
  ue: "#ff6b6b",
  gnb: "#4dabf7"
};

const CFG = {
  width: 950,
  ueX: 250,
  gnbX: 700,
  topY: 90,
  rowH: 50,
  padBottom: 40,
  labelFontSize: 14
};

function notify(text) {
  el.statusText.textContent = text;
}

function activeLayers() {
  return el.layerCbs.filter((cb) => cb.checked).map((cb) => cb.dataset.layer);
}

function layerMatches(packet, layers) {
  if (!layers.length) {
    return true;
  }
  const packetLayer = (packet.protocol || "").toUpperCase();
  const key = (packet.colorKey || "").toUpperCase();
  return layers.some((layer) => {
    if (layer === "NAS") {
      return packetLayer.includes("NAS") || key === "NAS";
    }
    return packetLayer === layer || key === layer;
  });
}

function applyFilters() {
  const layers = activeLayers();
  const ue = (el.ueFilter.value || "").trim().toLowerCase();

  state.filteredPackets = state.allPackets.filter((p) => {
    const okLayer = layerMatches(p, layers);
    if (!okLayer) {
      return false;
    }
    if (!ue) {
      return true;
    }
    return (
      (p.src || "").toLowerCase().includes(ue) ||
      (p.dst || "").toLowerCase().includes(ue) ||
      (p.info || "").toLowerCase().includes(ue)
    );
  });

  state.page = 0;
  state.selectedRow = -1;
  drawCurrentPage();
}

function totalPages() {
  if (!state.filteredPackets.length) {
    return 0;
  }
  return Math.ceil(state.filteredPackets.length / state.pageSize);
}

function pageSlice() {
  const start = state.page * state.pageSize;
  return state.filteredPackets.slice(start, start + state.pageSize);
}

function updatePageLabel() {
  const pages = totalPages();
  if (!pages) {
    el.pageLabel.textContent = "Page 0 / 0";
    return;
  }
  const start = state.page * state.pageSize + 1;
  const end = Math.min((state.page + 1) * state.pageSize, state.filteredPackets.length);
  el.pageLabel.textContent = `Page ${state.page + 1} / ${pages} (#${start}-#${end})`;
}

function drawCurrentPage() {
  drawLadder(pageSlice());
  updatePageLabel();
  if (!state.filteredPackets.length) {
    notify("No packets loaded");
  } else {
    notify(`${state.filteredPackets.length} messages total`);
  }
}

function drawLadder(packets) {
  const canvas = el.canvas;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const h = CFG.topY + packets.length * CFG.rowH + CFG.padBottom;

  canvas.style.width = `${CFG.width}px`;
  canvas.style.height = `${h}px`;
  canvas.width = Math.floor(CFG.width * dpr);
  canvas.height = Math.floor(h * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  state.hitRegions = [];
  ctx.fillStyle = COLORS.bg;
  ctx.fillRect(0, 0, CFG.width, h);

  ctx.textAlign = "center";
  ctx.font = 'bold 18px "JetBrains Mono", monospace';
  ctx.fillStyle = "#9aa0b4";
  ctx.fillText("Proto", 150, 30);
  ctx.fillStyle = COLORS.ue;
  ctx.fillText("UE", CFG.ueX, 30);
  ctx.fillStyle = COLORS.gnb;
  ctx.fillText("gNB", CFG.gnbX, 30);

  ctx.save();
  ctx.setLineDash([6, 4]);
  ctx.strokeStyle = COLORS.lifeline;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(CFG.ueX, CFG.topY);
  ctx.lineTo(CFG.ueX, h - 10);
  ctx.stroke();
  ctx.strokeStyle = COLORS.lifelineGnb;
  ctx.beginPath();
  ctx.moveTo(CFG.gnbX, CFG.topY);
  ctx.lineTo(CFG.gnbX, h - 10);
  ctx.stroke();
  ctx.restore();

  if (!packets.length) {
    ctx.fillStyle = COLORS.text;
    ctx.font = "italic 16px monospace";
    ctx.fillText("No packets loaded - choose a PCAP file", CFG.width / 2, 180);
    return;
  }

  for (let i = 0; i < packets.length; i += 1) {
    const pkt = packets[i];
    const y = CFG.topY + i * CFG.rowH + 25;
    const isUL = pkt.direction === "ul";
    const fromX = isUL ? CFG.ueX : CFG.gnbX;
    const toX = isUL ? CFG.gnbX : CFG.ueX;
    const color = COLORS[pkt.colorKey] || COLORS.other;

    if (i === state.selectedRow) {
      ctx.fillStyle = "rgba(255,255,255,0.08)";
      ctx.fillRect(0, y - CFG.rowH / 2 + 2, CFG.width, CFG.rowH);
    }

    ctx.save();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.setLineDash([4, 3]);
    ctx.beginPath();
    ctx.moveTo(fromX, y);
    ctx.lineTo(toX, y);
    ctx.stroke();
    ctx.restore();

    const headLen = 10;
    const dir = isUL ? 1 : -1;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.moveTo(toX, y);
    ctx.lineTo(toX - dir * headLen, y - 5);
    ctx.lineTo(toX - dir * headLen, y + 5);
    ctx.closePath();
    ctx.fill();

    ctx.beginPath();
    ctx.arc(fromX, y, 4, 0, Math.PI * 2);
    ctx.fill();

    const midX = (fromX + toX) / 2;
    const labelText = pkt.messageType || "(unknown)";
    ctx.fillStyle = color;
    ctx.font = `italic ${CFG.labelFontSize}px "JetBrains Mono", monospace`;
    ctx.textAlign = "center";
    ctx.fillText(labelText, midX, y - 8);

    const metrics = ctx.measureText(labelText);
    state.hitRegions.push({
      x: midX - metrics.width / 2 - 4,
      y: y - 8 - CFG.labelFontSize,
      w: metrics.width + 8,
      h: CFG.labelFontSize + 6,
      rowIndex: i,
      frameNum: pkt.index
    });

    ctx.fillStyle = "#667491";
    ctx.font = "10px monospace";
    ctx.textAlign = "right";
    ctx.fillText(`${Number(pkt.relativeTime).toFixed(4)}s`, 55, y + 3);

    ctx.fillStyle = color;
    ctx.font = '11px "JetBrains Mono", monospace';
    ctx.textAlign = "center";
    ctx.fillText((pkt.protocol || "").toUpperCase(), 150, y + 3);
  }
}

function clearTree(label) {
  el.detailsTree.innerHTML = "";
  const p = document.createElement("p");
  p.className = "tree-label";
  p.textContent = label;
  el.detailsTree.appendChild(p);
}

function renderTreeNode(node, parent, depth = 0) {
  const row = document.createElement("div");
  const hasChildren = Array.isArray(node.children) && node.children.length > 0;
  row.className = "tree-node";
  if (hasChildren) {
    row.classList.add("has-children");
    row.classList.add("collapsed");
  }

  const item = document.createElement("div");
  item.className = "tree-item";

  if (hasChildren) {
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "tree-toggle";
    toggle.textContent = "▾";
    toggle.addEventListener("click", () => {
      row.classList.toggle("collapsed");
    });
    item.appendChild(toggle);
  } else {
    const spacer = document.createElement("span");
    spacer.className = "tree-spacer";
    item.appendChild(spacer);
  }

  const label = document.createElement("div");
  label.className = "tree-label";
  label.textContent = node.label;
  item.appendChild(label);
  row.appendChild(item);

  if (hasChildren) {
    const childrenWrap = document.createElement("div");
    childrenWrap.className = "tree-children";
    for (const child of node.children) {
      renderTreeNode(child, childrenWrap, depth + 1);
    }
    row.appendChild(childrenWrap);
  }

  parent.appendChild(row);
}

function setTreeExpanded(expanded) {
  const nodes = el.detailsTree.querySelectorAll(".tree-node.has-children");
  for (const node of nodes) {
    node.classList.toggle("collapsed", !expanded);
  }
}

async function loadPacketDetails(frameNum) {
  const invoke = getInvoke();
  if (!invoke) {
    return;
  }

  try {
    const nodes = await invoke("get_packet_details", {
      filePath: state.loadedPath,
      frameNum,
      selectedDecodeOpts: state.selectedDecodeOpts
    });
    el.detailsTree.innerHTML = "";
    for (const node of nodes) {
      renderTreeNode(node, el.detailsTree);
    }
  } catch (err) {
    clearTree(`Failed to fetch details: ${String(err)}`);
  }
}

function clampPage(page) {
  const pages = totalPages();
  if (!pages) {
    return 0;
  }
  return Math.max(0, Math.min(page, pages - 1));
}

async function loadCaptureFromPath(path) {
  const invoke = getInvoke();
  if (!invoke) {
    notify("Tauri API unavailable");
    return;
  }
  if (!path || !path.trim()) {
    notify("Select a PCAP path first");
    return;
  }

  notify("Decoding PCAP with tshark...");
  clearTree("Click a message to see details");

  try {
    const result = await invoke("parse_pcap", { filePath: path.trim() });
    state.loadedPath = path.trim();
    state.tsharkBin = result.tsharkBin || "";
    state.selectedDecodeOpts = result.selectedDecodeOpts || [];
    state.allPackets = result.packets || [];
    state.filteredPackets = [...state.allPackets];
    state.page = 0;
    state.selectedRow = -1;
    el.tsharkPath.textContent = state.tsharkBin ? `tshark: ${state.tsharkBin}` : "";
    applyFilters();
  } catch (err) {
    state.allPackets = [];
    state.filteredPackets = [];
    state.selectedDecodeOpts = [];
    drawCurrentPage();
    notify(`Load failed: ${String(err)}`);
    clearTree("Load a valid PCAP and click a message");
  }
}

function bindEvents() {
  el.pickBtn.addEventListener("click", async () => {
    const openDialog = getOpenDialog();
    if (!openDialog) {
      notify("File dialog not available");
      return;
    }
    const selected = await openDialog({
      multiple: false,
      filters: [{ name: "PCAP", extensions: ["pcap", "pcapng"] }]
    });
    if (typeof selected === "string") {
      el.pcapPath.value = selected;
    }
  });

  el.loadBtn.addEventListener("click", () => {
    loadCaptureFromPath(el.pcapPath.value);
  });

  el.ueFilter.addEventListener("input", () => applyFilters());
  for (const cb of el.layerCbs) {
    cb.addEventListener("change", () => applyFilters());
  }

  el.firstPage.addEventListener("click", () => {
    state.page = 0;
    state.selectedRow = -1;
    drawCurrentPage();
  });

  el.prevPage.addEventListener("click", () => {
    state.page = clampPage(state.page - 1);
    state.selectedRow = -1;
    drawCurrentPage();
  });

  el.nextPage.addEventListener("click", () => {
    state.page = clampPage(state.page + 1);
    state.selectedRow = -1;
    drawCurrentPage();
  });

  el.lastPage.addEventListener("click", () => {
    state.page = clampPage(999999);
    state.selectedRow = -1;
    drawCurrentPage();
  });

  el.expandAllBtn?.addEventListener("click", () => {
    setTreeExpanded(true);
  });

  el.collapseAllBtn?.addEventListener("click", () => {
    setTreeExpanded(false);
  });

  el.canvas.addEventListener("mousemove", (event) => {
    const { x, y } = toCanvasPoint(event);
    const onLabel = state.hitRegions.some((r) => contains(r, x, y));
    el.canvas.style.cursor = onLabel ? "pointer" : "default";
  });

  el.canvas.addEventListener("click", async (event) => {
    const { x, y } = toCanvasPoint(event);
    const pagePackets = pageSlice();

    for (let i = state.hitRegions.length - 1; i >= 0; i -= 1) {
      const r = state.hitRegions[i];
      if (contains(r, x, y)) {
        state.selectedRow = r.rowIndex;
        drawCurrentPage();
        await loadPacketDetails(r.frameNum);
        return;
      }
    }

    const clickedIndex = Math.floor((y - CFG.topY - 25 + CFG.rowH / 2) / CFG.rowH);
    if (clickedIndex >= 0 && clickedIndex < pagePackets.length) {
      state.selectedRow = clickedIndex;
      drawCurrentPage();
      await loadPacketDetails(pagePackets[clickedIndex].index);
    }
  });
}

function contains(rect, x, y) {
  return x >= rect.x && x <= rect.x + rect.w && y >= rect.y && y <= rect.y + rect.h;
}

function toCanvasPoint(event) {
  const rect = el.canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const scaleX = (el.canvas.width / dpr) / rect.width;
  const scaleY = (el.canvas.height / dpr) / rect.height;
  return {
    x: (event.clientX - rect.left) * scaleX,
    y: (event.clientY - rect.top) * scaleY
  };
}

function init() {
  bindEvents();
  clearTree("Click a message to see details");
  drawCurrentPage();
}

init();
