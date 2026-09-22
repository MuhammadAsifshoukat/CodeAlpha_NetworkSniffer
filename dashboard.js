const socket = io();

/* ---------- Clock ---------- */
function tickClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(tickClock, 1000);
tickClock();

/* ---------- Uptime ---------- */
let startedAt = null;
setInterval(() => {
  if (!startedAt) return;
  const s = Math.floor((Date.now() - startedAt) / 1000);
  const h = String(Math.floor(s / 3600)).padStart(2, '0');
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const sec = String(s % 60).padStart(2, '0');
  document.getElementById('statUptime').textContent = `${h}:${m}:${sec}`;
}, 1000);

/* ---------- Helpers ---------- */
function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(2) + ' MB';
}

/* ---------- Charts ---------- */
Chart.defaults.color = '#6b7d93';
Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.font.size = 10;

const throughputCtx = document.getElementById('throughputChart');
const throughputChart = new Chart(throughputCtx, {
  type: 'line',
  data: {
    labels: Array(30).fill(''),
    datasets: [{
      data: Array(30).fill(0),
      borderColor: '#22e6b0',
      backgroundColor: 'rgba(34,230,176,0.12)',
      fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: { duration: 300 },
    plugins: { legend: { display: false } },
    scales: {
      x: { display: false },
      y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }
    }
  }
});

const protoColors = { TCP: '#4c8bff', UDP: '#22e6b0', ICMP: '#ffb454', ARP: '#c792ea', DNS: '#7cd6ff', OTHER: '#6b7d93' };
const protocolChart = new Chart(document.getElementById('protocolChart'), {
  type: 'doughnut',
  data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
  options: {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, padding: 8 } } },
    cutout: '65%'
  }
});

const talkersChart = new Chart(document.getElementById('talkersChart'), {
  type: 'bar',
  data: { labels: [], datasets: [{ data: [], backgroundColor: '#4c8bff', borderRadius: 4 }] },
  options: {
    responsive: true, maintainAspectRatio: false,
    indexAxis: 'y',
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: 'rgba(255,255,255,0.04)' } },
      y: { grid: { display: false } }
    }
  }
});

/* rolling packets/sec counter */
let secondBucket = 0;
setInterval(() => {
  throughputChart.data.datasets[0].data.push(secondBucket);
  throughputChart.data.datasets[0].data.shift();
  throughputChart.update('none');
  secondBucket = 0;
}, 1000);

/* ---------- Packet table ---------- */
const packetBody = document.getElementById('packetBody');
const tableCount = document.getElementById('tableCount');
let allRows = [];
let activeFilter = '';
let activeProto = null;
const MAX_ROWS = 300;

function renderRow(p) {
  const tr = document.createElement('tr');
  tr.className = `proto-${p.protocol} ${p.risk === 'suspicious' ? 'risk-suspicious' : ''}`;
  tr.dataset.packet = JSON.stringify(p);
  tr.innerHTML = `
    <td>${p.time}</td><td>${p.src}</td><td>${p.dst}</td>
    <td>${p.protocol}</td><td>${p.sport}</td><td>${p.dport}</td>
    <td>${p.length}</td><td>${p.info || ''}</td>`;
  tr.addEventListener('click', () => showInspector(p, tr));
  return tr;
}

function passesFilter(p) {
  if (activeProto && p.protocol !== activeProto) return false;
  if (!activeFilter) return true;
  const f = activeFilter.toLowerCase();
  return [p.src, p.dst, String(p.sport), String(p.dport), p.protocol, p.info]
    .join(' ').toLowerCase().includes(f);
}

function refreshTable() {
  packetBody.innerHTML = '';
  const visible = allRows.filter(passesFilter).slice(-MAX_ROWS).reverse();
  visible.forEach(p => packetBody.appendChild(renderRow(p)));
  tableCount.textContent = `${visible.length} shown`;
}

socket.on('new_packet', (p) => {
  allRows.push(p);
  if (allRows.length > 1000) allRows.shift();
  secondBucket++;
  if (passesFilter(p)) {
    packetBody.insertBefore(renderRow(p), packetBody.firstChild);
    while (packetBody.children.length > MAX_ROWS) packetBody.removeChild(packetBody.lastChild);
    tableCount.textContent = `${packetBody.children.length} shown`;
  }
});

/* ---------- Inspector ---------- */
function showInspector(p, tr) {
  document.querySelectorAll('#packetBody tr').forEach(r => r.classList.remove('selected'));
  tr.classList.add('selected');
  const box = document.getElementById('inspector');
  box.className = '';
  box.innerHTML = `
    <div class="inspector-row"><span>Timestamp</span><span>${p.time}</span></div>
    <div class="inspector-row"><span>Source</span><span>${p.src}:${p.sport}</span></div>
    <div class="inspector-row"><span>Destination</span><span>${p.dst}:${p.dport}</span></div>
    <div class="inspector-row"><span>Protocol</span><span>${p.protocol}</span></div>
    <div class="inspector-row"><span>Length</span><span>${p.length} bytes</span></div>
    <div class="inspector-row"><span>Detail</span><span>${p.info || '—'}</span></div>
    <span class="risk-badge ${p.risk}">${p.risk === 'suspicious' ? '⚠ suspicious activity' : '✓ normal traffic'}</span>
    ${p.payload ? `<div class="payload-box">${escapeHtml(p.payload)}</div>` : ''}
  `;
}
function escapeHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

/* ---------- Filter controls ---------- */
document.getElementById('filterInput').addEventListener('input', (e) => {
  activeFilter = e.target.value.trim();
  refreshTable();
});
const protoChips = document.getElementById('protoChips');
['TCP', 'UDP', 'ICMP', 'ARP', 'DNS'].forEach(proto => {
  const chip = document.createElement('div');
  chip.className = 'chip';
  chip.textContent = proto;
  chip.addEventListener('click', () => {
    activeProto = activeProto === proto ? null : proto;
    document.querySelectorAll('.chip').forEach(c => c.classList.toggle('active', c.textContent === activeProto));
    refreshTable();
  });
  protoChips.appendChild(chip);
});

/* ---------- Stats & mode ---------- */
socket.on('stats_update', (s) => {
  document.getElementById('statPackets').textContent = s.total_packets;
  document.getElementById('statBytes').textContent = fmtBytes(s.total_bytes);
  document.getElementById('statAlerts').textContent = s.alerts;

  protocolChart.data.labels = s.top_protocols.map(x => x.protocol);
  protocolChart.data.datasets[0].data = s.top_protocols.map(x => x.count);
  protocolChart.data.datasets[0].backgroundColor = s.top_protocols.map(x => protoColors[x.protocol] || '#6b7d93');
  protocolChart.update('none');

  talkersChart.data.labels = s.top_talkers.map(x => x.ip);
  talkersChart.data.datasets[0].data = s.top_talkers.map(x => x.bytes);
  talkersChart.update('none');
});

socket.on('mode_info', (m) => setMode(m.mode));
socket.on('capture_state', (c) => {
  document.getElementById('startBtn').disabled = c.capturing;
  document.getElementById('stopBtn').disabled = !c.capturing;
  if (c.capturing) { startedAt = Date.now(); } else { startedAt = null; }
  setMode(c.mode);
});

function setMode(mode) {
  const pill = document.getElementById('modePill');
  const label = document.getElementById('modeLabel');
  pill.classList.remove('live', 'demo');
  if (mode === 'live') {
    pill.classList.add('live');
    label.textContent = 'Live capture (raw sockets)';
  } else {
    pill.classList.add('demo');
    label.textContent = 'Demo mode (synthetic traffic)';
  }
}

/* ---------- Buttons ---------- */
document.getElementById('startBtn').addEventListener('click', () => {
  socket.emit('start_capture', {});
  document.getElementById('startBtn').disabled = true;
  document.getElementById('stopBtn').disabled = false;
  startedAt = Date.now();
});
document.getElementById('stopBtn').addEventListener('click', () => {
  socket.emit('stop_capture');
  document.getElementById('startBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
});
document.getElementById('clearBtn').addEventListener('click', () => {
  socket.emit('clear_data');
  allRows = [];
  packetBody.innerHTML = '';
  tableCount.textContent = '0 shown';
  document.getElementById('inspector').className = 'inspector-empty';
  document.getElementById('inspector').textContent = 'Select a packet from the stream to inspect its payload & metadata.';
});
