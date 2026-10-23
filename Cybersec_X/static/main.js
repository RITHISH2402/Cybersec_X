/* ═══════════════════════════════════════════════════════════
   CyberSec Forensics Workbench — main.js
   Modernized operational controller:
   - Real-time bitplane capacity calculations
   - OWASP security header assessment
   - TLS/SSL socket certificate validation
   - Interactive audit logger (no mock slop loops)
   ═══════════════════════════════════════════════════════════ */

'use strict';

// ─────────────────────────────────────────────
//  Application State
// ─────────────────────────────────────────────
const state = {
  currentSection: 'home',
  stegMode: 'encode',
  stegFile: null,
  stegCapacity: 0,
  encodedImageB64: null,
};

// ─────────────────────────────────────────────
//  System Clock
// ─────────────────────────────────────────────
function updateClock() {
  const clockEl = document.getElementById('clock');
  if (!clockEl) return;
  const now = new Date();
  clockEl.textContent = [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map(v => String(v).padStart(2, '0'))
    .join(':');
}
setInterval(updateClock, 1000);
updateClock();

// ─────────────────────────────────────────────
//  Navigation Management
// ─────────────────────────────────────────────
const sectionNames = {
  home:    'Overview',
  steg:    'Steganography',
  scanner: 'Web Scanner',
  ssl:     'SSL Checker',
};

function navigate(section) {
  if (!sectionNames[section]) return;

  // Toggle active views
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

  const targetSection = document.getElementById(`section-${section}`);
  const targetNavBtn  = document.getElementById(`nav-${section}`);
  const breadcrumbEl  = document.getElementById('breadcrumb-page');

  if (targetSection) targetSection.classList.add('active');
  if (targetNavBtn)  targetNavBtn.classList.add('active');
  if (breadcrumbEl)  breadcrumbEl.textContent = sectionNames[section];

  state.currentSection = section;

  // Collapse sidebar on small screens upon selection
  if (window.innerWidth <= 768) {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.remove('open');
  }

  addLog('NAV', `Navigated to ${sectionNames[section]} console`, 'info');
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (sidebar) sidebar.classList.toggle('open');
}

// ─────────────────────────────────────────────
//  Operational Activity Logger
// ─────────────────────────────────────────────
function addLog(type, message, level = 'info') {
  const body = document.getElementById('log-body');
  if (!body) return;

  const now = new Date();
  const time = [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map(v => String(v).padStart(2, '0')).join(':');

  const tagClassMap = {
    info:  'tag-info',
    ok:    'tag-ok',
    warn:  'tag-warn',
    error: 'tag-err'
  };
  const tagClass = tagClassMap[level] || 'tag-info';

  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-tag ${tagClass}">[${escHtml(type)}]</span>
    <span class="log-msg">${escHtml(message)}</span>
  `;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;

  // Maintain buffer size
  while (body.children.length > 60) {
    body.removeChild(body.firstChild);
  }
}

function clearActivityLog() {
  const body = document.getElementById('log-body');
  if (body) {
    body.innerHTML = '';
    addLog('SYS', 'Operational log cleared', 'info');
  }
}

// ─────────────────────────────────────────────
//  Loading Overlay Controls
// ─────────────────────────────────────────────
function showLoading(text = 'Processing request...') {
  const txtEl = document.getElementById('loading-text');
  const overlay = document.getElementById('loading-overlay');
  if (txtEl) txtEl.textContent = text;
  if (overlay) overlay.classList.remove('hidden');
}

function hideLoading() {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) overlay.classList.add('hidden');
}

// ─────────────────────────────────────────────
//  Steganography Studio Logic
// ─────────────────────────────────────────────
function setStegMode(mode) {
  state.stegMode = mode;
  const isEncode = mode === 'encode';

  const btnEncode = document.getElementById('mode-encode');
  const btnDecode = document.getElementById('mode-decode');
  const encodeFields = document.getElementById('encode-fields');
  const decodeFields = document.getElementById('decode-fields');
  const resultPanel  = document.getElementById('steg-result-panel');

  if (btnEncode) btnEncode.classList.toggle('active', isEncode);
  if (btnDecode) btnDecode.classList.toggle('active', !isEncode);
  if (encodeFields) encodeFields.classList.toggle('hidden', !isEncode);
  if (decodeFields) decodeFields.classList.toggle('hidden', isEncode);

  if (resultPanel) {
    resultPanel.innerHTML = `
      <div class="empty-results-state">
        <div class="empty-state-icon" aria-hidden="true">◈</div>
        <div class="empty-state-title">Awaiting Action</div>
        <p class="empty-state-desc">Select an image to ${isEncode ? 'encode a payload' : 'extract hidden data'}.</p>
      </div>`;
  }
  state.encodedImageB64 = null;
  updateStegButtons();
}

function handleDragOver(e) {
  e.preventDefault();
  e.currentTarget.classList.add('drag-over');
}

function handleDragLeave(e) {
  e.currentTarget.classList.remove('drag-over');
}

function handleDrop(e, tool) {
  e.preventDefault();
  e.currentTarget.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) {
    loadImageFile(file, tool);
  } else {
    alert('Please supply a valid image file (PNG, JPG, BMP, WebP).');
  }
}

function handleFileSelect(e, tool) {
  const file = e.target.files[0];
  if (file) loadImageFile(file, tool);
}

function loadImageFile(file, tool) {
  if (tool === 'steg') {
    state.stegFile = file;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const preview = document.getElementById('steg-preview');
      const dropContent = document.getElementById('steg-drop-content');
      if (preview) {
        preview.src = ev.target.result;
        preview.classList.remove('hidden');
      }
      if (dropContent) dropContent.classList.add('hidden');
    };
    reader.readAsDataURL(file);

    fetchCapacity(file);
    updateStegButtons();
    addLog('STEG', `Loaded image: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, 'info');
  }
}

async function fetchCapacity(file) {
  const form = new FormData();
  form.append('image', file);
  try {
    const res = await fetch('/api/steg/capacity', { method: 'POST', body: form });
    const data = await res.json();
    if (data.error) {
      addLog('STEG', `Capacity probe error: ${data.error}`, 'error');
      return;
    }

    state.stegCapacity = data.capacity_chars;
    const capContainer = document.getElementById('capacity-container');
    const capLabel     = document.getElementById('capacity-label');
    if (capContainer) capContainer.classList.remove('hidden');
    if (capLabel) {
      capLabel.textContent = `${data.width} × ${data.height} px · ${data.format} · Max: ~${data.capacity_chars.toLocaleString()} chars (~${data.capacity_kb} KB)`;
    }
    updateCapacity();
  } catch (err) {
    addLog('STEG', 'Network failure querying image capacity', 'error');
  }
}

function updateCapacity() {
  const msgEl   = document.getElementById('secret-message');
  const charEl  = document.getElementById('char-count');
  const fillEl  = document.getElementById('capacity-fill');
  const usedEl  = document.getElementById('capacity-used');

  const msg  = msgEl ? msgEl.value : '';
  const used = msg.length;
  const cap  = state.stegCapacity;
  const pct  = cap > 0 ? Math.min(100, Math.round((used / cap) * 100)) : 0;

  if (charEl) charEl.textContent = used.toLocaleString();
  if (fillEl) fillEl.style.width = `${pct}%`;
  if (usedEl) usedEl.textContent = `${pct}% capacity used`;
}

function updateStegButtons() {
  const hasFile = !!state.stegFile;
  const encBtn  = document.getElementById('encode-btn');
  const decBtn  = document.getElementById('decode-btn');
  if (encBtn) encBtn.disabled = !hasFile;
  if (decBtn) decBtn.disabled = !hasFile;
}

async function encodeMessage() {
  const msgEl = document.getElementById('secret-message');
  const message = msgEl ? msgEl.value.trim() : '';

  if (!state.stegFile) {
    alert('Please select a carrier image first.');
    return;
  }
  if (!message) {
    alert('Please enter a secret message payload.');
    return;
  }

  showLoading('Injecting payload into carrier image...');
  const form = new FormData();
  form.append('image', state.stegFile);
  form.append('message', message);

  try {
    const res = await fetch('/api/steg/encode', { method: 'POST', body: form });
    const data = await res.json();
    hideLoading();

    if (data.error) {
      renderStegError(data.error);
      addLog('STEG', `Encoding failed: ${data.error}`, 'error');
    } else {
      state.encodedImageB64 = data.image_b64;
      renderEncodeSuccess(message.length);
      addLog('STEG', `Encoded message successfully (${message.length} chars)`, 'ok');
    }
  } catch (e) {
    hideLoading();
    renderStegError('Network error connecting to Flask backend.');
  }
}

async function decodeMessage() {
  if (!state.stegFile) {
    alert('Please select an image first.');
    return;
  }

  showLoading('Scanning image bitplanes for sentinel...');
  const form = new FormData();
  form.append('image', state.stegFile);

  try {
    const res = await fetch('/api/steg/decode', { method: 'POST', body: form });
    const data = await res.json();
    hideLoading();

    if (data.error) {
      renderStegError(data.error);
      addLog('STEG', `Extraction notice: ${data.error}`, 'warn');
    } else {
      renderDecodeSuccess(data.message);
      addLog('STEG', `Decoded hidden payload (${data.message.length} characters)`, 'ok');
    }
  } catch (e) {
    hideLoading();
    renderStegError('Network error connecting to Flask backend.');
  }
}

function renderEncodeSuccess(charCount) {
  const panel = document.getElementById('steg-result-panel');
  if (!panel) return;

  panel.innerHTML = `
    <div class="res-card-header">
      <div class="res-card-title">
        <span class="title-glyph steg-accent" aria-hidden="true">◉</span>
        <span>Steganographic Encoding Complete</span>
      </div>
      <span class="badge badge-ok">SUCCESS</span>
    </div>

    <div class="data-row">
      <span class="data-k">Payload Length</span>
      <span class="data-v">${charCount.toLocaleString()} characters</span>
    </div>
    <div class="data-row">
      <span class="data-k">Encoding Algorithm</span>
      <span class="data-v">3-Channel LSB (RGB Least Significant Bits)</span>
    </div>
    <div class="data-row">
      <span class="data-k">Container Format</span>
      <span class="data-v">Lossless PNG Array</span>
    </div>
    <div class="data-row">
      <span class="data-k">Sentinel</span>
      <span class="data-v">####END####</span>
    </div>

    <p style="color:var(--text-muted); font-size:12px; margin-top:14px; line-height:1.5;">
      The output image is visually identical to the original carrier, with low-order bits modified to preserve the payload.
    </p>

    <button class="btn-download-tray" onclick="downloadEncodedImage()">
      <span>&darr;</span> Download Encoded PNG
    </button>
  `;
}

function renderDecodeSuccess(message) {
  const panel = document.getElementById('steg-result-panel');
  if (!panel) return;

  panel.innerHTML = `
    <div class="res-card-header">
      <div class="res-card-title">
        <span class="title-glyph steg-accent" aria-hidden="true">&#x25C9;</span>
        <span>Hidden Payload Extracted</span>
      </div>
      <span class="badge badge-ok">DECODED</span>
    </div>

    <div class="data-row">
      <span class="data-k">Payload Length</span>
      <span class="data-v">${message.length.toLocaleString()} characters</span>
    </div>
    <div class="data-row">
      <span class="data-k">Sentinel Verified</span>
      <span class="data-v">Valid EOT Found</span>
    </div>

    <div style="margin-top:14px;">
      <span class="data-k" style="font-size:11px; text-transform:uppercase; letter-spacing:0.04em;">Decoded Content:</span>
      <div class="decoded-content-box">${escHtml(message)}</div>
    </div>
  `;
}

function renderStegError(msg) {
  const panel = document.getElementById('steg-result-panel');
  if (!panel) return;

  panel.innerHTML = `
    <div class="res-card-header">
      <div class="res-card-title">
        <span class="title-glyph" style="color:var(--status-danger)">[!]</span>
        <span>Operation Failed</span>
      </div>
      <span class="badge badge-vuln">FAILED</span>
    </div>
    <div class="error-notification-box">${escHtml(msg)}</div>
  `;
}

function downloadEncodedImage() {
  if (!state.encodedImageB64) return;
  const link = document.createElement('a');
  link.href = `data:image/png;base64,${state.encodedImageB64}`;
  link.download = `steg_payload_${Date.now()}.png`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  addLog('STEG', 'Downloaded encoded carrier image', 'ok');
}

// ─────────────────────────────────────────────
//  Web Scanner Logic
// ─────────────────────────────────────────────
function setScanSample(sampleUrl) {
  const input = document.getElementById('scan-url');
  if (input) {
    input.value = sampleUrl;
    input.focus();
  }
}

async function runScan() {
  const input = document.getElementById('scan-url');
  const url = input ? input.value.trim() : '';

  if (!url) {
    alert('Please enter a target URL or host.');
    return;
  }

  showLoading(`Connecting and analyzing headers: ${url}...`);
  addLog('SCAN', `Dispatched scan probe to ${url}`, 'info');

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    hideLoading();

    if (data.error) {
      renderScanError(data.error);
      addLog('SCAN', `Scan failed: ${data.error}`, 'error');
    } else {
      renderScanResults(data);
      const isClean = data.risk_score < 40;
      addLog('SCAN', `Scan finished for ${data.url} (Risk: ${data.risk_score}/100)`, isClean ? 'ok' : 'warn');
    }
  } catch (e) {
    hideLoading();
    renderScanError('Network request failed. Is the Flask service running?');
  }
}

function getRiskCategory(score) {
  if (score >= 70) return { label: 'CRITICAL', color: 'var(--status-danger)', badge: 'badge-vuln' };
  if (score >= 40) return { label: 'MEDIUM', color: 'var(--status-warning)', badge: 'badge-warn' };
  return { label: 'LOW', color: 'var(--status-success)', badge: 'badge-ok' };
}

function renderScanResults(data) {
  const panel = document.getElementById('scanner-result-panel');
  if (!panel) return;

  const risk = getRiskCategory(data.risk_score);

  const headerRows = data.headers.map(h => `
    <tr>
      <td style="font-family:var(--font-mono); font-size:12px; font-weight:500;">${escHtml(h.header)}</td>
      <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:var(--font-mono); font-size:11px; color:var(--text-low);">
        ${h.value ? escHtml(h.value) : '<span style="color:var(--text-muted)">—</span>'}
      </td>
      <td style="text-align:right;">
        <span class="badge ${h.present ? 'badge-ok' : 'badge-vuln'}">
          ${h.present ? 'PASS' : 'FAIL'}
        </span>
      </td>
    </tr>
  `).join('');

  panel.innerHTML = `
    <div class="res-card-header">
      <div class="res-card-title">
        <span class="title-glyph scanner-accent" aria-hidden="true">◎</span>
        <span>Security Assessment Results</span>
      </div>
      <span class="badge badge-info">HTTP ${data.status_code}</span>
    </div>

    <div class="data-row">
      <span class="data-k">Evaluated Target</span>
      <span class="data-v">${escHtml(data.url)}</span>
    </div>

    <!-- Risk Gauge -->
    <div class="risk-meter-box" style="margin-top:12px;">
      <div class="risk-meter-header">
        <span class="risk-meter-title">Calculated Vulnerability Risk</span>
        <span class="risk-score-value" style="color:${risk.color}">
          ${data.risk_score}/100 &nbsp;·&nbsp; ${risk.label}
        </span>
      </div>
      <div class="risk-meter-track">
        <div class="risk-meter-fill" style="width:${data.risk_score}%; background-color:${risk.color};"></div>
      </div>
    </div>

    <!-- Headers Table -->
    <table class="data-table">
      <thead>
        <tr>
          <th>Security Header</th>
          <th>Received Value</th>
          <th style="text-align:right;">Status</th>
        </tr>
      </thead>
      <tbody>
        ${headerRows}
      </tbody>
    </table>

    <!-- Additional Findings -->
    <div class="data-row">
      <span class="data-k">Directory Indexing</span>
      <span class="badge ${data.directory_listing ? 'badge-vuln' : 'badge-ok'}">
        ${data.directory_listing ? 'EXPOSED' : 'SECURE'}
      </span>
    </div>
    <div class="data-row">
      <span class="data-k">Server Header Banner</span>
      <span class="data-v">${data.server_header ? escHtml(data.server_header) : '<span class="badge badge-ok">HIDDEN</span>'}</span>
    </div>
    ${data.powered_by ? `
    <div class="data-row">
      <span class="data-k">X-Powered-By</span>
      <span class="data-v"><span class="badge badge-warn">${escHtml(data.powered_by)}</span></span>
    </div>` : ''}
  `;
}

function renderScanError(msg) {
  const panel = document.getElementById('scanner-result-panel');
  if (!panel) return;

  panel.innerHTML = `
    <div class="res-card-header">
      <div class="res-card-title">
        <span class="title-glyph" style="color:var(--status-danger)">[!]</span>
        <span>Scan Failed</span>
      </div>
      <span class="badge badge-vuln">ERROR</span>
    </div>
    <div class="error-notification-box">${escHtml(msg)}</div>
  `;
}

// ─────────────────────────────────────────────
//  SSL Certificate Inspector Logic
// ─────────────────────────────────────────────
function setSSLSample(domain) {
  const input = document.getElementById('ssl-domain');
  if (input) {
    input.value = domain;
    input.focus();
  }
}

async function checkSSL() {
  const input = document.getElementById('ssl-domain');
  const domain = input ? input.value.trim() : '';

  if (!domain) {
    alert('Please enter a target domain name.');
    return;
  }

  showLoading(`Establishing TLS socket handshake with ${domain}:443...`);
  addLog('SSL', `Handshake initiated with ${domain}:443`, 'info');

  try {
    const res = await fetch('/api/ssl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    hideLoading();

    if (data.error) {
      renderSSLError(data.error);
      addLog('SSL', `TLS inspection failed: ${data.error}`, 'error');
    } else {
      renderSSLResults(data);
      const isOk = data.status === 'valid';
      addLog('SSL', `Certificate verified for ${data.domain} (${data.days_remaining} days left)`, isOk ? 'ok' : 'warn');
    }
  } catch (e) {
    hideLoading();
    renderSSLError('Network connection error querying TLS backend.');
  }
}

function renderSSLResults(data) {
  const panel = document.getElementById('ssl-result-panel');
  if (!panel) return;

  const badgeMap = {
    valid:   { badge: 'badge-ok',   text: 'CERTIFICATE VALID', color: 'var(--status-success)' },
    warning: { badge: 'badge-warn', text: 'EXPIRING SOON',     color: 'var(--status-warning)' },
    expired: { badge: 'badge-vuln', text: 'CERTIFICATE EXPIRED', color: 'var(--status-danger)' }
  };
  const certStatus = badgeMap[data.status] || badgeMap.valid;

  const sanHtml = (data.san && data.san.length)
    ? `<div class="san-grid">${data.san.map(s => `<span class="san-pill">${escHtml(s)}</span>`).join('')}</div>`
    : '<span style="color:var(--text-muted); font-size:12px;">No alternative names registered</span>';

  panel.innerHTML = `
    <div class="res-card-header">
      <div class="res-card-title">
        <span class="title-glyph ssl-accent" aria-hidden="true">&#x25C7;</span>
        <span>TLS / SSL Peer Certificate</span>
      </div>
      <span class="badge ${certStatus.badge}">${certStatus.text}</span>
    </div>

    <!-- Countdown banner -->
    <div class="ssl-countdown-banner">
      <div class="ssl-countdown-number" style="color:${certStatus.color}">${data.days_remaining}</div>
      <div class="ssl-countdown-label">Days remaining until expiration</div>
    </div>

    <div class="data-row">
      <span class="data-k">Target Host</span>
      <span class="data-v">${escHtml(data.domain)}</span>
    </div>
    <div class="data-row">
      <span class="data-k">Common Name (CN)</span>
      <span class="data-v">${escHtml(data.common_name)}</span>
    </div>
    <div class="data-row">
      <span class="data-k">Certificate Authority</span>
      <span class="data-v">${escHtml(data.issuer)}</span>
    </div>
    <div class="data-row">
      <span class="data-k">Negotiated Protocol</span>
      <span class="data-v"><span class="badge badge-info">${escHtml(data.ssl_version)}</span></span>
    </div>
    <div class="data-row">
      <span class="data-k">Serial Number</span>
      <span class="data-v" style="font-size:11px;">${escHtml(data.serial)}</span>
    </div>
    <div class="data-row">
      <span class="data-k">Validity Period Closes</span>
      <span class="data-v">${escHtml(data.valid_until)}</span>
    </div>

    <div style="margin-top:14px;">
      <span class="data-k" style="font-size:11px; text-transform:uppercase; letter-spacing:0.04em;">
        Subject Alternative Names (${data.san ? data.san.length : 0})
      </span>
      ${sanHtml}
    </div>
  `;
}

function renderSSLError(msg) {
  const panel = document.getElementById('ssl-result-panel');
  if (!panel) return;

  panel.innerHTML = `
    <div class="res-card-header">
      <div class="res-card-title">
        <span class="title-glyph" style="color:var(--status-danger)">[!]</span>
        <span>Certificate Handshake Failed</span>
      </div>
      <span class="badge badge-vuln">TLS ERROR</span>
    </div>
    <div class="error-notification-box">${escHtml(msg)}</div>
  `;
}

// ─────────────────────────────────────────────
//  Utilities
// ─────────────────────────────────────────────
function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─────────────────────────────────────────────
//  Initialization
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  navigate('home');
  addLog('INIT', 'Forensics workbench console online', 'ok');
});
