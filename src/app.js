import { analyze, analyzeEntries } from "./parser.js";

  // ───────────────────────────────────────────────
  // STATE
  // ───────────────────────────────────────────────
  let analysisData = null;
  let fullAnalysisData = null;
  let activeTimeRange = null;
  let timelineState = null;
  let timelineDrag = null;
  let geoData = {};
  let currentFilter = 'all';
  let currentSort = { col: 'requests', dir: 'desc' };
  let currentPage = 0;
  let expandedIPs = new Set();
  let geoLookupRunId = 0;
  let subnetHostnameLookupRunId = 0;
  let subnetHostnames = {};
  const PAGE_SIZE = 50;
  const GEO_BATCH_SIZE = 60;
  const GEO_BATCH_DELAY_MS = 60000;
  const GEO_REQUEST_DELAY_MS = Math.ceil(GEO_BATCH_DELAY_MS / GEO_BATCH_SIZE);
  const GEO_ENDPOINT = 'https://free.freeipapi.com/api/json/';
  const DNS_ENDPOINT = 'https://dns.google/resolve';
  const SUBNET_HOSTNAME_CANDIDATE_LIMIT = 10;
  const geoCacheReady = registerGeoCacheWorker();

  async function registerGeoCacheWorker() {
    if (!('serviceWorker' in navigator)) return null;

    try {
      await navigator.serviceWorker.register('./sw.js');
      return await navigator.serviceWorker.ready;
    } catch (e) {
      console.warn('GeoIP service worker registration failed:', e.message);
      return null;
    }
  }

  // ───────────────────────────────────────────────
  // DRAG & DROP
  // ───────────────────────────────────────────────
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  fileInput.addEventListener('change', () => { if (fileInput.files[0]) handleFile(fileInput.files[0]); });

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = e => {
      document.getElementById('log-input').value = e.target.result;
      updateLineCount();
    };
    reader.readAsText(file);
  }

  document.getElementById('log-input').addEventListener('input', updateLineCount);
  document.getElementById('error-log-input').addEventListener('input', updateLineCount);

  function updateLineCount() {
    const lines = document.getElementById('log-input').value.split('\n').filter(l => l.trim()).length;
    const errorLines = document.getElementById('error-log-input').value.split('\n').filter(l => l.trim()).length;
    const parts = [];
    if (lines) parts.push(`${fmt(lines)} access lines`);
    if (errorLines) parts.push(`${fmt(errorLines)} error lines`);
    document.getElementById('line-count').textContent = parts.join(' · ');
  }

  // ───────────────────────────────────────────────
  // ANALYSIS
  // ───────────────────────────────────────────────
  async function runAnalysis() {
    const text = document.getElementById('log-input').value.trim();
    const errorText = document.getElementById('error-log-input').value.trim();
    if (!text && !errorText) { alert('Please paste or upload at least one log file first.'); return; }

    showLoading('Parsing log entries…');

    try {
      fullAnalysisData = analyze(text, errorText);
      activeTimeRange = null;
      analysisData = buildFilteredAnalysis();
      geoData = {};
      subnetHostnames = {};
      expandedIPs = new Set();
      renderResults();
      initTimeline();
      startGeoLookup();
      startSubnetHostnameLookup();
    } catch (err) {
      hideLoading();
      alert('Analysis failed: ' + err.message);
    }
  }

  function buildFilteredAnalysis() {
    if (!fullAnalysisData) return null;
    const entries = activeTimeRange
      ? fullAnalysisData.entries.filter((entry) => {
        if (!Number.isFinite(entry.timestamp)) return true;
        return entry.timestamp >= activeTimeRange.start && entry.timestamp <= activeTimeRange.end;
      })
      : fullAnalysisData.entries;
    const errorEntries = activeTimeRange
      ? fullAnalysisData.errorEntries.filter((entry) => {
        if (!Number.isFinite(entry.timestamp)) return true;
        return entry.timestamp >= activeTimeRange.start && entry.timestamp <= activeTimeRange.end;
      })
      : fullAnalysisData.errorEntries;

    return analyzeEntries(
      entries,
      fullAnalysisData.meta.skippedLines,
      fullAnalysisData.meta.totalLines,
      errorEntries,
      fullAnalysisData.meta.skippedErrorLines,
      fullAnalysisData.meta.errorLogLines
    );
  }

  function refreshForTimeFilter() {
    if (!fullAnalysisData) return;
    analysisData = buildFilteredAnalysis();
    currentPage = 0;
    subnetHostnameLookupRunId++;
    renderSummary();
    renderTimeline();
    renderIPTable();
    renderSubnets();
    startSubnetHostnameLookup();
  }

  function resetTimeFilter() {
    if (!fullAnalysisData?.meta.requestTimeRange?.hasTimestamps) return;
    activeTimeRange = null;
    refreshForTimeFilter();
  }

  // ───────────────────────────────────────────────
  // RENDER RESULTS
  // ───────────────────────────────────────────────
  function renderSummary() {
    const d = analysisData;
    const attackers = d.ips.filter(i => i.classification === 'attacker').length;
    const suspicious = d.ips.filter(i => i.classification === 'suspicious').length;
    const legitimate = d.ips.filter(i => i.classification === 'legitimate').length;

    // Header
    document.getElementById('h-ips').textContent = fmt(d.meta.uniqueIPs);
    document.getElementById('h-reqs').textContent = fmt(d.meta.totalRequests);
    document.getElementById('h-att').textContent = attackers;
    document.getElementById('h-sus').textContent = suspicious;

    // Summary cards
    document.getElementById('summary-cards').innerHTML = `
    <div class="card fade-in info">
      <div class="card-label">Total Requests</div>
      <div class="card-value">${fmt(d.meta.totalRequests)}</div>
      <div class="card-sub">${fmt(d.meta.parsedEntries)} parsed · ${d.meta.skippedLines} skipped</div>
    </div>
    <div class="card fade-in info" style="animation-delay:.05s">
      <div class="card-label">Unique IPs</div>
      <div class="card-value">${fmt(d.meta.uniqueIPs)}</div>
      <div class="card-sub">${d.meta.uniqueSubnets} subnets</div>
    </div>
    <div class="card fade-in ${attackers > 0 ? 'danger' : 'ok'}" style="animation-delay:.1s">
      <div class="card-label">Attackers</div>
      <div class="card-value">${attackers}</div>
      <div class="card-sub">threat score ≥ 70</div>
    </div>
    <div class="card fade-in ${suspicious > 0 ? 'warn' : 'ok'}" style="animation-delay:.15s">
      <div class="card-label">Suspicious</div>
      <div class="card-value">${suspicious}</div>
      <div class="card-sub">score 35–69</div>
    </div>
    <div class="card fade-in ok" style="animation-delay:.2s">
      <div class="card-label">Legitimate</div>
      <div class="card-value">${legitimate}</div>
      <div class="card-sub">score &lt; 35</div>
    </div>
    <div class="card fade-in" style="animation-delay:.25s">
      <div class="card-label">Data Transferred</div>
      <div class="card-value">${fmtBytes(d.meta.totalBytes)}</div>
      <div class="card-sub">across all IPs</div>
    </div>
    <div class="card fade-in ${d.meta.wafBlocks > 0 ? 'danger' : 'ok'}" style="animation-delay:.3s">
      <div class="card-label">WAF Blocks</div>
      <div class="card-value">${fmt(d.meta.wafBlocks)}</div>
      <div class="card-sub">${fmt(d.meta.parsedErrorEntries)} parsed error entries</div>
    </div>
    <div class="card fade-in ${d.meta.timeoutErrors > 0 ? 'warn' : 'ok'}" style="animation-delay:.35s">
      <div class="card-label">Server Errors</div>
      <div class="card-value">${fmt(d.meta.timeoutErrors)}</div>
      <div class="card-sub">proxy/timeouts from error log</div>
    </div>
  `;
  }

  function renderResults() {
    hideLoading();
    document.getElementById('upload-section').style.display = 'none';
    document.getElementById('results').style.display = 'block';
    document.getElementById('header-stats').style.display = 'flex';

    renderSummary();
    renderTimeline();
    renderIPTable();
    renderSubnets();
    document.getElementById('results').classList.add('fade-in');
  }

  // ───────────────────────────────────────────────
  // TIMELINE
  // ───────────────────────────────────────────────
  function initTimeline() {
    const canvas = document.getElementById('timeline-chart');
    if (!canvas || canvas.dataset.bound === '1') {
      renderTimeline();
      return;
    }

    canvas.dataset.bound = '1';
    canvas.addEventListener('pointerdown', onTimelinePointerDown);
    canvas.addEventListener('pointermove', onTimelinePointerMove);
    canvas.addEventListener('pointerup', onTimelinePointerUp);
    canvas.addEventListener('pointercancel', onTimelinePointerUp);
    window.addEventListener('resize', renderTimeline);
    renderTimeline();
  }

  function renderTimeline() {
    const wrap = document.getElementById('timeline-wrap');
    const canvas = document.getElementById('timeline-chart');
    const label = document.getElementById('timeline-range');
    if (!wrap || !canvas || !label) return;

    const timeRange = fullAnalysisData?.meta.requestTimeRange;
    if (!fullAnalysisData || !timeRange?.hasTimestamps) {
      wrap.style.display = 'none';
      return;
    }

    wrap.style.display = 'block';
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.round(rect.width * dpr));
    canvas.height = Math.max(1, Math.round(rect.height * dpr));

    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const width = rect.width;
    const height = rect.height;
    const pad = { left: 46, right: 18, top: 14, bottom: 30 };
    const plot = {
      x: pad.left,
      y: pad.top,
      w: Math.max(1, width - pad.left - pad.right),
      h: Math.max(1, height - pad.top - pad.bottom),
    };
    const start = timeRange.first;
    const end = timeRange.last;
    const selection = activeTimeRange || { start, end };
    const bins = buildTimelineBins(start, end, Math.max(24, Math.min(140, Math.floor(plot.w / 8))));
    const maxCount = Math.max(1, ...bins.map((b) => b.count));

    timelineState = { start, end, plot, width, height };

    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = '#111418';
    ctx.fillRect(0, 0, width, height);

    ctx.strokeStyle = '#1e2530';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) {
      const y = plot.y + (plot.h / 3) * i;
      ctx.beginPath();
      ctx.moveTo(plot.x, y);
      ctx.lineTo(plot.x + plot.w, y);
      ctx.stroke();
    }

    const barGap = 1;
    const barW = Math.max(2, plot.w / bins.length - barGap);
    for (let i = 0; i < bins.length; i++) {
      const bin = bins[i];
      const x = plot.x + i * (plot.w / bins.length);
      const h = Math.max(1, (bin.count / maxCount) * plot.h);
      ctx.fillStyle = bin.end < selection.start || bin.start > selection.end ? '#33404f' : '#00d4ff';
      ctx.fillRect(x, plot.y + plot.h - h, barW, h);
    }

    const leftX = timeToX(selection.start);
    const rightX = timeToX(selection.end);
    ctx.fillStyle = 'rgba(0, 0, 0, 0.58)';
    ctx.fillRect(plot.x, plot.y, Math.max(0, leftX - plot.x), plot.h);
    ctx.fillRect(rightX, plot.y, Math.max(0, plot.x + plot.w - rightX), plot.h);

    drawTimelineHandle(ctx, leftX, plot.y, plot.h, 'start');
    drawTimelineHandle(ctx, rightX, plot.y, plot.h, 'end');
    drawTimelineAxis(ctx, plot, start, end, maxCount);

    const selectedRequests = analysisData?.meta.totalRequests ?? fullAnalysisData.entries.length;
    label.textContent = `${formatTime(selection.start)} - ${formatTime(selection.end)} · ${fmt(selectedRequests)} requests`;
  }

  function buildTimelineBins(start, end, count) {
    const bins = Array.from({ length: count }, (_, i) => ({
      start: start + ((end - start) * i) / count,
      end: start + ((end - start) * (i + 1)) / count,
      count: 0,
    }));

    const span = Math.max(1, end - start);
    for (const entry of fullAnalysisData.entries) {
      if (!Number.isFinite(entry.timestamp)) continue;
      const idx = Math.min(count - 1, Math.max(0, Math.floor(((entry.timestamp - start) / span) * count)));
      bins[idx].count++;
    }
    return bins;
  }

  function drawTimelineHandle(ctx, x, y, h) {
    ctx.fillStyle = '#00d4ff';
    ctx.fillRect(x - 2, y - 5, 4, h + 10);
    ctx.fillStyle = '#0a0c0f';
    ctx.fillRect(x - 7, y + h / 2 - 11, 14, 22);
    ctx.strokeStyle = '#00d4ff';
    ctx.strokeRect(x - 7.5, y + h / 2 - 11.5, 15, 23);
    ctx.fillStyle = '#00d4ff';
    ctx.fillRect(x - 3, y + h / 2 - 6, 1, 12);
    ctx.fillRect(x + 2, y + h / 2 - 6, 1, 12);
  }

  function drawTimelineAxis(ctx, plot, start, end, maxCount) {
    ctx.fillStyle = '#5a6476';
    ctx.font = '10px IBM Plex Mono, monospace';
    ctx.textBaseline = 'top';
    ctx.fillText(String(maxCount), 8, plot.y - 1);
    ctx.fillText('0', 28, plot.y + plot.h - 8);
    for (let i = 0; i <= 4; i++) {
      const t = start + ((end - start) * i) / 4;
      const text = formatTick(t);
      const x = plot.x + (plot.w * i) / 4;
      ctx.textAlign = i === 0 ? 'left' : i === 4 ? 'right' : 'center';
      ctx.fillText(text, x, plot.y + plot.h + 9);
    }
    ctx.textAlign = 'left';
  }

  function onTimelinePointerDown(event) {
    if (!timelineState) return;
    if (!activeTimeRange) {
      activeTimeRange = { start: timelineState.start, end: timelineState.end };
    }
    const x = event.offsetX;
    const leftX = timeToX(activeTimeRange.start);
    const rightX = timeToX(activeTimeRange.end);
    timelineDrag = Math.abs(x - leftX) <= Math.abs(x - rightX) ? 'start' : 'end';
    event.currentTarget.setPointerCapture(event.pointerId);
    updateTimelineDrag(x);
  }

  function onTimelinePointerMove(event) {
    if (!timelineDrag) return;
    updateTimelineDrag(event.offsetX);
  }

  function onTimelinePointerUp(event) {
    if (!timelineDrag) return;
    timelineDrag = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    refreshForTimeFilter();
  }

  function updateTimelineDrag(x) {
    const { start, end } = timelineState;
    const minSpan = Math.max(1000, (end - start) / 400);
    const next = xToTime(x);

    if (timelineDrag === 'start') {
      activeTimeRange.start = Math.min(Math.max(start, next), activeTimeRange.end - minSpan);
    } else {
      activeTimeRange.end = Math.max(Math.min(end, next), activeTimeRange.start + minSpan);
    }

    analysisData = buildFilteredAnalysis();
    renderTimeline();
  }

  function timeToX(time) {
    const { start, end, plot } = timelineState;
    return plot.x + ((time - start) / Math.max(1, end - start)) * plot.w;
  }

  function xToTime(x) {
    const { start, end, plot } = timelineState;
    const pct = Math.max(0, Math.min(1, (x - plot.x) / plot.w));
    return start + (end - start) * pct;
  }

  function formatTime(ms) {
    return new Date(ms).toLocaleString(undefined, {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }

  function formatTick(ms) {
    return new Date(ms).toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  // ───────────────────────────────────────────────
  // IP TABLE
  // ───────────────────────────────────────────────
  function setFilter(f) {
    currentFilter = f;
    currentPage = 0;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.f-${f}`).classList.add('active');
    renderIPTable();
  }

  function sortBy(col) {
    if (currentSort.col === col) {
      currentSort.dir = currentSort.dir === 'desc' ? 'asc' : 'desc';
    } else {
      currentSort = { col, dir: 'desc' };
    }
    document.querySelectorAll('thead th').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
    });
    const headers = { requests: 0, bytes: 1, ip: 2, threatScore: 3, classification: 4 };
    const idx = headers[col];
    if (idx !== undefined) {
      const ths = document.querySelectorAll('#ip-table thead th');
      ths[idx].classList.add(currentSort.dir === 'asc' ? 'sort-asc' : 'sort-desc');
    }
    renderIPTable();
  }

  function getFilteredIPs() {
    if (!analysisData) return [];
    let ips = [...analysisData.ips];

    if (currentFilter !== 'all') ips = ips.filter(i => i.classification === currentFilter);

    const q = document.getElementById('ip-search').value.toLowerCase().trim();
    if (q) {
      ips = ips.filter(i => {
        const geo = geoData[i.ip];
        const geoStr = geo ? `${geo.countryName||''} ${geo.cityName||''} ${geo.regionName||''} ${geo.asnOrganization||''}`.toLowerCase() : '';
        const errorStr = [
          ...(i.wafRules || []),
          ...(i.wafMessages || []),
          ...(i.errorUris || []),
          ...(i.errorModules || [])
        ].join(' ').toLowerCase();
        return i.ip.includes(q) ||
          i.userAgents.some(ua => ua.toLowerCase().includes(q)) ||
          errorStr.includes(q) ||
          geoStr.includes(q);
      });
    }

    const { col, dir } = currentSort;
    ips.sort((a, b) => {
      let va = a[col], vb = b[col];
      if (typeof va === 'string') va = va.toLowerCase(), vb = vb.toLowerCase();
      if (va < vb) return dir === 'asc' ? -1 : 1;
      if (va > vb) return dir === 'asc' ? 1 : -1;
      return 0;
    });

    return ips;
  }

  function renderIPTable() {
    const ips = getFilteredIPs();
    document.getElementById('ip-count').textContent = `${ips.length} IP${ips.length !== 1 ? 's' : ''}`;

    const maxRequests = analysisData ? Math.max(1, ...analysisData.ips.map(i => i.requests)) : 1;
    const tbody = document.getElementById('ip-tbody');
    const page = ips.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

    tbody.innerHTML = page.map(ip => {
      const geo = geoData[ip.ip];
      const isExpanded = expandedIPs.has(ip.ip);
      const flag = geo ? flagImage(geo.countryCode, geo.countryName) : '';
      const geoCell = renderGeoCell(ip.ip);

      const errorRate = ip.requests > 0 ? (ip.errors / ip.requests * 100).toFixed(0) : 0;
      const scanRate = ip.requests > 0 ? (ip.scanPatterns / ip.requests * 100).toFixed(0) : 0;
      const errorLogCount = ip.serverErrors || 0;
      const errorLogLabel = errorLogCount
        ? `${fmt(errorLogCount)} <span style="font-size:10px;color:var(--text-dim)">(${fmt(ip.wafBlocks || 0)} WAF)</span>`
        : '0';
      const threatColor = ip.threatScore >= 70 ? 'var(--red)' : ip.threatScore >= 35 ? 'var(--orange)' : 'var(--green)';

      return `
    <tr id="row-${safeId(ip.ip)}" class="${isExpanded ? 'expanded' : ''}">
      <td><strong style="color:var(--text-bright)">${fmt(ip.requests)}</strong></td>
      <td class="bytes-cell">${fmtBytes(ip.bytes)}</td>
      <td class="ip-cell">
        <span class="ip-flag">${flag}</span>
        <a href="https://www.abuseipdb.com/check/${ip.ip}" target="_blank" rel="noopener" title="AbuseIPDB">
          ${ip.ip}
        </a>
      </td>
      <td>
        <div class="threat-bar-wrap">
          <div class="threat-bar"><div class="threat-bar-fill" style="width:${ip.threatScore}%;background:${threatColor}"></div></div>
          <span class="threat-score-val" style="color:${threatColor}">${ip.threatScore}</span>
        </div>
      </td>
      <td><span class="badge badge-${ip.classification}">${ip.classification}</span></td>
      <td style="color:${ip.errors > 0 ? 'var(--orange)' : 'var(--text-dim)'}">${fmt(ip.errors)} <span style="font-size:10px;color:var(--text-dim)">(${errorRate}%)</span></td>
      <td style="color:${ip.scanPatterns > 0 ? 'var(--red)' : 'var(--text-dim)'}">${ip.scanPatterns} <span style="font-size:10px;color:var(--text-dim)">(${scanRate}%)</span></td>
      <td style="color:${errorLogCount > 0 ? 'var(--red)' : 'var(--text-dim)'}">${errorLogLabel}</td>
      <td style="color:var(--text-dim);font-size:11px">${ip.userAgents.length}</td>
      <td class="geo-cell">${geoCell}</td>
      <td><button class="expand-btn" onclick="toggleDetail('${ip.ip}')">${isExpanded ? '▲' : '▼'}</button></td>
    </tr>
    <tr class="detail-row" id="detail-${safeId(ip.ip)}" ${isExpanded ? '' : 'style="display:none"'}>
      <td colspan="11">
        <div class="detail-inner">
          <div class="detail-section">
            <h4>Sample Requests</h4>
            <pre>${escHtml(ip.paths.slice(0, 10).join('\n') || 'none')}</pre>
          </div>
          <div class="detail-section">
            <h4>User Agents</h4>
            <pre>${escHtml(ip.userAgents.join('\n') || 'none')}</pre>
            <div style="margin-top:10px">
              <h4>Status Codes</h4>
              <pre>${Object.entries(ip.statuses).map(([k,v]) => `${k}: ${v}`).join('\n')}</pre>
            </div>
          </div>
          <div class="detail-section">
            <h4>Error Log Evidence</h4>
            <pre>${escHtml(formatErrorEvidence(ip))}</pre>
          </div>
        </div>
      </td>
    </tr>`;
    }).join('');

    // Pagination
    const totalPages = Math.ceil(ips.length / PAGE_SIZE);
    const pag = document.getElementById('ip-pagination');
    if (totalPages <= 1) { pag.innerHTML = ''; return; }
    pag.innerHTML = `
    <button class="filter-btn" onclick="changePage(-1)" ${currentPage === 0 ? 'disabled' : ''}>← Prev</button>
    <span>Page ${currentPage + 1} / ${totalPages} &nbsp;(${ips.length} total)</span>
    <button class="filter-btn" onclick="changePage(1)" ${currentPage >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
  `;
  }

  function renderGeoCell(ip) {
    const geo = geoData[ip];
    if (!geo) return `<span class="geo-loading">-</span>`;

    const flag = flagImage(geo.countryCode, geo.countryName);
    const location = [geo.cityName, geo.regionName, geo.countryName].filter(Boolean).join(', ');
    return `<span class="geo-flag">${flag}</span>${escHtml(location)}`;
  }

  function updateGeoIPRows(results) {
    for (const result of results) {
      const ip = result?.ipAddress;
      if (!ip) continue;
      updateGeoIPRow(ip);
    }
  }

  function updateGeoIPRow(ip) {
    const row = document.getElementById(`row-${safeId(ip)}`);
    if (!row) return;

    const geoCell = row.querySelector('.geo-cell');
    if (geoCell) geoCell.innerHTML = renderGeoCell(ip);

    const geo = geoData[ip];
    const flagCell = row.querySelector('.ip-flag');
    if (flagCell) flagCell.innerHTML = geo ? flagImage(geo.countryCode, geo.countryName) : '';
  }

  function changePage(dir) {
    const ips = getFilteredIPs();
    const total = Math.ceil(ips.length / PAGE_SIZE);
    currentPage = Math.max(0, Math.min(total - 1, currentPage + dir));
    renderIPTable();
  }

  function toggleDetail(ip) {
    const row = document.getElementById(`detail-${safeId(ip)}`);
    const mainRow = document.getElementById(`row-${safeId(ip)}`);
    const btn = document.querySelector(`#row-${safeId(ip)} .expand-btn`);
    if (!row || !btn) return;
    if (expandedIPs.has(ip)) {
      expandedIPs.delete(ip);
      row.style.display = 'none';
      mainRow?.classList.remove('expanded');
      btn.textContent = '▼';
    } else {
      expandedIPs.add(ip);
      row.style.display = '';
      mainRow?.classList.add('expanded');
      btn.textContent = '▲';
    }
  }

  // ───────────────────────────────────────────────
  // SUBNETS
  // ───────────────────────────────────────────────
  function renderSubnets() {
    const subnets = getVisibleSubnets();
    const maxReq = Math.max(1, ...subnets.map(s => s.requests));
    document.getElementById('subnet-grid').innerHTML = subnets.map(s => {
      const scanColor = s.scanPatterns > 0 ? 'var(--red)' : 'var(--text-dim)';
      const flags = subnetFlags(s);
      return `
    <div class="subnet-card">
      <div class="subnet-title">
        <span class="subnet-flags">${flags}</span>
        <div class="subnet-heading ip-cell">
          <a href="https://www.abuseipdb.com/check-block/${s.subnet}">
            ${s.subnet}
          </a>
          <div class="subnet-hostname">${subnetHostnameLabel(s)}</div>
        </div>
      </div>
      <div class="subnet-meta">
        <span><b>${fmt(s.requests)}</b> reqs</span>
        <span><b>${fmtBytes(s.bytes)}</b> DL</span>
        <span><b>${s.ips.length}</b> IPs</span>
        <span style="color:${scanColor}"><b>${s.scanPatterns}</b> scans</span>
      </div>
      <div class="subnet-bar-wrap">
        <div class="subnet-bar"><div class="subnet-bar-fill" style="width:${(s.requests/maxReq*100).toFixed(1)}%"></div></div>
        <span style="font-size:10px;color:var(--text-dim)">${((s.requests/maxReq)*100).toFixed(0)}%</span>
      </div>
    </div>`;
    }).join('');
  }

  async function startSubnetHostnameLookup() {
    if (!analysisData) return;
    const runId = ++subnetHostnameLookupRunId;
    const subnets = getVisibleSubnets();

    for (const subnet of subnets) {
      if (runId !== subnetHostnameLookupRunId) return;
      if (subnetHostnames[subnet.subnet]) continue;

      subnetHostnames[subnet.subnet] = { status: 'loading', hostname: '' };
      renderSubnets();

      const hostname = await fetchSubnetHostname(subnet);
      if (runId !== subnetHostnameLookupRunId) return;

      subnetHostnames[subnet.subnet] = {
        status: hostname ? 'found' : 'missing',
        hostname
      };
      renderSubnets();
    }
  }

  function getVisibleSubnets() {
    return analysisData.subnets.slice(0, 100).filter(
      (i) => i.ips.length > 1
    ).sort(
      (a,b) => b.ips.length - a.ips.length
    );
  }

  function subnetHostnameLabel(subnet) {
    const result = subnetHostnames[subnet.subnet];
    if (!result || result.status === 'loading') return '<span class="geo-loading">hostname lookup...</span>';
    if (!result.hostname) return '<span class="geo-loading">no hostname</span>';
    return `<span title="${escAttr(result.hostname)}">${escHtml(result.hostname)}</span>`;
  }

  async function fetchSubnetHostname(subnet) {
    const candidates = [
      subnetBaseAddress(subnet.subnet),
      ...subnet.ips
    ].filter((ip, idx, all) => ip && !ip.includes(':') && all.indexOf(ip) === idx)
      .slice(0, SUBNET_HOSTNAME_CANDIDATE_LIMIT);

    for (const ip of candidates) {
      const hostname = await fetchPtrHostname(ip);
      if (hostname) return hostname;
    }

    return '';
  }

  async function fetchPtrHostname(ip) {
    const ptrName = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    try {
      const response = await fetch(`${DNS_ENDPOINT}?name=${encodeURIComponent(ptrName)}&type=PTR`, {
        method: 'GET',
        headers: { 'Accept': 'application/dns-json' }
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      const ptr = data.Answer?.find(a => a.type === 12 && a.data)?.data || '';
      return ptr.replace(/\.$/, '');
    } catch (e) {
      console.warn(`PTR lookup failed for ${ip}:`, e.message);
      return '';
    }
  }

  function subnetBaseAddress(subnet) {
    return String(subnet).split('/')[0];
  }

  // ───────────────────────────────────────────────
  // GEOIP
  // ───────────────────────────────────────────────
  async function fetchGeoIPClientSide(ips, runId, onBatchComplete) {
    if (!Array.isArray(ips) || ips.length === 0) return [];

    const results = [];
    while (runId === geoLookupRunId) {
      const pendingIps = ips.filter(ip => !geoData[ip]);
      if (pendingIps.length === 0) return results;

      let retriedThisRound = 0;
      const resolvedCount = ips.filter(ip => geoData[ip]).length;
      updateGeoProgress(resolvedCount, ips.length, `Geo lookup ${resolvedCount}/${ips.length}`);

      for (const ip of pendingIps) {
        if (runId !== geoLookupRunId) return results;

        const result = await fetchFreeGeoIP(ip);

        if (result) {
          results.push(result);
          if (onBatchComplete) onBatchComplete([result], ips.filter(ip => geoData[ip]).length + 1, ips.length);
        } else {
          retriedThisRound++;
          if (onBatchComplete) onBatchComplete([], ips.filter(ip => geoData[ip]).length, ips.length);
        }

        if (!result || result.__geoCacheStatus !== 'hit') {
          await waitWithCountdown(GEO_REQUEST_DELAY_MS, runId, ips.filter(ip => geoData[ip]).length, ips.length);
        }
      }

      if (retriedThisRound > 0) {
        await waitWithCountdown(GEO_BATCH_DELAY_MS, runId, ips.filter(ip => geoData[ip]).length, ips.length, 'Retrying missed IPs');
      }
    }

    return results;
  }

  async function fetchFreeGeoIP(ip) {
    try {
      const response = await fetch(`${GEO_ENDPOINT}${encodeURIComponent(ip)}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const result = {
        ...data,
        ipAddress: data.ipAddress || ip
      };
      Object.defineProperty(result, '__geoCacheStatus', {
        value: response.headers.get('X-GeoIP-Cache') || 'unknown'
      });
      return result;
    } catch (e) {
      console.warn(`FreeIPAPI lookup failed for ${ip}:`, e.message);
      return null;
    }
  }

  async function loadCachedGeoIPData(ips) {
    if (!('serviceWorker' in navigator)) return [];

    const registration = await geoCacheReady;
    const worker = navigator.serviceWorker.controller || registration?.active;
    if (!worker || !Array.isArray(ips) || ips.length === 0) return [];

    return new Promise(resolve => {
      const channel = new MessageChannel();
      const timeout = setTimeout(() => resolve([]), 2000);

      channel.port1.onmessage = event => {
        clearTimeout(timeout);
        const results = event.data?.results;
        resolve(Array.isArray(results) ? results : []);
      };

      worker.postMessage({ type: 'GET_CACHED_GEOIPS', ips }, [channel.port2]);
    });
  }

  async function startGeoLookup() {
    if (!analysisData) return;
    const runId = ++geoLookupRunId;

    const ips = analysisData.ips.map(i => i.ip);
    let done = 0;

    updateGeoProgress(done, ips.length, 'Geo lookup starting');
    const cachedResults = await loadCachedGeoIPData(ips);
    if (runId !== geoLookupRunId) return;
    if (cachedResults.length > 0) {
      for (const r of cachedResults) {
        geoData[r.ipAddress] = r;
      }
      done = ips.filter(ip => geoData[ip]).length;
      updateGeoProgress(done, ips.length, `Loaded ${done}/${ips.length} cached geo records`);
      updateGeoIPRows(cachedResults);
      renderSubnets();
    }

    await fetchGeoIPClientSide(ips, runId, (results, processed) => {
      if (runId !== geoLookupRunId) return;
      for (const r of results) {
        geoData[r.ipAddress] = r;
      }
      done = processed;
      updateGeoProgress(done, ips.length, `Geo lookup ${done}/${ips.length}`);
      updateGeoIPRows(results);
      renderSubnets();
    });

    if (runId === geoLookupRunId) updateGeoProgress(done, ips.length, `Geo lookup complete (${done}/${ips.length})`);
  }

  // ───────────────────────────────────────────────
  // TABS
  // ───────────────────────────────────────────────
  function showTab(name) {
    document.querySelectorAll('.tab').forEach((t, i) => {
      const names = ['ips', 'subnets'];
      t.classList.toggle('active', names[i] === name);
    });
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.getElementById(`tab-${name}`).classList.add('active');
  }

  // ───────────────────────────────────────────────
  // SAMPLE DATA
  // ───────────────────────────────────────────────
  function loadSample() {
    const sample = `66.249.66.1 - - [01/Jun/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 4523 "-" "Googlebot/2.1"
66.249.66.1 - - [01/Jun/2025:10:00:05 +0000] "GET /blog HTTP/1.1" 200 3210 "-" "Googlebot/2.1"
66.249.66.1 - - [01/Jun/2025:10:00:10 +0000] "GET /about HTTP/1.1" 200 2100 "-" "Googlebot/2.1"
185.220.101.45 - - [01/Jun/2025:10:01:00 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "sqlmap/1.7"
185.220.101.45 - - [01/Jun/2025:10:01:01 +0000] "GET /wp-login.php HTTP/1.1" 200 980 "-" "sqlmap/1.7"
185.220.101.45 - - [01/Jun/2025:10:01:02 +0000] "POST /wp-login.php HTTP/1.1" 403 234 "-" "sqlmap/1.7"
185.220.101.45 - - [01/Jun/2025:10:01:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "sqlmap/1.7"
185.220.101.45 - - [01/Jun/2025:10:01:04 +0000] "GET /admin HTTP/1.1" 404 162 "-" "sqlmap/1.7"
185.220.101.45 - - [01/Jun/2025:10:01:05 +0000] "GET /.env HTTP/1.1" 404 162 "-" "sqlmap/1.7"
185.220.101.46 - - [01/Jun/2025:10:01:10 +0000] "GET /etc/passwd HTTP/1.1" 400 512 "-" "Nikto/2.1.6"
185.220.101.46 - - [01/Jun/2025:10:01:11 +0000] "GET /shell.php HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
185.220.101.46 - - [01/Jun/2025:10:01:12 +0000] "GET /config.bak HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
8.8.8.8 - - [01/Jun/2025:10:02:00 +0000] "GET / HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
8.8.8.8 - - [01/Jun/2025:10:02:30 +0000] "GET /blog/post-1 HTTP/1.1" 200 8100 "https://google.com" "Mozilla/5.0 (Windows NT 10.0) Chrome/120"
1.1.1.1 - - [01/Jun/2025:10:03:00 +0000] "GET / HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Macintosh) Safari/537"
1.1.1.2 - - [01/Jun/2025:10:03:10 +0000] "GET /union+select+1,2,3 HTTP/1.1" 400 512 "-" "curl/7.64.0"
10.0.0.5 - - [01/Jun/2025:10:04:00 +0000] "GET / HTTP/1.1" 200 4523 "-" "Mozilla/5.0 Firefox/115"
10.0.0.5 - - [01/Jun/2025:10:04:10 +0000] "GET /contact HTTP/1.1" 200 1900 "https://example.com" "Mozilla/5.0 Firefox/115"
`.trim();
    const errorSample = `[Thu Jun 04 16:30:41.641717 2026] [proxy_fcgi:error] [pid 1504794:tid 140627555641088] (70007)The timeout specified has expired: [client 185.251.8.99:0] AH01075: Error dispatching request to : (polling), referer: https://www.google.com/
[Thu Jun 04 17:01:27.407479 2026] [security2:error] [pid 1524715:tid 140626976806656] [client 185.220.101.45:0] ModSecurity: Access denied with code 403 (phase 2). Operator EQ matched 0 at REQUEST_COOKIES_NAMES. [file "/etc/apache2/modsecurity.d/rules/comodo_free/26_Apps_WordPress.conf"] [line "155"] [id "225170"] [rev "3"] [msg "COMODO WAF: Sensitive Information Disclosure Vulnerability in WordPress 4.7 (CVE-2017-5487)||codekraft.it|F|2"] [severity "CRITICAL"] [tag "CWAF"] [tag "WordPress"] [hostname "codekraft.it"] [uri "/wp-json/wp/v2/users/"] [unique_id "aiGvZ1qjBXdJJZ5unk3vhAAAABc"]
[Thu Jun 04 17:01:30.507128 2026] [security2:error] [pid 1504794:tid 140627245242112] [client 185.220.101.45:0] ModSecurity: Access denied with code 403 (phase 2). Operator EQ matched 0 at IP. [file "/etc/apache2/modsecurity.d/rules/comodo_free/30_Apps_OtherApps.conf"] [line "5956"] [id "240335"] [rev "5"] [msg "COMODO WAF: XML-RPC Attack Identified (CVE-2013-0235)|Source 185.220.101.45 (+1 hits since last alert)|codekraft.it|F|2"] [severity "CRITICAL"] [tag "CWAF"] [tag "OtherApps"] [hostname "codekraft.it"] [uri "/xmlrpc.php"] [unique_id "aiGvarrMKlVa8AfcLAKw4AAAAJA"]`;
    document.getElementById('log-input').value = sample;
    document.getElementById('error-log-input').value = errorSample;
    updateLineCount();
  }

  // ───────────────────────────────────────────────
  // UI HELPERS
  // ───────────────────────────────────────────────
  function showLoading(msg) {
    document.getElementById('upload-section').style.display = 'none';
    document.getElementById('results').style.display = 'none';
    document.getElementById('loading').style.display = 'block';
    document.getElementById('loading-msg').textContent = msg;
  }

  function hideLoading() {
    document.getElementById('loading').style.display = 'none';
  }

  function resetUI() {
    geoLookupRunId++;
    subnetHostnameLookupRunId++;
    document.getElementById('upload-section').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    document.getElementById('header-stats').style.display = 'none';
    document.getElementById('geo-progress-wrap').style.display = 'none';
    analysisData = null;
    fullAnalysisData = null;
    activeTimeRange = null;
    timelineState = null;
    timelineDrag = null;
    geoData = {};
    subnetHostnames = {};
    expandedIPs = new Set();
  }

  function fmt(n) {
    if (n == null) return '—';
    return n.toLocaleString();
  }

  function fmtBytes(b) {
    if (!b) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let u = 0;
    while (b >= 1024 && u < units.length - 1) { b /= 1024; u++; }
    return `${b.toFixed(u > 0 ? 1 : 0)} ${units[u]}`;
  }

  function safeId(ip) { return ip.replace(/[.:/]/g, '_'); }
  function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  function formatErrorEvidence(ip) {
    if (!ip.serverErrors) return 'none';

    const lines = [
      `error log entries: ${fmt(ip.serverErrors)}`,
      `waf blocks: ${fmt(ip.wafBlocks || 0)}`,
      `timeouts: ${fmt(ip.timeoutErrors || 0)}`
    ];

    if (ip.errorModules?.length) lines.push(`modules: ${ip.errorModules.join(', ')}`);
    if (ip.wafRules?.length) lines.push(`rule ids: ${ip.wafRules.join(', ')}`);
    if (ip.errorUris?.length) lines.push(`uris: ${ip.errorUris.slice(0, 8).join(', ')}`);
    if (ip.wafMessages?.length) {
      lines.push('messages:');
      lines.push(...ip.wafMessages.slice(0, 5).map((msg) => `- ${msg}`));
    }
    if (ip.errorSamples?.length) {
      lines.push('samples:');
      lines.push(...ip.errorSamples.slice(0, 6).map((entry) => {
        const uri = entry.uri ? ` ${entry.uri}` : '';
        const rule = entry.ruleId ? ` rule ${entry.ruleId}` : '';
        const status = entry.status ? ` status ${entry.status}` : '';
        return `- ${entry.time} [${entry.module}:${entry.level}]${status}${rule}${uri} ${entry.message}`;
      }));
    }

    return lines.join('\n');
  }

  function updateGeoProgress(done, total, label) {
    const wrap = document.getElementById('geo-progress-wrap');
    const fill = document.getElementById('geo-progress-fill');
    const text = document.getElementById('geo-progress-text');
    const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 100;
    wrap.style.display = total > 0 ? 'block' : 'none';
    fill.style.width = `${pct}%`;
    text.textContent = label;
  }

  async function waitWithCountdown(ms, runId, done, total) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (runId !== geoLookupRunId) return;
      const seconds = Math.ceil((end - Date.now()) / 1000);
      updateGeoProgress(done, total, `Next geo batch in ${seconds}s`);
      await new Promise(r => setTimeout(r, Math.min(1000, Math.max(0, end - Date.now()))));
    }
  }

  function subnetFlags(subnet) {
    const flags = [...new Set(subnet.ips.map(ip => {
      const geo = geoData[ip];
      return geo ? flagImage(geo.countryCode, geo.countryName) : '';
    }).filter(Boolean))];
    return flags.slice(0, 4).join('');
  }

  function flagImage(code, label = '') {
    if (!code || code.length !== 2) return '';
    const iso = code.toLowerCase();
    if (!/^[a-z]{2}$/.test(iso)) return '';
    const alt = escAttr(label || code.toUpperCase());
    return `<img class="flag-img" src="https://hatscripts.github.io/circle-flags/flags/${iso}.svg" alt="${alt}" title="${alt}" loading="lazy">`;
  }

  function escAttr(s) { return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

Object.assign(window, {
  resetUI,
  runAnalysis,
  loadSample,
  showTab,
  renderIPTable,
  resetTimeFilter,
  setFilter,
  sortBy,
  toggleDetail,
  changePage
});
