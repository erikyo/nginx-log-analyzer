import { analyze } from "./parser.js";

  // ───────────────────────────────────────────────
  // STATE
  // ───────────────────────────────────────────────
  let analysisData = null;
  let geoData = {};
  let currentFilter = 'all';
  let currentSort = { col: 'requests', dir: 'desc' };
  let currentPage = 0;
  let expandedIPs = new Set();
  let geoLookupRunId = 0;
  const PAGE_SIZE = 50;
  const GEO_BATCH_SIZE = 60;
  const GEO_BATCH_DELAY_MS = 60000;
  const GEO_REQUEST_DELAY_MS = Math.ceil(GEO_BATCH_DELAY_MS / GEO_BATCH_SIZE);
  const GEO_ENDPOINT = 'https://free.freeipapi.com/api/json/';
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

  function updateLineCount() {
    const lines = document.getElementById('log-input').value.split('\n').filter(l => l.trim()).length;
    document.getElementById('line-count').textContent = lines ? `${fmt(lines)} lines` : '';
  }

  // ───────────────────────────────────────────────
  // ANALYSIS
  // ───────────────────────────────────────────────
  async function runAnalysis() {
    const text = document.getElementById('log-input').value.trim();
    if (!text) { alert('Please paste or upload a log file first.'); return; }

    showLoading('Parsing log entries…');

    try {
      analysisData = analyze(text);
      geoData = {};
      expandedIPs = new Set();
      renderResults();
      startGeoLookup();
    } catch (err) {
      hideLoading();
      alert('Analysis failed: ' + err.message);
    }
  }

  // ───────────────────────────────────────────────
  // RENDER RESULTS
  // ───────────────────────────────────────────────
  function renderResults() {
    hideLoading();
    document.getElementById('upload-section').style.display = 'none';
    document.getElementById('results').style.display = 'block';
    document.getElementById('header-stats').style.display = 'flex';

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
  `;

    renderIPTable();
    renderSubnets();
    document.getElementById('results').classList.add('fade-in');
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
        return i.ip.includes(q) ||
          i.userAgents.some(ua => ua.toLowerCase().includes(q)) ||
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

    const maxRequests = analysisData ? Math.max(...analysisData.ips.map(i => i.requests)) : 1;
    const tbody = document.getElementById('ip-tbody');
    const page = ips.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

    tbody.innerHTML = page.map(ip => {
      const geo = geoData[ip.ip];
      const isExpanded = expandedIPs.has(ip.ip);
      const flag = geo ? flagImage(geo.countryCode, geo.countryName) : '';
      const geoCell = geo
        ? `<span class="geo-flag">${flag}</span>${[geo.cityName, geo.regionName, geo.countryName].filter(Boolean).join(', ')}`
        : `<span class="geo-loading">—</span>`;

      const errorRate = ip.requests > 0 ? (ip.errors / ip.requests * 100).toFixed(0) : 0;
      const scanRate = ip.requests > 0 ? (ip.scanPatterns / ip.requests * 100).toFixed(0) : 0;
      const threatColor = ip.threatScore >= 70 ? 'var(--red)' : ip.threatScore >= 35 ? 'var(--orange)' : 'var(--green)';

      return `
    <tr id="row-${safeId(ip.ip)}" class="${isExpanded ? 'expanded' : ''}">
      <td><strong style="color:var(--text-bright)">${fmt(ip.requests)}</strong></td>
      <td class="bytes-cell">${fmtBytes(ip.bytes)}</td>
      <td class="ip-cell">
        <span class="ip-flag">${flag}</span><a href="https://www.shodan.io/host/${ip.ip}" target="_blank" rel="noopener" title="Shodan lookup">${ip.ip}</a>
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
      <td style="color:var(--text-dim);font-size:11px">${ip.userAgents.length}</td>
      <td class="geo-cell">${geoCell}</td>
      <td><button class="expand-btn" onclick="toggleDetail('${ip.ip}')">${isExpanded ? '▲' : '▼'}</button></td>
    </tr>
    <tr class="detail-row" id="detail-${safeId(ip.ip)}" ${isExpanded ? '' : 'style="display:none"'}>
      <td colspan="10">
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
    const subnets = analysisData.subnets;
    const maxReq = Math.max(...subnets.map(s => s.requests));
    document.getElementById('subnet-grid').innerHTML = subnets.slice(0, 100).filter(
      (i) => i.ips.length > 1
    ).sort(
      // sort by ips.length (descending)
      (a,b) => b.ips.length - a.ips.length
    ).map(s => {
      const scanColor = s.scanPatterns > 0 ? 'var(--red)' : 'var(--text-dim)';
      const flags = subnetFlags(s);
      return `
    <div class="subnet-card">
      <div class="subnet-title">
        <span class="subnet-flags">${flags}</span>
        <h4>${s.subnet}</h4>
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
      renderIPTable();
      renderSubnets();
    }

    await fetchGeoIPClientSide(ips, runId, (results, processed) => {
      if (runId !== geoLookupRunId) return;
      for (const r of results) {
        geoData[r.ipAddress] = r;
      }
      done = processed;
      updateGeoProgress(done, ips.length, `Geo lookup ${done}/${ips.length}`);
      renderIPTable(); // refresh geo column
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
    document.getElementById('log-input').value = sample;
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
    document.getElementById('upload-section').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    document.getElementById('header-stats').style.display = 'none';
    document.getElementById('geo-progress-wrap').style.display = 'none';
    analysisData = null;
    geoData = {};
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
  setFilter,
  sortBy,
  toggleDetail,
  changePage
});
