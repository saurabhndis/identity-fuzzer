// Traffic Generator GUI — renderer-side logic for the Traffic Gen tab
// Sub-tabs: TCP, HTTP, HTTP/2 — each filters scenarios by protocol category

(function () {
  'use strict';

  // ── DOM References ──────────────────────────────────────────────────────────
  const page = document.getElementById('trafficPage');
  if (!page) return;

  // Detail panel elements
  const detailPanel = page.querySelector('#trafficScenarioDetail');
  const detailName = page.querySelector('#trafficDetailName');
  const detailCategory = page.querySelector('#trafficDetailCategory');
  const detailDesc = page.querySelector('#trafficDetailDesc');
  const detailSide = page.querySelector('#trafficDetailSide');
  const detailExpected = page.querySelector('#trafficDetailExpected');
  const detailReason = page.querySelector('#trafficDetailReason');
  const detailDscp = page.querySelector('#trafficDetailDscp');
  const detailDscpRow = page.querySelector('#trafficDetailDscpRow');
  const detailSteps = page.querySelector('#trafficDetailSteps');

  const modeSelect = page.querySelector('#trafficModeSelect');
  const hostInput = page.querySelector('#trafficHostInput');
  const portInput = page.querySelector('#trafficPortInput');
  const dscpSelect = page.querySelector('#trafficDscpSelect');
  const httpHostInput = page.querySelector('#trafficHttpHostInput');
  const httpEndpointInput = page.querySelector('#trafficHttpEndpointInput');
  const http2EndpointInput = page.querySelector('#trafficHttp2EndpointInput');
  const httpToolbar = page.querySelector('#trafficHttpToolbar');
  const httpEndpointGroup = page.querySelector('#trafficHttpEndpointGroup');
  const http2EndpointGroup = page.querySelector('#trafficHttp2EndpointGroup');
  const timeoutInput = page.querySelector('#trafficTimeoutInput');
  const delayInput = page.querySelector('#trafficDelayInput');
  const scenariosList = page.querySelector('#trafficScenariosList');
  const selectAllBtn = page.querySelector('#trafficSelectAllBtn');
  const deselectAllBtn = page.querySelector('#trafficDeselectAllBtn');
  const runBtn = page.querySelector('#trafficRunBtn');
  const stopBtn = page.querySelector('#trafficStopBtn');
  const progressBar = page.querySelector('#trafficProgressBar');
  const progressText = page.querySelector('#trafficProgressText');
  const resultsBody = page.querySelector('#trafficResultsBody');
  const logArea = page.querySelector('#trafficLog');
  const clearLogBtn = page.querySelector('#trafficClearLogBtn');
  const copyLogBtn = page.querySelector('#trafficCopyLogBtn');
  const statusBadge = page.querySelector('#trafficStatusBadge');

  // Sub-tab buttons
  const tabTcp = page.querySelector('#trafficTabTcp');
  const tabHttp = page.querySelector('#trafficTabHttp');
  const tabHttp2 = page.querySelector('#trafficTabHttp2');

  // ── Protocol → Category mapping ────────────────────────────────────────────
  const PROTOCOL_CATEGORIES = {
    tcp:   ['TA', 'TB', 'TC'],
    http:  ['HD', 'HE', 'HF', 'HG', 'HH', 'HI'],
    http2: ['H2A', 'H2B', 'H2C', 'H2D', 'H2E', 'H2F'],
  };

  // ── State ───────────────────────────────────────────────────────────────────
  const pcapBtn = page.querySelector('#trafficPcapBtn');

  let allScenarios = {};
  let categories = {};
  let categorySeverity = {};
  let running = false;
  let results = [];
  let activeProtocol = 'tcp';
  let pcapEnabled = false;
  let pcapFile = null;

  // Build a flat lookup of all scenarios by name
  let scenarioLookup = {};

  /**
   * Show scenario details in the detail panel when a scenario is clicked.
   */
  function showScenarioDetail(scenarioName) {
    var s = scenarioLookup[scenarioName];
    if (!s || !detailPanel) return;

    detailPanel.style.display = '';
    if (detailName) detailName.textContent = s.name;
    if (detailCategory) {
      var catInfo = categories[s.category] || {};
      detailCategory.textContent = s.category + ' — ' + (catInfo.name || '');
    }
    if (detailDesc) detailDesc.textContent = s.description || '—';
    if (detailSide) detailSide.textContent = (s.side || 'client').toUpperCase();
    if (detailExpected) detailExpected.textContent = s.expected || '—';
    if (detailReason) detailReason.textContent = s.expectedReason || '—';

    // DSCP info
    if (detailDscpRow && detailDscp) {
      if (s.dscp !== undefined && s.dscp !== 0) {
        detailDscpRow.style.display = '';
        detailDscp.textContent = '0x' + s.dscp.toString(16).padStart(2, '0');
      } else {
        detailDscpRow.style.display = 'none';
      }
    }

    // Steps
    if (detailSteps && s.steps) {
      var stepsText = s.steps.map(function (step, i) {
        var parts = [(i + 1) + '. ' + step.type.toUpperCase()];
        if (step.label) parts.push('  label: ' + step.label);
        if (step.mode) parts.push('  mode: ' + step.mode);
        if (step.port) parts.push('  port: ' + step.port);
        if (step.dscp) parts.push('  dscp: 0x' + step.dscp.toString(16));
        if (step.alpn) parts.push('  alpn: ' + step.alpn);
        if (step.timeout) parts.push('  timeout: ' + step.timeout + 'ms');
        if (step.ms) parts.push('  sleep: ' + step.ms + 'ms');
        if (step.count) parts.push('  count: ' + step.count);
        if (step.expectStatus) parts.push('  expect: HTTP ' + step.expectStatus);
        return parts.join('\n');
      }).join('\n');
      detailSteps.textContent = stepsText;
    } else if (detailSteps) {
      detailSteps.textContent = '(server-side handler — no step list)';
    }
  }

  // ── Init ────────────────────────────────────────────────────────────────────
  async function init() {
    if (!window.traffic) return;
    try {
      const data = await window.traffic.listScenarios();
      categories = data.categories || {};
      allScenarios = data.scenarios || {};
      categorySeverity = data.categorySeverity || {};

      // Build flat lookup
      scenarioLookup = {};
      for (var cat in allScenarios) {
        var items = allScenarios[cat];
        for (var i = 0; i < items.length; i++) {
          scenarioLookup[items[i].name] = items[i];
        }
      }

      renderScenarios();
      updateToolbarVisibility();
    } catch (err) {
      console.error('Failed to load traffic scenarios:', err);
    }
  }

  // ── Sub-tab switching ─────────────────────────────────────────────────────
  function switchProtocol(protocol) {
    activeProtocol = protocol;

    // Update sub-tab styles
    [tabTcp, tabHttp, tabHttp2].forEach(function (btn) {
      if (btn) {
        if (btn.dataset.protocol === protocol) {
          btn.classList.add('active-sub-tab');
          btn.style.background = '#e8f4fd';
          btn.style.borderBottom = '3px solid #2196F3';
        } else {
          btn.classList.remove('active-sub-tab');
          btn.style.background = '#f5f5f5';
          btn.style.borderBottom = '3px solid transparent';
        }
      }
    });

    // Update default port
    if (portInput) {
      if (protocol === 'tcp') portInput.value = '8080';
      else if (protocol === 'http') portInput.value = '8080';
      else if (protocol === 'http2') portInput.value = '8443';
    }

    updateToolbarVisibility();
    renderScenarios();
  }

  function updateToolbarVisibility() {
    if (httpToolbar) {
      httpToolbar.style.display = (activeProtocol === 'tcp') ? 'none' : '';
    }
    if (httpEndpointGroup) {
      httpEndpointGroup.style.display = (activeProtocol === 'http') ? '' : 'none';
    }
    if (http2EndpointGroup) {
      http2EndpointGroup.style.display = (activeProtocol === 'http2') ? '' : 'none';
    }
  }

  // ── Sub-tab event listeners ───────────────────────────────────────────────
  if (tabTcp) tabTcp.addEventListener('click', function () { switchProtocol('tcp'); });
  if (tabHttp) tabHttp.addEventListener('click', function () { switchProtocol('http'); });
  if (tabHttp2) tabHttp2.addEventListener('click', function () { switchProtocol('http2'); });

  // ── Scenario Rendering ──────────────────────────────────────────────────────
  function renderScenarios() {
    if (!scenariosList) return;
    scenariosList.innerHTML = '';
    const side = modeSelect ? modeSelect.value : 'client';
    const allowedCats = PROTOCOL_CATEGORIES[activeProtocol] || [];

    for (var ci = 0; ci < allowedCats.length; ci++) {
      var cat = allowedCats[ci];
      var items = allScenarios[cat];
      if (!items || items.length === 0) continue;

      var filtered = items.filter(function (s) { return !s.side || s.side === side; });
      if (filtered.length === 0) continue;

      var catInfo = categories[cat] || {};
      var severity = categorySeverity[cat] || 'info';

      var group = document.createElement('div');
      group.className = 'category-group';
      group.dataset.category = cat;

      // Category header
      var header = document.createElement('div');
      header.className = 'category-header';
      header.innerHTML =
        '<span class="chevron">&#x25BE;</span>' +
        '<input type="checkbox" class="cat-toggle" checked>' +
        '<strong>' + cat + '</strong> — ' + (catInfo.name || cat) +
        ' <span class="cat-count">(' + filtered.length + ')</span>' +
        ' <span class="severity-badge sev-' + severity + '">' + severity + '</span>' +
        '<span class="cat-actions">' +
        '<button class="cat-all small-btn">All</button>' +
        '<button class="cat-none small-btn">None</button>' +
        '</span>';

      var body = document.createElement('div');
      body.className = 'category-body';

      // Scenario items
      for (var j = 0; j < filtered.length; j++) {
        var s = filtered[j];
        var item = document.createElement('div');
        item.className = 'scenario-item';
        item.dataset.name = s.name.toLowerCase();
        item.dataset.description = (s.description || '').toLowerCase();

        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.id = 'tcb-' + s.name;
        cb.value = s.name;
        cb.checked = true;

        var label = document.createElement('label');
        label.htmlFor = 'tcb-' + s.name;
        label.textContent = s.name;
        label.title = s.description || '';

        // Run button for individual scenario
        var runOneBtn = document.createElement('button');
        runOneBtn.className = 'run-one-btn';
        runOneBtn.innerHTML = '&#x25B6;';
        runOneBtn.title = 'Run this scenario';

        item.appendChild(cb);
        item.appendChild(label);
        item.appendChild(runOneBtn);

        // Click on the item (not checkbox/button) shows detail
        (function (scenarioName, runBtn) {
          item.addEventListener('click', function (e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON') return;
            showScenarioDetail(scenarioName);
            scenariosList.querySelectorAll('.scenario-item').forEach(function (el) {
              el.classList.remove('selected');
            });
            item.classList.add('selected');
          });
          // Run single scenario
          runBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            if (running) return;
            runSingleScenario(scenarioName);
          });
        })(s.name, runOneBtn);

        body.appendChild(item);
      }

      group.appendChild(header);
      group.appendChild(body);
      scenariosList.appendChild(group);

      // Category toggle
      (function (h, b) {
        var catToggle = h.querySelector('.cat-toggle');
        catToggle.addEventListener('change', function () {
          b.querySelectorAll('input[type=checkbox]').forEach(function (c) { c.checked = catToggle.checked; });
        });
        h.querySelector('.cat-all').addEventListener('click', function (e) {
          e.stopPropagation();
          b.querySelectorAll('input[type=checkbox]').forEach(function (c) { c.checked = true; });
          catToggle.checked = true;
        });
        h.querySelector('.cat-none').addEventListener('click', function (e) {
          e.stopPropagation();
          b.querySelectorAll('input[type=checkbox]').forEach(function (c) { c.checked = false; });
          catToggle.checked = false;
        });
        h.addEventListener('click', function (e) {
          if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON') return;
          b.classList.toggle('collapsed');
          var chevron = h.querySelector('.chevron');
          chevron.innerHTML = b.classList.contains('collapsed') ? '&#x25B8;' : '&#x25BE;';
        });
      })(header, body);
    }
  }

  // ── Run Single Scenario ─────────────────────────────────────────────────────
  async function runSingleScenario(scenarioName) {
    if (running) return;
    running = true;
    if (resultsBody) resultsBody.innerHTML = '';
    if (logArea) logArea.value = '';
    if (statusBadge) { statusBadge.textContent = 'RUNNING'; statusBadge.className = 'status-badge running'; }
    if (runBtn) runBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;

    appendLog('▶ Running single scenario: ' + scenarioName);

    try {
      await window.traffic.run({
        mode: modeSelect ? modeSelect.value : 'client',
        host: hostInput ? hostInput.value : 'localhost',
        port: portInput ? parseInt(portInput.value, 10) : 8080,
        dscp: dscpSelect ? dscpSelect.value : '0',
        httpHost: httpHostInput ? httpHostInput.value : undefined,
        httpEndpoint: httpEndpointInput ? httpEndpointInput.value : undefined,
        http2Endpoint: http2EndpointInput ? http2EndpointInput.value : undefined,
        timeout: timeoutInput ? parseInt(timeoutInput.value, 10) : 10,
        delay: 0,
        scenarios: [scenarioName],
        pcapFile: pcapEnabled ? pcapFile : undefined,
      });
    } catch (err) {
      appendLog('✗ Error: ' + err.message);
    }

    running = false;
    if (runBtn) runBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;
  }

  // ── Event Listeners ─────────────────────────────────────────────────────────
  if (modeSelect) {
    modeSelect.addEventListener('change', renderScenarios);
  }

  if (selectAllBtn) {
    selectAllBtn.addEventListener('click', function () {
      scenariosList.querySelectorAll('input[type="checkbox"]').forEach(function (cb) { cb.checked = true; });
    });
  }

  if (deselectAllBtn) {
    deselectAllBtn.addEventListener('click', function () {
      scenariosList.querySelectorAll('input[type="checkbox"]').forEach(function (cb) { cb.checked = false; });
    });
  }

  if (runBtn) {
    runBtn.addEventListener('click', async function () {
      if (running) return;
      running = true;
      results = [];
      if (resultsBody) resultsBody.innerHTML = '';
      if (statusBadge) { statusBadge.textContent = 'RUNNING'; statusBadge.className = 'status-badge running'; }
      runBtn.disabled = true;
      if (stopBtn) stopBtn.disabled = false;

      var selected = [];
      scenariosList.querySelectorAll('input[type=checkbox]:checked').forEach(function (cb) {
        if (cb.value && cb.value !== 'on') selected.push(cb.value);
      });

      try {
        await window.traffic.run({
          mode: modeSelect ? modeSelect.value : 'client',
          host: hostInput ? hostInput.value : 'localhost',
          port: portInput ? parseInt(portInput.value, 10) : 8080,
          dscp: dscpSelect ? dscpSelect.value : '0',
          httpHost: httpHostInput ? httpHostInput.value : undefined,
          httpEndpoint: httpEndpointInput ? httpEndpointInput.value : undefined,
          http2Endpoint: http2EndpointInput ? http2EndpointInput.value : undefined,
          timeout: timeoutInput ? parseInt(timeoutInput.value, 10) : 10,
          delay: delayInput ? parseInt(delayInput.value, 10) : 100,
          scenarios: selected,
          pcapFile: pcapEnabled ? pcapFile : undefined,
        });
      } catch (err) {
        console.error('Traffic run error:', err);
      }

      running = false;
      runBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener('click', function () {
      window.traffic.stop();
      running = false;
      if (runBtn) runBtn.disabled = false;
      stopBtn.disabled = true;
      if (statusBadge) { statusBadge.textContent = 'STOPPED'; statusBadge.className = 'status-badge'; }
    });
  }

  // PCAP toggle
  if (pcapBtn) {
    pcapBtn.addEventListener('click', async function () {
      if (pcapEnabled) {
        pcapEnabled = false;
        pcapFile = null;
        pcapBtn.textContent = 'PCAP Off';
        pcapBtn.classList.remove('active');
      } else {
        // Ask user for save location
        if (window.fuzzer && window.fuzzer.savePcapDialog) {
          var result = await window.fuzzer.savePcapDialog();
          if (result && !result.canceled && result.filePath) {
            pcapFile = result.filePath;
            pcapEnabled = true;
            pcapBtn.textContent = 'PCAP On';
            pcapBtn.classList.add('active');
            appendLog('ℹ PCAP capture enabled: ' + pcapFile);
          }
        } else {
          // Fallback — use default path
          pcapFile = 'traffic-capture.pcap';
          pcapEnabled = true;
          pcapBtn.textContent = 'PCAP On';
          pcapBtn.classList.add('active');
          appendLog('ℹ PCAP capture enabled: ' + pcapFile);
        }
      }
    });
  }

  if (clearLogBtn && logArea) {
    clearLogBtn.addEventListener('click', function () { logArea.value = ''; });
  }

  if (copyLogBtn && logArea) {
    copyLogBtn.addEventListener('click', function () {
      logArea.select();
      document.execCommand('copy');
      copyLogBtn.textContent = 'Copied!';
      setTimeout(function () { copyLogBtn.textContent = 'Copy'; }, 1500);
    });
  }

  // Helper to append to log textarea
  function appendLog(line) {
    if (!logArea) return;
    logArea.value += line + '\n';
    logArea.scrollTop = logArea.scrollHeight;
  }

  // ── IPC Listeners ───────────────────────────────────────────────────────────
  if (window.traffic) {
    window.traffic.onResult(function (data) {
      results.push(data);
      if (resultsBody) {
        var icon = data.status === 'PASSED' ? '&#x2713;' : data.status === 'ERROR' ? '&#x2717;' : '?';
        var verdict = data.verdict ? ' [' + data.verdict + ']' : '';
        var statusClass = data.status === 'PASSED' ? 'status-pass' : data.status === 'ERROR' ? 'status-fail' : '';
        var tr = document.createElement('tr');
        tr.innerHTML =
          '<td>' + icon + '</td>' +
          '<td title="' + (data.description || '') + '">' + data.scenario + '</td>' +
          '<td>' + (data.category || '') + '</td>' +
          '<td class="' + statusClass + '">' + data.status + '</td>' +
          '<td title="' + (data.response || '') + '">' + ((data.response || '').substring(0, 60)) + verdict + '</td>' +
          '<td>' + (data.duration || 0) + 'ms</td>';
        resultsBody.appendChild(tr);
        tr.scrollIntoView({ block: 'nearest' });
      }
    });

    window.traffic.onLog(function (data) {
      var ts = data.ts || new Date().toISOString().substring(11, 23);
      var type = data.type || 'info';
      var line = '';

      if (type === 'info') {
        line = ts + ' ℹ ' + (data.message || '');
      } else if (type === 'error') {
        line = ts + ' ✗ ' + (data.message || '');
      } else if (type === 'sent') {
        line = ts + ' → ' + (data.label || 'Data') + ' (' + (data.size || 0) + ' bytes)';
        if (data.hex) {
          line += '\n' + formatHexForGUI(data.hex);
        }
      } else if (type === 'received') {
        line = ts + ' ← ' + (data.label || 'Data') + ' (' + (data.size || 0) + ' bytes)';
        if (data.hex) {
          line += '\n' + formatHexForGUI(data.hex);
        }
      } else if (type === 'tcp') {
        var arrow = data.direction === 'sent' ? '→' : '←';
        line = ts + ' ' + arrow + ' [TCP] ' + (data.event || '');
      } else if (type === 'scenario') {
        line = '\n━━━ Scenario: ' + (data.name || '') + ' ━━━\n    ' + (data.description || '');
      } else {
        line = ts + ' ' + (data.message || data.event || JSON.stringify(data));
      }

      appendLog(line);
    });

    window.traffic.onProgress(function (data) {
      if (progressBar) {
        var pct = data.total > 0 ? Math.round((data.current / data.total) * 100) : 0;
        progressBar.style.width = pct + '%';
      }
      if (progressText) {
        progressText.textContent = data.total > 0
          ? data.current + '/' + data.total + ' — ' + data.scenario
          : data.scenario;
      }
    });

    window.traffic.onReport(function (data) {
      if (statusBadge) {
        statusBadge.textContent = 'DONE (' + data.passed + '/' + data.total + ')';
        statusBadge.className = data.failed > 0 ? 'status-badge failed' : 'status-badge passed';
      }
    });
  }

  /**
   * Format a hex string into a Wireshark-style hex dump for the GUI log.
   * Input: hex string like "504f5354..."
   * Output: multi-line hex dump with offset, hex bytes, and ASCII
   */
  function formatHexForGUI(hexStr) {
    if (!hexStr) return '';
    var bytes = [];
    for (var i = 0; i < hexStr.length; i += 2) {
      bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    var lines = [];
    var maxLines = 16; // Limit to 16 lines (256 bytes) in GUI
    for (var offset = 0; offset < bytes.length && lines.length < maxLines; offset += 16) {
      var hex = '';
      var ascii = '';
      for (var j = 0; j < 16; j++) {
        if (offset + j < bytes.length) {
          var b = bytes[offset + j];
          hex += b.toString(16).padStart(2, '0') + ' ';
          ascii += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.';
        } else {
          hex += '   ';
          ascii += ' ';
        }
        if (j === 7) hex += ' ';
      }
      lines.push('    ' + offset.toString(16).padStart(8, '0') + '  ' + hex + ' |' + ascii + '|');
    }
    if (bytes.length > maxLines * 16) {
      lines.push('    ... (' + (bytes.length - maxLines * 16) + ' more bytes)');
    }
    return lines.join('\n');
  }

  // Initialize when page loads
  init();
})();
