(function () {
  'use strict';

  // ── DOM References ──────────────────────────────────────────────────────────
  const modeSelect = document.getElementById('modeSelect');
  const hostInput = document.getElementById('hostInput');
  const portInput = document.getElementById('portInput');
  const delayInput = document.getElementById('delayInput');
  const timeoutInput = document.getElementById('timeoutInput');
  const workerInput = document.getElementById('workerInput');
  const localModeCheck = document.getElementById('localModeCheck');
  const scenarioSearch = document.getElementById('scenarioSearch');
  const scenariosList = document.getElementById('scenariosList');
  const selectAllBtn = document.getElementById('selectAllBtn');
  const deselectAllBtn = document.getElementById('deselectAllBtn');
  const runBtn = document.getElementById('runBtn');
  const rerunBtn = document.getElementById('rerunBtn');
  const stopBtn = document.getElementById('stopBtn');
  const loopInput = document.getElementById('loopInput');
  const pcapBtn = document.getElementById('pcapBtn');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const resultsBody = document.getElementById('resultsBody');
  const resultCount = document.getElementById('resultCount');
  const packetLog = document.getElementById('packetLog');
  const clearLogBtn = document.getElementById('clearLogBtn');
  const summaryBar = document.getElementById('summaryBar');
  const statusBadge = document.getElementById('statusBadge');

  // ── State ───────────────────────────────────────────────────────────────────
  let allScenarios = {};
  let categories = {};
  let categorySeverity = {};
  let defaultDisabled = new Set();
  let results = [];
  let failedScenarios = [];
  let running = false;
  let pcapEnabled = false;
  let pcapFile = null;

  // ── Init ────────────────────────────────────────────────────────────────────
  async function init() {
    try {
      const data = await window.fuzzer.listScenarios();
      categories = data.categories || {};
      allScenarios = data.scenarios || {};
      categorySeverity = data.categorySeverity || {};
      defaultDisabled = new Set(data.defaultDisabled || []);
      renderScenarios();
    } catch (err) {
      console.error('Failed to load scenarios:', err);
    }
  }
  init();

  // ── Scenario Rendering ──────────────────────────────────────────────────────
  function renderScenarios() {
    scenariosList.innerHTML = '';
    const side = modeSelect.value === 'server' ? 'server' : 'client';
    const sortedCats = Object.keys(allScenarios).sort();

    for (const cat of sortedCats) {
      const items = allScenarios[cat];
      if (!items || items.length === 0) continue;

      const filtered = items.filter(s => !s.side || s.side === side);
      if (filtered.length === 0) continue;

      const catInfo = categories[cat] || {};
      const severity = categorySeverity[cat] || 'info';
      const isDisabledByDefault = defaultDisabled.has(cat);

      const group = document.createElement('div');
      group.className = 'category-group';
      group.dataset.category = cat;

      // Header
      const header = document.createElement('div');
      header.className = 'category-header';
      header.innerHTML =
        '<span class="chevron">&#x25B8;</span>' +
        '<span class="category-name">' + esc(cat) + ' ' + esc(catInfo.name || '') + '</span>' +
        '<span class="category-count">(' + filtered.length + ')</span>' +
        '<span class="severity-badge sev-' + severity + '">' + severity + '</span>' +
        '<span class="category-actions">' +
          '<button class="cat-btn cat-all" title="Select all">All</button>' +
          '<button class="cat-btn cat-none" title="Deselect all">None</button>' +
        '</span>';

      // Category action buttons
      header.querySelector('.cat-all').addEventListener('click', function (e) {
        e.stopPropagation();
        group.querySelectorAll('.scenario-item input[type=checkbox]').forEach(function (cb) { cb.checked = true; });
      });
      header.querySelector('.cat-none').addEventListener('click', function (e) {
        e.stopPropagation();
        group.querySelectorAll('.scenario-item input[type=checkbox]').forEach(function (cb) { cb.checked = false; });
      });

      // Body (collapsible)
      const body = document.createElement('div');
      body.className = 'category-body collapsed';

      header.addEventListener('click', function () {
        body.classList.toggle('collapsed');
        var chevron = header.querySelector('.chevron');
        chevron.innerHTML = body.classList.contains('collapsed') ? '&#x25B8;' : '&#x25BE;';
      });

      // Scenario items
      for (var j = 0; j < filtered.length; j++) {
        var s = filtered[j];
        var item = document.createElement('div');
        item.className = 'scenario-item';
        item.dataset.name = s.name.toLowerCase();
        item.dataset.description = (s.description || '').toLowerCase();

        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.id = 'cb-' + s.name;
        cb.value = s.name;
        cb.checked = !isDisabledByDefault;

        var label = document.createElement('label');
        label.htmlFor = 'cb-' + s.name;
        label.textContent = s.name;
        label.title = s.description || '';

        item.appendChild(cb);
        item.appendChild(label);
        body.appendChild(item);
      }

      group.appendChild(header);
      group.appendChild(body);
      scenariosList.appendChild(group);
    }
  }

  // ── Search/filter ───────────────────────────────────────────────────────────
  scenarioSearch.addEventListener('input', function () {
    var q = scenarioSearch.value.toLowerCase().trim();
    document.querySelectorAll('.scenario-item').forEach(function (item) {
      var name = item.dataset.name || '';
      var desc = item.dataset.description || '';
      item.style.display = (!q || name.indexOf(q) >= 0 || desc.indexOf(q) >= 0) ? '' : 'none';
    });
    document.querySelectorAll('.category-group').forEach(function (group) {
      var visibleItems = group.querySelectorAll('.scenario-item');
      var anyVisible = false;
      visibleItems.forEach(function (el) {
        if (el.style.display !== 'none') anyVisible = true;
      });
      group.style.display = anyVisible ? '' : 'none';
    });
  });

  // ── Select All / Deselect All ───────────────────────────────────────────────
  selectAllBtn.addEventListener('click', function () {
    scenariosList.querySelectorAll('.scenario-item input[type=checkbox]').forEach(function (cb) {
      if (cb.closest('.scenario-item').style.display !== 'none') cb.checked = true;
    });
  });
  deselectAllBtn.addEventListener('click', function () {
    scenariosList.querySelectorAll('input[type=checkbox]').forEach(function (cb) { cb.checked = false; });
  });

  // ── Mode switching ──────────────────────────────────────────────────────────
  modeSelect.addEventListener('change', function () {
    if (modeSelect.value === 'server') {
      hostInput.disabled = true;
      hostInput.value = 'localhost';
    } else {
      hostInput.disabled = false;
    }
    renderScenarios();
  });

  // ── PCAP toggle ─────────────────────────────────────────────────────────────
  pcapBtn.addEventListener('click', async function () {
    if (!pcapEnabled) {
      var result = await window.fuzzer.savePcapDialog();
      if (result && result.filePath) {
        pcapFile = result.filePath;
        pcapEnabled = true;
        pcapBtn.textContent = 'PCAP On';
        pcapBtn.classList.add('pcap-on');
      }
    } else {
      pcapEnabled = false;
      pcapFile = null;
      pcapBtn.textContent = 'PCAP Off';
      pcapBtn.classList.remove('pcap-on');
    }
  });

  // ── Get selected scenarios ──────────────────────────────────────────────────
  function getSelectedScenarios() {
    var names = [];
    scenariosList.querySelectorAll('input[type=checkbox]:checked').forEach(function (cb) {
      names.push(cb.value);
    });
    return names;
  }

  // ── Run ─────────────────────────────────────────────────────────────────────
  runBtn.addEventListener('click', function () { startRun(getSelectedScenarios()); });

  rerunBtn.addEventListener('click', function () {
    if (failedScenarios.length > 0) startRun(failedScenarios);
  });

  async function startRun(scenarioNames) {
    if (running || scenarioNames.length === 0) return;

    running = true;
    results = [];
    failedScenarios = [];
    resultsBody.innerHTML = '';
    packetLog.innerHTML = '';
    summaryBar.style.display = 'none';
    resultCount.textContent = '0 results';
    progressBar.style.width = '0%';
    progressText.textContent = '0%';
    setRunningState(true);

    var opts = {
      mode: modeSelect.value,
      host: hostInput.value,
      port: portInput.value,
      scenarioNames: scenarioNames,
      delay: parseInt(delayInput.value, 10) || 100,
      timeout: parseInt(timeoutInput.value, 10) || 10,
      pcapFile: pcapEnabled ? pcapFile : null,
      verbose: true,
      loopCount: parseInt(loopInput.value, 10) || 1,
      localMode: localModeCheck.checked,
      workers: parseInt(workerInput.value, 10) || 1,
    };

    try {
      await window.fuzzer.run(opts);
    } catch (err) {
      addLogEntry('log-error', 'Error: ' + (err.message || err));
    }
  }

  // ── Stop ────────────────────────────────────────────────────────────────────
  stopBtn.addEventListener('click', async function () {
    await window.fuzzer.stop();
    setRunningState(false);
    statusBadge.textContent = 'STOPPED';
    statusBadge.className = 'status-badge error';
  });

  // ── Clear log ───────────────────────────────────────────────────────────────
  clearLogBtn.addEventListener('click', function () { packetLog.innerHTML = ''; });

  // ── Expand / Collapse packet log ───────────────────────────────────────────
  var packetPanel = document.getElementById('packetPanel');
  var expandLogBtn = document.getElementById('expandLogBtn');
  var resultsPanel = document.querySelector('.results-panel');
  var controlsBar = document.querySelector('.controls-bar');
  var logExpanded = false;

  expandLogBtn.addEventListener('click', function () {
    logExpanded = !logExpanded;
    if (logExpanded) {
      packetPanel.classList.add('expanded');
      resultsPanel.style.display = 'none';
      controlsBar.style.display = 'none';
      expandLogBtn.innerHTML = '&#x2199; Collapse';
    } else {
      packetPanel.classList.remove('expanded');
      resultsPanel.style.display = '';
      controlsBar.style.display = '';
      expandLogBtn.innerHTML = '&#x2197; Expand';
    }
  });

  // ── UI state ────────────────────────────────────────────────────────────────
  function setRunningState(state) {
    running = state;
    runBtn.disabled = state;
    rerunBtn.disabled = true;
    stopBtn.disabled = !state;
    modeSelect.disabled = state;
    statusBadge.textContent = state ? 'RUNNING' : 'IDLE';
    statusBadge.className = 'status-badge' + (state ? ' running' : '');
  }

  // ── Event listeners ─────────────────────────────────────────────────────────
  window.fuzzer.onPacket(function (pkt) {
    switch (pkt.type) {
      case 'scenario':
        addLogEntry('log-scenario', '\u2501\u2501\u2501 ' + pkt.name + ' \u2501\u2501\u2501');
        if (pkt.description) addLogEntry('log-info', '    ' + pkt.description);
        break;
      case 'sent':
        addLogEntry('log-sent', '\u2192 ' + pkt.label + ' (' + pkt.size + ' bytes)');
        if (pkt.hex) addHexDump(pkt.hex);
        break;
      case 'received':
        addLogEntry('log-received', '\u2190 ' + pkt.label + ' (' + pkt.size + ' bytes)');
        if (pkt.hex) addHexDump(pkt.hex);
        break;
      case 'tcp':
        addLogEntry('log-tcp', (pkt.direction === 'sent' ? '\u2192' : '\u2190') + ' [TCP] ' + pkt.event);
        break;
      case 'fuzz':
        addLogEntry('log-fuzz', '\u26A1 [FUZZ] ' + pkt.message);
        break;
      case 'info':
        addLogEntry('log-info', pkt.message);
        break;
      case 'error':
        addLogEntry('log-error', '\u2717 ' + pkt.message);
        break;
      case 'result':
        addLogEntry('log-result', '  Result: ' + pkt.status + ' (' + (pkt.response || '') + ')');
        break;
    }
  });

  window.fuzzer.onResult(function (r) {
    results.push(r);
    resultCount.textContent = results.length + ' results';

    if (r.status === 'ERROR' || r.status === 'DROPPED' || r.status === 'TIMEOUT') {
      failedScenarios.push(r.scenario);
    }
    addResultRow(r, results.length);
  });

  window.fuzzer.onProgress(function (p) {
    var pct = p.total > 0 ? Math.round((p.current / p.total) * 100) : 0;
    progressBar.style.width = pct + '%';
    progressText.textContent = pct + '% (' + p.current + '/' + p.total + ')';
  });

  window.fuzzer.onReport(function (report) {
    setRunningState(false);
    running = false;
    statusBadge.textContent = 'DONE';
    statusBadge.className = 'status-badge done';
    rerunBtn.disabled = failedScenarios.length === 0;
    showSummary(report);
  });

  // ── Log entry ───────────────────────────────────────────────────────────────
  function addLogEntry(cls, text) {
    var div = document.createElement('div');
    div.className = 'log-entry ' + cls;
    div.textContent = text;
    packetLog.appendChild(div);
    while (packetLog.children.length > 500) packetLog.removeChild(packetLog.firstChild);
    packetLog.scrollTop = packetLog.scrollHeight;
  }

  // ── LDAP Structured Hex Decoder ─────────────────────────────────────────────
  var LDAP_OPS = {
    0x60: 'BindRequest', 0x61: 'BindResponse',
    0x42: 'UnbindRequest',
    0x63: 'SearchRequest', 0x64: 'SearchResultEntry', 0x65: 'SearchResultDone', 0x73: 'SearchResultRef',
    0x66: 'ModifyRequest', 0x67: 'ModifyResponse',
    0x68: 'AddRequest', 0x69: 'AddResponse',
    0x4a: 'DelRequest', 0x6b: 'DelResponse',
    0x6c: 'ModifyDNRequest', 0x6d: 'ModifyDNResponse',
    0x6e: 'CompareRequest', 0x6f: 'CompareResponse',
    0x50: 'AbandonRequest',
    0x77: 'ExtendedRequest', 0x78: 'ExtendedResponse',
    0x79: 'IntermediateResponse',
  };

  var LDAP_RESULTS = {
    0: 'success', 1: 'operationsError', 2: 'protocolError', 3: 'timeLimitExceeded',
    4: 'sizeLimitExceeded', 7: 'authMethodNotSupported', 8: 'strongerAuthRequired',
    10: 'referral', 11: 'adminLimitExceeded', 13: 'confidentialityRequired',
    14: 'saslBindInProgress', 16: 'noSuchAttribute', 32: 'noSuchObject',
    34: 'invalidDNSyntax', 48: 'inappropriateAuthentication', 49: 'invalidCredentials',
    50: 'insufficientAccessRights', 51: 'busy', 52: 'unavailable',
    53: 'unwillingToPerform', 64: 'namingViolation', 65: 'objectClassViolation',
    68: 'entryAlreadyExists', 80: 'other',
  };

  function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function readBerLength(hex, pos) {
    if (pos >= hex.length) return { length: 0, nextPos: pos };
    var b0 = parseInt(hex.substr(pos, 2), 16);
    pos += 2;
    if (b0 < 0x80) return { length: b0, nextPos: pos };
    if (b0 === 0x80) return { length: -1, nextPos: pos };
    var numBytes = b0 & 0x7f;
    var length = 0;
    for (var i = 0; i < numBytes && pos < hex.length; i++) {
      length = (length << 8) | parseInt(hex.substr(pos, 2), 16);
      pos += 2;
    }
    return { length: length, nextPos: pos };
  }

  function readInt(hex, pos, len) {
    var val = 0;
    for (var i = 0; i < len && pos < hex.length; i++) {
      val = (val << 8) | parseInt(hex.substr(pos, 2), 16);
      pos += 2;
    }
    return { value: val, nextPos: pos };
  }

  function readOctetString(hex, pos, len) {
    var bytes = [];
    for (var i = 0; i < len && pos < hex.length; i++) {
      bytes.push(parseInt(hex.substr(pos, 2), 16));
      pos += 2;
    }
    var s = bytes.map(function (b) { return (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'; }).join('');
    return { value: s, nextPos: pos };
  }

  function decodeLdapHex(hex) {
    try {
      if (!hex || hex.length < 4) return null;
      var pos = 0;
      var lines = [];

      while (pos < hex.length - 4) {
        var tag = parseInt(hex.substr(pos, 2), 16);
        if (tag !== 0x30) break;
        pos += 2;
        var seqLen = readBerLength(hex, pos);
        pos = seqLen.nextPos;

        var msgIdTag = parseInt(hex.substr(pos, 2), 16);
        if (msgIdTag !== 0x02) break;
        pos += 2;
        var msgIdLen = readBerLength(hex, pos);
        pos = msgIdLen.nextPos;
        var msgId = readInt(hex, pos, msgIdLen.length);
        pos = msgId.nextPos;

        var opTag = parseInt(hex.substr(pos, 2), 16);
        pos += 2;
        var opLen = readBerLength(hex, pos);
        pos = opLen.nextPos;
        var opEnd = pos + opLen.length * 2;

        var opName = LDAP_OPS[opTag] || 'Unknown(0x' + opTag.toString(16) + ')';
        var detail = '';

        if (opTag === 0x60 && pos < opEnd) { // BindRequest
          pos += 2;
          var vLen = readBerLength(hex, pos); pos = vLen.nextPos;
          var ver = readInt(hex, pos, vLen.length); pos = ver.nextPos;
          pos += 2;
          var dnLen = readBerLength(hex, pos); pos = dnLen.nextPos;
          var dn = readOctetString(hex, pos, dnLen.length); pos = dn.nextPos;
          detail = ' version=' + ver.value + ' dn="' + esc(dn.value) + '"';
        } else if (opTag === 0x61 && pos < opEnd) { // BindResponse
          pos += 2;
          var rcLen = readBerLength(hex, pos); pos = rcLen.nextPos;
          var rc = readInt(hex, pos, rcLen.length); pos = rc.nextPos;
          detail = ' <span class="ldap-result-code">' + esc(LDAP_RESULTS[rc.value] || 'code(' + rc.value + ')') + '</span>';
        } else if (opTag === 0x64 && pos < opEnd) { // SearchResultEntry
          pos += 2;
          var dnL2 = readBerLength(hex, pos); pos = dnL2.nextPos;
          var dn2 = readOctetString(hex, pos, dnL2.length); pos = dn2.nextPos;
          detail = ' dn="' + esc(dn2.value) + '"';
        } else if ((opTag === 0x65 || opTag === 0x67 || opTag === 0x69 || opTag === 0x6b || opTag === 0x6d || opTag === 0x6f) && pos < opEnd) {
          pos += 2;
          var rcLen2 = readBerLength(hex, pos); pos = rcLen2.nextPos;
          var rc2 = readInt(hex, pos, rcLen2.length); pos = rc2.nextPos;
          detail = ' <span class="ldap-result-code">' + esc(LDAP_RESULTS[rc2.value] || 'code(' + rc2.value + ')') + '</span>';
        } else if (opTag === 0x63 && pos < opEnd) { // SearchRequest
          pos += 2;
          var dnL3 = readBerLength(hex, pos); pos = dnL3.nextPos;
          var dn3 = readOctetString(hex, pos, dnL3.length); pos = dn3.nextPos;
          detail = ' baseDN="' + esc(dn3.value) + '"';
        }

        lines.push('<span class="ldap-msgid">msgId=' + msgId.value + '</span> <span class="ldap-op">' + esc(opName) + '</span>' + detail);
        pos = opEnd;
      }

      return lines.length > 0 ? lines.join('\n') : null;
    } catch (_) {
      return null;
    }
  }

  // ── Hex dump display ────────────────────────────────────────────────────────
  function addHexDump(hex) {
    if (!hex) return;
    var structured = decodeLdapHex(hex);
    if (structured) {
      var pre = document.createElement('pre');
      pre.className = 'hex-dump ldap-structured';
      pre.innerHTML = structured;
      packetLog.appendChild(pre);
    } else {
      var pre2 = document.createElement('pre');
      pre2.className = 'hex-dump';
      var formatted = '';
      for (var i = 0; i < hex.length && i < 256; i += 2) {
        formatted += hex.substr(i, 2) + ' ';
        if ((i / 2 + 1) % 16 === 0) formatted += '\n';
      }
      if (hex.length > 256) formatted += '\n... (' + Math.floor(hex.length / 2) + ' bytes total)';
      pre2.textContent = formatted.trim();
      packetLog.appendChild(pre2);
    }
    packetLog.scrollTop = packetLog.scrollHeight;
  }

  // ── Result row ──────────────────────────────────────────────────────────────
  function addResultRow(r, idx) {
    var tr = document.createElement('tr');
    var severity = categorySeverity[r.category] || 'info';
    var findingGrade = r.finding ? (typeof r.finding === 'string' ? r.finding.toUpperCase() : r.finding.grade || '\u2014') : '\u2014';
    var findingClass = findingGrade === 'PASS' ? 'finding-pass' : findingGrade === 'FAIL' ? 'finding-fail' : findingGrade === 'WARN' ? 'finding-warn' : 'finding-info';
    var statusClass = r.status === 'PASSED' ? 'status-pass' : r.status === 'DROPPED' ? 'status-fail' : r.status === 'TIMEOUT' ? 'status-timeout' : r.status === 'ERROR' ? 'status-error' : '';
    var verdictClass = r.verdict === 'AS EXPECTED' ? 'verdict-expected' : r.verdict === 'UNEXPECTED' ? 'verdict-unexpected' : '';

    tr.innerHTML =
      '<td>' + idx + '</td>' +
      '<td title="' + esc(r.description || '') + '">' + esc(r.scenario) + '</td>' +
      '<td>' + esc(r.category || '') + '</td>' +
      '<td><span class="severity-badge sev-' + severity + '">' + severity + '</span></td>' +
      '<td class="' + statusClass + '">' + esc(r.status) + '</td>' +
      '<td class="' + findingClass + '">' + esc(findingGrade) + '</td>' +
      '<td class="' + verdictClass + '">' + esc(r.verdict || 'N/A') + '</td>' +
      '<td title="' + esc(r.response || '') + '">' + esc((r.response || '').substring(0, 60)) + '</td>';
    resultsBody.appendChild(tr);
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  function showSummary(report) {
    if (!report) return;
    summaryBar.style.display = 'flex';
    summaryBar.innerHTML =
      '<span class="grade-badge grade-' + report.grade + '">' + report.grade + '</span>' +
      '<span class="summary-label">' + esc(report.label) + '</span>' +
      '<span class="stat stat-pass"><span class="stat-label">Pass:</span> <span class="stat-value">' + (report.stats.pass || 0) + '</span></span>' +
      '<span class="stat stat-fail"><span class="stat-label">Fail:</span> <span class="stat-value">' + (report.stats.fail || 0) + '</span></span>' +
      '<span class="stat stat-warn"><span class="stat-label">Warn:</span> <span class="stat-value">' + (report.stats.warn || 0) + '</span></span>' +
      '<span class="stat"><span class="stat-label">Info:</span> <span class="stat-value">' + (report.stats.info || 0) + '</span></span>';
  }

})();
