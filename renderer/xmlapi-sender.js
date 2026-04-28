(function () {
  'use strict';

  // ── Utility ─────────────────────────────────────────────────────────────────
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // ── Tab Switching (xmlapi page) ───────────────────────────────────────────
  var xmlapiPage = document.getElementById('xmlapiPage');
  if (!xmlapiPage) return;

  xmlapiPage.querySelectorAll('.xmlapi-tabs .adsim-tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      var tabName = tab.dataset.tab;
      xmlapiPage.querySelectorAll('.xmlapi-tabs .adsim-tab').forEach(function (t) { t.classList.remove('active'); });
      xmlapiPage.querySelectorAll('.xmlapi-tab-content .adsim-panel').forEach(function (p) {
        p.style.display = 'none';
        p.classList.remove('active');
      });
      tab.classList.add('active');
      var panel = xmlapiPage.querySelector('[data-tab-panel="' + tabName + '"]');
      if (panel) {
        panel.style.display = '';
        panel.classList.add('active');
      }
    });
  });

  // ── State ───────────────────────────────────────────────────────────────────
  var logEntries = [];
  var running = false;

  // ── DOM References: Send tab ────────────────────────────────────────────────
  var xmlapiFirewall = document.getElementById('xmlapiFirewall');
  var xmlapiPort = document.getElementById('xmlapiPort');
  var xmlapiKey = document.getElementById('xmlapiKey');
  var xmlapiVerifySSL = document.getElementById('xmlapiVerifySSL');
  var xmlapiKeygenUser = document.getElementById('xmlapiKeygenUser');
  var xmlapiKeygenPass = document.getElementById('xmlapiKeygenPass');
  var xmlapiKeygenBtn = document.getElementById('xmlapiKeygenBtn');
  var xmlapiOperation = document.getElementById('xmlapiOperation');
  var xmlapiUsername = document.getElementById('xmlapiUsername');
  var xmlapiIPAddress = document.getElementById('xmlapiIPAddress');
  var xmlapiDomain = document.getElementById('xmlapiDomain');
  var xmlapiTimeout = document.getElementById('xmlapiTimeout');
  var xmlapiGroupDn = document.getElementById('xmlapiGroupDn');
  var xmlapiMembers = document.getElementById('xmlapiMembers');
  var xmlapiTags = document.getElementById('xmlapiTags');
  var xmlapiSendBtn = document.getElementById('xmlapiSendBtn');
  var xmlapiPreviewBtn = document.getElementById('xmlapiPreviewBtn');
  var xmlapiSendResults = document.getElementById('xmlapiSendResults');
  var xmlapiStatusBadge = document.getElementById('xmlapiStatusBadge');

  // Conditional field rows
  var xmlapiUsernameRow = document.getElementById('xmlapiUsernameRow');
  var xmlapiIPRow = document.getElementById('xmlapiIPRow');
  var xmlapiDomainRow = document.getElementById('xmlapiDomainRow');
  var xmlapiTimeoutRow = document.getElementById('xmlapiTimeoutRow');
  var xmlapiGroupDnRow = document.getElementById('xmlapiGroupDnRow');
  var xmlapiMembersRow = document.getElementById('xmlapiMembersRow');
  var xmlapiTagsRow = document.getElementById('xmlapiTagsRow');

  // ── DOM References: Bulk tab ────────────────────────────────────────────────
  var xmlapiBulkFirewall = document.getElementById('xmlapiBulkFirewall');
  var xmlapiBulkKey = document.getElementById('xmlapiBulkKey');
  var xmlapiBulkOperation = document.getElementById('xmlapiBulkOperation');
  var xmlapiBulkCount = document.getElementById('xmlapiBulkCount');
  var xmlapiBulkPattern = document.getElementById('xmlapiBulkPattern');
  var xmlapiBulkBaseIP = document.getElementById('xmlapiBulkBaseIP');
  var xmlapiBulkDomain = document.getElementById('xmlapiBulkDomain');
  var xmlapiBulkTags = document.getElementById('xmlapiBulkTags');
  var xmlapiBulkDelay = document.getElementById('xmlapiBulkDelay');
  var xmlapiBulkRunBtn = document.getElementById('xmlapiBulkRunBtn');
  var xmlapiBulkStopBtn = document.getElementById('xmlapiBulkStopBtn');
  var xmlapiBulkResults = document.getElementById('xmlapiBulkResults');
  var xmlapiBulkProgressWrap = document.getElementById('xmlapiBulkProgressWrap');
  var xmlapiBulkProgressBar = document.getElementById('xmlapiBulkProgressBar');
  var xmlapiBulkProgressText = document.getElementById('xmlapiBulkProgressText');
  var xmlapiBulkTagsRow = document.getElementById('xmlapiBulkTagsRow');

  // ── DOM References: Scenario tab ────────────────────────────────────────────
  var xmlapiScenarioFirewall = document.getElementById('xmlapiScenarioFirewall');
  var xmlapiScenarioKey = document.getElementById('xmlapiScenarioKey');
  var xmlapiScenarioName = document.getElementById('xmlapiScenarioName');
  var xmlapiScenarioUsers = document.getElementById('xmlapiScenarioUsers');
  var xmlapiScenarioDomain = document.getElementById('xmlapiScenarioDomain');
  var xmlapiScenarioGroupDn = document.getElementById('xmlapiScenarioGroupDn');
  var xmlapiScenarioMembers = document.getElementById('xmlapiScenarioMembers');
  var xmlapiScenarioTags = document.getElementById('xmlapiScenarioTags');
  var xmlapiScenarioRunBtn = document.getElementById('xmlapiScenarioRunBtn');
  var xmlapiScenarioResults = document.getElementById('xmlapiScenarioResults');
  var xmlapiScenarioUsersRow = document.getElementById('xmlapiScenarioUsersRow');
  var xmlapiScenarioDomainRow = document.getElementById('xmlapiScenarioDomainRow');
  var xmlapiScenarioGroupRow = document.getElementById('xmlapiScenarioGroupRow');
  var xmlapiScenarioMembersRow = document.getElementById('xmlapiScenarioMembersRow');
  var xmlapiScenarioTagsRow = document.getElementById('xmlapiScenarioTagsRow');

  // ── DOM References: Log tab ─────────────────────────────────────────────────
  var xmlapiLogContainer = document.getElementById('xmlapiLogContainer');
  var xmlapiLogCount = document.getElementById('xmlapiLogCount');
  var xmlapiLogClearBtn = document.getElementById('xmlapiLogClearBtn');

  // ── Operation field visibility ──────────────────────────────────────────────
  function updateOperationFields() {
    var op = xmlapiOperation.value;
    var isLogin = op === 'login';
    var isLogout = op === 'logout';
    var isGroup = op === 'groups';
    var isTag = op === 'tag-register' || op === 'tag-unregister';

    xmlapiUsernameRow.style.display = (isLogin || isLogout) ? '' : 'none';
    xmlapiIPRow.style.display = (isLogin || isLogout || isTag) ? '' : 'none';
    xmlapiDomainRow.style.display = (isLogin || isLogout || isGroup) ? '' : 'none';
    xmlapiTimeoutRow.style.display = isLogin ? '' : 'none';
    xmlapiGroupDnRow.style.display = isGroup ? '' : 'none';
    xmlapiMembersRow.style.display = isGroup ? '' : 'none';
    xmlapiTagsRow.style.display = isTag ? '' : 'none';
  }
  xmlapiOperation.addEventListener('change', updateOperationFields);
  updateOperationFields();

  // Bulk operation field visibility
  function updateBulkFields() {
    var op = xmlapiBulkOperation.value;
    var isTag = op === 'tag-register' || op === 'tag-unregister';
    xmlapiBulkTagsRow.style.display = isTag ? '' : 'none';
  }
  xmlapiBulkOperation.addEventListener('change', updateBulkFields);
  updateBulkFields();

  // Scenario field visibility
  function updateScenarioFields() {
    var name = xmlapiScenarioName.value;
    var showUsers = ['login-logout', 'bulk-login', 'mixed'].indexOf(name) >= 0;
    var showDomain = ['login-logout', 'bulk-login', 'mixed', 'group-push'].indexOf(name) >= 0;
    var showGroup = ['group-push', 'mixed'].indexOf(name) >= 0;
    var showMembers = name === 'group-push';
    var showTags = ['tag-register', 'tag-unregister', 'mixed'].indexOf(name) >= 0;

    xmlapiScenarioUsersRow.style.display = showUsers ? '' : 'none';
    xmlapiScenarioDomainRow.style.display = showDomain ? '' : 'none';
    xmlapiScenarioGroupRow.style.display = showGroup ? '' : 'none';
    xmlapiScenarioMembersRow.style.display = showMembers ? '' : 'none';
    xmlapiScenarioTagsRow.style.display = showTags ? '' : 'none';
  }
  xmlapiScenarioName.addEventListener('change', updateScenarioFields);
  updateScenarioFields();

  // ── Helper: get send opts ───────────────────────────────────────────────────
  function getSendOpts(dryRun) {
    return {
      firewall: xmlapiFirewall.value,
      port: parseInt(xmlapiPort.value, 10) || 443,
      apiKey: xmlapiKey.value,
      verifySSL: xmlapiVerifySSL.checked,
      operation: xmlapiOperation.value,
      username: xmlapiUsername.value,
      ipAddress: xmlapiIPAddress.value,
      domain: xmlapiDomain.value || undefined,
      timeout: xmlapiTimeout.value ? parseInt(xmlapiTimeout.value, 10) : undefined,
      groupDn: xmlapiGroupDn.value || undefined,
      members: xmlapiMembers.value || undefined,
      tags: xmlapiTags.value || undefined,
      dryRun: dryRun || false,
    };
  }

  // ── Keygen ──────────────────────────────────────────────────────────────────
  xmlapiKeygenBtn.addEventListener('click', async function () {
    var fw = xmlapiFirewall.value;
    var user = xmlapiKeygenUser.value;
    var pass = xmlapiKeygenPass.value;
    if (!fw || !user || !pass) {
      xmlapiSendResults.innerHTML = '<p class="text-danger">Firewall IP, username, and password are required for keygen.</p>';
      return;
    }
    xmlapiKeygenBtn.disabled = true;
    xmlapiKeygenBtn.textContent = '⏳ Generating...';
    try {
      var result = await window.xmlapi.keygen({ firewall: fw, port: parseInt(xmlapiPort.value, 10) || 443, username: user, password: pass, verifySSL: xmlapiVerifySSL.checked });
      if (result.ok) {
        xmlapiKey.value = result.apiKey;
        xmlapiSendResults.innerHTML = '<p class="text-success">✅ API key generated and filled in.</p>';
      } else {
        xmlapiSendResults.innerHTML = '<p class="text-danger">❌ Keygen failed: ' + esc(result.error) + '</p>';
      }
    } catch (e) {
      xmlapiSendResults.innerHTML = '<p class="text-danger">❌ ' + esc(e.message) + '</p>';
    }
    xmlapiKeygenBtn.disabled = false;
    xmlapiKeygenBtn.textContent = '🔑 Generate Key';
  });

  // ── Preview ─────────────────────────────────────────────────────────────────
  xmlapiPreviewBtn.addEventListener('click', async function () {
    var opts = getSendOpts(true);
    if (!opts.firewall) { xmlapiSendResults.innerHTML = '<p class="text-danger">Firewall IP is required.</p>'; return; }
    if (!opts.apiKey) { xmlapiSendResults.innerHTML = '<p class="text-danger">API Key is required.</p>'; return; }
    try {
      var result = await window.xmlapi.send(opts);
      if (result.ok && result.dryRun) {
        xmlapiSendResults.innerHTML = '<div class="xml-preview"><strong>Operation:</strong> ' + esc(result.operation) +
          '<br><strong>Entries:</strong> ' + result.entryCount +
          '<pre>' + esc(formatXml(result.xml)) + '</pre></div>';
      } else {
        xmlapiSendResults.innerHTML = '<p class="text-danger">Preview failed: ' + esc(result.error || 'Unknown error') + '</p>';
      }
    } catch (e) {
      xmlapiSendResults.innerHTML = '<p class="text-danger">' + esc(e.message) + '</p>';
    }
  });

  // ── Send ────────────────────────────────────────────────────────────────────
  xmlapiSendBtn.addEventListener('click', async function () {
    var opts = getSendOpts(false);
    if (!opts.firewall) { xmlapiSendResults.innerHTML = '<p class="text-danger">Firewall IP is required.</p>'; return; }
    if (!opts.apiKey) { xmlapiSendResults.innerHTML = '<p class="text-danger">API Key is required.</p>'; return; }

    xmlapiSendBtn.disabled = true;
    xmlapiStatusBadge.textContent = 'SENDING';
    xmlapiStatusBadge.className = 'status-badge running';

    try {
      var result = await window.xmlapi.send(opts);
      if (result.ok) {
        xmlapiSendResults.innerHTML = '<p class="text-success">✅ ' + esc(opts.operation) + ' — ' + esc(result.response.status) + '</p>' +
          (result.response.message ? '<p>' + esc(result.response.message) + '</p>' : '') +
          '<pre>' + esc(formatXml(result.xml)) + '</pre>';
        addLogEntry({ operation: opts.operation, status: 'success', message: result.response.message });
      } else {
        xmlapiSendResults.innerHTML = '<p class="text-danger">❌ ' + esc(result.error || (result.response && result.response.message) || 'Failed') + '</p>' +
          (result.xml ? '<pre>' + esc(formatXml(result.xml)) + '</pre>' : '');
        addLogEntry({ operation: opts.operation, status: 'error', message: result.error || 'Failed' });
      }
    } catch (e) {
      xmlapiSendResults.innerHTML = '<p class="text-danger">❌ ' + esc(e.message) + '</p>';
      addLogEntry({ operation: opts.operation, status: 'error', message: e.message });
    }

    xmlapiSendBtn.disabled = false;
    xmlapiStatusBadge.textContent = 'IDLE';
    xmlapiStatusBadge.className = 'status-badge';
  });

  // ── Bulk Run ────────────────────────────────────────────────────────────────
  xmlapiBulkRunBtn.addEventListener('click', async function () {
    var fw = xmlapiBulkFirewall.value || xmlapiFirewall.value;
    var key = xmlapiBulkKey.value || xmlapiKey.value;
    if (!fw || !key) { xmlapiBulkResults.innerHTML = '<p class="text-danger">Firewall IP and API Key are required.</p>'; return; }

    running = true;
    xmlapiBulkRunBtn.disabled = true;
    xmlapiBulkStopBtn.disabled = false;
    xmlapiBulkProgressWrap.style.display = '';
    xmlapiStatusBadge.textContent = 'RUNNING';
    xmlapiStatusBadge.className = 'status-badge running';

    try {
      var result = await window.xmlapi.bulk({
        firewall: fw,
        apiKey: key,
        port: parseInt(xmlapiPort.value, 10) || 443,
        verifySSL: xmlapiVerifySSL.checked,
        operation: xmlapiBulkOperation.value,
        count: parseInt(xmlapiBulkCount.value, 10) || 100,
        usernamePattern: xmlapiBulkPattern.value || 'user{n}',
        baseIP: xmlapiBulkBaseIP.value || '10.0.0.1',
        domain: xmlapiBulkDomain.value || undefined,
        tags: xmlapiBulkTags.value || undefined,
        chunkDelay: parseInt(xmlapiBulkDelay.value, 10) || 200,
      });

      if (result.ok) {
        xmlapiBulkResults.innerHTML = '<p class="text-success">✅ Bulk complete — ' + result.requestsSent + ' requests, ' + result.totalEntries + ' entries</p>';
      } else {
        xmlapiBulkResults.innerHTML = '<p class="text-danger">❌ ' + esc(result.error || 'Failed') + '</p>' +
          (result.errors && result.errors.length > 0 ? '<ul>' + result.errors.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>' : '');
      }
      addLogEntry({ operation: 'bulk-' + xmlapiBulkOperation.value, status: result.ok ? 'success' : 'error', message: result.requestsSent + ' requests' });
    } catch (e) {
      xmlapiBulkResults.innerHTML = '<p class="text-danger">❌ ' + esc(e.message) + '</p>';
    }

    running = false;
    xmlapiBulkRunBtn.disabled = false;
    xmlapiBulkStopBtn.disabled = true;
    xmlapiStatusBadge.textContent = 'IDLE';
    xmlapiStatusBadge.className = 'status-badge';
  });

  xmlapiBulkStopBtn.addEventListener('click', function () {
    window.xmlapi.stop();
    xmlapiBulkStopBtn.disabled = true;
  });

  // ── Scenario Run ────────────────────────────────────────────────────────────
  xmlapiScenarioRunBtn.addEventListener('click', async function () {
    var fw = xmlapiScenarioFirewall.value || xmlapiFirewall.value;
    var key = xmlapiScenarioKey.value || xmlapiKey.value;
    if (!fw || !key) { xmlapiScenarioResults.innerHTML = '<p class="text-danger">Firewall IP and API Key are required.</p>'; return; }

    xmlapiScenarioRunBtn.disabled = true;
    xmlapiStatusBadge.textContent = 'RUNNING';
    xmlapiStatusBadge.className = 'status-badge running';

    var scenarioOpts = {
      firewall: fw,
      apiKey: key,
      port: parseInt(xmlapiPort.value, 10) || 443,
      verifySSL: xmlapiVerifySSL.checked,
      name: xmlapiScenarioName.value,
      numUsers: parseInt(xmlapiScenarioUsers.value, 10) || 5,
      count: parseInt(xmlapiScenarioUsers.value, 10) || 10,
      domain: xmlapiScenarioDomain.value || undefined,
      groupDn: xmlapiScenarioGroupDn.value || undefined,
      members: xmlapiScenarioMembers.value || undefined,
      tags: xmlapiScenarioTags.value || undefined,
    };

    try {
      var result = await window.xmlapi.scenario(scenarioOpts);
      if (result.ok) {
        var r = result.result;
        var html = '<p class="text-success">✅ Scenario: ' + esc(r.scenario) + ' — ' + esc(r.status) + '</p>';
        html += '<table class="result-table"><tbody>';
        html += '<tr><td>Requests Sent</td><td>' + r.requestsSent + '</td></tr>';
        if (r.loginCount > 0) html += '<tr><td>Logins</td><td>' + r.loginCount + '</td></tr>';
        if (r.logoutCount > 0) html += '<tr><td>Logouts</td><td>' + r.logoutCount + '</td></tr>';
        if (r.groupCount > 0) html += '<tr><td>Group Members</td><td>' + r.groupCount + '</td></tr>';
        if (r.tagRegisterCount > 0) html += '<tr><td>Tags Registered</td><td>' + r.tagRegisterCount + '</td></tr>';
        if (r.tagUnregisterCount > 0) html += '<tr><td>Tags Unregistered</td><td>' + r.tagUnregisterCount + '</td></tr>';
        html += '</tbody></table>';
        if (r.errors && r.errors.length > 0) {
          html += '<p class="text-danger">Errors:</p><ul>' + r.errors.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>';
        }
        if (r.details && r.details.tests) {
          html += '<h4>Edge Case Results</h4><table class="result-table"><thead><tr><th>Test</th><th>Result</th><th>Description</th></tr></thead><tbody>';
          r.details.tests.forEach(function (t) {
            html += '<tr><td>' + esc(t.name) + '</td><td>' + (t.passed ? '✅' : '❌') + '</td><td>' + esc(t.description) + '</td></tr>';
          });
          html += '</tbody></table>';
        }
        xmlapiScenarioResults.innerHTML = html;
        addLogEntry({ operation: 'scenario-' + r.scenario, status: r.status, message: r.requestsSent + ' requests' });
      } else {
        xmlapiScenarioResults.innerHTML = '<p class="text-danger">❌ ' + esc(result.error) + '</p>';
      }
    } catch (e) {
      xmlapiScenarioResults.innerHTML = '<p class="text-danger">❌ ' + esc(e.message) + '</p>';
    }

    xmlapiScenarioRunBtn.disabled = false;
    xmlapiStatusBadge.textContent = 'IDLE';
    xmlapiStatusBadge.className = 'status-badge';
  });

  // ── Progress listener ───────────────────────────────────────────────────────
  if (window.xmlapi && window.xmlapi.onProgress) {
    window.xmlapi.onProgress(function (info) {
      if (info && info.total > 0) {
        var pct = Math.round((info.current / info.total) * 100);
        if (xmlapiBulkProgressBar) {
          xmlapiBulkProgressBar.style.width = pct + '%';
          xmlapiBulkProgressText.textContent = info.phase + ': ' + info.current + '/' + info.total + ' (' + pct + '%)';
        }
      }
    });
  }

  // ── Log ─────────────────────────────────────────────────────────────────────
  function addLogEntry(entry) {
    var ts = new Date().toLocaleTimeString();
    logEntries.push({ ts: ts, ...entry });
    renderLog();
  }

  function renderLog() {
    if (!xmlapiLogContainer) return;
    xmlapiLogCount.textContent = String(logEntries.length);
    if (logEntries.length === 0) {
      xmlapiLogContainer.innerHTML = '<p class="text-muted">Send operations to see the log.</p>';
      return;
    }
    var html = '';
    for (var i = logEntries.length - 1; i >= 0; i--) {
      var e = logEntries[i];
      var cls = e.status === 'success' ? 'log-success' : (e.status === 'error' ? 'log-error' : 'log-info');
      html += '<div class="log-entry ' + cls + '">';
      html += '<span class="log-ts">' + esc(e.ts) + '</span> ';
      html += '<span class="log-op">[' + esc(e.operation) + ']</span> ';
      html += '<span class="log-status">' + esc(e.status) + '</span>';
      if (e.message) html += ' — ' + esc(e.message);
      html += '</div>';
    }
    xmlapiLogContainer.innerHTML = html;
  }

  if (xmlapiLogClearBtn) {
    xmlapiLogClearBtn.addEventListener('click', function () {
      logEntries = [];
      renderLog();
    });
  }

  // Also listen for log events from main process
  if (window.xmlapi && window.xmlapi.onLog) {
    window.xmlapi.onLog(function (entry) {
      addLogEntry(entry);
    });
  }

  // ── XML formatting helper ───────────────────────────────────────────────────
  function formatXml(xml) {
    if (!xml) return '';
    // Simple XML pretty-print
    var formatted = '';
    var indent = 0;
    var parts = xml.replace(/(>)(<)/g, '$1\n$2').split('\n');
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i].trim();
      if (!part) continue;
      if (part.match(/^<\//)) indent--;
      formatted += '  '.repeat(Math.max(0, indent)) + part + '\n';
      if (part.match(/^<[^/!?]/) && !part.match(/\/>$/) && !part.match(/<\/[^>]+>$/)) indent++;
    }
    return formatted.trim();
  }

})();
