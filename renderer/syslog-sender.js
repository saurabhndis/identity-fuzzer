(function () {
  'use strict';

  // ── Utility ─────────────────────────────────────────────────────────────────
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // ── Tab Switching (syslog page) ─────────────────────────────────────────────
  var syslogPage = document.getElementById('syslogPage');
  if (!syslogPage) return;

  syslogPage.querySelectorAll('.syslog-tabs .adsim-tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      var tabName = tab.dataset.tab;
      // Deactivate all tabs
      syslogPage.querySelectorAll('.syslog-tabs .adsim-tab').forEach(function (t) { t.classList.remove('active'); });
      syslogPage.querySelectorAll('.syslog-tab-content .adsim-panel').forEach(function (p) {
        p.style.display = 'none';
        p.classList.remove('active');
      });
      // Activate selected
      tab.classList.add('active');
      var panel = syslogPage.querySelector('[data-tab-panel="' + tabName + '"]');
      if (panel) {
        panel.style.display = '';
        panel.classList.add('active');
      }
    });
  });

  // ── State ───────────────────────────────────────────────────────────────────
  var logEntries = [];
  var running = false;

  // ── DOM References ──────────────────────────────────────────────────────────
  // Send tab
  var syslogFirewall = document.getElementById('syslogFirewall');
  var syslogTransport = document.getElementById('syslogTransport');
  var syslogPort = document.getElementById('syslogPort');
  var syslogSourceIP = document.getElementById('syslogSourceIP');
  var syslogCertFile = document.getElementById('syslogCertFile');
  var syslogKeyFile = document.getElementById('syslogKeyFile');
  var syslogVerifySSL = document.getElementById('syslogVerifySSL');
  var syslogUsername = document.getElementById('syslogUsername');
  var syslogIPAddress = document.getElementById('syslogIPAddress');
  var syslogEventType = document.getElementById('syslogEventType');
  var syslogDomain = document.getElementById('syslogDomain');
  var syslogTemplate = document.getElementById('syslogTemplate');
  var syslogCount = document.getElementById('syslogCount');
  var syslogInterval = document.getElementById('syslogInterval');
  var syslogSendBtn = document.getElementById('syslogSendBtn');
  var syslogPreviewBtn = document.getElementById('syslogPreviewBtn');
  var syslogSendResults = document.getElementById('syslogSendResults');
  var syslogStatusBadge = document.getElementById('syslogStatusBadge');

  // Stress tab
  var stressFirewall = document.getElementById('stressFirewall');
  var stressTransport = document.getElementById('stressTransport');
  var stressSenders = document.getElementById('stressSenders');
  var stressMessages = document.getElementById('stressMessages');
  var stressTemplate = document.getElementById('stressTemplate');
  var stressRate = document.getElementById('stressRate');
  var stressDomain = document.getElementById('stressDomain');
  var stressWhiteNoise = document.getElementById('stressWhiteNoise');
  var stressRunBtn = document.getElementById('stressRunBtn');
  var stressStopBtn = document.getElementById('stressStopBtn');
  var stressResults = document.getElementById('stressResults');
  var stressProgressWrap = document.getElementById('stressProgressWrap');
  var stressProgressBar = document.getElementById('stressProgressBar');
  var stressProgressText = document.getElementById('stressProgressText');

  // Scenario tab
  var scenarioFirewall = document.getElementById('scenarioFirewall');
  var scenarioTransport = document.getElementById('scenarioTransport');
  var scenarioName = document.getElementById('scenarioName');
  var scenarioUsers = document.getElementById('scenarioUsers');
  var scenarioDomain = document.getElementById('scenarioDomain');
  var scenarioNoLogout = document.getElementById('scenarioNoLogout');
  var scenarioRunBtn = document.getElementById('scenarioRunBtn');
  var scenarioResults = document.getElementById('scenarioResults');
  var scenarioUsersRow = document.getElementById('scenarioUsersRow');
  var scenarioLogoutRow = document.getElementById('scenarioLogoutRow');

  // Templates tab
  var templatesList = document.getElementById('templatesList');
  var templateCount = document.getElementById('templateCount');
  var profilesList = document.getElementById('profilesList');
  var profileCount = document.getElementById('profileCount');

  // Log tab
  var syslogLogContainer = document.getElementById('syslogLogContainer');
  var syslogLogCount = document.getElementById('syslogLogCount');
  var syslogLogClearBtn = document.getElementById('syslogLogClearBtn');

  // ── Helper: Get connection opts from Send tab ───────────────────────────────
  function getSendOpts() {
    return {
      firewall: syslogFirewall.value.trim(),
      transport: syslogTransport.value,
      port: syslogPort.value ? parseInt(syslogPort.value, 10) : null,
      sourceIP: syslogSourceIP.value.trim() || null,
      certFile: syslogCertFile.value.trim() || null,
      keyFile: syslogKeyFile.value.trim() || null,
      verifySSL: syslogVerifySSL.checked,
    };
  }

  // ── Helper: Set status badge ────────────────────────────────────────────────
  function setStatus(text, type) {
    syslogStatusBadge.textContent = text;
    syslogStatusBadge.className = 'badge' + (type ? ' badge-' + type : '');
  }

  // ── Helper: Add log entry ──────────────────────────────────────────────────
  function addLogEntry(entry) {
    logEntries.push(entry);
    var ts = new Date().toLocaleTimeString();
    var div = document.createElement('div');
    div.className = 'log-entry log-' + (entry.status || 'info');

    if (entry.status === 'sent') {
      div.textContent = '[' + ts + '] ✓ ' + entry.eventType + ': ' + entry.username + ' → ' + entry.ipAddress + ' (' + entry.bytes + ' bytes)';
    } else if (entry.status === 'error') {
      div.textContent = '[' + ts + '] ✗ Error: ' + entry.error;
    } else {
      div.textContent = '[' + ts + '] ' + JSON.stringify(entry);
    }

    // Check if placeholder text exists
    var placeholder = syslogLogContainer.querySelector('.text-muted');
    if (placeholder) placeholder.remove();

    syslogLogContainer.appendChild(div);
    syslogLogContainer.scrollTop = syslogLogContainer.scrollHeight;
    syslogLogCount.textContent = logEntries.length + ' messages';
  }

  // ── Event Listeners: Log ────────────────────────────────────────────────────
  window.syslog.onLog(function (entry) {
    addLogEntry(entry);
  });

  syslogLogClearBtn.addEventListener('click', function () {
    logEntries = [];
    syslogLogContainer.innerHTML = '<p class="text-muted">Send events to see the message log.</p>';
    syslogLogCount.textContent = '0 messages';
  });

  // ── Send Events ─────────────────────────────────────────────────────────────
  syslogSendBtn.addEventListener('click', async function () {
    var conn = getSendOpts();
    if (!conn.firewall) {
      syslogSendResults.innerHTML = '<p class="text-error">Please enter a firewall IP address.</p>';
      return;
    }

    setStatus('● Sending...', 'running');
    syslogSendBtn.disabled = true;
    syslogSendResults.innerHTML = '<p class="text-muted">Sending...</p>';

    try {
      var result = await window.syslog.send({
        ...conn,
        username: syslogUsername.value.trim(),
        ipAddress: syslogIPAddress.value.trim(),
        eventType: syslogEventType.value,
        domain: syslogDomain.value.trim() || null,
        template: syslogTemplate.value,
        count: parseInt(syslogCount.value, 10) || 1,
        interval: parseFloat(syslogInterval.value) || 0,
      });

      if (result.ok) {
        var html = '<div class="syslog-result-success">';
        html += '<div class="syslog-result-header">✓ Sent ' + result.sent + '/' + result.total + ' events via ' + conn.transport.toUpperCase() + ' to ' + esc(conn.firewall) + '</div>';
        html += '<div class="syslog-result-stat">Total bytes: ' + result.bytesSent + '</div>';
        if (result.results) {
          html += '<div class="syslog-result-list">';
          result.results.forEach(function (r) {
            var icon = r.status === 'sent' ? '✓' : '✗';
            var cls = r.status === 'sent' ? 'success' : 'error';
            html += '<div class="syslog-result-item syslog-' + cls + '">[' + r.index + '] ' + icon + ' ' + esc(r.eventType || '') + ': ' + esc(r.username || '') + ' → ' + esc(r.ipAddress || '') + '</div>';
          });
          html += '</div>';
        }
        html += '</div>';
        syslogSendResults.innerHTML = html;
        setStatus('● Connected', 'success');
      } else {
        syslogSendResults.innerHTML = '<p class="text-error">Error: ' + esc(result.error) + '</p>';
        setStatus('● Error', 'error');
      }
    } catch (e) {
      syslogSendResults.innerHTML = '<p class="text-error">Error: ' + esc(e.message) + '</p>';
      setStatus('● Error', 'error');
    } finally {
      syslogSendBtn.disabled = false;
    }
  });

  // ── Preview ─────────────────────────────────────────────────────────────────
  syslogPreviewBtn.addEventListener('click', async function () {
    var conn = getSendOpts();
    try {
      var result = await window.syslog.send({
        ...conn,
        firewall: conn.firewall || 'preview',
        username: syslogUsername.value.trim(),
        ipAddress: syslogIPAddress.value.trim(),
        eventType: syslogEventType.value,
        domain: syslogDomain.value.trim() || null,
        template: syslogTemplate.value,
        count: parseInt(syslogCount.value, 10) || 1,
        dryRun: true,
      });

      if (result.ok && result.dryRun) {
        var html = '<div class="syslog-preview">';
        html += '<div class="syslog-result-header">Preview — ' + result.count + ' message(s)</div>';
        result.messages.forEach(function (m) {
          html += '<div class="syslog-preview-msg"><code>' + esc(m.message) + '</code></div>';
        });
        html += '</div>';
        syslogSendResults.innerHTML = html;
      }
    } catch (e) {
      syslogSendResults.innerHTML = '<p class="text-error">Preview error: ' + esc(e.message) + '</p>';
    }
  });

  // ── Stress Test ─────────────────────────────────────────────────────────────
  stressRunBtn.addEventListener('click', async function () {
    var fw = stressFirewall.value.trim();
    if (!fw) {
      stressResults.innerHTML = '<p class="text-error">Please enter a firewall IP address.</p>';
      return;
    }

    running = true;
    stressRunBtn.disabled = true;
    stressStopBtn.disabled = false;
    stressProgressWrap.style.display = '';
    stressResults.innerHTML = '<p class="text-muted">Running stress test...</p>';
    setStatus('● Stress Test Running...', 'running');

    try {
      var result = await window.syslog.stress({
        firewall: fw,
        transport: stressTransport.value,
        senders: parseInt(stressSenders.value, 10) || 5,
        messages: parseInt(stressMessages.value, 10) || 100,
        template: stressTemplate.value,
        rate: parseFloat(stressRate.value) || 0,
        domain: stressDomain.value.trim() || null,
        whiteNoise: stressWhiteNoise.checked,
      });

      if (result.ok && result.result) {
        renderStressResult(result.result);
      } else {
        stressResults.innerHTML = '<p class="text-error">Error: ' + esc(result.error) + '</p>';
      }
    } catch (e) {
      stressResults.innerHTML = '<p class="text-error">Error: ' + esc(e.message) + '</p>';
    } finally {
      running = false;
      stressRunBtn.disabled = false;
      stressStopBtn.disabled = true;
      stressProgressWrap.style.display = 'none';
      setStatus('● Disconnected', '');
    }
  });

  stressStopBtn.addEventListener('click', function () {
    window.syslog.stop();
    stressStopBtn.disabled = true;
  });

  function renderStressResult(r) {
    var statusClass = r.status === 'passed' ? 'success' : 'error';
    var html = '<div class="syslog-result-' + statusClass + '">';
    html += '<div class="syslog-result-header">' + r.status.toUpperCase() + '</div>';
    html += '<div class="syslog-result-stat">Messages sent: ' + r.messagesSent + '/' + (r.details.totalExpected || '?') + '</div>';
    html += '<div class="syslog-result-stat">Duration: ' + r.durationSeconds.toFixed(2) + 's</div>';
    html += '<div class="syslog-result-stat">Throughput: ' + (r.details.messagesPerSecond || 0).toFixed(1) + ' msg/s</div>';
    html += '<div class="syslog-result-stat">Errors: ' + (r.errors ? r.errors.length : 0) + '</div>';

    if (r.details.senderStats && r.details.senderStats.length > 0) {
      html += '<div class="syslog-result-header" style="margin-top:8px;">Per-Sender Stats</div>';
      html += '<table class="results-table"><thead><tr><th>#</th><th>Type</th><th>Sent</th><th>Bytes</th><th>Errors</th><th>Duration</th><th>msg/s</th></tr></thead><tbody>';
      r.details.senderStats.forEach(function (s) {
        html += '<tr><td>' + s.id + '</td><td>' + esc(s.type) + '</td><td>' + s.sent + '</td><td>' + s.bytes + '</td><td>' + s.errors + '</td><td>' + s.duration.toFixed(3) + 's</td><td>' + s.msgPerSec.toFixed(1) + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    if (r.errors && r.errors.length > 0) {
      html += '<div class="syslog-result-header" style="margin-top:8px;color:var(--red);">Errors</div>';
      r.errors.slice(0, 10).forEach(function (e) {
        html += '<div class="syslog-result-item syslog-error">• ' + esc(e) + '</div>';
      });
      if (r.errors.length > 10) {
        html += '<div class="text-muted">... and ' + (r.errors.length - 10) + ' more</div>';
      }
    }

    html += '</div>';
    stressResults.innerHTML = html;
  }

  // ── Scenarios ───────────────────────────────────────────────────────────────
  scenarioName.addEventListener('change', function () {
    var isLoginLogout = scenarioName.value === 'login-logout';
    scenarioUsersRow.style.display = isLoginLogout ? '' : 'none';
    scenarioLogoutRow.style.display = isLoginLogout ? '' : 'none';
  });

  scenarioRunBtn.addEventListener('click', async function () {
    var fw = scenarioFirewall.value.trim();
    if (!fw) {
      scenarioResults.innerHTML = '<p class="text-error">Please enter a firewall IP address.</p>';
      return;
    }

    scenarioRunBtn.disabled = true;
    scenarioResults.innerHTML = '<p class="text-muted">Running scenario...</p>';
    setStatus('● Running Scenario...', 'running');

    try {
      var result = await window.syslog.scenario({
        firewall: fw,
        transport: scenarioTransport.value,
        name: scenarioName.value,
        users: parseInt(scenarioUsers.value, 10) || 10,
        domain: scenarioDomain.value.trim() || null,
        sendLogout: !scenarioNoLogout.checked,
      });

      if (result.ok && result.result) {
        renderScenarioResult(result.result);
      } else {
        scenarioResults.innerHTML = '<p class="text-error">Error: ' + esc(result.error) + '</p>';
      }
    } catch (e) {
      scenarioResults.innerHTML = '<p class="text-error">Error: ' + esc(e.message) + '</p>';
    } finally {
      scenarioRunBtn.disabled = false;
      setStatus('● Disconnected', '');
    }
  });

  function renderScenarioResult(r) {
    var statusClass = r.status === 'passed' ? 'success' : 'error';
    var html = '<div class="syslog-result-' + statusClass + '">';
    html += '<div class="syslog-result-header">' + esc(r.name) + ' — ' + r.status.toUpperCase() + '</div>';
    html += '<div class="syslog-result-stat">Messages sent: ' + r.messagesSent + '</div>';
    html += '<div class="syslog-result-stat">Duration: ' + r.durationSeconds.toFixed(2) + 's</div>';

    // Edge case test results
    if (r.details && r.details.tests) {
      html += '<div class="syslog-result-stat">Tests: ' + r.details.passed + '/' + r.details.totalTests + ' passed</div>';
      html += '<div class="syslog-edge-tests">';
      r.details.tests.forEach(function (t) {
        var icon = t.passed ? '<span class="syslog-pass">✓</span>' : '<span class="syslog-fail">✗</span>';
        html += '<div class="syslog-edge-test">' + icon + ' <strong>' + esc(t.name) + '</strong>: ' + esc(t.description) + '</div>';
      });
      html += '</div>';
    }

    if (r.errors && r.errors.length > 0) {
      html += '<div class="syslog-result-header" style="margin-top:8px;color:var(--red);">Errors</div>';
      r.errors.forEach(function (e) {
        html += '<div class="syslog-result-item syslog-error">• ' + esc(e) + '</div>';
      });
    }

    html += '</div>';
    scenarioResults.innerHTML = html;
  }

  // ── Templates & Profiles ────────────────────────────────────────────────────
  async function loadTemplatesAndProfiles() {
    try {
      var templates = await window.syslog.listTemplates();
      templateCount.textContent = templates.length + ' templates';
      templatesList.innerHTML = '';
      templates.forEach(function (t) {
        var tr = document.createElement('tr');
        tr.innerHTML =
          '<td><strong>' + esc(t.name) + '</strong></td>' +
          '<td>' + esc(t.eventType) + '</td>' +
          '<td><code>' + esc(t.compatibleProfile) + '</code></td>' +
          '<td>' + esc(t.description) + '</td>' +
          '<td><code class="syslog-example">' + esc(t.example) + '</code></td>';
        templatesList.appendChild(tr);
      });

      var profiles = await window.syslog.listProfiles();
      profileCount.textContent = profiles.length + ' profiles';
      profilesList.innerHTML = '';
      profiles.forEach(function (p) {
        var tr = document.createElement('tr');
        tr.innerHTML =
          '<td><strong>' + esc(p.name) + '</strong></td>' +
          '<td>' + esc(p.profileType) + '</td>' +
          '<td>' + esc(p.eventType) + '</td>' +
          '<td><code>' + esc(p.eventString) + '</code></td>' +
          '<td>' + esc(p.description) + '</td>';
        profilesList.appendChild(tr);
      });
    } catch (e) {
      console.error('Failed to load templates/profiles:', e);
    }
  }

  // ── Populate template dropdown dynamically ──────────────────────────────────
  async function populateTemplateDropdown() {
    try {
      var templates = await window.syslog.listTemplates();
      syslogTemplate.innerHTML = '';
      templates.forEach(function (t) {
        var opt = document.createElement('option');
        opt.value = t.name;
        opt.textContent = t.name + ' (' + t.eventType + ')';
        syslogTemplate.appendChild(opt);
      });
    } catch (e) {
      console.error('Failed to populate template dropdown:', e);
    }
  }

  // ── Progress listener ───────────────────────────────────────────────────────
  window.syslog.onProgress(function (info) {
    if (info.phase === 'done') return;

    // Update stress progress bar
    if (stressProgressWrap.style.display !== 'none' && info.senderId !== undefined) {
      // Approximate progress
      var total = parseInt(stressSenders.value, 10) * parseInt(stressMessages.value, 10);
      // We don't have exact count, so just show activity
      stressProgressText.textContent = 'Sender ' + info.senderId + ' active...';
    }
  });

  // ── Init ────────────────────────────────────────────────────────────────────
  populateTemplateDropdown();
  loadTemplatesAndProfiles();

})();
