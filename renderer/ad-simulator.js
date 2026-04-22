(function () {
  'use strict';

  // ── Utility Functions ──────────────────────────────────────────────────────
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  function showToast(message, type) {
    type = type || 'info';
    console.log('[AD Sim ' + type + ']', message);
    // Brief visual feedback via the status badge area
    var badge = document.getElementById('adSimStatusBadge');
    if (type === 'error') {
      var prev = badge.textContent;
      var prevClass = badge.className;
      badge.textContent = '✖ ' + message;
      badge.className = 'badge badge-error';
      setTimeout(function () {
        if (badge.textContent === '✖ ' + message) {
          badge.textContent = prev;
          badge.className = prevClass;
        }
      }, 6000);
    }
    // Also append to the error log area
    appendErrorLog(message, type);
  }

  function appendErrorLog(message, type) {
    var errorLog = document.getElementById('adSimErrorLog');
    if (!errorLog) return;
    var ts = new Date().toLocaleTimeString();
    var prefix = type === 'error' ? '❌' : type === 'warn' ? '⚠️' : 'ℹ️';
    var entry = document.createElement('div');
    entry.className = 'error-log-entry error-log-' + type;
    entry.textContent = '[' + ts + '] ' + prefix + ' ' + message;
    errorLog.appendChild(entry);
    errorLog.scrollTop = errorLog.scrollHeight;
    // Show the error log container
    var container = document.getElementById('adSimErrorLogContainer');
    if (container) container.style.display = 'block';
  }

  function setButtonsEnabled(enabled) {
    var btns = [
      'adSimStopBtn', 'adSimSeedBtn', 'adSimSaveBtn', 'adSimLoadBtn',
      'adSimAddUserBtn', 'adSimRefreshTreeBtn', 'adSimAddGroupBtn',
      'adSimRefreshGroupsBtn', 'adSimAddMemberBtn', 'adSimRemoveMemberBtn',
      'adSimFuzzRunBtn', 'adSimFuzzRefreshBtn', 'adSimLogRefreshBtn',
      'adSimTreeAddGroupBtn'
    ];
    btns.forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.disabled = !enabled;
    });
    var startBtn = document.getElementById('adSimStartBtn');
    if (startBtn) startBtn.disabled = enabled;
  }

  // ── State ──────────────────────────────────────────────────────────────────
  var serverRunning = false;
  var serverConfig = {};

  // ── DOM References — Pages & Nav ───────────────────────────────────────────
  var navBtns = document.querySelectorAll('.nav-btn');
  var ldapPage = document.getElementById('ldapPage');
  var adsimPage = document.getElementById('adsimPage');
  var syslogPage = document.getElementById('syslogPage');

  // ── DOM References — Tabs (scoped to adsim page only) ─────────────────────
  var tabs = adsimPage.querySelectorAll('.adsim-tabs .adsim-tab');
  var tabPanels = adsimPage.querySelectorAll('.adsim-tab-content .adsim-panel');

  // ── DOM References — Server Control ────────────────────────────────────────
  var adSimStartBtn = document.getElementById('adSimStartBtn');
  var adSimStopBtn = document.getElementById('adSimStopBtn');
  var adSimStatusBadge = document.getElementById('adSimStatusBadge');
  var adSimInfo = document.getElementById('adSimInfo');

  // Config inputs
  var adSimDomain = document.getElementById('adSimDomain');
  var adSimBaseDn = document.getElementById('adSimBaseDn');
  var adSimPort = document.getElementById('adSimPort');
  var adSimSslPort = document.getElementById('adSimSslPort');
  var adSimAdminPw = document.getElementById('adSimAdminPw');

  // Seed
  var adSimSeedBtn = document.getElementById('adSimSeedBtn');
  var adSimSeedCount = document.getElementById('adSimSeedCount');

  // Save / Load
  var adSimSaveBtn = document.getElementById('adSimSaveBtn');
  var adSimLoadBtn = document.getElementById('adSimLoadBtn');

  // ── DOM References — Directory Browser (Tree View) ─────────────────────────
  var adSimRefreshTreeBtn = document.getElementById('adSimRefreshTreeBtn');
  var adSimCollapseAllBtn = document.getElementById('adSimCollapseAllBtn');
  var adSimExpandAllBtn = document.getElementById('adSimExpandAllBtn');
  var adSimTreeContainer = document.getElementById('adSimTreeContainer');
  var adSimDetailTitle = document.getElementById('adSimDetailTitle');
  var adSimDetailsContainer = document.getElementById('adSimDetailsContainer');
  var adSimTreeAddUserSection = document.getElementById('adSimTreeAddUserSection');
  var adSimTreeAddGroupSection = document.getElementById('adSimTreeAddGroupSection');
  var adSimAddUserBtn = document.getElementById('adSimAddUserBtn');
  var adSimNewUserCn = document.getElementById('adSimNewUserCn');
  var adSimNewUserSam = document.getElementById('adSimNewUserSam');
  var adSimNewUserEmail = document.getElementById('adSimNewUserEmail');
  var adSimNewUserUpn = document.getElementById('adSimNewUserUpn');
  var adSimNewUserPw = document.getElementById('adSimNewUserPw');
  var adSimNewUserOu = document.getElementById('adSimNewUserOu');
  var adSimNewUserCA1Name = document.getElementById('adSimNewUserCA1Name');
  var adSimNewUserCA1Value = document.getElementById('adSimNewUserCA1Value');
  var adSimNewUserCA2Name = document.getElementById('adSimNewUserCA2Name');
  var adSimNewUserCA2Value = document.getElementById('adSimNewUserCA2Value');
  var adSimTreeAddGroupBtn = document.getElementById('adSimTreeAddGroupBtn');
  var adSimTreeNewGroupName = document.getElementById('adSimTreeNewGroupName');
  var adSimTreeNewGroupEmail = document.getElementById('adSimTreeNewGroupEmail');
  var adSimTreeNewGroupOu = document.getElementById('adSimTreeNewGroupOu');

  // ── DOM References — Groups ────────────────────────────────────────────────
  var adSimRefreshGroupsBtn = document.getElementById('adSimRefreshGroupsBtn');
  var adSimGroupsList = document.getElementById('adSimGroupsList');
  var adSimAddGroupBtn = document.getElementById('adSimAddGroupBtn');
  var adSimNewGroupName = document.getElementById('adSimNewGroupName');
  var adSimNewGroupOu = document.getElementById('adSimNewGroupOu');
  var adSimAddMemberBtn = document.getElementById('adSimAddMemberBtn');
  var adSimRemoveMemberBtn = document.getElementById('adSimRemoveMemberBtn');
  var adSimMemberGroupDn = document.getElementById('adSimMemberGroupDn');
  var adSimMemberUserDn = document.getElementById('adSimMemberUserDn');

  // ── DOM References — Fuzzer ────────────────────────────────────────────────
  var adSimFuzzRefreshBtn = document.getElementById('adSimFuzzRefreshBtn');
  var adSimFuzzSelectAll = document.getElementById('adSimFuzzSelectAll');
  var adSimFuzzScenariosList = document.getElementById('adSimFuzzScenariosList');
  var adSimFuzzRunBtn = document.getElementById('adSimFuzzRunBtn');
  var adSimFuzzProgress = document.getElementById('adSimFuzzProgress');
  var adSimFuzzProgressFill = document.getElementById('adSimFuzzProgressFill');
  var adSimFuzzProgressText = document.getElementById('adSimFuzzProgressText');
  var adSimFuzzResultsList = document.getElementById('adSimFuzzResultsList');

  // ── DOM References — Log ───────────────────────────────────────────────────
  var adSimLogRefreshBtn = document.getElementById('adSimLogRefreshBtn');
  var adSimLogClearBtn = document.getElementById('adSimLogClearBtn');
  var adSimLogContainer = document.getElementById('adSimLogContainer');

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. Page Navigation (Sidebar Switching)
  // ═══════════════════════════════════════════════════════════════════════════
  navBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (btn.classList.contains('disabled')) return;

      var page = btn.dataset.page;
      var allPages = [ldapPage, adsimPage, syslogPage];

      // Update active button
      navBtns.forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');

      // Hide all pages
      allPages.forEach(function (p) {
        if (p) { p.style.display = 'none'; p.classList.remove('active'); }
      });

      // Show selected page
      if (page === 'ldap' && ldapPage) {
        ldapPage.style.display = '';
        ldapPage.classList.add('active');
      } else if (page === 'adsim' && adsimPage) {
        adsimPage.style.display = '';
        adsimPage.classList.add('active');
      } else if (page === 'syslog' && syslogPage) {
        syslogPage.style.display = '';
        syslogPage.classList.add('active');
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. Tab Navigation
  // ═══════════════════════════════════════════════════════════════════════════
  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      var targetTab = tab.dataset.tab;

      tabs.forEach(function (t) { t.classList.remove('active'); });
      tab.classList.add('active');

      tabPanels.forEach(function (panel) {
        if (panel.dataset.tabPanel === targetTab) {
          panel.style.display = '';
          panel.classList.add('active');
        } else {
          panel.style.display = 'none';
          panel.classList.remove('active');
        }
      });
    });
  });

  // ── Error Log Controls ──────────────────────────────────────────────────────
  var clearErrorLogBtn = document.getElementById('adSimClearErrorLog');
  var copyErrorLogBtn = document.getElementById('adSimCopyErrorLog');
  var toggleErrorLogBtn = document.getElementById('adSimToggleErrorLog');
  var errorLogBody = document.getElementById('adSimErrorLog');
  var errorLogContainer = document.getElementById('adSimErrorLogContainer');

  if (clearErrorLogBtn) {
    clearErrorLogBtn.addEventListener('click', function () {
      if (errorLogBody) errorLogBody.innerHTML = '';
    });
  }
  if (copyErrorLogBtn) {
    copyErrorLogBtn.addEventListener('click', function () {
      if (errorLogBody) {
        var text = errorLogBody.innerText || errorLogBody.textContent;
        navigator.clipboard.writeText(text).then(function () {
          copyErrorLogBtn.textContent = 'Copied!';
          setTimeout(function () { copyErrorLogBtn.textContent = 'Copy'; }, 2000);
        });
      }
    });
  }
  if (toggleErrorLogBtn) {
    toggleErrorLogBtn.addEventListener('click', function () {
      if (errorLogBody) {
        var hidden = errorLogBody.style.display === 'none';
        errorLogBody.style.display = hidden ? '' : 'none';
        toggleErrorLogBtn.textContent = hidden ? 'Hide' : 'Show';
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. Server Control
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Start Server ───────────────────────────────────────────────────────────
  adSimStartBtn.addEventListener('click', async function () {
    var config = {
      domain: adSimDomain.value.trim(),
      base_dn: adSimBaseDn.value.trim(),
      port: parseInt(adSimPort.value, 10) || 10389,
      ssl_port: parseInt(adSimSslPort.value, 10) || 10636,
      admin_password: adSimAdminPw.value
    };

    adSimStartBtn.disabled = true;
    adSimStatusBadge.textContent = '● Starting...';
    adSimStatusBadge.className = 'badge badge-warning';

    try {
      var result = await window.adSim.start(config);
      if (!result.ok) {
        showToast(result.error || 'Failed to start server', 'error');
        adSimStatusBadge.textContent = '● Error';
        adSimStatusBadge.className = 'badge badge-error';
        adSimStartBtn.disabled = false;
        return;
      }

      serverRunning = true;
      serverConfig = config;

      adSimStatusBadge.textContent = '● Running on port ' + config.port;
      adSimStatusBadge.className = 'badge badge-success';
      setButtonsEnabled(true);

      // Show server info
      var data = result.data || {};
      adSimInfo.innerHTML =
        '<div class="info-grid">' +
          '<div class="info-item"><span class="info-label">Domain:</span> <span class="info-value">' + esc(config.domain) + '</span></div>' +
          '<div class="info-item"><span class="info-label">LDAP Port:</span> <span class="info-value">' + esc(String(config.port)) + '</span></div>' +
          '<div class="info-item"><span class="info-label">LDAPS Port:</span> <span class="info-value">' + esc(String(config.ssl_port)) + '</span></div>' +
          '<div class="info-item"><span class="info-label">Base DN:</span> <span class="info-value">' + esc(config.base_dn) + '</span></div>' +
          '<div class="info-item"><span class="info-label">Admin DN:</span> <span class="info-value">CN=Administrator,CN=Users,' + esc(config.base_dn) + '</span></div>' +
          '<div class="info-item"><span class="info-label">Status:</span> <span class="info-value">' + esc(data.status || 'running') + '</span></div>' +
        '</div>';

      // Auto-refresh tree and groups after server start
      refreshTree();
      refreshGroups();

    } catch (err) {
      showToast(err.message || 'Failed to start server', 'error');
      adSimStatusBadge.textContent = '● Error';
      adSimStatusBadge.className = 'badge badge-error';
      adSimStartBtn.disabled = false;
    }
  });

  // ── Stop Server ────────────────────────────────────────────────────────────
  adSimStopBtn.addEventListener('click', async function () {
    adSimStopBtn.disabled = true;
    adSimStatusBadge.textContent = '● Stopping...';
    adSimStatusBadge.className = 'badge badge-warning';

    try {
      var result = await window.adSim.stop();
      if (!result.ok) {
        showToast(result.error || 'Failed to stop server', 'error');
        adSimStopBtn.disabled = false;
        return;
      }

      serverRunning = false;
      serverConfig = {};

      adSimStatusBadge.textContent = '● Stopped';
      adSimStatusBadge.className = 'badge';
      setButtonsEnabled(false);

      adSimInfo.innerHTML = '<p class="text-muted">Start the server to see connection details.</p>';

    } catch (err) {
      showToast(err.message || 'Failed to stop server', 'error');
      adSimStopBtn.disabled = false;
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. Seed Directory
  // ═══════════════════════════════════════════════════════════════════════════
  adSimSeedBtn.addEventListener('click', async function () {
    var count = parseInt(adSimSeedCount.value, 10) || 50;
    adSimSeedBtn.disabled = true;

    try {
      var result = await window.adSim.seed(count);
      if (!result.ok) {
        showToast(result.error || 'Seed failed', 'error');
        adSimSeedBtn.disabled = false;
        return;
      }
      showToast('Seeded ' + count + ' users successfully', 'info');
      adSimSeedBtn.disabled = false;
      // Auto-refresh tree
      refreshTree();
    } catch (err) {
      showToast(err.message || 'Seed failed', 'error');
      adSimSeedBtn.disabled = false;
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. Save / Load State
  // ═══════════════════════════════════════════════════════════════════════════
  adSimSaveBtn.addEventListener('click', async function () {
    adSimSaveBtn.disabled = true;
    try {
      var result = await window.adSim.save('ad_state.json');
      if (!result.ok) {
        showToast(result.error || 'Save failed', 'error');
      } else {
        showToast('State saved to ad_state.json', 'info');
      }
    } catch (err) {
      showToast(err.message || 'Save failed', 'error');
    }
    if (serverRunning) adSimSaveBtn.disabled = false;
  });

  adSimLoadBtn.addEventListener('click', async function () {
    adSimLoadBtn.disabled = true;
    try {
      var result = await window.adSim.load('ad_state.json');
      if (!result.ok) {
        showToast(result.error || 'Load failed', 'error');
      } else {
        showToast('State loaded from ad_state.json', 'info');
        refreshTree();
        refreshGroups();
      }
    } catch (err) {
      showToast(err.message || 'Load failed', 'error');
    }
    if (serverRunning) adSimLoadBtn.disabled = false;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. Directory Browser — Tree View
  // ═══════════════════════════════════════════════════════════════════════════

  var selectedTreeNode = null; // Currently selected node data
  var treeData = null;         // Full tree data from backend

  // ── Icon helpers ────────────────────────────────────────────────────────────
  var typeIcons = {
    domain: '🏢',
    ou: '📁',
    container: '📁',
    user: '👤',
    group: '👥',
    other: '📄'
  };

  function getIcon(type) {
    return typeIcons[type] || '📄';
  }

  function isContainer(type) {
    return type === 'domain' || type === 'ou' || type === 'container';
  }

  // ── Render Tree ─────────────────────────────────────────────────────────────
  function renderTreeNode(node, depth) {
    depth = depth || 0;
    var hasChildren = node.children && node.children.length > 0;
    var isExpanded = true; // default expanded for first 2 levels
    if (depth >= 2) isExpanded = false;

    var li = document.createElement('li');
    li.className = 'tree-node';
    li.dataset.dn = node.dn || '';
    li.dataset.type = node.type || 'other';

    // Node row
    var row = document.createElement('div');
    row.className = 'tree-node-row';
    row.style.paddingLeft = (depth * 18 + 4) + 'px';

    // Chevron (expand/collapse)
    var chevron = document.createElement('span');
    chevron.className = 'tree-chevron';
    if (hasChildren) {
      chevron.textContent = isExpanded ? '▼' : '▶';
      chevron.classList.add('has-children');
    } else {
      chevron.textContent = ' ';
    }
    row.appendChild(chevron);

    // Icon
    var icon = document.createElement('span');
    icon.className = 'tree-icon';
    icon.textContent = getIcon(node.type);
    row.appendChild(icon);

    // Label
    var label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = node.name || '';
    label.title = node.dn || '';
    row.appendChild(label);

    // Count badge for containers
    if (hasChildren && isContainer(node.type)) {
      var badge = document.createElement('span');
      badge.className = 'tree-count';
      badge.textContent = node.children.length;
      row.appendChild(badge);
    }

    li.appendChild(row);

    // Children container
    if (hasChildren) {
      var childUl = document.createElement('ul');
      childUl.className = 'tree-children';
      if (!isExpanded) childUl.style.display = 'none';

      node.children.forEach(function (child) {
        childUl.appendChild(renderTreeNode(child, depth + 1));
      });
      li.appendChild(childUl);
    }

    // Click handlers
    chevron.addEventListener('click', function (e) {
      e.stopPropagation();
      if (!hasChildren) return;
      var childList = li.querySelector(':scope > .tree-children');
      if (childList) {
        var hidden = childList.style.display === 'none';
        childList.style.display = hidden ? '' : 'none';
        chevron.textContent = hidden ? '▼' : '▶';
      }
    });

    row.addEventListener('click', function (e) {
      e.stopPropagation();
      // Deselect previous
      var prev = adSimTreeContainer.querySelector('.tree-node-row.selected');
      if (prev) prev.classList.remove('selected');
      // Select this
      row.classList.add('selected');
      selectedTreeNode = node;
      showNodeDetails(node);
    });

    return li;
  }

  // ── Refresh Tree ────────────────────────────────────────────────────────────
  async function refreshTree() {
    try {
      var result = await window.adSim.listTree();
      if (!result.ok) {
        showToast(result.error || 'Failed to load directory tree', 'error');
        return;
      }
      var data = result.data || {};
      treeData = data.tree;

      adSimTreeContainer.innerHTML = '';

      if (!treeData) {
        adSimTreeContainer.innerHTML = '<p class="text-muted" style="padding:12px;">No directory data available.</p>';
        return;
      }

      var ul = document.createElement('ul');
      ul.className = 'tree-root';
      ul.appendChild(renderTreeNode(treeData, 0));
      adSimTreeContainer.appendChild(ul);

      // Reset details panel
      selectedTreeNode = null;
      adSimDetailTitle.textContent = 'Details';
      adSimDetailsContainer.innerHTML = '<p class="text-muted" style="padding:12px;">Select a node in the tree to view details.</p>';
      adSimTreeAddUserSection.style.display = 'none';
      adSimTreeAddGroupSection.style.display = 'none';

    } catch (err) {
      showToast(err.message || 'Failed to load directory tree', 'error');
    }
  }

  adSimRefreshTreeBtn.addEventListener('click', refreshTree);

  // ── Collapse / Expand All ───────────────────────────────────────────────────
  adSimCollapseAllBtn.addEventListener('click', function () {
    adSimTreeContainer.querySelectorAll('.tree-children').forEach(function (ul) {
      ul.style.display = 'none';
    });
    adSimTreeContainer.querySelectorAll('.tree-chevron.has-children').forEach(function (ch) {
      ch.textContent = '▶';
    });
  });

  adSimExpandAllBtn.addEventListener('click', function () {
    adSimTreeContainer.querySelectorAll('.tree-children').forEach(function (ul) {
      ul.style.display = '';
    });
    adSimTreeContainer.querySelectorAll('.tree-chevron.has-children').forEach(function (ch) {
      ch.textContent = '▼';
    });
  });

  // ── Show Node Details ───────────────────────────────────────────────────────
  function showNodeDetails(node) {
    adSimDetailTitle.textContent = getIcon(node.type) + ' ' + (node.name || 'Unknown');

    var html = '<div class="node-details">';
    html += '<div class="detail-row"><span class="detail-label">DN:</span> <span class="detail-value detail-dn">' + esc(node.dn || '') + '</span></div>';
    html += '<div class="detail-row"><span class="detail-label">Type:</span> <span class="detail-value">' + esc(node.type || '') + '</span></div>';
    html += '<div class="detail-row"><span class="detail-label">Name:</span> <span class="detail-value">' + esc(node.name || '') + '</span></div>';

    if (node.type === 'user') {
      if (node.sam_account_name) {
        html += '<div class="detail-row"><span class="detail-label">SAM Account:</span> <span class="detail-value">' + esc(node.sam_account_name) + '</span></div>';
      }
      if (node.display_name) {
        html += '<div class="detail-row"><span class="detail-label">Display Name:</span> <span class="detail-value">' + esc(node.display_name) + '</span></div>';
      }
      if (node.email) {
        html += '<div class="detail-row"><span class="detail-label">Email:</span> <span class="detail-value">' + esc(node.email) + '</span></div>';
      }
      // Change password form
      html += '<div class="detail-password-section" style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);">';
      html += '<div class="detail-row"><span class="detail-label" style="font-weight:600;">Change Password:</span></div>';
      html += '<div style="display:flex;gap:6px;align-items:center;margin-top:4px;">';
      html += '<input type="password" id="adSimTreeNewPassword" class="input" placeholder="New password" style="flex:1;font-size:12px;padding:4px 8px;" />';
      html += '<button class="small-btn" id="adSimTreeSetPwBtn">🔑 Set</button>';
      html += '</div>';
      html += '</div>';
      // Delete button for users
      html += '<div class="detail-actions"><button class="small-btn btn-danger" id="adSimTreeDeleteUserBtn">🗑 Delete User</button></div>';
    }

    if (node.type === 'group') {
      if (node.sam_account_name) {
        html += '<div class="detail-row"><span class="detail-label">SAM Account:</span> <span class="detail-value">' + esc(node.sam_account_name) + '</span></div>';
      }
      html += '<div class="detail-row"><span class="detail-label">Members:</span> <span class="detail-value">' + esc(String(node.member_count || 0)) + '</span></div>';
    }

    if (isContainer(node.type) && node.children) {
      var userCount = 0, groupCount = 0, ouCount = 0;
      node.children.forEach(function (c) {
        if (c.type === 'user') userCount++;
        else if (c.type === 'group') groupCount++;
        else if (c.type === 'ou' || c.type === 'container') ouCount++;
      });
      html += '<div class="detail-row"><span class="detail-label">Contents:</span> <span class="detail-value">';
      var parts = [];
      if (ouCount > 0) parts.push(ouCount + ' container(s)');
      if (groupCount > 0) parts.push(groupCount + ' group(s)');
      if (userCount > 0) parts.push(userCount + ' user(s)');
      html += parts.length > 0 ? esc(parts.join(', ')) : 'Empty';
      html += '</span></div>';

      // Children table
      if (node.children.length > 0) {
        html += '<div class="detail-children-table"><table class="results-table"><thead><tr><th></th><th>Name</th><th>Type</th><th>Actions</th></tr></thead><tbody>';
        node.children.forEach(function (child) {
          html += '<tr>';
          html += '<td>' + getIcon(child.type) + '</td>';
          html += '<td title="' + esc(child.dn || '') + '">' + esc(child.name || '') + '</td>';
          html += '<td>' + esc(child.type || '') + '</td>';
          html += '<td>';
          if (child.type === 'user' || child.type === 'group') {
            html += '<button class="small-btn btn-danger tree-delete-entry" data-dn="' + esc(child.dn || '') + '" data-type="' + esc(child.type) + '">🗑</button>';
          }
          html += '</td>';
          html += '</tr>';
        });
        html += '</tbody></table></div>';
      }
    }

    html += '</div>';
    adSimDetailsContainer.innerHTML = html;

    // Show/hide add forms based on node type
    if (isContainer(node.type)) {
      // Determine the OU/container path relative to base DN
      var containerDn = node.dn || '';
      // Extract the part before the base DN for the OU parameter
      var ouPath = extractOuPath(containerDn);

      adSimNewUserOu.value = ouPath;
      adSimTreeNewGroupOu.value = ouPath;
      adSimTreeAddUserSection.style.display = '';
      adSimTreeAddGroupSection.style.display = '';
    } else {
      adSimTreeAddUserSection.style.display = 'none';
      adSimTreeAddGroupSection.style.display = 'none';
    }

    // Attach delete handlers
    var deleteUserBtn = document.getElementById('adSimTreeDeleteUserBtn');
    if (deleteUserBtn) {
      deleteUserBtn.addEventListener('click', function () {
        deleteEntry(node.dn, 'user');
      });
    }

    // Attach set password handler
    var setPwBtn = document.getElementById('adSimTreeSetPwBtn');
    if (setPwBtn) {
      setPwBtn.addEventListener('click', async function () {
        var pwInput = document.getElementById('adSimTreeNewPassword');
        var newPw = pwInput ? pwInput.value : '';
        if (!newPw) {
          showToast('Please enter a new password', 'error');
          return;
        }
        setPwBtn.disabled = true;
        try {
          var result = await window.adSim.setPassword({ dn: node.dn, password: newPw });
          if (!result.ok) {
            showToast(result.error || 'Failed to set password', 'error');
          } else {
            showToast('Password changed for ' + (node.sam_account_name || node.name), 'info');
            if (pwInput) pwInput.value = '';
          }
        } catch (err) {
          showToast(err.message || 'Failed to set password', 'error');
        }
        setPwBtn.disabled = false;
      });
    }

    adSimDetailsContainer.querySelectorAll('.tree-delete-entry').forEach(function (btn) {
      btn.addEventListener('click', function () {
        deleteEntry(btn.dataset.dn, btn.dataset.type);
      });
    });
  }

  // ── Extract OU path from DN ─────────────────────────────────────────────────
  function extractOuPath(dn) {
    // Given a full DN like "CN=Users,DC=testlab,DC=local" or "OU=Engineering,DC=testlab,DC=local"
    // We need to extract the relative path for the add-user/add-group 'ou' parameter
    // The bridge expects something like "CN=Users" or "OU=Engineering"
    if (!dn) return '';

    // Split on comma, find the parts before DC= components
    var parts = dn.split(',');
    var ouParts = [];
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (p.toUpperCase().startsWith('DC=')) break;
      ouParts.push(p);
    }
    return ouParts.join(',');
  }

  // ── Delete Entry ────────────────────────────────────────────────────────────
  async function deleteEntry(dn, type) {
    if (!dn) return;
    try {
      var result = await window.adSim.deleteUser(dn);
      if (!result.ok) {
        showToast(result.error || 'Failed to delete ' + type, 'error');
        return;
      }
      showToast((type === 'user' ? 'User' : 'Entry') + ' deleted', 'info');
      refreshTree();
    } catch (err) {
      showToast(err.message || 'Failed to delete ' + type, 'error');
    }
  }

  // ── Add User (Tree View) ───────────────────────────────────────────────────
  adSimAddUserBtn.addEventListener('click', async function () {
    var userData = {
      cn: adSimNewUserCn.value.trim(),
      sam_account_name: adSimNewUserSam.value.trim(),
      password: adSimNewUserPw.value,
      ou: adSimNewUserOu.value.trim() || undefined,
      email: adSimNewUserEmail.value.trim() || undefined,
      upn_format: adSimNewUserUpn.value.trim() || undefined,
      custom_attr1_name: adSimNewUserCA1Name.value.trim() || undefined,
      custom_attr1_value: adSimNewUserCA1Value.value.trim() || undefined,
      custom_attr2_name: adSimNewUserCA2Name.value.trim() || undefined,
      custom_attr2_value: adSimNewUserCA2Value.value.trim() || undefined
    };

    if (!userData.cn || !userData.sam_account_name) {
      showToast('Common Name and SAM Account Name are required', 'error');
      return;
    }

    adSimAddUserBtn.disabled = true;
    try {
      var result = await window.adSim.addUser(userData);
      if (!result.ok) {
        showToast(result.error || 'Failed to add user', 'error');
        adSimAddUserBtn.disabled = false;
        return;
      }

      // Clear form
      adSimNewUserCn.value = '';
      adSimNewUserSam.value = '';
      adSimNewUserEmail.value = '';
      adSimNewUserUpn.value = '';
      adSimNewUserPw.value = 'Password123!';
      adSimNewUserCA1Name.value = '';
      adSimNewUserCA1Value.value = '';
      adSimNewUserCA2Name.value = '';
      adSimNewUserCA2Value.value = '';

      showToast('User added successfully', 'info');
      adSimAddUserBtn.disabled = false;
      refreshTree();
    } catch (err) {
      showToast(err.message || 'Failed to add user', 'error');
      adSimAddUserBtn.disabled = false;
    }
  });

  // ── Add Group (Tree View) ──────────────────────────────────────────────────
  adSimTreeAddGroupBtn.addEventListener('click', async function () {
    var groupData = {
      name: adSimTreeNewGroupName.value.trim(),
      ou: adSimTreeNewGroupOu.value.trim() || undefined,
      email: adSimTreeNewGroupEmail.value.trim() || undefined
    };

    if (!groupData.name) {
      showToast('Group name is required', 'error');
      return;
    }

    adSimTreeAddGroupBtn.disabled = true;
    try {
      var result = await window.adSim.addGroup(groupData);
      if (!result.ok) {
        showToast(result.error || 'Failed to add group', 'error');
        adSimTreeAddGroupBtn.disabled = false;
        return;
      }

      adSimTreeNewGroupName.value = '';
      adSimTreeNewGroupEmail.value = '';
      showToast('Group added successfully', 'info');
      adSimTreeAddGroupBtn.disabled = false;
      refreshTree();
    } catch (err) {
      showToast(err.message || 'Failed to add group', 'error');
      adSimTreeAddGroupBtn.disabled = false;
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. Groups Tab
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Refresh Groups ─────────────────────────────────────────────────────────
  async function refreshGroups() {
    try {
      var result = await window.adSim.listGroups();
      if (!result.ok) {
        showToast(result.error || 'Failed to list groups', 'error');
        return;
      }
      var data = result.data || {};
      var groups = Array.isArray(data) ? data : (data.groups || []);
      adSimGroupsList.innerHTML = '';

      if (groups.length === 0) {
        adSimGroupsList.innerHTML = '<tr><td colspan="4" class="text-muted">No groups found.</td></tr>';
        return;
      }

      groups.forEach(function (group) {
        var memberCount = (group.members && Array.isArray(group.members)) ? group.members.length : (group.member_count || 0);
        var tr = document.createElement('tr');
        tr.innerHTML =
          '<td>' + esc(group.name || group.cn || '') + '</td>' +
          '<td title="' + esc(group.dn || '') + '">' + esc(group.dn || '') + '</td>' +
          '<td>' + esc(String(memberCount)) + '</td>' +
          '<td></td>';
        adSimGroupsList.appendChild(tr);
      });

    } catch (err) {
      showToast(err.message || 'Failed to list groups', 'error');
    }
  }

  adSimRefreshGroupsBtn.addEventListener('click', refreshGroups);

  // ── Add Group ──────────────────────────────────────────────────────────────
  adSimAddGroupBtn.addEventListener('click', async function () {
    var groupData = {
      name: adSimNewGroupName.value.trim(),
      ou: adSimNewGroupOu.value.trim() || undefined
    };

    if (!groupData.name) {
      showToast('Group name is required', 'error');
      return;
    }

    adSimAddGroupBtn.disabled = true;
    try {
      var result = await window.adSim.addGroup(groupData);
      if (!result.ok) {
        showToast(result.error || 'Failed to add group', 'error');
        adSimAddGroupBtn.disabled = false;
        return;
      }

      adSimNewGroupName.value = '';
      adSimNewGroupOu.value = '';

      showToast('Group added successfully', 'info');
      adSimAddGroupBtn.disabled = false;
      refreshGroups();
    } catch (err) {
      showToast(err.message || 'Failed to add group', 'error');
      adSimAddGroupBtn.disabled = false;
    }
  });

  // ── Add Member ─────────────────────────────────────────────────────────────
  adSimAddMemberBtn.addEventListener('click', async function () {
    var groupDn = adSimMemberGroupDn.value.trim();
    var memberDn = adSimMemberUserDn.value.trim();

    if (!groupDn || !memberDn) {
      showToast('Both Group DN and Member DN are required', 'error');
      return;
    }

    adSimAddMemberBtn.disabled = true;
    try {
      var result = await window.adSim.addMember(groupDn, memberDn);
      if (!result.ok) {
        showToast(result.error || 'Failed to add member', 'error');
        adSimAddMemberBtn.disabled = false;
        return;
      }
      showToast('Member added to group', 'info');
      adSimAddMemberBtn.disabled = false;
      refreshGroups();
    } catch (err) {
      showToast(err.message || 'Failed to add member', 'error');
      adSimAddMemberBtn.disabled = false;
    }
  });

  // ── Remove Member ──────────────────────────────────────────────────────────
  adSimRemoveMemberBtn.addEventListener('click', async function () {
    var groupDn = adSimMemberGroupDn.value.trim();
    var memberDn = adSimMemberUserDn.value.trim();

    if (!groupDn || !memberDn) {
      showToast('Both Group DN and Member DN are required', 'error');
      return;
    }

    adSimRemoveMemberBtn.disabled = true;
    try {
      var result = await window.adSim.removeMember(groupDn, memberDn);
      if (!result.ok) {
        showToast(result.error || 'Failed to remove member', 'error');
        adSimRemoveMemberBtn.disabled = false;
        return;
      }
      showToast('Member removed from group', 'info');
      adSimRemoveMemberBtn.disabled = false;
      refreshGroups();
    } catch (err) {
      showToast(err.message || 'Failed to remove member', 'error');
      adSimRemoveMemberBtn.disabled = false;
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. Fuzzer Tab
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Load Scenarios ─────────────────────────────────────────────────────────
  async function refreshFuzzScenarios() {
    try {
      var result = await window.adSim.fuzzList();
      if (!result.ok) {
        showToast(result.error || 'Failed to load fuzz scenarios', 'error');
        return;
      }
      var data = result.data || {};
      var scenarios = Array.isArray(data) ? data : (data.scenarios || []);
      adSimFuzzScenariosList.innerHTML = '';

      if (scenarios.length === 0) {
        adSimFuzzScenariosList.innerHTML = '<tr><td colspan="4" class="text-muted">No scenarios available.</td></tr>';
        return;
      }

      scenarios.forEach(function (scenario) {
        var tr = document.createElement('tr');
        tr.innerHTML =
          '<td><input type="checkbox" class="adsim-fuzz-cb" value="' + esc(scenario.name || '') + '" checked></td>' +
          '<td>' + esc(scenario.name || '') + '</td>' +
          '<td>' + esc(scenario.category || '') + '</td>' +
          '<td>' + esc(scenario.description || '') + '</td>';
        adSimFuzzScenariosList.appendChild(tr);
      });

    } catch (err) {
      showToast(err.message || 'Failed to load fuzz scenarios', 'error');
    }
  }

  adSimFuzzRefreshBtn.addEventListener('click', refreshFuzzScenarios);

  // ── Select All checkbox ────────────────────────────────────────────────────
  adSimFuzzSelectAll.addEventListener('change', function () {
    var checked = adSimFuzzSelectAll.checked;
    adSimFuzzScenariosList.querySelectorAll('.adsim-fuzz-cb').forEach(function (cb) {
      cb.checked = checked;
    });
  });

  // ── Run Fuzzer ─────────────────────────────────────────────────────────────
  adSimFuzzRunBtn.addEventListener('click', async function () {
    var selectedNames = [];
    adSimFuzzScenariosList.querySelectorAll('.adsim-fuzz-cb:checked').forEach(function (cb) {
      selectedNames.push(cb.value);
    });

    if (selectedNames.length === 0) {
      showToast('No scenarios selected', 'error');
      return;
    }

    adSimFuzzRunBtn.disabled = true;
    adSimFuzzResultsList.innerHTML = '';
    adSimFuzzProgress.style.display = '';
    adSimFuzzProgressFill.style.width = '0%';
    adSimFuzzProgressText.textContent = '0/' + selectedNames.length;

    try {
      var result = await window.adSim.fuzzRun({ scenarios: selectedNames });
      if (!result.ok) {
        showToast(result.error || 'Fuzz run failed', 'error');
        adSimFuzzRunBtn.disabled = false;
        adSimFuzzProgress.style.display = 'none';
        return;
      }

      // Populate results
      var results = result.data || [];
      if (Array.isArray(results)) {
        results.forEach(function (r) {
          var statusClass = r.status === 'pass' || r.status === 'PASS' ? 'status-pass' : 'status-fail';
          var tr = document.createElement('tr');
          tr.innerHTML =
            '<td>' + esc(r.scenario || r.name || '') + '</td>' +
            '<td class="' + statusClass + '">' + esc(r.status || '') + '</td>' +
            '<td>' + esc(r.details || r.message || '') + '</td>';
          adSimFuzzResultsList.appendChild(tr);
        });
      }

      adSimFuzzProgressFill.style.width = '100%';
      adSimFuzzProgressText.textContent = selectedNames.length + '/' + selectedNames.length;
      showToast('Fuzz run complete', 'info');

    } catch (err) {
      showToast(err.message || 'Fuzz run failed', 'error');
    }

    if (serverRunning) adSimFuzzRunBtn.disabled = false;
  });

  // ── Fuzz Progress (event listener) ─────────────────────────────────────────
  window.adSim.onFuzzProgress(function (data) {
    if (!data) return;
    var current = data.current || 0;
    var total = data.total || 1;
    var pct = total > 0 ? Math.round((current / total) * 100) : 0;

    adSimFuzzProgress.style.display = '';
    adSimFuzzProgressFill.style.width = pct + '%';
    adSimFuzzProgressText.textContent = current + '/' + total;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 9. Connection Log Tab
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Refresh Log ────────────────────────────────────────────────────────────
  adSimLogRefreshBtn.addEventListener('click', async function () {
    try {
      var result = await window.adSim.getLog(200);
      if (!result.ok) {
        showToast(result.error || 'Failed to get log', 'error');
        return;
      }
      var entries = result.data || [];
      adSimLogContainer.innerHTML = '';

      if (entries.length === 0) {
        adSimLogContainer.innerHTML = '<p class="text-muted">No log entries.</p>';
        return;
      }

      entries.forEach(function (entry) {
        appendLogEntry(entry);
      });

      adSimLogContainer.scrollTop = adSimLogContainer.scrollHeight;
    } catch (err) {
      showToast(err.message || 'Failed to get log', 'error');
    }
  });

  // ── Clear Log ──────────────────────────────────────────────────────────────
  adSimLogClearBtn.addEventListener('click', function () {
    adSimLogContainer.innerHTML = '';
  });

  // ── Live Log (event listener) ──────────────────────────────────────────────
  window.adSim.onLog(function (entry) {
    if (!entry) return;
    appendLogEntry(entry);
    // Auto-scroll
    adSimLogContainer.scrollTop = adSimLogContainer.scrollHeight;
    // Cap at 500 entries
    while (adSimLogContainer.children.length > 500) {
      adSimLogContainer.removeChild(adSimLogContainer.firstChild);
    }
  });

  function appendLogEntry(entry) {
    var div = document.createElement('div');
    div.className = 'log-entry';

    var timestamp = entry.timestamp || '';
    var operation = entry.operation || entry.op || '';
    var dn = entry.dn || '';
    var success = entry.success !== undefined ? entry.success : true;

    var statusCls = success ? 'log-success' : 'log-fail';
    var statusText = success ? '✓' : '✗';

    div.innerHTML =
      '<span class="log-timestamp">' + esc(timestamp) + '</span> ' +
      '<span class="log-operation">' + esc(operation) + '</span> ' +
      '<span class="log-dn">' + esc(dn) + '</span> ' +
      '<span class="' + statusCls + '">' + statusText + '</span>';

    adSimLogContainer.appendChild(div);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 10. Status Event Listener
  // ═══════════════════════════════════════════════════════════════════════════
  window.adSim.onStatus(function (data) {
    if (!data) return;

    var status = data.status || 'unknown';

    if (status === 'running') {
      serverRunning = true;
      var port = data.port || (serverConfig.port || '');
      adSimStatusBadge.textContent = '● Running on port ' + port;
      adSimStatusBadge.className = 'badge badge-success';
      setButtonsEnabled(true);
    } else if (status === 'stopped' || status === 'exited') {
      serverRunning = false;
      adSimStatusBadge.textContent = '● Stopped';
      adSimStatusBadge.className = 'badge';
      setButtonsEnabled(false);

      // Handle unexpected exit
      if (status === 'exited' && data.error) {
        adSimStatusBadge.textContent = '● Exited: ' + (data.error || 'unexpected');
        adSimStatusBadge.className = 'badge badge-error';
        adSimInfo.innerHTML = '<p class="text-muted">Server exited unexpectedly: ' + esc(data.error || '') + '</p>';
      }
    } else if (status === 'error') {
      adSimStatusBadge.textContent = '● Error: ' + (data.error || 'unknown');
      adSimStatusBadge.className = 'badge badge-error';
    }
  });

})();
