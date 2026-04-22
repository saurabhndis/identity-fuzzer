const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { fork, spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { Logger } = require('./lib/logger');
const { LdapFuzzerClient } = require('./lib/ldap/fuzzer-client');
const { LdapFuzzerServer } = require('./lib/ldap/fuzzer-server');
const { listLdapScenarios, getLdapScenario, LDAP_CATEGORIES, LDAP_CATEGORY_SEVERITY, LDAP_CATEGORY_DEFAULT_DISABLED } = require('./lib/ldap/scenarios');
const { computeOverallGrade, gradeResult } = require('./lib/grader');
const { WellBehavedClient } = require('./lib/well-behaved-client');
const { LdapEchoServer } = require('./lib/ldap-echo-server');
const syslog = require('./lib/syslog');

let mainWindow;
let activeClient = null;
let activeServer = null;
let aborted = false;

// ── Syslog Sender state ─────────────────────────────────────────────────────────
let syslogTransport = null;
let syslogAborted = false;

// ── AD Simulator state ──────────────────────────────────────────────────────────
let adSimProcess = null;    // child_process.ChildProcess
let adSimReady = false;     // bridge.py has sent "ready" event
let adSimPending = {};      // pending command callbacks: { id: { resolve, reject, timer } }

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 950,
    minWidth: 900,
    minHeight: 700,
    backgroundColor: '#ffffff',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
    title: 'Identity Fuzzer',
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

function send(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data);
  }
}

// ── List scenarios ──────────────────────────────────────────────────────────────
ipcMain.handle('list-scenarios', () => {
  const { categories, scenarios } = listLdapScenarios();
  const stripped = {};
  for (const [cat, items] of Object.entries(scenarios)) {
    stripped[cat] = items.map(s => ({
      name: s.name,
      category: s.category,
      description: s.description,
      side: s.side,
      expected: s.expected,
      expectedReason: s.expectedReason,
    }));
  }
  return {
    categories,
    scenarios: stripped,
    defaultDisabled: [...LDAP_CATEGORY_DEFAULT_DISABLED],
    categorySeverity: LDAP_CATEGORY_SEVERITY,
  };
});

// ── Run fuzzer ──────────────────────────────────────────────────────────────────
ipcMain.handle('run-fuzzer', async (_event, opts) => {
  const { mode, host, port, scenarioNames, delay, timeout, pcapFile, verbose, loopCount: rawLoop, localMode, workers } = opts;
  const loopCount = Math.max(1, Math.min(1000, parseInt(rawLoop, 10) || 1));
  aborted = false;

  const logger = new Logger({ verbose });
  let currentScenarioPackets = [];
  logger.onEvent((evt) => {
    if (['sent', 'received', 'tcp', 'fuzz'].includes(evt.type)) {
      currentScenarioPackets.push(evt);
    }
    send('fuzzer-packet', evt);
  });

  const portNum = parseInt(port, 10);
  if (!portNum || portNum < 1 || portNum > 65535) {
    return { error: 'Invalid port' };
  }

  const scenarios = (scenarioNames || []).map(n => getLdapScenario(n)).filter(Boolean);
  if (scenarios.length === 0) {
    return { error: 'No valid scenarios selected' };
  }

  const results = [];
  const totalWithLoops = scenarios.length * loopCount;

  // ── Client mode ──
  if (mode === 'client') {
    let localServer = null;
    let clientHost = host || 'localhost';
    let clientPort = portNum;

    if (localMode) {
      localServer = new LdapEchoServer({ port: portNum, hostname: '::', logger });
      try {
        await localServer.start();
        clientPort = localServer.port || portNum;
        send('fuzzer-packet', { type: 'info', message: `Local LDAP echo server started on port ${clientPort}` });
      } catch (err) {
        return { error: `Failed to start local server: ${err.message}` };
      }
    }

    try {
      if (workers > 1) {
        send('fuzzer-packet', { type: 'info', message: `Forking ${workers} worker processes...` });
        const queue = [];
        for (let loop = 0; loop < loopCount; loop++) {
          for (const s of scenarios) queue.push(s);
        }
        const numWorkers = Math.min(workers, queue.length);
        let activeWorkers = 0;

        await new Promise((resolve) => {
          for (let i = 0; i < numWorkers; i++) {
            const worker = fork(path.join(__dirname, 'lib', 'worker.js'));
            activeWorkers++;

            worker.on('message', (msg) => {
              if (msg.type === 'ready') {
                if (queue.length > 0 && !aborted) {
                  const s = queue.shift();
                  send('fuzzer-progress', { scenario: s.name, total: totalWithLoops, current: results.length + 1 });
                  worker.send({ cmd: 'run', scenarioName: s.name });
                } else {
                  worker.send({ cmd: 'abort' });
                }
              } else if (msg.type === 'result') {
                results.push(msg.result);
                send('fuzzer-result', msg.result);
                if (msg.result.packets) {
                  msg.result.packets.forEach(p => send('fuzzer-packet', p));
                }
              } else if (msg.type === 'log') {
                send('fuzzer-packet', msg.data);
              }
            });

            worker.on('exit', () => {
              activeWorkers--;
              if (activeWorkers === 0) resolve();
            });

            worker.send({
              cmd: 'init-client', host: clientHost, port: clientPort, timeout, delay, verbose, pcapFile
            });
          }
        });
      } else {
        // Single-worker client mode
        const client = new LdapFuzzerClient({
          host: clientHost,
          port: clientPort,
          timeout: timeout * 1000,
          delay,
          logger,
          pcapFile,
        });
        activeClient = client;

        for (let loop = 0; loop < loopCount && !aborted; loop++) {
          for (let i = 0; i < scenarios.length && !aborted; i++) {
            const s = scenarios[i];
            currentScenarioPackets = [];
            send('fuzzer-progress', { scenario: s.name, total: totalWithLoops, current: results.length + 1 });

            try {
              const result = await client.runScenario(s);
              result.packets = currentScenarioPackets;
              result.category = s.category;
              result.description = s.description;

              // Grade the result
              const finding = gradeResult(result, s);
              result.finding = finding;

              // Determine verdict
              if (s.expected) {
                const effective = result.status === 'TIMEOUT' ? 'DROPPED' : result.status;
                result.verdict = effective === s.expected ? 'AS EXPECTED' : 'UNEXPECTED';
                result.expectedReason = s.expectedReason;
              }

              results.push(result);
              send('fuzzer-result', result);
            } catch (err) {
              const errResult = {
                scenario: s.name,
                category: s.category,
                description: s.description,
                status: 'ERROR',
                response: err.message,
                finding: { grade: 'INFO', severity: 'low', reason: 'Scenario error' },
              };
              results.push(errResult);
              send('fuzzer-result', errResult);
            }
          }
        }
        activeClient = null;
      }
    } finally {
      if (localServer) {
        try { localServer.stop(); } catch (_) {}
      }
    }
  }

  // ── Server mode ──
  else if (mode === 'server') {
    const server = new LdapFuzzerServer({
      port: portNum,
      hostname: '::',
      timeout: timeout * 1000,
      delay,
      logger,
      pcapFile,
    });
    activeServer = server;

    try {
      await server.start();
      send('fuzzer-packet', { type: 'info', message: `LDAP fuzzer server listening on port ${server.port || portNum}` });

      for (let loop = 0; loop < loopCount && !aborted; loop++) {
        for (let i = 0; i < scenarios.length && !aborted; i++) {
          const s = scenarios[i];
          currentScenarioPackets = [];
          send('fuzzer-progress', { scenario: s.name, total: totalWithLoops, current: results.length + 1 });

          // Spawn local client if needed
          let localClient = null;
          if (localMode) {
            localClient = new WellBehavedClient({ host: 'localhost', port: server.port || portNum, logger });
            setTimeout(() => localClient.connectLDAP().catch(() => {}), 500);
          }

          try {
            const result = await server.runScenario(s);
            result.packets = currentScenarioPackets;
            result.category = s.category;
            result.description = s.description;

            const finding = gradeResult(result, s);
            result.finding = finding;

            if (s.expected) {
              const effective = result.status === 'TIMEOUT' ? 'DROPPED' : result.status;
              result.verdict = effective === s.expected ? 'AS EXPECTED' : 'UNEXPECTED';
            }

            results.push(result);
            send('fuzzer-result', result);
          } catch (err) {
            const errResult = {
              scenario: s.name,
              category: s.category,
              description: s.description,
              status: 'ERROR',
              response: err.message,
              finding: { grade: 'INFO', severity: 'low', reason: 'Scenario error' },
            };
            results.push(errResult);
            send('fuzzer-result', errResult);
          }

          if (localClient) {
            try { localClient.stop(); } catch (_) {}
          }
        }
      }
    } finally {
      try { server.stop(); } catch (_) {}
      activeServer = null;
    }
  }

  // Compute overall grade
  const report = computeOverallGrade(results);
  send('fuzzer-report', report);
  return { results: results.length, report };
});

// ── Stop fuzzer ─────────────────────────────────────────────────────────────────
ipcMain.handle('stop-fuzzer', () => {
  aborted = true;
  if (activeClient) {
    try { activeClient.abort(); } catch (_) {}
    activeClient = null;
  }
  if (activeServer) {
    try { activeServer.stop(); } catch (_) {}
    activeServer = null;
  }
  return { ok: true };
});

// ── Save PCAP dialog ────────────────────────────────────────────────────────────
ipcMain.handle('save-pcap-dialog', async () => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save PCAP Capture',
    defaultPath: 'ldap-fuzzer.pcap',
    filters: [{ name: 'PCAP Files', extensions: ['pcap'] }],
  });
  return result;
});

// ── Save log to file ────────────────────────────────────────────────────────────
ipcMain.handle('save-log-to-file', async (_event, filePath, content) => {
  try {
    fs.writeFileSync(filePath, content, 'utf8');
    return { ok: true };
  } catch (err) {
    return { error: err.message };
  }
});

// ── AD Simulator helpers ────────────────────────────────────────────────────────

function spawnAdSim() {
  if (adSimProcess) return; // already running

  const adSimDir = path.join(__dirname, 'lib', 'ad-simulator');
  const bridgePath = path.join(adSimDir, 'bridge.py');

  // Prefer venv Python if available, fallback to system python3/python
  // macOS/Linux: .venv/bin/python3   Windows: .venv\Scripts\python.exe
  const isWin = process.platform === 'win32';
  const venvPython = isWin
    ? path.join(adSimDir, '.venv', 'Scripts', 'python.exe')
    : path.join(adSimDir, '.venv', 'bin', 'python3');
  const systemPython = isWin ? 'python' : 'python3';
  const pythonCmd = fs.existsSync(venvPython) ? venvPython : systemPython;

  adSimProcess = spawn(pythonCmd, [bridgePath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: adSimDir,
  });

  let buffer = '';
  adSimProcess.stdout.on('data', (chunk) => {
    buffer += chunk.toString();
    let lines = buffer.split('\n');
    buffer = lines.pop(); // keep incomplete line in buffer

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);

        // Handle events (no id)
        if (msg.event) {
          if (msg.event === 'ready') {
            adSimReady = true;
            send('ad-sim-status-event', { ready: true });
          } else if (msg.event === 'status') {
            send('ad-sim-status-event', msg.data);
          } else if (msg.event === 'log') {
            send('ad-sim-log', msg.data);
          } else if (msg.event === 'fuzz-progress') {
            send('ad-sim-fuzz-progress', msg.data);
          }
          continue;
        }

        // Handle responses (has id)
        if (msg.id && adSimPending[msg.id]) {
          const { resolve, reject, timer } = adSimPending[msg.id];
          clearTimeout(timer);
          delete adSimPending[msg.id];

          if (msg.ok) {
            resolve(msg.data);
          } else {
            reject(new Error(msg.error || 'Unknown error'));
          }
        }
      } catch (e) {
        console.error('[ad-sim] Failed to parse JSON:', line, e);
      }
    }
  });

  adSimProcess.stderr.on('data', (chunk) => {
    const text = chunk.toString();
    console.error('[ad-sim stderr]', text);
    send('ad-sim-log', { type: 'stderr', message: text.trim(), ts: new Date().toISOString() });
  });

  adSimProcess.on('exit', (code, signal) => {
    console.log(`[ad-sim] Process exited: code=${code}, signal=${signal}`);
    adSimProcess = null;
    adSimReady = false;
    // Reject all pending commands
    for (const id of Object.keys(adSimPending)) {
      const { reject, timer } = adSimPending[id];
      clearTimeout(timer);
      reject(new Error('AD Simulator process exited'));
      delete adSimPending[id];
    }
    send('ad-sim-status-event', { running: false, exited: true, code, signal });
  });

  adSimProcess.on('error', (err) => {
    console.error('[ad-sim] Process error:', err);
    send('ad-sim-status-event', { running: false, error: err.message });
  });
}

function sendAdSimCommand(cmd, args = {}, timeout = 30000) {
  return new Promise((resolve, reject) => {
    if (!adSimProcess || adSimProcess.killed) {
      return reject(new Error('AD Simulator process not running'));
    }

    const id = crypto.randomUUID();
    const msg = JSON.stringify({ id, cmd, args }) + '\n';

    const timer = setTimeout(() => {
      delete adSimPending[id];
      reject(new Error(`Command '${cmd}' timed out after ${timeout}ms`));
    }, timeout);

    adSimPending[id] = { resolve, reject, timer };

    try {
      adSimProcess.stdin.write(msg);
    } catch (e) {
      clearTimeout(timer);
      delete adSimPending[id];
      reject(new Error(`Failed to send command: ${e.message}`));
    }
  });
}

function killAdSim() {
  if (adSimProcess) {
    try {
      adSimProcess.stdin.end();
      adSimProcess.kill('SIGTERM');
    } catch (e) {
      console.error('[ad-sim] Kill error:', e);
    }
    adSimProcess = null;
    adSimReady = false;
    adSimPending = {};
  }
}

// ── AD Simulator IPC handlers ──────────────────────────────────────────────────

ipcMain.handle('ad-sim-start', async (_event, config) => {
  try {
    // Spawn process if not running
    if (!adSimProcess) {
      spawnAdSim();
      // Wait for ready event (up to 10 seconds)
      await new Promise((resolve, reject) => {
        const check = setInterval(() => {
          if (adSimReady) { clearInterval(check); resolve(); }
        }, 100);
        setTimeout(() => { clearInterval(check); reject(new Error('Bridge startup timeout')); }, 10000);
      });
    }

    // Send start command
    const result = await sendAdSimCommand('start', config || {});
    return { ok: true, data: result };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('ad-sim-stop', async () => {
  try {
    if (adSimProcess && adSimReady) {
      await sendAdSimCommand('stop', {}, 5000);
    }
    killAdSim();
    return { ok: true };
  } catch (e) {
    killAdSim();
    return { ok: true }; // Still return ok since we killed the process
  }
});

ipcMain.handle('ad-sim-status', async () => {
  try {
    if (!adSimProcess || !adSimReady) {
      return { ok: true, data: { running: false, processAlive: !!adSimProcess } };
    }
    const result = await sendAdSimCommand('status', {}, 5000);
    return { ok: true, data: result };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

ipcMain.handle('ad-sim-command', async (_event, { cmd, args }) => {
  try {
    if (!adSimProcess || !adSimReady) {
      return { ok: false, error: 'AD Simulator not running. Start the server first.' };
    }
    const result = await sendAdSimCommand(cmd, args);
    return { ok: true, data: result };
  } catch (e) {
    return { ok: false, error: e.message };
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SYSLOG SENDER IPC HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

ipcMain.handle('syslog-list-templates', () => {
  const templates = syslog.listTemplates();
  return templates.map(t => ({
    name: t.name, eventType: t.eventType, description: t.description,
    compatibleProfile: t.compatibleProfile,
    example: syslog.renderTemplate(t, { username: 'john', ip: '10.0.0.1' }),
  }));
});

ipcMain.handle('syslog-list-profiles', () => {
  return Object.values(syslog.PREDEFINED_PROFILES).map(p => ({
    name: p.name, profileType: p.profileType, eventType: p.eventType,
    eventString: p.eventString, description: p.description,
  }));
});

ipcMain.handle('syslog-send', async (_event, opts) => {
  const { firewall, transport: transportType, port, sourceIP, certFile, keyFile, caFile, verifySSL,
    username, ipAddress, eventType, domain, template, count, interval, dryRun } = opts;
  syslogAborted = false;
  const gen = new syslog.MessageGenerator({ defaultTemplate: template || 'field-login', defaultDomain: domain || null });
  const messages = [];
  const ipGen = new syslog.IPGenerator(ipAddress || '192.168.1.1');
  for (let n = 0; n < (count || 1); n++) {
    const ip = n === 0 ? (ipAddress || '192.168.1.1') : ipGen.next();
    const user = (count || 1) > 1 ? `${username}_${n}` : username;
    if (eventType === 'logout') { messages.push(gen.logout(user, ip, { domain, template })); }
    else { messages.push(gen.login(user, ip, { domain, template })); }
  }
  if (dryRun) {
    return { ok: true, dryRun: true, messages: messages.map((m, i) => ({
      index: i + 1, message: m.message.trimEnd(), username: m.username, ipAddress: m.ipAddress, eventType: m.eventType,
    })), count: messages.length };
  }
  let transport;
  try {
    transport = syslog.createTransport(transportType || 'ssl');
    syslogTransport = transport;
    const connectOpts = {};
    if (sourceIP) connectOpts.sourceIP = sourceIP;
    if (transportType === 'ssl') {
      connectOpts.verify = verifySSL || false;
      if (certFile) connectOpts.certFile = certFile;
      if (keyFile) connectOpts.keyFile = keyFile;
      if (caFile) connectOpts.caFile = caFile;
    }
    await transport.connect(firewall, port || undefined, connectOpts);
  } catch (e) { return { ok: false, error: `Connection failed: ${e.message}` }; }
  const results = [];
  try {
    for (let i = 0; i < messages.length && !syslogAborted; i++) {
      const msg = messages[i];
      try {
        await transport.send(msg.message);
        const entry = { index: i + 1, status: 'sent', username: msg.username, ipAddress: msg.ipAddress, eventType: msg.eventType, bytes: Buffer.byteLength(msg.message, 'utf8') };
        results.push(entry); send('syslog-log', entry);
      } catch (e) { results.push({ index: i + 1, status: 'error', error: e.message }); send('syslog-log', { index: i + 1, status: 'error', error: e.message }); }
      if ((interval || 0) > 0 && i < messages.length - 1) { await new Promise(r => setTimeout(r, interval * 1000)); }
    }
    return { ok: true, sent: results.filter(r => r.status === 'sent').length, total: messages.length, bytesSent: transport.stats.bytesSent, results };
  } catch (e) { return { ok: false, error: e.message }; }
  finally { transport.close(); syslogTransport = null; }
});

ipcMain.handle('syslog-stress', async (_event, opts) => {
  syslogAborted = false;
  try {
    const result = await syslog.runStress({
      host: opts.firewall, port: opts.port || undefined, numSenders: opts.senders || 5,
      messagesPerSender: opts.messages || 100, transportType: opts.transport || 'udp',
      usernamePattern: opts.usernamePattern || 'stress_{sender}_{n}', baseIP: opts.baseIP || '10.0.0.1',
      messageTemplate: opts.template || 'minimal-login', sendInterval: opts.rate || 0,
      domain: opts.domain || null, includeWhiteNoise: opts.whiteNoise || false,
      sourceIP: opts.sourceIP, certFile: opts.certFile, keyFile: opts.keyFile, verifySSL: opts.verifySSL || false,
      onProgress: (info) => { send('syslog-progress', info); },
    });
    send('syslog-result', result);
    return { ok: true, result };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('syslog-scenario', async (_event, opts) => {
  syslogAborted = false;
  const transportType = opts.transport || 'ssl';
  let transport;
  try {
    transport = syslog.createTransport(transportType);
    syslogTransport = transport;
    const connectOpts = {};
    if (opts.sourceIP) connectOpts.sourceIP = opts.sourceIP;
    if (transportType === 'ssl') { connectOpts.verify = opts.verifySSL || false; if (opts.certFile) connectOpts.certFile = opts.certFile; if (opts.keyFile) connectOpts.keyFile = opts.keyFile; }
    const defaultPort = transportType === 'ssl' ? 6514 : 514;
    await transport.connect(opts.firewall, opts.port || defaultPort, connectOpts);
  } catch (e) { return { ok: false, error: `Connection failed: ${e.message}` }; }
  try {
    let result;
    if (opts.name === 'login-logout') {
      result = await syslog.runLoginLogout(transport, { numUsers: opts.users || 10, domain: opts.domain || null, sendLogout: opts.sendLogout !== false, loginInterval: 50, logoutInterval: 50, pauseBetween: 1000, onProgress: (info) => { send('syslog-progress', info); } });
    } else if (opts.name === 'edge-cases') {
      result = await syslog.runEdgeCases(transport, { onProgress: (info) => { send('syslog-progress', info); } });
    } else { return { ok: false, error: `Unknown scenario: ${opts.name}` }; }
    send('syslog-result', result);
    return { ok: true, result };
  } catch (e) { return { ok: false, error: e.message }; }
  finally { transport.close(); syslogTransport = null; }
});

ipcMain.handle('syslog-generate-certs', async (_event, opts) => {
  try {
    if (opts.selfSigned) {
      const result = syslog.generateSelfSigned({ commonName: opts.cn || 'syslog-sender-sim', days: opts.days || 365, keySize: opts.keySize || 2048, outputDir: opts.outputDir || path.join(__dirname, 'certs', 'syslog') });
      return { ok: true, ...result };
    } else {
      const result = syslog.generateCAAndClient({ caCN: opts.caCN || 'syslog-sim-ca', clientCN: opts.cn || 'syslog-sender-sim', days: opts.days || 365, keySize: opts.keySize || 2048, outputDir: opts.outputDir || path.join(__dirname, 'certs', 'syslog') });
      return { ok: true, ...result };
    }
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('syslog-stop', () => {
  syslogAborted = true;
  if (syslogTransport) { try { syslogTransport.close(); } catch (_) {} syslogTransport = null; }
  return { ok: true };
});

// ── Cleanup on quit ─────────────────────────────────────────────────────────────
app.on('before-quit', () => {
  killAdSim();
  if (syslogTransport) { try { syslogTransport.close(); } catch (_) {} syslogTransport = null; }
});
