const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { fork } = require('child_process');
const path = require('path');
const fs = require('fs');
const { Logger } = require('./lib/logger');
const { LdapFuzzerClient } = require('./lib/ldap/fuzzer-client');
const { LdapFuzzerServer } = require('./lib/ldap/fuzzer-server');
const { listLdapScenarios, getLdapScenario, LDAP_CATEGORIES, LDAP_CATEGORY_SEVERITY, LDAP_CATEGORY_DEFAULT_DISABLED } = require('./lib/ldap/scenarios');
const { computeOverallGrade, gradeResult } = require('./lib/grader');
const { WellBehavedClient } = require('./lib/well-behaved-client');
const { LdapEchoServer } = require('./lib/ldap-echo-server');

let mainWindow;
let activeClient = null;
let activeServer = null;
let aborted = false;

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
