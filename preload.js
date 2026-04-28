const { contextBridge, ipcRenderer } = require('electron');
const os = require('os');

contextBridge.exposeInMainWorld('fuzzer', {
  cpuCount: os.cpus().length,
  listScenarios: () => ipcRenderer.invoke('list-scenarios'),
  run: (opts) => ipcRenderer.invoke('run-fuzzer', opts),
  stop: () => ipcRenderer.invoke('stop-fuzzer'),
  savePcapDialog: () => ipcRenderer.invoke('save-pcap-dialog'),
  saveLogToFile: (p, content) => ipcRenderer.invoke('save-log-to-file', p, content),
  onPacket: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-packet', listener);
    return () => ipcRenderer.removeListener('fuzzer-packet', listener);
  },
  onResult: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-result', listener);
    return () => ipcRenderer.removeListener('fuzzer-result', listener);
  },
  onProgress: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-progress', listener);
    return () => ipcRenderer.removeListener('fuzzer-progress', listener);
  },
  onReport: (cb) => {
    const listener = (_e, data) => cb(data);
    ipcRenderer.on('fuzzer-report', listener);
    return () => ipcRenderer.removeListener('fuzzer-report', listener);
  },
});

contextBridge.exposeInMainWorld('adSim', {
  // Server lifecycle
  start: (config) => ipcRenderer.invoke('ad-sim-start', config),
  stop: () => ipcRenderer.invoke('ad-sim-stop'),
  status: () => ipcRenderer.invoke('ad-sim-status'),

  // Directory management
  seed: (count) => ipcRenderer.invoke('ad-sim-command', { cmd: 'seed', args: { count } }),
  listUsers: () => ipcRenderer.invoke('ad-sim-command', { cmd: 'list-users', args: {} }),
  addUser: (user) => ipcRenderer.invoke('ad-sim-command', { cmd: 'add-user', args: user }),
  deleteUser: (dn) => ipcRenderer.invoke('ad-sim-command', { cmd: 'delete-user', args: { dn } }),
  setPassword: (args) => ipcRenderer.invoke('ad-sim-command', { cmd: 'set-password', args }),
  listGroups: () => ipcRenderer.invoke('ad-sim-command', { cmd: 'list-groups', args: {} }),
  addGroup: (group) => ipcRenderer.invoke('ad-sim-command', { cmd: 'add-group', args: group }),
  listTree: () => ipcRenderer.invoke('ad-sim-command', { cmd: 'list-tree', args: {} }),
  addMember: (groupDn, memberDn) => ipcRenderer.invoke('ad-sim-command', { cmd: 'add-member', args: { group_dn: groupDn, member_dn: memberDn } }),
  removeMember: (groupDn, memberDn) => ipcRenderer.invoke('ad-sim-command', { cmd: 'remove-member', args: { group_dn: groupDn, member_dn: memberDn } }),

  // Fuzzer
  fuzzList: () => ipcRenderer.invoke('ad-sim-command', { cmd: 'fuzz-list', args: {} }),
  fuzzRun: (opts) => ipcRenderer.invoke('ad-sim-command', { cmd: 'fuzz-run', args: opts || {} }),

  // State persistence
  save: (path) => ipcRenderer.invoke('ad-sim-command', { cmd: 'save', args: { path } }),
  load: (path) => ipcRenderer.invoke('ad-sim-command', { cmd: 'load', args: { path } }),

  // Log
  getLog: (limit) => ipcRenderer.invoke('ad-sim-command', { cmd: 'get-log', args: { limit } }),

  // Event listeners (return unsubscribe functions, matching existing pattern)
  onLog: (cb) => {
    const handler = (_e, data) => cb(data);
    ipcRenderer.on('ad-sim-log', handler);
    return () => ipcRenderer.removeListener('ad-sim-log', handler);
  },
  onStatus: (cb) => {
    const handler = (_e, data) => cb(data);
    ipcRenderer.on('ad-sim-status-event', handler);
    return () => ipcRenderer.removeListener('ad-sim-status-event', handler);
  },
  onFuzzProgress: (cb) => {
    const handler = (_e, data) => cb(data);
    ipcRenderer.on('ad-sim-fuzz-progress', handler);
    return () => ipcRenderer.removeListener('ad-sim-fuzz-progress', handler);
  },
});

// ── Syslog Sender API ───────────────────────────────────────────────────────────
contextBridge.exposeInMainWorld('syslog', {
  listTemplates: () => ipcRenderer.invoke('syslog-list-templates'),
  listProfiles: () => ipcRenderer.invoke('syslog-list-profiles'),
  send: (opts) => ipcRenderer.invoke('syslog-send', opts),
  stress: (opts) => ipcRenderer.invoke('syslog-stress', opts),
  scenario: (opts) => ipcRenderer.invoke('syslog-scenario', opts),
  generateCerts: (opts) => ipcRenderer.invoke('syslog-generate-certs', opts),
  stop: () => ipcRenderer.invoke('syslog-stop'),
  onProgress: (cb) => { const h = (_e, d) => cb(d); ipcRenderer.on('syslog-progress', h); return () => ipcRenderer.removeListener('syslog-progress', h); },
  onLog: (cb) => { const h = (_e, d) => cb(d); ipcRenderer.on('syslog-log', h); return () => ipcRenderer.removeListener('syslog-log', h); },
  onResult: (cb) => { const h = (_e, d) => cb(d); ipcRenderer.on('syslog-result', h); return () => ipcRenderer.removeListener('syslog-result', h); },
});

// ── XML API User-ID API ─────────────────────────────────────────────────────────
contextBridge.exposeInMainWorld('xmlapi', {
  keygen: (opts) => ipcRenderer.invoke('xmlapi-keygen', opts),
  send: (opts) => ipcRenderer.invoke('xmlapi-send', opts),
  bulk: (opts) => ipcRenderer.invoke('xmlapi-bulk', opts),
  scenario: (opts) => ipcRenderer.invoke('xmlapi-scenario', opts),
  stop: () => ipcRenderer.invoke('xmlapi-stop'),
  onProgress: (cb) => { const h = (_e, d) => cb(d); ipcRenderer.on('xmlapi-progress', h); return () => ipcRenderer.removeListener('xmlapi-progress', h); },
  onLog: (cb) => { const h = (_e, d) => cb(d); ipcRenderer.on('xmlapi-log', h); return () => ipcRenderer.removeListener('xmlapi-log', h); },
  onResult: (cb) => { const h = (_e, d) => cb(d); ipcRenderer.on('xmlapi-result', h); return () => ipcRenderer.removeListener('xmlapi-result', h); },
});
