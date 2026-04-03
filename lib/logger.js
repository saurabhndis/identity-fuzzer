// Color-coded logging with hex dump support

const COLORS = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  red:     '\x1b[31m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  blue:    '\x1b[34m',
  magenta: '\x1b[35m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',
  gray:    '\x1b[90m',
  bgRed:   '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow:'\x1b[43m',
};

class Logger {
  constructor(opts = {}) {
    this.verbose = opts.verbose || false;
    this.json = opts.json || false;
    this.events = []; // for UI streaming
    this.listeners = [];
  }

  onEvent(fn) {
    this.listeners.push(fn);
    return () => { this.listeners = this.listeners.filter(l => l !== fn); };
  }

  _emit(event) {
    this.events.push(event);
    for (const fn of this.listeners) fn(event);
  }

  timestamp() {
    const d = new Date();
    return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
  }

  scenario(name, description) {
    const ts = this.timestamp();
    const event = { type: 'scenario', ts, name, description };
    this._emit(event);
    if (!this.json) {
      console.log(`\n${COLORS.bold}${COLORS.magenta}━━━ Scenario: ${name} ━━━${COLORS.reset}`);
      console.log(`${COLORS.gray}    ${description}${COLORS.reset}`);
    }
  }

  sent(data, label) {
    const ts = this.timestamp();
    const desc = label || describeData(data);
    const size = data ? (data.length || 0) : 0;
    const hex = data ? data.toString('hex') : '';
    const event = { type: 'sent', ts, label: desc, size, hex };
    this._emit(event);
    if (!this.json) {
      console.log(`${COLORS.cyan}${ts} → ${desc} (${size} bytes)${COLORS.reset}`);
      if (this.verbose && data) hexDump(data, COLORS.cyan);
    }
  }

  received(data, label) {
    const ts = this.timestamp();
    const desc = label || describeData(data);
    const size = data ? (data.length || 0) : 0;
    const hex = data ? data.toString('hex') : '';
    const event = { type: 'received', ts, label: desc, size, hex };
    this._emit(event);
    if (!this.json) {
      console.log(`${COLORS.yellow}${ts} ← ${desc} (${size} bytes)${COLORS.reset}`);
      if (this.verbose && data) hexDump(data, COLORS.yellow);
    }
  }

  tcpEvent(direction, eventName) {
    const ts = this.timestamp();
    const arrow = direction === 'sent' ? '→' : '←';
    const color = direction === 'sent' ? COLORS.cyan : COLORS.yellow;
    const event = { type: 'tcp', ts, direction, event: eventName };
    this._emit(event);
    if (!this.json) {
      console.log(`${color}${ts} ${arrow} [TCP] ${eventName}${COLORS.reset}`);
    }
  }

  fuzz(message) {
    const ts = this.timestamp();
    const event = { type: 'fuzz', ts, message };
    this._emit(event);
    if (!this.json) {
      console.log(`${COLORS.red}${COLORS.bold}${ts} ⚡ [FUZZ] ${message}${COLORS.reset}`);
    }
  }

  info(message) {
    const ts = this.timestamp();
    const event = { type: 'info', ts, message };
    this._emit(event);
    if (!this.json) {
      console.log(`${COLORS.green}${ts} ℹ ${message}${COLORS.reset}`);
    }
  }

  error(message) {
    const ts = this.timestamp();
    const event = { type: 'error', ts, message };
    this._emit(event);
    if (!this.json) {
      console.log(`${COLORS.red}${ts} ✗ ${message}${COLORS.reset}`);
    }
  }

  hostDown(host, port, scenarioName) {
    const ts = this.timestamp();
    const event = { type: 'host-down', ts, host, port, scenario: scenarioName };
    this._emit(event);
    if (!this.json) {
      console.log(`${COLORS.bgRed}${COLORS.bold}${COLORS.white}${ts} !! HOST DOWN — ${host}:${port} is unreachable after "${scenarioName}" !!${COLORS.reset}`);
      console.log(`${COLORS.red}    This may indicate a crash/DoS vulnerability${COLORS.reset}`);
    }
  }

  healthProbe(host, port, probe) {
    const ts = this.timestamp();
    const event = { type: 'health-probe', ts, host, port, probe };
    this._emit(event);
    if (!this.json) {
      const ping = probe.tcp || probe.udp;
      if (ping) {
        const status = ping.alive
          ? `${COLORS.green}Ping OK${COLORS.reset} ${COLORS.gray}(${ping.latency}ms)${COLORS.reset}`
          : `${COLORS.red}Ping FAIL${COLORS.reset} ${COLORS.gray}(${ping.error})${COLORS.reset}`;
        console.log(`${COLORS.blue}${ts} ♥ Health: ${status}${COLORS.reset}`);
      }
    }
  }

  result(scenarioName, status, response, verdict, expectedReason, hostDown = false, finding = null, compliance = null) {
    const ts = this.timestamp();
    const event = { type: 'result', ts, scenario: scenarioName, status, response, verdict, hostDown, finding, compliance };
    this._emit(event);
    if (!this.json) {
      const statusColor = status === 'DROPPED' ? COLORS.red
        : status === 'PASSED' ? COLORS.green
        : COLORS.yellow;
      let verdictStr = '';
      if (verdict === 'AS EXPECTED') {
        verdictStr = ` ${COLORS.green}[AS EXPECTED]${COLORS.reset}`;
      } else if (verdict === 'UNEXPECTED') {
        verdictStr = ` ${COLORS.bold}${COLORS.red}[UNEXPECTED]${COLORS.reset}`;
        if (expectedReason) verdictStr += ` ${COLORS.gray}(${expectedReason})${COLORS.reset}`;
      }
      let hostDownStr = '';
      if (hostDown) {
        hostDownStr = ` ${COLORS.bgRed}${COLORS.white} HOST DOWN ${COLORS.reset}`;
      }
      let findingStr = '';
      if (finding) {
        const gc = finding.grade === 'PASS' ? COLORS.green
          : finding.grade === 'FAIL' ? COLORS.red
          : finding.grade === 'WARN' ? COLORS.yellow
          : COLORS.gray;
        findingStr = ` ${gc}[${finding.grade}]${COLORS.reset}`;
        if (finding.reason) findingStr += ` ${COLORS.gray}${finding.reason}${COLORS.reset}`;
      }
      console.log(`${COLORS.bold}${statusColor}  Result: ${status}${COLORS.reset} ${COLORS.gray}(${response})${COLORS.reset}${verdictStr}${hostDownStr}${findingStr}`);
    }
  }

  summary(results, report = null) {
    if (this.json) {
      console.log(JSON.stringify({ results, report }, null, 2));
      return;
    }
    const total = results.length;
    const dropped = results.filter(r => r.status === 'DROPPED').length;
    const passed = results.filter(r => r.status === 'PASSED').length;
    const errors = results.filter(r => r.status === 'ERROR').length;
    const timeout = results.filter(r => r.status === 'TIMEOUT').length;
    const hostDownCount = results.filter(r => r.hostDown).length;
    const asExpected = results.filter(r => r.verdict === 'AS EXPECTED').length;
    const unexpected = results.filter(r => r.verdict === 'UNEXPECTED').length;

    if (report) {
      const gradeColors = { A: COLORS.green, B: COLORS.blue, C: COLORS.yellow, D: COLORS.magenta, F: COLORS.red };
      const gc = gradeColors[report.grade] || COLORS.white;
      console.log(`\n${COLORS.bold}${gc}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${COLORS.reset}`);
      console.log(`${COLORS.bold}${gc}┃  OVERALL GRADE: ${report.grade}  —  ${report.label.padEnd(32)}┃${COLORS.reset}`);
      console.log(`${COLORS.bold}${gc}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${COLORS.reset}`);
      console.log(`  ${COLORS.green}PASS: ${report.stats.pass}${COLORS.reset}  ${COLORS.red}FAIL: ${report.stats.fail}${COLORS.reset}  ${COLORS.yellow}WARN: ${report.stats.warn}${COLORS.reset}  ${COLORS.gray}INFO: ${report.stats.info}${COLORS.reset}`);
      if (report.findings.length > 0) {
        console.log(`\n  ${COLORS.bold}${COLORS.red}Security Findings:${COLORS.reset}`);
        for (const f of report.findings) {
          const sevColor = f.severity === 'critical' ? COLORS.red
            : f.severity === 'high' ? COLORS.magenta
            : f.severity === 'medium' ? COLORS.yellow
            : COLORS.gray;
          console.log(`  ${sevColor}[${f.severity.toUpperCase()}]${COLORS.reset} ${f.scenario} — ${f.reason}`);
        }
      }
    } else {
      console.log(`\n${COLORS.bold}${COLORS.white}━━━ Summary ━━━${COLORS.reset}`);
    }

    console.log(`\n  Total: ${total}  ${COLORS.red}Dropped: ${dropped}${COLORS.reset}  ${COLORS.green}Passed: ${passed}${COLORS.reset}  ${COLORS.yellow}Errors: ${errors}${COLORS.reset}  ${COLORS.gray}Timeout: ${timeout}${COLORS.reset}`);
    if (hostDownCount > 0) {
      console.log(`  ${COLORS.bgRed}${COLORS.white}${COLORS.bold} HOST DOWN: ${hostDownCount} ${COLORS.reset} — target became unreachable during testing`);
    }
    console.log(`  ${COLORS.green}As Expected: ${asExpected}${COLORS.reset}  ${unexpected > 0 ? COLORS.bold + COLORS.red : COLORS.gray}Unexpected: ${unexpected}${COLORS.reset}`);
    console.log('');
    console.log(`  ${'Scenario'.padEnd(40)} ${'Description'.padEnd(50)} ${'Status'.padEnd(10)} ${'Finding'.padEnd(8)} ${'Verdict'.padEnd(14)} Response`);
    console.log(`  ${'─'.repeat(40)} ${'─'.repeat(50)} ${'─'.repeat(10)} ${'─'.repeat(8)} ${'─'.repeat(14)} ${'─'.repeat(30)}`);
    for (const r of results) {
      const statusColor = r.status === 'DROPPED' ? COLORS.red
        : r.status === 'PASSED' ? COLORS.green
        : COLORS.yellow;
      const verdictColor = r.verdict === 'AS EXPECTED' ? COLORS.green
        : r.verdict === 'UNEXPECTED' ? COLORS.red
        : COLORS.gray;
      const verdict = (r.verdict || 'N/A').padEnd(14);
      const downFlag = r.hostDown ? ` ${COLORS.bgRed}${COLORS.white}DOWN${COLORS.reset}` : '';
      const fg = r.finding ? (typeof r.finding === 'string' ? r.finding.toUpperCase() : r.finding.grade) : '—';
      const fColor = fg === 'PASS' ? COLORS.green : fg === 'FAIL' ? COLORS.red : fg === 'WARN' ? COLORS.yellow : COLORS.gray;
      const desc = (r.description || '').substring(0, 48).padEnd(50);
      console.log(`  ${r.scenario.padEnd(40)} ${COLORS.gray}${desc}${COLORS.reset} ${statusColor}${r.status.padEnd(10)}${COLORS.reset} ${fColor}${fg.padEnd(8)}${COLORS.reset} ${verdictColor}${verdict}${COLORS.reset} ${r.response}${downFlag}`);
    }
    console.log('');
  }
}

/**
 * Describe data for logging — LDAP-aware label
 */
function describeData(buf) {
  if (!buf || buf.length < 2) return `Data (${buf ? buf.length : 0} bytes)`;
  // LDAP messages start with SEQUENCE tag (0x30)
  if (buf[0] === 0x30) {
    return `LDAP message (${buf.length} bytes)`;
  }
  return `Data (${buf.length} bytes)`;
}

function hexDump(buf, color = '') {
  const reset = COLORS.reset;
  const dim = COLORS.dim;
  const lines = Math.min(Math.ceil(buf.length / 16), 16);
  for (let i = 0; i < lines; i++) {
    const offset = (i * 16).toString(16).padStart(8, '0');
    const hex = [];
    const ascii = [];
    for (let j = 0; j < 16; j++) {
      const idx = i * 16 + j;
      if (idx < buf.length) {
        hex.push(buf[idx].toString(16).padStart(2, '0'));
        ascii.push(buf[idx] >= 32 && buf[idx] <= 126 ? String.fromCharCode(buf[idx]) : '.');
      } else {
        hex.push('  ');
        ascii.push(' ');
      }
    }
    const hexStr = hex.slice(0, 8).join(' ') + '  ' + hex.slice(8).join(' ');
    console.log(`${dim}    ${offset}  ${color}${hexStr}  ${dim}|${ascii.join('')}|${reset}`);
  }
  if (buf.length > 256) {
    console.log(`${dim}    ... (${buf.length - 256} more bytes)${reset}`);
  }
}

module.exports = { Logger, describeData, hexDump, COLORS };
