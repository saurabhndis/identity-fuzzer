# 🛡️ Identity Fuzzer

**LDAP Protocol Security Fuzzer** — Test LDAP/Active Directory servers with 149 crafted protocol scenarios across 12 attack categories.

Identity Fuzzer sends malformed, malicious, and edge-case LDAP packets to discover vulnerabilities in directory servers including buffer overflows, injection flaws, DoS weaknesses, and protocol violations.

![Electron](https://img.shields.io/badge/Electron-40.x-blue) ![Node.js](https://img.shields.io/badge/Node.js-18%2B-green) ![Scenarios](https://img.shields.io/badge/Scenarios-149-orange) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📋 Prerequisites

- **Node.js** 18+ (recommended: use [nvm](https://github.com/nvm-sh/nvm))
- **npm** (comes with Node.js)
- **macOS**, **Linux**, or **Windows**

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/saurabhndis/identity-fuzzer.git
cd identity-fuzzer
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Run the GUI

```bash
npm start
```

> **⚠️ VS Code Terminal Users:** If launching from VS Code's integrated terminal, you must unset the `ELECTRON_RUN_AS_NODE` environment variable first:
> ```bash
> unset ELECTRON_RUN_AS_NODE && npm start
> ```
> VS Code sets `ELECTRON_RUN_AS_NODE=1` which prevents Electron from initializing its browser UI. Run from a standalone terminal to avoid this issue.

### 4. Run via CLI (Headless)

```bash
# List all available scenarios
node cli.js --list

# Run all client-mode scenarios against a target
node cli.js --host ldap.example.com --port 389

# Run specific category
node cli.js --host ldap.example.com --port 389 --category LA

# Run a single scenario
node cli.js --host ldap.example.com --port 389 --scenario ldap-anon-bind

# Run in server mode (fuzzes connecting clients)
node cli.js --mode server --port 10389

# Output results as JSON
node cli.js --host ldap.example.com --port 389 --json

# Save packet capture
node cli.js --host ldap.example.com --port 389 --pcap capture.pcap

# Verbose output with packet hex dumps
node cli.js --host ldap.example.com --port 389 --verbose
```

---

## 🖥️ GUI Usage

The Electron GUI provides a visual interface for running fuzzing scenarios:

1. **Select Mode**: Choose **Client** (fuzz a server) or **Server** (fuzz connecting clients)
2. **Set Target**: Enter the target hostname and port (default: `localhost:389`)
3. **Select Scenarios**: Browse and select scenarios by category. Use the search filter to find specific tests.
4. **Configure Options**:
   - **Delay (ms)**: Pause between scenarios (default: 100ms)
   - **Timeout (s)**: Per-scenario timeout (default: 10s)
   - **Workers**: Parallel workers for faster testing (default: 1)
   - **Local Target**: Check this to spin up a local echo server for self-testing
5. **Run**: Click the Run button to start fuzzing
6. **Review Results**: View pass/fail status, packet logs, and the overall security grade

---

## 🧪 Testing Locally (Self-Test)

To test the fuzzer against itself without a real LDAP server:

### Option A: Use Local Target Mode (GUI)
1. Open the GUI (`npm start`)
2. Check the **"Local Target"** checkbox
3. Click **Run** — the fuzzer will start a built-in echo server and test against it

### Option B: Run Server + Client via CLI
```bash
# Terminal 1: Start the fuzzer in server mode
node cli.js --mode server --port 10389

# Terminal 2: Run client against the server
node cli.js --host localhost --port 10389
```

### Option C: Single Command
```bash
# Start server in background, run client, then kill server
node cli.js --mode server --port 10389 &
SERVER_PID=$!
sleep 2
node cli.js --host localhost --port 10389
kill $SERVER_PID
```

---

## 📊 Scenario Categories

| Code | Category | Severity | Scenarios | Description |
|------|----------|----------|-----------|-------------|
| **LA** | Authentication Attacks | 🔴 Critical | 15 | Anonymous bind, SASL, credential stuffing, buffer overflow |
| **LB** | Search Filter Injection | 🟠 High | 12 | Wildcard, OR/AND/NOT injection, substring, extensible match |
| **LC** | BER/ASN.1 Encoding Violations | 🟠 High | 15 | Malformed lengths, nested depth bombs, integer overflow |
| **LD** | Protocol Sequence Violations | 🟡 Medium | 10 | Out-of-order operations, unbind abuse, abandon flood |
| **LE** | Resource Exhaustion | 🟠 High | 12 | Connection flood, large payloads, search bombs |
| **LF** | LDAPS/StartTLS Transport | 🔴 Critical | 10 | TLS downgrade, certificate manipulation, cipher abuse |
| **LG** | AD-Specific Attacks | 🔴 Critical | 15 | LAPS password extraction, SPN enumeration, GPO abuse |
| **LH** | Operation Fuzzing | 🟡 Medium | 12 | Modify/Add/Delete with malformed data |
| **LI** | Extended Operations | 🟡 Medium | 8 | Password modify, whoami, cancel, custom OIDs |
| **LJ** | Server-to-Client Attacks | 🟠 High | 30 | Malicious server responses (disabled by default) |
| **LK** | CVE Reproductions | 🔴 Critical | — | Known vulnerability reproductions (disabled by default) |
| **LL** | Connectivity & Baseline | ℹ️ Info | 10 | Basic connectivity, ping, echo tests |

---

## 📝 CLI Reference

```
Usage: node cli.js [options]

Options:
  --host <host>       Target host (default: localhost)
  --port <port>       Target port (default: 389)
  --mode <mode>       client or server (default: client)
  --category <cat>    Run only scenarios in this category (e.g. LA, LB, LJ)
  --scenario <name>   Run a specific scenario by name
  --timeout <sec>     Timeout per scenario in seconds (default: 10)
  --delay <ms>        Delay between scenarios in ms (default: 100)
  --pcap <file>       Save PCAP capture to file
  --list              List all scenarios and exit
  --verbose           Show detailed packet logs
  --json              Output results as JSON
  --help              Show this help
```

---

## 🏗️ Architecture

```
identity-fuzzer/
├── main.js                    # Electron main process (GUI orchestration)
├── preload.js                 # Secure IPC bridge (contextBridge)
├── cli.js                     # Headless CLI entry point
├── renderer/
│   ├── index.html             # GUI layout
│   ├── app.js                 # Frontend logic
│   └── styles.css             # Styling
└── lib/
    ├── ldap/
    │   ├── scenarios.js       # All 149 LDAP fuzzing scenarios
    │   ├── fuzzer-client.js   # Client-mode fuzzer engine
    │   ├── fuzzer-server.js   # Server-mode fuzzer engine
    │   ├── packet.js          # LDAP/BER packet builder & parser
    │   ├── constants.js       # LDAP protocol constants
    │   └── index.js           # LDAP module exports
    ├── grader.js              # Security grade computation
    ├── logger.js              # Event logging & formatting
    ├── pcap-writer.js         # PCAP file writer
    ├── tcp-tricks.js          # TCP FIN/RST helpers
    ├── well-behaved-client.js # Standard LDAP client for server-mode
    ├── ldap-echo-server.js    # Echo server for local testing
    └── worker.js              # Multi-worker process handler
```

---

## 📈 Grading System

Results are graded on a scale from **A** (excellent) to **F** (critical issues):

| Grade | Meaning |
|-------|---------|
| **A** | All tests passed — robust LDAP implementation |
| **B** | Minor issues — mostly cosmetic or informational |
| **C** | Moderate issues — some unexpected behaviors |
| **D** | Significant issues — multiple failures detected |
| **F** | Critical issues — server crashed or major vulnerabilities found |

Each scenario result includes:
- **Status**: PASSED, DROPPED, TIMEOUT, ERROR
- **Finding**: PASS, WARN, FAIL, INFO
- **Verdict**: AS EXPECTED or UNEXPECTED

---

## 🔒 Security Notice

This tool is designed for **authorized security testing only**. Only use it against systems you own or have explicit permission to test. Unauthorized use against production systems may violate laws and regulations.

---

## 📄 License

MIT
