#!/usr/bin/env node
// Identity Fuzzer CLI — headless LDAP fuzzing without Electron
const { LdapFuzzerClient } = require('./lib/ldap/fuzzer-client');
const { LdapFuzzerServer } = require('./lib/ldap/fuzzer-server');
const { listLdapScenarios, getLdapScenario, listLdapClientScenarios, listLdapServerScenarios } = require('./lib/ldap/scenarios');
const { Logger } = require('./lib/logger');
const { computeOverallGrade, gradeResult } = require('./lib/grader');

const args = process.argv.slice(2);

function usage() {
  console.log(`
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

Examples:
  node cli.js --host ldap.example.com --port 389 --category LA
  node cli.js --mode server --port 10389 --category LJ
  node cli.js --list
`);
}

// Parse args
const opts = {
  host: 'localhost', port: 389, mode: 'client', category: null, scenario: null,
  timeout: 10, delay: 100, pcap: null, list: false, verbose: false, json: false,
};

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--host': opts.host = args[++i]; break;
    case '--port': opts.port = parseInt(args[++i], 10); break;
    case '--mode': opts.mode = args[++i]; break;
    case '--category': opts.category = args[++i]; break;
    case '--scenario': opts.scenario = args[++i]; break;
    case '--timeout': opts.timeout = parseInt(args[++i], 10); break;
    case '--delay': opts.delay = parseInt(args[++i], 10); break;
    case '--pcap': opts.pcap = args[++i]; break;
    case '--list': opts.list = true; break;
    case '--verbose': opts.verbose = true; break;
    case '--json': opts.json = true; break;
    case '--help': case '-h': usage(); process.exit(0);
    default: console.error(`Unknown option: ${args[i]}`); usage(); process.exit(1);
  }
}

async function main() {
  // List mode
  if (opts.list) {
    const { categories, scenarios } = listLdapScenarios();
    for (const [cat, catInfo] of Object.entries(categories)) {
      const items = scenarios[cat] || [];
      console.log(`\n${cat} — ${catInfo.name} (${items.length} scenarios) [${catInfo.severity || 'info'}]`);
      for (const s of items) {
        console.log(`  ${s.name.padEnd(45)} ${(s.side || 'client').padEnd(8)} ${s.description}`);
      }
    }
    console.log(`\nTotal: ${Object.values(scenarios).reduce((t, items) => t + items.length, 0)} scenarios`);
    return;
  }

  // Resolve scenarios
  let scenarioList;
  if (opts.scenario) {
    const s = getLdapScenario(opts.scenario);
    if (!s) { console.error(`Scenario not found: ${opts.scenario}`); process.exit(1); }
    scenarioList = [s];
  } else if (opts.category) {
    const { scenarios } = listLdapScenarios();
    scenarioList = scenarios[opts.category];
    if (!scenarioList || scenarioList.length === 0) {
      console.error(`No scenarios found for category: ${opts.category}`);
      process.exit(1);
    }
  } else {
    // All scenarios for the mode
    if (opts.mode === 'server') {
      scenarioList = listLdapServerScenarios();
    } else {
      scenarioList = listLdapClientScenarios();
    }
  }

  const logger = new Logger({ verbose: opts.verbose, json: opts.json });
  const results = [];

  if (opts.mode === 'client') {
    const client = new LdapFuzzerClient({
      host: opts.host,
      port: opts.port,
      timeout: opts.timeout * 1000,
      delay: opts.delay,
      logger,
      pcapFile: opts.pcap,
    });

    for (const s of scenarioList) {
      try {
        const result = await client.runScenario(s);
        result.category = s.category;
        result.description = s.description;
        result.finding = gradeResult(result, s);
        if (s.expected) {
          const effective = result.status === 'TIMEOUT' ? 'DROPPED' : result.status;
          result.verdict = effective === s.expected ? 'AS EXPECTED' : 'UNEXPECTED';
        }
        results.push(result);
      } catch (err) {
        results.push({ scenario: s.name, category: s.category, status: 'ERROR', response: err.message });
      }
    }
  } else {
    const server = new LdapFuzzerServer({
      port: opts.port,
      hostname: '::',
      timeout: opts.timeout * 1000,
      delay: opts.delay,
      logger,
      pcapFile: opts.pcap,
    });

    await server.start();
    console.log(`LDAP fuzzer server listening on port ${server.actualPort || opts.port}`);

    for (const s of scenarioList) {
      try {
        const result = await server.runScenario(s);
        result.category = s.category;
        result.description = s.description;
        result.finding = gradeResult(result, s);
        results.push(result);
      } catch (err) {
        results.push({ scenario: s.name, category: s.category, status: 'ERROR', response: err.message });
      }
    }

    server.stop();
  }

  // Summary
  const report = computeOverallGrade(results);
  logger.summary(results, report);
  process.exit(report.grade === 'F' ? 1 : 0);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(2);
});
