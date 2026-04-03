// LDAP fuzzer worker process — forked by main.js for multi-worker mode
const { LdapFuzzerClient } = require('./ldap/fuzzer-client');
const { LdapFuzzerServer } = require('./ldap/fuzzer-server');
const { Logger } = require('./logger');
const { getLdapScenario } = require('./ldap/scenarios');
const { gradeResult } = require('./grader');

let client = null;
let server = null;
let logger = null;
let packets = [];

process.on('message', async (msg) => {
  if (msg.cmd === 'init-client') {
    logger = new Logger({ verbose: msg.verbose });
    logger.onEvent((evt) => {
      if (['sent', 'received', 'tcp', 'fuzz'].includes(evt.type)) {
        packets.push(evt);
      }
      process.send({ type: 'log', data: evt });
    });

    client = new LdapFuzzerClient({
      host: msg.host,
      port: msg.port,
      timeout: (msg.timeout || 10) * 1000,
      delay: msg.delay || 100,
      logger,
      pcapFile: msg.pcapFile,
    });
    process.send({ type: 'ready' });

  } else if (msg.cmd === 'init-server') {
    logger = new Logger({ verbose: msg.verbose });
    logger.onEvent((evt) => {
      if (['sent', 'received', 'tcp', 'fuzz'].includes(evt.type)) {
        packets.push(evt);
      }
      process.send({ type: 'log', data: evt });
    });

    server = new LdapFuzzerServer({
      port: msg.port,
      hostname: '::',
      timeout: (msg.timeout || 10) * 1000,
      delay: msg.delay || 100,
      logger,
      pcapFile: msg.pcapFile,
    });
    await server.start();
    process.send({ type: 'ready' });

  } else if (msg.cmd === 'run') {
    const scenario = getLdapScenario(msg.scenarioName);
    if (!scenario) {
      process.send({ type: 'result', result: { scenario: msg.scenarioName, status: 'ERROR', response: 'Unknown scenario' } });
      process.send({ type: 'ready' });
      return;
    }

    packets = [];
    try {
      let result;
      if (client) {
        result = await client.runScenario(scenario);
      } else if (server) {
        result = await server.runScenario(scenario);
      } else {
        result = { scenario: scenario.name, status: 'ERROR', response: 'No client or server initialized' };
      }

      result.packets = packets;
      result.category = scenario.category;
      result.description = scenario.description;
      result.finding = gradeResult(result, scenario);

      if (scenario.expected) {
        const effective = result.status === 'TIMEOUT' ? 'DROPPED' : result.status;
        result.verdict = effective === scenario.expected ? 'AS EXPECTED' : 'UNEXPECTED';
      }

      process.send({ type: 'result', result });
    } catch (err) {
      process.send({
        type: 'result',
        result: { scenario: scenario.name, category: scenario.category, status: 'ERROR', response: err.message, packets }
      });
    }
    process.send({ type: 'ready' });

  } else if (msg.cmd === 'abort') {
    if (client) try { client.abort(); } catch (_) {}
    if (server) try { server.stop(); } catch (_) {}
    process.exit(0);
  }
});
