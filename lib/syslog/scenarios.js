// Syslog sender test scenarios — LoginLogout, Stress, EdgeCases
// Port of: AI-Agent/anton/apps/useridd/syslogsender/src/syslog_sender_sim/scenarios/
//
// PAN-OS Reference:
//   - pan_user_id_syslog.h: PAN_SYSLOG_SERVER_EVENT_TYPE_LOGIN / LOGOUT
//   - pan_user_id_syslog.h: PAN_USER_ID_SYSLOG_SERVER_MAX = 50

const { MessageGenerator } = require('./generator');
const { createTransport } = require('./transport');
const { SCENARIO_STATUS, MAX_SYSLOG_SENDERS } = require('./constants');

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function _now() { return Date.now(); }


// ═══════════════════════════════════════════════════════════════════════════════
//  SCENARIO RESULT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * @typedef {Object} ScenarioResult
 * @property {string} name
 * @property {string} status - 'pending'|'running'|'passed'|'failed'|'error'
 * @property {number} messagesSent
 * @property {number} loginCount
 * @property {number} logoutCount
 * @property {string[]} errors
 * @property {number} durationSeconds
 * @property {Object} details
 * @property {boolean} passed
 */

function makeResult(name) {
  return {
    name,
    status: SCENARIO_STATUS.PENDING,
    messagesSent: 0,
    loginCount: 0,
    logoutCount: 0,
    errors: [],
    durationSeconds: 0,
    details: {},
    get passed() { return this.status === SCENARIO_STATUS.PASSED; },
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
//  LOGIN/LOGOUT SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Login/Logout test scenario.
 * Sends login events, pauses, then sends matching logout events.
 *
 * @param {Object} transport - Connected SSLTransport or UDPTransport
 * @param {Object} opts
 * @param {number} [opts.numUsers=10]
 * @param {string} [opts.usernamePattern='testuser_{n}']
 * @param {string} [opts.baseIP='192.168.1.1']
 * @param {string} [opts.domain]
 * @param {string} [opts.loginTemplate='field-login']
 * @param {string} [opts.logoutTemplate='field-logout']
 * @param {number} [opts.loginInterval=100] - ms between login messages
 * @param {number} [opts.logoutInterval=100] - ms between logout messages
 * @param {number} [opts.pauseBetween=2000] - ms between login and logout phases
 * @param {boolean} [opts.sendLogout=true]
 * @param {Function} [opts.onProgress] - callback(info)
 * @returns {Promise<ScenarioResult>}
 */
async function runLoginLogout(transport, opts = {}) {
  const numUsers = opts.numUsers || 10;
  const usernamePattern = opts.usernamePattern || 'testuser_{n}';
  const baseIP = opts.baseIP || '192.168.1.1';
  const domain = opts.domain || null;
  const loginTemplate = opts.loginTemplate || 'field-login';
  const logoutTemplate = opts.logoutTemplate || 'field-logout';
  const loginInterval = opts.loginInterval !== undefined ? opts.loginInterval : 100;
  const logoutInterval = opts.logoutInterval !== undefined ? opts.logoutInterval : 100;
  const pauseBetween = opts.pauseBetween !== undefined ? opts.pauseBetween : 2000;
  const sendLogout = opts.sendLogout !== false;
  const onProgress = opts.onProgress || (() => {});

  const result = makeResult('login-logout');
  result.status = SCENARIO_STATUS.RUNNING;
  const startTime = _now();

  const gen = new MessageGenerator({
    defaultTemplate: loginTemplate,
    defaultDomain: domain,
  });

  try {
    // Phase 1: Login events
    onProgress({ phase: 'login', current: 0, total: numUsers });
    const loginMessages = gen.batchLogin({
      usernamePattern,
      count: numUsers,
      baseIP,
      domain,
      template: loginTemplate,
    });

    for (let i = 0; i < loginMessages.length; i++) {
      const msg = loginMessages[i];
      try {
        await transport.send(msg.message);
        result.loginCount++;
        result.messagesSent++;
        onProgress({ phase: 'login', current: i + 1, total: numUsers, user: msg.username, ip: msg.ipAddress });
      } catch (e) {
        result.errors.push(`Login send error for ${msg.username}: ${e.message}`);
      }
      if (loginInterval > 0 && i < loginMessages.length - 1) {
        await _sleep(loginInterval);
      }
    }

    // Phase 2: Pause
    if (sendLogout && pauseBetween > 0) {
      onProgress({ phase: 'pause', duration: pauseBetween });
      await _sleep(pauseBetween);
    }

    // Phase 3: Logout events
    if (sendLogout) {
      onProgress({ phase: 'logout', current: 0, total: numUsers });
      const logoutMessages = gen.batchLogout({
        usernamePattern,
        count: numUsers,
        baseIP,
        domain,
        template: logoutTemplate,
      });

      for (let i = 0; i < logoutMessages.length; i++) {
        const msg = logoutMessages[i];
        try {
          await transport.send(msg.message);
          result.logoutCount++;
          result.messagesSent++;
          onProgress({ phase: 'logout', current: i + 1, total: numUsers, user: msg.username, ip: msg.ipAddress });
        } catch (e) {
          result.errors.push(`Logout send error for ${msg.username}: ${e.message}`);
        }
        if (logoutInterval > 0 && i < logoutMessages.length - 1) {
          await _sleep(logoutInterval);
        }
      }
    }

    // Determine result
    const expectedTotal = numUsers * (sendLogout ? 2 : 1);
    result.status = (result.messagesSent === expectedTotal && result.errors.length === 0)
      ? SCENARIO_STATUS.PASSED
      : (result.errors.length > 0 ? SCENARIO_STATUS.FAILED : SCENARIO_STATUS.PASSED);

    result.details = {
      numUsers,
      usernamePattern,
      baseIP,
      domain,
      loginTemplate,
      logoutTemplate,
      transportStats: transport.stats.toJSON(),
    };

  } catch (e) {
    result.status = SCENARIO_STATUS.ERROR;
    result.errors.push(`Scenario error: ${e.message}`);
  }

  result.durationSeconds = (_now() - startTime) / 1000;
  onProgress({ phase: 'done', result });
  return result;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  STRESS SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * High-volume stress test scenario.
 * Creates multiple concurrent senders that each send messages.
 *
 * @param {Object} opts
 * @param {string} opts.host - PAN-OS firewall IP
 * @param {number} [opts.port]
 * @param {number} [opts.numSenders=5]
 * @param {number} [opts.messagesPerSender=100]
 * @param {string} [opts.transportType='udp']
 * @param {string} [opts.usernamePattern='stress_{sender}_{n}']
 * @param {string} [opts.baseIP='10.0.0.1']
 * @param {string} [opts.messageTemplate='minimal-login']
 * @param {number} [opts.sendInterval=0] - ms between messages per sender
 * @param {string} [opts.domain]
 * @param {boolean} [opts.includeWhiteNoise=false]
 * @param {number} [opts.whiteNoiseRatio=0.1]
 * @param {string} [opts.sourceIP]
 * @param {string} [opts.certFile]
 * @param {string} [opts.keyFile]
 * @param {boolean} [opts.verifySSL=false]
 * @param {Function} [opts.onProgress]
 * @returns {Promise<ScenarioResult>}
 */
async function runStress(opts = {}) {
  const host = opts.host;
  const port = opts.port;
  const numSenders = Math.min(opts.numSenders || 5, MAX_SYSLOG_SENDERS);
  const messagesPerSender = opts.messagesPerSender || 100;
  const transportType = (opts.transportType || 'udp').toLowerCase();
  const usernamePattern = opts.usernamePattern || 'stress_{sender}_{n}';
  const baseIP = opts.baseIP || '10.0.0.1';
  const messageTemplate = opts.messageTemplate || 'minimal-login';
  const sendInterval = opts.sendInterval || 0;
  const domain = opts.domain || null;
  const includeWhiteNoise = opts.includeWhiteNoise || false;
  const whiteNoiseRatio = opts.whiteNoiseRatio || 0.1;
  const onProgress = opts.onProgress || (() => {});

  const result = makeResult('stress-test');
  result.status = SCENARIO_STATUS.RUNNING;
  const startTime = _now();

  const senderStats = [];

  // Create sender workers as concurrent promises
  const senderPromises = [];

  for (let i = 0; i < numSenders; i++) {
    const senderType = transportType === 'both'
      ? (i % 2 === 0 ? 'ssl' : 'udp')
      : transportType;

    const stats = {
      senderId: i,
      transportType: senderType,
      messagesSent: 0,
      bytesSent: 0,
      errors: 0,
      durationSeconds: 0,
      errorMessages: [],
    };
    senderStats.push(stats);

    senderPromises.push(_senderWorker(i, stats, {
      host, port, senderType,
      usernamePattern, baseIP, messageTemplate,
      sendInterval, domain, includeWhiteNoise, whiteNoiseRatio,
      messagesPerSender,
      sourceIP: opts.sourceIP,
      certFile: opts.certFile,
      keyFile: opts.keyFile,
      verifySSL: opts.verifySSL,
      onProgress: (info) => {
        onProgress({ ...info, senderId: i, totalSenders: numSenders });
      },
    }));
  }

  // Wait for all senders to complete
  await Promise.all(senderPromises);

  // Aggregate results
  for (const stats of senderStats) {
    result.messagesSent += stats.messagesSent;
    result.loginCount += stats.messagesSent;
    if (stats.errorMessages.length > 0) {
      result.errors.push(...stats.errorMessages);
    }
  }

  result.durationSeconds = (_now() - startTime) / 1000;

  const totalExpected = numSenders * messagesPerSender;
  result.status = (result.messagesSent === totalExpected && result.errors.length === 0)
    ? SCENARIO_STATUS.PASSED
    : (result.errors.length > 0 ? SCENARIO_STATUS.FAILED : SCENARIO_STATUS.PASSED);

  const totalBytes = senderStats.reduce((s, st) => s + st.bytesSent, 0);
  const totalErrors = senderStats.reduce((s, st) => s + st.errors, 0);
  const msgsPerSec = result.durationSeconds > 0
    ? result.messagesSent / result.durationSeconds : 0;

  result.details = {
    numSenders,
    messagesPerSender,
    totalExpected,
    totalBytes,
    totalErrors,
    messagesPerSecond: Math.round(msgsPerSec * 100) / 100,
    transportType,
    senderStats: senderStats.map(s => ({
      id: s.senderId,
      type: s.transportType,
      sent: s.messagesSent,
      bytes: s.bytesSent,
      errors: s.errors,
      duration: Math.round(s.durationSeconds * 1000) / 1000,
      msgPerSec: s.durationSeconds > 0
        ? Math.round((s.messagesSent / s.durationSeconds) * 100) / 100 : 0,
    })),
  };

  onProgress({ phase: 'done', result });
  return result;
}

/**
 * Worker function for each sender in the stress test.
 * @private
 */
async function _senderWorker(senderId, stats, opts) {
  const startTime = _now();
  let transport;

  try {
    transport = createTransport(opts.senderType);

    const connectOpts = {};
    if (opts.sourceIP) connectOpts.sourceIP = opts.sourceIP;
    if (opts.senderType === 'ssl') {
      connectOpts.verify = opts.verifySSL || false;
      if (opts.certFile) connectOpts.certFile = opts.certFile;
      if (opts.keyFile) connectOpts.keyFile = opts.keyFile;
    }

    const defaultPort = opts.senderType === 'ssl' ? 6514 : 514;
    await transport.connect(opts.host, opts.port || defaultPort, connectOpts);

    // Generate messages
    const gen = new MessageGenerator({
      defaultTemplate: opts.messageTemplate,
      defaultDomain: opts.domain,
    });

    // Compute IP offset for this sender to avoid collisions
    const ipParts = opts.baseIP.split('.');
    ipParts[2] = String((parseInt(ipParts[2], 10) + senderId) % 256);
    const senderBaseIP = ipParts.join('.');

    const pattern = opts.usernamePattern.replace('{sender}', String(senderId));

    let messages = gen.batchLogin({
      usernamePattern: pattern,
      count: opts.messagesPerSender,
      baseIP: senderBaseIP,
      domain: opts.domain,
      template: opts.messageTemplate,
    });

    // Optionally mix in white noise
    if (opts.includeWhiteNoise) {
      const noiseGen = new MessageGenerator({ defaultTemplate: 'white-noise' });
      const noiseCount = Math.floor(messages.length * opts.whiteNoiseRatio);
      const noiseMsgs = [];
      for (let j = 0; j < noiseCount; j++) {
        noiseMsgs.push(noiseGen.custom(`White noise from sender ${senderId} seq ${j}\r\n`));
      }
      // Interleave noise messages
      const combined = [];
      let noiseIdx = 0;
      const step = Math.max(1, Math.floor(1 / opts.whiteNoiseRatio));
      for (let k = 0; k < messages.length; k++) {
        combined.push(messages[k]);
        if (noiseIdx < noiseMsgs.length && k % step === 0) {
          combined.push(noiseMsgs[noiseIdx++]);
        }
      }
      messages = combined;
    }

    // Send all messages
    for (const msg of messages) {
      try {
        const bytesSent = await transport.send(msg.message);
        stats.messagesSent++;
        stats.bytesSent += bytesSent;
      } catch (e) {
        stats.errors++;
        stats.errorMessages.push(`Sender ${senderId}: ${e.message}`);
      }

      if (opts.sendInterval > 0) {
        await _sleep(opts.sendInterval);
      }
    }

  } catch (e) {
    stats.errors++;
    stats.errorMessages.push(`Sender ${senderId} connection/setup error: ${e.message}`);
  } finally {
    if (transport) {
      try { transport.close(); } catch (_) {}
    }
    stats.durationSeconds = (_now() - startTime) / 1000;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  EDGE CASE SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Edge case test names and descriptions.
 */
const EDGE_CASE_TESTS = [
  'malformed_message',
  'message_without_newline',
  'message_with_only_newline',
  'empty_message',
  'oversized_username',
  'special_chars_username',
  'unicode_username',
  'duplicate_ip_different_users',
  'same_user_different_ips',
  'white_noise_mixed',
  'multiple_events_one_message',
  'partial_auth_message',
  'very_long_message',
  'null_bytes_in_message',
];

/**
 * Run edge case tests against a connected transport.
 *
 * @param {Object} transport - Connected SSLTransport or UDPTransport
 * @param {Object} [opts]
 * @param {string[]} [opts.tests] - Specific tests to run (null = all)
 * @param {Function} [opts.onProgress]
 * @returns {Promise<ScenarioResult>}
 */
async function runEdgeCases(transport, opts = {}) {
  const testNames = opts.tests || EDGE_CASE_TESTS;
  const onProgress = opts.onProgress || (() => {});

  const result = makeResult('edge-cases');
  result.status = SCENARIO_STATUS.RUNNING;
  const startTime = _now();

  const gen = new MessageGenerator();
  const testResults = [];

  for (let i = 0; i < testNames.length; i++) {
    const testName = testNames[i];
    onProgress({ phase: 'test', current: i + 1, total: testNames.length, testName });

    let testResult;
    try {
      testResult = await _runEdgeCaseTest(testName, transport, gen);
    } catch (e) {
      testResult = {
        name: testName,
        passed: false,
        description: 'Test raised exception',
        error: e.message,
        details: {},
      };
    }
    testResults.push(testResult);
    result.messagesSent += testResult.details.messagesSent || 0;
  }

  // Aggregate
  const passed = testResults.filter(t => t.passed).length;
  const failed = testResults.filter(t => !t.passed).length;

  result.durationSeconds = (_now() - startTime) / 1000;
  result.status = failed === 0 ? SCENARIO_STATUS.PASSED : SCENARIO_STATUS.FAILED;
  result.errors = testResults
    .filter(t => !t.passed && t.error)
    .map(t => `${t.name}: ${t.error}`);

  result.details = {
    totalTests: testResults.length,
    passed,
    failed,
    tests: testResults.map(t => ({
      name: t.name,
      passed: t.passed,
      description: t.description,
      error: t.error || null,
    })),
  };

  onProgress({ phase: 'done', result });
  return result;
}

/**
 * Run a single edge case test.
 * @private
 */
async function _runEdgeCaseTest(testName, transport, gen) {
  switch (testName) {

    case 'malformed_message': {
      const msg = 'This is a random log message with no auth data\r\n';
      await transport.send(msg);
      return { name: testName, passed: true, description: 'Sent malformed message (no username/IP). PAN-OS should ignore it.', details: { messagesSent: 1 } };
    }

    case 'message_without_newline': {
      const msg = 'Username:noterm Address:10.0.0.1 Authentication Success';
      await transport.send(msg); // transport auto-terminates
      return { name: testName, passed: true, description: 'Message without newline was auto-terminated by transport layer.', details: { messagesSent: 1 } };
    }

    case 'message_with_only_newline': {
      await transport.send('\r\n');
      return { name: testName, passed: true, description: 'Sent empty line. PAN-OS should skip it.', details: { messagesSent: 1 } };
    }

    case 'empty_message': {
      await transport.send('');
      return { name: testName, passed: true, description: 'Sent empty message (auto-terminated). PAN-OS should skip it.', details: { messagesSent: 1 } };
    }

    case 'oversized_username': {
      const longUser = 'u'.repeat(300);
      const msg = `Username:${longUser} Address:10.0.0.1 Authentication Success\r\n`;
      await transport.send(msg);
      return { name: testName, passed: true, description: `Sent message with ${longUser.length}-char username.`, details: { messagesSent: 1, usernameLength: longUser.length } };
    }

    case 'special_chars_username': {
      const specialUsers = ['user@domain.com', 'DOMAIN\\user', 'user.name', 'user-name', 'user_name', 'user+tag'];
      let sent = 0;
      for (const user of specialUsers) {
        const msg = gen.login(user, '10.0.0.1');
        await transport.send(msg.message);
        sent++;
      }
      return {
        name: testName,
        passed: sent === specialUsers.length,
        description: `Sent ${sent}/${specialUsers.length} messages with special char usernames.`,
        error: sent < specialUsers.length ? `Only ${sent}/${specialUsers.length} sent` : null,
        details: { messagesSent: sent, totalUsers: specialUsers.length },
      };
    }

    case 'unicode_username': {
      const msg = 'Username:用户名 Address:10.0.0.1 Authentication Success\r\n';
      await transport.send(msg);
      return { name: testName, passed: true, description: 'Sent message with unicode username.', details: { messagesSent: 1 } };
    }

    case 'duplicate_ip_different_users': {
      const ip = '10.99.99.99';
      const users = ['user_first', 'user_second', 'user_third'];
      let sent = 0;
      for (const user of users) {
        const msg = gen.login(user, ip);
        await transport.send(msg.message);
        sent++;
      }
      return {
        name: testName,
        passed: sent === users.length,
        description: `Sent ${sent} login events for different users with same IP (${ip}). PAN-OS should map IP to last user.`,
        details: { messagesSent: sent, ip, users },
      };
    }

    case 'same_user_different_ips': {
      const user = 'multiip_user';
      const ips = ['10.1.1.1', '10.1.1.2', '10.1.1.3'];
      let sent = 0;
      for (const ip of ips) {
        const msg = gen.login(user, ip);
        await transport.send(msg.message);
        sent++;
      }
      return {
        name: testName,
        passed: sent === ips.length,
        description: `Sent ${sent} login events for same user (${user}) with different IPs. PAN-OS should create multiple mappings.`,
        details: { messagesSent: sent, user, ips },
      };
    }

    case 'white_noise_mixed': {
      const messages = [
        'Random system log entry #1\r\n',
        'Username:valid1 Address:10.0.0.1 Authentication Success\r\n',
        'kernel: [12345.678] eth0: link up\r\n',
        'Username:valid2 Address:10.0.0.2 Authentication Success\r\n',
        'sshd[1234]: Connection closed by 10.0.0.1\r\n',
        'Username:valid3 Address:10.0.0.3 Authentication Success\r\n',
      ];
      let sent = 0;
      for (const msg of messages) {
        await transport.send(msg);
        sent++;
      }
      return {
        name: testName,
        passed: sent === messages.length,
        description: `Sent ${sent} messages (3 auth + 3 noise). PAN-OS should parse 3 auth messages and ignore 3 noise.`,
        details: { messagesSent: sent, authCount: 3, noiseCount: 3 },
      };
    }

    case 'multiple_events_one_message': {
      const combined =
        'Username:multi1 Address:10.0.0.1 Authentication Success\r\n' +
        'Username:multi2 Address:10.0.0.2 Authentication Success\r\n' +
        'Username:multi3 Address:10.0.0.3 Authentication Success\r\n';
      await transport.send(combined);
      return {
        name: testName,
        passed: true,
        description: 'Sent 3 auth events in one send call. SSL: PAN-OS should parse all 3. UDP: PAN-OS parses first event only.',
        details: { messagesSent: 1, eventsInMessage: 3 },
      };
    }

    case 'partial_auth_message': {
      const messages = [
        'Authentication Success\r\n',
        'Username:partial1 Authentication Success\r\n',
        'Address:10.0.0.1 Authentication Success\r\n',
      ];
      let sent = 0;
      for (const msg of messages) {
        await transport.send(msg);
        sent++;
      }
      return {
        name: testName,
        passed: sent === messages.length,
        description: `Sent ${sent} partial auth messages (missing fields). PAN-OS should not create mappings for incomplete messages.`,
        details: { messagesSent: sent },
      };
    }

    case 'very_long_message': {
      const padding = 'x'.repeat(7900);
      const msg = `Username:longmsg Address:10.0.0.1 ${padding} Authentication Success\r\n`;
      await transport.send(msg);
      return {
        name: testName,
        passed: true,
        description: `Sent ${msg.length}-byte message (near SSL buffer limit).`,
        details: { messagesSent: 1, messageSize: msg.length },
      };
    }

    case 'null_bytes_in_message': {
      const msg = 'Username:null\x00test Address:10.0.0.1 Authentication Success\r\n';
      await transport.send(msg);
      return {
        name: testName,
        passed: true,
        description: 'Sent message with embedded null byte. PAN-OS may truncate at null (C string behavior).',
        details: { messagesSent: 1 },
      };
    }

    default:
      return {
        name: testName,
        passed: false,
        description: `Unknown test: ${testName}`,
        error: `No implementation for test '${testName}'`,
        details: {},
      };
  }
}


module.exports = {
  EDGE_CASE_TESTS,
  SCENARIO_STATUS,
  runLoginLogout,
  runStress,
  runEdgeCases,
  makeResult,
};
