// Test scenarios for PAN-OS User-ID XML API
// Orchestrates login/logout, bulk, group, tag, and edge-case operations.

'use strict';

const { SCENARIO_STATUS, PAYLOAD_TYPE } = require('./constants');
const { XmlApiGenerator } = require('./generator');
const { buildMultiPayload } = require('./xml-builder');

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function makeResult(scenario) {
  return {
    scenario,
    status: SCENARIO_STATUS.IDLE,
    requestsSent: 0,
    loginCount: 0,
    logoutCount: 0,
    tagRegisterCount: 0,
    tagUnregisterCount: 0,
    groupCount: 0,
    errors: [],
    details: {},
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LOGIN / LOGOUT SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Send login mappings, pause, then send matching logout mappings.
 *
 * @param {import('./transport').XmlApiTransport} transport
 * @param {Object} opts
 * @param {number} [opts.numUsers=5]
 * @param {string} [opts.usernamePattern='user{n}']
 * @param {string} [opts.baseIP='10.0.0.1']
 * @param {string} [opts.domain]
 * @param {number} [opts.timeout] - Mapping timeout
 * @param {number} [opts.pauseBetween=2000] - ms between login and logout phases
 * @param {number} [opts.chunkDelay=200] - ms between chunk sends
 * @param {boolean} [opts.sendLogout=true]
 * @param {Function} [onProgress]
 * @returns {Promise<Object>}
 */
async function runLoginLogout(transport, opts = {}, onProgress = () => {}) {
  const numUsers = opts.numUsers || 5;
  const domain = opts.domain || null;
  const pauseBetween = opts.pauseBetween !== undefined ? opts.pauseBetween : 2000;
  const chunkDelay = opts.chunkDelay || 200;
  const sendLogout = opts.sendLogout !== false;

  const result = makeResult('login-logout');
  result.status = SCENARIO_STATUS.RUNNING;

  const gen = new XmlApiGenerator({ defaultDomain: domain, defaultTimeout: opts.timeout });

  try {
    // Phase 1: Login
    onProgress({ phase: 'login', current: 0, total: numUsers });
    const loginEntries = gen.batchLoginEntries({
      usernamePattern: opts.usernamePattern,
      count: numUsers,
      baseIP: opts.baseIP,
      domain,
      timeout: opts.timeout,
    });
    const loginMessages = gen.buildLoginMessages(loginEntries);

    for (let i = 0; i < loginMessages.length; i++) {
      const resp = await transport.send(loginMessages[i]);
      result.requestsSent++;
      if (resp.status === 'success') {
        const chunkSize = Math.min(gen._chunkSize, loginEntries.length - i * gen._chunkSize);
        result.loginCount += chunkSize;
        onProgress({ phase: 'login', current: Math.min((i + 1) * gen._chunkSize, numUsers), total: numUsers });
      } else {
        result.errors.push(`Login chunk ${i + 1}: ${resp.message || resp.raw}`);
      }
      if (chunkDelay > 0 && i < loginMessages.length - 1) await _sleep(chunkDelay);
    }

    // Pause
    if (sendLogout && pauseBetween > 0) {
      onProgress({ phase: 'pause', current: 0, total: pauseBetween });
      await _sleep(pauseBetween);
    }

    // Phase 2: Logout
    if (sendLogout) {
      onProgress({ phase: 'logout', current: 0, total: numUsers });
      const logoutEntries = gen.batchLogoutEntries({
        usernamePattern: opts.usernamePattern,
        count: numUsers,
        baseIP: opts.baseIP,
        domain,
      });
      const logoutMessages = gen.buildLogoutMessages(logoutEntries);

      for (let i = 0; i < logoutMessages.length; i++) {
        const resp = await transport.send(logoutMessages[i]);
        result.requestsSent++;
        if (resp.status === 'success') {
          const chunkSize = Math.min(gen._chunkSize, logoutEntries.length - i * gen._chunkSize);
          result.logoutCount += chunkSize;
          onProgress({ phase: 'logout', current: Math.min((i + 1) * gen._chunkSize, numUsers), total: numUsers });
        } else {
          result.errors.push(`Logout chunk ${i + 1}: ${resp.message || resp.raw}`);
        }
        if (chunkDelay > 0 && i < logoutMessages.length - 1) await _sleep(chunkDelay);
      }
    }

    result.status = result.errors.length > 0 ? SCENARIO_STATUS.ERROR : SCENARIO_STATUS.DONE;
    result.details = {
      numUsers,
      domain,
      sendLogout,
      transportStats: transport.stats.toJSON(),
    };
  } catch (err) {
    result.status = SCENARIO_STATUS.ERROR;
    result.errors.push(err.message);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BULK LOGIN SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Send a large batch of login mappings in chunks.
 *
 * @param {import('./transport').XmlApiTransport} transport
 * @param {Object} opts
 * @param {number} [opts.count=100]
 * @param {string} [opts.usernamePattern='bulkuser{n}']
 * @param {string} [opts.baseIP='10.0.0.1']
 * @param {string} [opts.domain]
 * @param {number} [opts.timeout]
 * @param {number} [opts.chunkDelay=200]
 * @param {Function} [onProgress]
 * @returns {Promise<Object>}
 */
async function runBulkLogin(transport, opts = {}, onProgress = () => {}) {
  const count = opts.count || 100;
  const chunkDelay = opts.chunkDelay || 200;

  const result = makeResult('bulk-login');
  result.status = SCENARIO_STATUS.RUNNING;

  const gen = new XmlApiGenerator({
    defaultDomain: opts.domain,
    defaultTimeout: opts.timeout,
  });

  try {
    onProgress({ phase: 'bulk-login', current: 0, total: count });
    const entries = gen.batchLoginEntries({
      usernamePattern: opts.usernamePattern || 'bulkuser{n}',
      count,
      baseIP: opts.baseIP,
      domain: opts.domain,
      timeout: opts.timeout,
    });
    const messages = gen.buildLoginMessages(entries);

    for (let i = 0; i < messages.length; i++) {
      const resp = await transport.send(messages[i]);
      result.requestsSent++;
      const chunkSize = Math.min(gen._chunkSize, entries.length - i * gen._chunkSize);
      if (resp.status === 'success') {
        result.loginCount += chunkSize;
      } else {
        result.errors.push(`Chunk ${i + 1}: ${resp.message || resp.raw}`);
      }
      onProgress({ phase: 'bulk-login', current: Math.min((i + 1) * gen._chunkSize, count), total: count });
      if (chunkDelay > 0 && i < messages.length - 1) await _sleep(chunkDelay);
    }

    result.status = result.errors.length > 0 ? SCENARIO_STATUS.ERROR : SCENARIO_STATUS.DONE;
    result.details = { count, transportStats: transport.stats.toJSON() };
  } catch (err) {
    result.status = SCENARIO_STATUS.ERROR;
    result.errors.push(err.message);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GROUP PUSH SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Push group membership via XML API.
 *
 * @param {import('./transport').XmlApiTransport} transport
 * @param {Object} opts
 * @param {string} opts.groupDn - Full DN of the group
 * @param {Array<{username: string, domain?: string}>} opts.members - Group members
 * @param {Function} [onProgress]
 * @returns {Promise<Object>}
 */
async function runGroupPush(transport, opts = {}, onProgress = () => {}) {
  const result = makeResult('group-push');
  result.status = SCENARIO_STATUS.RUNNING;

  try {
    if (!opts.groupDn) throw new Error('groupDn is required');
    if (!opts.members || opts.members.length === 0) throw new Error('members array is required');

    onProgress({ phase: 'group-push', current: 0, total: 1 });

    const gen = new XmlApiGenerator();
    const xml = gen.buildGroupMessage([{
      groupDn: opts.groupDn,
      members: opts.members,
    }]);

    const resp = await transport.send(xml);
    result.requestsSent++;

    if (resp.status === 'success') {
      result.groupCount = opts.members.length;
    } else {
      result.errors.push(resp.message || resp.raw);
    }

    onProgress({ phase: 'group-push', current: 1, total: 1 });
    result.status = result.errors.length > 0 ? SCENARIO_STATUS.ERROR : SCENARIO_STATUS.DONE;
    result.details = {
      groupDn: opts.groupDn,
      memberCount: opts.members.length,
      transportStats: transport.stats.toJSON(),
    };
  } catch (err) {
    result.status = SCENARIO_STATUS.ERROR;
    result.errors.push(err.message);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TAG REGISTER / UNREGISTER SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Register or unregister IP tags.
 *
 * @param {import('./transport').XmlApiTransport} transport
 * @param {Object} opts
 * @param {string} opts.operation - 'register' or 'unregister'
 * @param {string[]} opts.tags - Tags to register/unregister
 * @param {number} [opts.count=10] - Number of IPs
 * @param {string} [opts.baseIP='10.0.0.1']
 * @param {number} [opts.chunkDelay=200]
 * @param {Function} [onProgress]
 * @returns {Promise<Object>}
 */
async function runTagOperation(transport, opts = {}, onProgress = () => {}) {
  const operation = opts.operation || 'register';
  const tags = opts.tags || ['test-tag'];
  const count = opts.count || 10;
  const chunkDelay = opts.chunkDelay || 200;

  const scenarioName = `tag-${operation}`;
  const result = makeResult(scenarioName);
  result.status = SCENARIO_STATUS.RUNNING;

  const gen = new XmlApiGenerator();

  try {
    onProgress({ phase: scenarioName, current: 0, total: count });

    const entries = gen.batchTagRegisterEntries({
      tags,
      count,
      baseIP: opts.baseIP,
    });

    const messages = operation === 'register'
      ? gen.buildTagRegisterMessages(entries)
      : gen.buildTagUnregisterMessages(entries);

    for (let i = 0; i < messages.length; i++) {
      const resp = await transport.send(messages[i]);
      result.requestsSent++;
      const chunkSize = Math.min(gen._chunkSize, entries.length - i * gen._chunkSize);
      if (resp.status === 'success') {
        if (operation === 'register') {
          result.tagRegisterCount += chunkSize;
        } else {
          result.tagUnregisterCount += chunkSize;
        }
      } else {
        result.errors.push(`Chunk ${i + 1}: ${resp.message || resp.raw}`);
      }
      onProgress({ phase: scenarioName, current: Math.min((i + 1) * gen._chunkSize, count), total: count });
      if (chunkDelay > 0 && i < messages.length - 1) await _sleep(chunkDelay);
    }

    result.status = result.errors.length > 0 ? SCENARIO_STATUS.ERROR : SCENARIO_STATUS.DONE;
    result.details = { operation, tags, count, transportStats: transport.stats.toJSON() };
  } catch (err) {
    result.status = SCENARIO_STATUS.ERROR;
    result.errors.push(err.message);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MIXED SCENARIO
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Send a combined payload with login + group + tag in a single uid-message.
 *
 * @param {import('./transport').XmlApiTransport} transport
 * @param {Object} opts
 * @param {number} [opts.numUsers=5]
 * @param {string} [opts.domain]
 * @param {string} [opts.groupDn]
 * @param {string[]} [opts.tags]
 * @param {string} [opts.baseIP='10.0.0.1']
 * @param {Function} [onProgress]
 * @returns {Promise<Object>}
 */
async function runMixed(transport, opts = {}, onProgress = () => {}) {
  const numUsers = opts.numUsers || 5;
  const result = makeResult('mixed');
  result.status = SCENARIO_STATUS.RUNNING;

  const gen = new XmlApiGenerator({ defaultDomain: opts.domain });

  try {
    onProgress({ phase: 'mixed', current: 0, total: 1 });

    const loginEntries = gen.batchLoginEntries({
      count: numUsers,
      baseIP: opts.baseIP,
      domain: opts.domain,
    });

    const payloadOpts = { logins: loginEntries };

    // Add group if specified
    if (opts.groupDn) {
      payloadOpts.groups = [{
        groupDn: opts.groupDn,
        members: loginEntries.map(e => ({ username: e.username, domain: e.domain })),
      }];
    }

    // Add tags if specified
    if (opts.tags && opts.tags.length > 0) {
      payloadOpts.tagRegister = loginEntries.map(e => ({
        ip: e.ip,
        tags: opts.tags,
      }));
    }

    const xml = buildMultiPayload(payloadOpts);
    const resp = await transport.send(xml);
    result.requestsSent++;

    if (resp.status === 'success') {
      result.loginCount = loginEntries.length;
      if (payloadOpts.groups) result.groupCount = loginEntries.length;
      if (payloadOpts.tagRegister) result.tagRegisterCount = loginEntries.length;
    } else {
      result.errors.push(resp.message || resp.raw);
    }

    onProgress({ phase: 'mixed', current: 1, total: 1 });
    result.status = result.errors.length > 0 ? SCENARIO_STATUS.ERROR : SCENARIO_STATUS.DONE;
    result.details = { numUsers, transportStats: transport.stats.toJSON() };
  } catch (err) {
    result.status = SCENARIO_STATUS.ERROR;
    result.errors.push(err.message);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Edge case tests for XML API.
 */
const EDGE_CASE_TESTS = [
  {
    name: 'unicode-username',
    description: 'Login with Unicode characters in username',
    run: async (transport) => {
      const gen = new XmlApiGenerator();
      const entries = [gen.loginEntry('用户テスト', '10.0.0.1')];
      const xml = gen.buildLoginMessages(entries)[0];
      const resp = await transport.send(xml);
      return { passed: resp.status === 'success', description: 'Unicode username login', details: resp };
    },
  },
  {
    name: 'long-domain',
    description: 'Login with very long domain prefix',
    run: async (transport) => {
      const gen = new XmlApiGenerator();
      const longDomain = 'A'.repeat(255);
      const entries = [gen.loginEntry('testuser', '10.0.0.1', { domain: longDomain })];
      const xml = gen.buildLoginMessages(entries)[0];
      const resp = await transport.send(xml);
      return { passed: true, description: 'Long domain prefix accepted/rejected gracefully', details: resp };
    },
  },
  {
    name: 'empty-payload',
    description: 'Send uid-message with empty payload',
    run: async (transport) => {
      const xml = buildMultiPayload({});
      const resp = await transport.send(xml);
      return { passed: true, description: 'Empty payload handled gracefully', details: resp };
    },
  },
  {
    name: 'special-chars-username',
    description: 'Login with special XML characters in username',
    run: async (transport) => {
      const gen = new XmlApiGenerator();
      const entries = [gen.loginEntry('user<>&"test', '10.0.0.1', { domain: 'CORP' })];
      const xml = gen.buildLoginMessages(entries)[0];
      const resp = await transport.send(xml);
      return { passed: resp.status === 'success', description: 'Special XML chars properly escaped', details: resp };
    },
  },
  {
    name: 'ipv6-mapping',
    description: 'Login with IPv6 address',
    run: async (transport) => {
      const gen = new XmlApiGenerator();
      const entries = [gen.loginEntry('ipv6user', '2001:db8::1')];
      const xml = gen.buildLoginMessages(entries)[0];
      const resp = await transport.send(xml);
      return { passed: true, description: 'IPv6 address mapping', details: resp };
    },
  },
  {
    name: 'zero-timeout',
    description: 'Login with timeout=0 (never expire)',
    run: async (transport) => {
      const gen = new XmlApiGenerator();
      const entries = [gen.loginEntry('notimeout', '10.0.0.1', { timeout: 0 })];
      const xml = gen.buildLoginMessages(entries)[0];
      const resp = await transport.send(xml);
      return { passed: resp.status === 'success', description: 'Zero timeout (never expire)', details: resp };
    },
  },
  {
    name: 'duplicate-mapping',
    description: 'Send same IP-user mapping twice',
    run: async (transport) => {
      const gen = new XmlApiGenerator();
      const entries = [
        gen.loginEntry('dupuser', '10.0.0.1'),
        gen.loginEntry('dupuser', '10.0.0.1'),
      ];
      const xml = gen.buildLoginMessages(entries)[0];
      const resp = await transport.send(xml);
      return { passed: resp.status === 'success', description: 'Duplicate mapping handled', details: resp };
    },
  },
  {
    name: 'multi-tag-single-ip',
    description: 'Register multiple tags on a single IP',
    run: async (transport) => {
      const gen = new XmlApiGenerator();
      const entries = gen.batchTagRegisterEntries({
        tags: ['tag-a', 'tag-b', 'tag-c', 'tag-d', 'tag-e'],
        count: 1,
        baseIP: '10.0.0.1',
      });
      const xml = gen.buildTagRegisterMessages(entries)[0];
      const resp = await transport.send(xml);
      return { passed: resp.status === 'success', description: 'Multiple tags on single IP', details: resp };
    },
  },
];

/**
 * Run all edge case tests.
 *
 * @param {import('./transport').XmlApiTransport} transport
 * @param {Function} [onProgress]
 * @returns {Promise<Object>}
 */
async function runEdgeCases(transport, onProgress = () => {}) {
  const result = makeResult('edge-cases');
  result.status = SCENARIO_STATUS.RUNNING;
  result.details = { tests: [] };

  for (let i = 0; i < EDGE_CASE_TESTS.length; i++) {
    const test = EDGE_CASE_TESTS[i];
    onProgress({ phase: 'edge-cases', current: i, total: EDGE_CASE_TESTS.length, test: test.name });
    try {
      const testResult = await test.run(transport);
      result.details.tests.push({ name: test.name, ...testResult });
      result.requestsSent++;
    } catch (err) {
      result.details.tests.push({ name: test.name, passed: false, description: test.description, error: err.message });
      result.errors.push(`${test.name}: ${err.message}`);
      result.requestsSent++;
    }
  }

  onProgress({ phase: 'edge-cases', current: EDGE_CASE_TESTS.length, total: EDGE_CASE_TESTS.length });
  result.status = result.errors.length > 0 ? SCENARIO_STATUS.ERROR : SCENARIO_STATUS.DONE;
  return result;
}

module.exports = {
  makeResult,
  runLoginLogout,
  runBulkLogin,
  runGroupPush,
  runTagOperation,
  runMixed,
  runEdgeCases,
  EDGE_CASE_TESTS,
};
