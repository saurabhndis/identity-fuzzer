// Batch generator for PAN-OS User-ID XML API payloads
// Generates login/logout entries, group memberships, and tag operations
// with sequential IPs and configurable usernames.

'use strict';

const { IPGenerator } = require('../syslog/ip-generator');
const { MAX_ENTRIES_PER_MESSAGE } = require('./constants');
const {
  buildLoginPayload,
  buildLogoutPayload,
  buildGroupPayload,
  buildTagRegisterPayload,
  buildTagUnregisterPayload,
  buildUidMessage,
} = require('./xml-builder');


// ═══════════════════════════════════════════════════════════════════════════════
//  XML API GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════

class XmlApiGenerator {
  /**
   * @param {Object} [opts]
   * @param {string} [opts.defaultDomain] - Default domain prefix (e.g. "CORP")
   * @param {number} [opts.defaultTimeout] - Default mapping timeout in seconds
   * @param {number} [opts.chunkSize=500] - Max entries per uid-message
   */
  constructor(opts = {}) {
    this._defaultDomain = opts.defaultDomain || null;
    this._defaultTimeout = opts.defaultTimeout !== undefined ? opts.defaultTimeout : null;
    this._chunkSize = opts.chunkSize || MAX_ENTRIES_PER_MESSAGE;
  }

  // ── Single Entry Helpers ──────────────────────────────────────────────────

  /**
   * Create a single login entry object.
   * @param {string} username
   * @param {string} ip
   * @param {Object} [opts]
   * @param {string} [opts.domain]
   * @param {number} [opts.timeout]
   * @returns {{username: string, ip: string, domain?: string, timeout?: number}}
   */
  loginEntry(username, ip, opts = {}) {
    const entry = { username, ip };
    const domain = opts.domain || this._defaultDomain;
    if (domain) entry.domain = domain;
    const timeout = opts.timeout !== undefined ? opts.timeout : this._defaultTimeout;
    if (timeout !== null && timeout !== undefined) entry.timeout = timeout;
    return entry;
  }

  /**
   * Create a single logout entry object.
   * @param {string} username
   * @param {string} ip
   * @param {Object} [opts]
   * @param {string} [opts.domain]
   * @returns {{username: string, ip: string, domain?: string}}
   */
  logoutEntry(username, ip, opts = {}) {
    const entry = { username, ip };
    const domain = opts.domain || this._defaultDomain;
    if (domain) entry.domain = domain;
    return entry;
  }

  // ── Batch Generation ──────────────────────────────────────────────────────

  /**
   * Generate a batch of login entries with sequential IPs.
   *
   * @param {Object} [opts]
   * @param {string} [opts.usernamePattern='user{n}'] - Pattern with {n} placeholder
   * @param {number} [opts.count=10] - Number of entries
   * @param {string} [opts.baseIP='10.0.0.1'] - Starting IP address
   * @param {string} [opts.domain] - Domain prefix
   * @param {number} [opts.timeout] - Mapping timeout
   * @returns {Array<{username: string, ip: string, domain?: string, timeout?: number}>}
   */
  batchLoginEntries(opts = {}) {
    const pattern = opts.usernamePattern || 'user{n}';
    const count = opts.count || 10;
    const baseIP = opts.baseIP || '10.0.0.1';
    const ipGen = new IPGenerator(baseIP);
    const entries = [];

    for (let i = 0; i < count; i++) {
      const username = pattern.replace('{n}', String(i + 1));
      const ip = ipGen.next();
      entries.push(this.loginEntry(username, ip, {
        domain: opts.domain,
        timeout: opts.timeout,
      }));
    }
    return entries;
  }

  /**
   * Generate a batch of logout entries with sequential IPs.
   *
   * @param {Object} [opts] - Same as batchLoginEntries (minus timeout)
   * @returns {Array<{username: string, ip: string, domain?: string}>}
   */
  batchLogoutEntries(opts = {}) {
    const pattern = opts.usernamePattern || 'user{n}';
    const count = opts.count || 10;
    const baseIP = opts.baseIP || '10.0.0.1';
    const ipGen = new IPGenerator(baseIP);
    const entries = [];

    for (let i = 0; i < count; i++) {
      const username = pattern.replace('{n}', String(i + 1));
      const ip = ipGen.next();
      entries.push(this.logoutEntry(username, ip, { domain: opts.domain }));
    }
    return entries;
  }

  /**
   * Generate tag register entries for a batch of IPs.
   *
   * @param {Object} [opts]
   * @param {string[]} opts.tags - Tags to register
   * @param {number} [opts.count=10] - Number of IPs
   * @param {string} [opts.baseIP='10.0.0.1'] - Starting IP
   * @returns {Array<{ip: string, tags: string[]}>}
   */
  batchTagRegisterEntries(opts = {}) {
    const tags = opts.tags || ['test-tag'];
    const count = opts.count || 10;
    const baseIP = opts.baseIP || '10.0.0.1';
    const ipGen = new IPGenerator(baseIP);
    const entries = [];

    for (let i = 0; i < count; i++) {
      entries.push({ ip: ipGen.next(), tags: [...tags] });
    }
    return entries;
  }

  /**
   * Generate tag unregister entries for a batch of IPs.
   *
   * @param {Object} [opts] - Same as batchTagRegisterEntries
   * @returns {Array<{ip: string, tags: string[]}>}
   */
  batchTagUnregisterEntries(opts = {}) {
    return this.batchTagRegisterEntries(opts); // Same structure
  }

  // ── XML Message Generation ────────────────────────────────────────────────

  /**
   * Generate chunked uid-message XML payloads for login entries.
   * Splits entries into chunks of chunkSize to respect PAN-OS limits.
   *
   * @param {Array} entries - Login entries
   * @returns {string[]} Array of complete uid-message XML strings
   */
  buildLoginMessages(entries) {
    return this._chunkAndBuild(entries, buildLoginPayload);
  }

  /**
   * Generate chunked uid-message XML payloads for logout entries.
   * @param {Array} entries - Logout entries
   * @returns {string[]} Array of complete uid-message XML strings
   */
  buildLogoutMessages(entries) {
    return this._chunkAndBuild(entries, buildLogoutPayload);
  }

  /**
   * Generate a uid-message XML for group membership push.
   * @param {Array} groups - Group entries [{groupDn, members}]
   * @returns {string} Complete uid-message XML
   */
  buildGroupMessage(groups) {
    return buildUidMessage(buildGroupPayload(groups));
  }

  /**
   * Generate chunked uid-message XML payloads for tag register.
   * @param {Array} entries - Tag register entries
   * @returns {string[]} Array of complete uid-message XML strings
   */
  buildTagRegisterMessages(entries) {
    return this._chunkAndBuild(entries, buildTagRegisterPayload);
  }

  /**
   * Generate chunked uid-message XML payloads for tag unregister.
   * @param {Array} entries - Tag unregister entries
   * @returns {string[]} Array of complete uid-message XML strings
   */
  buildTagUnregisterMessages(entries) {
    return this._chunkAndBuild(entries, buildTagUnregisterPayload);
  }

  /**
   * Split entries into chunks and build uid-message XML for each chunk.
   * @private
   */
  _chunkAndBuild(entries, buildFn) {
    const messages = [];
    for (let i = 0; i < entries.length; i += this._chunkSize) {
      const chunk = entries.slice(i, i + this._chunkSize);
      messages.push(buildUidMessage(buildFn(chunk)));
    }
    return messages;
  }
}

module.exports = { XmlApiGenerator };
