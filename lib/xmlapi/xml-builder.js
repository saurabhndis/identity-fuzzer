// XML payload builder for PAN-OS User-ID XML API
// Constructs uid-message XML for login, logout, groups, and tag operations.
//
// PAN-OS Reference:
//   - User-ID XML API documentation
//   - pan_user_id_xmlapi.c: pan_user_id_xmlapi_parse_uid_message()

'use strict';

const { UID_MESSAGE_VERSION, UID_MESSAGE_TYPE } = require('./constants');

// ═══════════════════════════════════════════════════════════════════════════════
//  XML Escaping
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Escape special XML characters in attribute values and text content.
 * @param {string} str
 * @returns {string}
 */
function xmlEscape(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Format a username with optional domain prefix.
 * @param {string} username - The username (e.g. "jdoe")
 * @param {string} [domain] - Optional domain (e.g. "CORP")
 * @returns {string} Formatted as "DOMAIN\\username" or just "username"
 */
function formatUsername(username, domain) {
  if (domain) {
    return `${domain}\\${username}`;
  }
  return username;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Login / Logout Payloads
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a <login> payload with one or more entries.
 *
 * @param {Array<{username: string, ip: string, domain?: string, timeout?: number}>} entries
 * @returns {string} XML fragment: <login><entry .../> ...</login>
 *
 * @example
 *   buildLoginPayload([{ username: 'jdoe', ip: '10.1.1.1', domain: 'CORP', timeout: 60 }])
 *   // => '<login><entry name="CORP\\jdoe" ip="10.1.1.1" timeout="60"/></login>'
 */
function buildLoginPayload(entries) {
  if (!entries || entries.length === 0) return '';
  const items = entries.map(e => {
    const name = xmlEscape(formatUsername(e.username, e.domain));
    const ip = xmlEscape(e.ip);
    const timeout = e.timeout !== undefined && e.timeout !== null
      ? ` timeout="${xmlEscape(String(e.timeout))}"`
      : '';
    return `<entry name="${name}" ip="${ip}"${timeout}/>`;
  });
  return `<login>${items.join('')}</login>`;
}

/**
 * Build a <logout> payload with one or more entries.
 *
 * @param {Array<{username: string, ip: string, domain?: string}>} entries
 * @returns {string} XML fragment: <logout><entry .../> ...</logout>
 */
function buildLogoutPayload(entries) {
  if (!entries || entries.length === 0) return '';
  const items = entries.map(e => {
    const name = xmlEscape(formatUsername(e.username, e.domain));
    const ip = xmlEscape(e.ip);
    return `<entry name="${name}" ip="${ip}"/>`;
  });
  return `<logout>${items.join('')}</logout>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Group Membership Payload
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a <groups> payload for pushing group membership.
 *
 * @param {Array<{groupDn: string, members: Array<{username: string, domain?: string}>}>} groups
 * @returns {string} XML fragment
 *
 * @example
 *   buildGroupPayload([{
 *     groupDn: 'cn=vpn users,cn=users,dc=testlab,dc=local',
 *     members: [{ username: 'jdoe', domain: 'CORP' }]
 *   }])
 */
function buildGroupPayload(groups) {
  if (!groups || groups.length === 0) return '';
  const items = groups.map(g => {
    const groupName = xmlEscape(g.groupDn);
    const memberEntries = (g.members || []).map(m => {
      const name = xmlEscape(formatUsername(m.username, m.domain));
      return `<entry name="${name}"/>`;
    });
    return `<entry name="${groupName}"><members>${memberEntries.join('')}</members></entry>`;
  });
  return `<groups>${items.join('')}</groups>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  IP-Tag Payloads
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a <tag><register>...</register></tag> payload.
 *
 * @param {Array<{ip: string, tags: string[]}>} entries
 * @returns {string} XML fragment
 *
 * @example
 *   buildTagRegisterPayload([{ ip: '10.1.1.1', tags: ['web-server', 'production'] }])
 */
function buildTagRegisterPayload(entries) {
  if (!entries || entries.length === 0) return '';
  const items = entries.map(e => {
    const ip = xmlEscape(e.ip);
    const tagMembers = (e.tags || []).map(t => `<member>${xmlEscape(t)}</member>`);
    return `<entry ip="${ip}"><tag>${tagMembers.join('')}</tag></entry>`;
  });
  return `<tag><register>${items.join('')}</register></tag>`;
}

/**
 * Build a <tag><unregister>...</unregister></tag> payload.
 *
 * @param {Array<{ip: string, tags: string[]}>} entries
 * @returns {string} XML fragment
 */
function buildTagUnregisterPayload(entries) {
  if (!entries || entries.length === 0) return '';
  const items = entries.map(e => {
    const ip = xmlEscape(e.ip);
    const tagMembers = (e.tags || []).map(t => `<member>${xmlEscape(t)}</member>`);
    return `<entry ip="${ip}"><tag>${tagMembers.join('')}</tag></entry>`;
  });
  return `<tag><unregister>${items.join('')}</unregister></tag>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  uid-message Envelope
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Wrap payload XML in the uid-message envelope.
 *
 * @param {string} payloadXml - Inner payload XML (login, logout, groups, tag fragments)
 * @returns {string} Complete uid-message XML
 *
 * @example
 *   buildUidMessage(buildLoginPayload([...]))
 *   // => '<uid-message><version>2.0</version><type>update</type><payload>...</payload></uid-message>'
 */
function buildUidMessage(payloadXml) {
  return [
    '<uid-message>',
    `<version>${UID_MESSAGE_VERSION}</version>`,
    `<type>${UID_MESSAGE_TYPE}</type>`,
    `<payload>${payloadXml}</payload>`,
    '</uid-message>',
  ].join('');
}

/**
 * Build a complete uid-message with multiple payload sections.
 * Combines login, logout, groups, and tag operations into a single message.
 *
 * @param {Object} opts
 * @param {Array} [opts.logins] - Login entries
 * @param {Array} [opts.logouts] - Logout entries
 * @param {Array} [opts.groups] - Group membership entries
 * @param {Array} [opts.tagRegister] - Tag register entries
 * @param {Array} [opts.tagUnregister] - Tag unregister entries
 * @returns {string} Complete uid-message XML
 */
function buildMultiPayload(opts = {}) {
  const parts = [];
  if (opts.logins && opts.logins.length > 0) {
    parts.push(buildLoginPayload(opts.logins));
  }
  if (opts.logouts && opts.logouts.length > 0) {
    parts.push(buildLogoutPayload(opts.logouts));
  }
  if (opts.groups && opts.groups.length > 0) {
    parts.push(buildGroupPayload(opts.groups));
  }
  if (opts.tagRegister && opts.tagRegister.length > 0) {
    parts.push(buildTagRegisterPayload(opts.tagRegister));
  }
  if (opts.tagUnregister && opts.tagUnregister.length > 0) {
    parts.push(buildTagUnregisterPayload(opts.tagUnregister));
  }
  return buildUidMessage(parts.join(''));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Response Parsing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Parse a PAN-OS XML API response.
 *
 * Success: <response status="success"><msg>...</msg></response>
 * Error:   <response status="error" code="..."><msg><line>detail</line></msg></response>
 *
 * @param {string} responseXml - Raw XML response from PAN-OS
 * @returns {{status: string, message: string, code: string|null, raw: string}}
 */
function parseResponse(responseXml) {
  const raw = String(responseXml || '');

  // Extract status attribute
  const statusMatch = raw.match(/status="([^"]+)"/);
  const status = statusMatch ? statusMatch[1] : 'unknown';

  // Extract code attribute (error responses)
  const codeMatch = raw.match(/code="([^"]+)"/);
  const code = codeMatch ? codeMatch[1] : null;

  // Extract message — try <line> first (error), then <msg> (success)
  let message = '';
  const lineMatch = raw.match(/<line>([^<]*)<\/line>/);
  if (lineMatch) {
    message = lineMatch[1];
  } else {
    const msgMatch = raw.match(/<msg>([^<]*)<\/msg>/);
    if (msgMatch) {
      message = msgMatch[1];
    }
  }

  return { status, message, code, raw };
}

module.exports = {
  xmlEscape,
  formatUsername,
  buildLoginPayload,
  buildLogoutPayload,
  buildGroupPayload,
  buildTagRegisterPayload,
  buildTagUnregisterPayload,
  buildUidMessage,
  buildMultiPayload,
  parseResponse,
};
