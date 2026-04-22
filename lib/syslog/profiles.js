// PAN-OS syslog parse profile definitions
// Port of: AI-Agent/anton/apps/useridd/syslogsender/src/syslog_sender_sim/messages/profiles.py
//
// PAN-OS Reference:
//   - pan_user_id_syslog_profiles.h: pan_user_id_parse_profile_t structure
//   - pan_user_id_syslog_profiles.h: PAN_USER_ID_PROFILE_REGEX / PAN_USER_ID_PROFILE_FIELD
//   - syslog_test.c: Unit test showing field-based profile with prefix/delimiter

const { PROFILE_TYPE, EVENT_TYPE } = require('./constants');

/**
 * @typedef {Object} FieldConfig
 * @property {string} prefix - Prefix string to locate the field
 * @property {string} delimiter - Delimiter that ends the field value
 */

/**
 * @typedef {Object} RegexConfig
 * @property {string} pattern - PCRE regex pattern with capture group
 */

/**
 * @typedef {Object} ParseProfile
 * @property {string} name - Profile name
 * @property {string} profileType - 'field' or 'regex'
 * @property {string} eventString - String that identifies this as an auth event
 * @property {string} eventType - 'login' or 'logout'
 * @property {FieldConfig|RegexConfig} username - Username extraction config
 * @property {FieldConfig|RegexConfig} address - Address extraction config
 * @property {string} description - Human-readable description
 */

/**
 * Format a message that this profile can parse.
 * @param {ParseProfile} profile
 * @param {string} username
 * @param {string} ipAddress
 * @param {string} [domain]
 * @returns {string}
 */
function formatProfileMessage(profile, username, ipAddress, domain) {
  const fullUsername = domain ? `${domain}\\${username}` : username;

  if (profile.profileType === PROFILE_TYPE.FIELD) {
    const uCfg = profile.username;
    const aCfg = profile.address;
    return `${uCfg.prefix}${fullUsername}${uCfg.delimiter}${aCfg.prefix}${ipAddress}${aCfg.delimiter}${profile.eventString}`;
  } else {
    // Regex profiles — generate a message matching the configured patterns
    return `${profile.eventString}: Username:${fullUsername} Address:${ipAddress}`;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PREDEFINED PROFILES
// ═══════════════════════════════════════════════════════════════════════════════

const PREDEFINED_PROFILES = {
  // Default field-based profile (matches PAN-OS unit test format)
  'default-field-login': {
    name: 'default-field-login',
    profileType: PROFILE_TYPE.FIELD,
    eventString: 'Authentication Success',
    eventType: EVENT_TYPE.LOGIN,
    username: { prefix: 'Username:', delimiter: ' ' },
    address: { prefix: 'Address:', delimiter: ' ' },
    description: 'Default field-based login profile (matches PAN-OS unit test format)',
  },

  'default-field-logout': {
    name: 'default-field-logout',
    profileType: PROFILE_TYPE.FIELD,
    eventString: 'Authentication Logout',
    eventType: EVENT_TYPE.LOGOUT,
    username: { prefix: 'Username:', delimiter: ' ' },
    address: { prefix: 'Address:', delimiter: ' ' },
    description: 'Default field-based logout profile',
  },

  // Regex-based profiles
  'default-regex-login': {
    name: 'default-regex-login',
    profileType: PROFILE_TYPE.REGEX,
    eventString: 'Authentication Success',
    eventType: EVENT_TYPE.LOGIN,
    username: { pattern: 'Username:([^ ]+)' },
    address: { pattern: 'Address:([^ ]+)' },
    description: 'Default regex-based login profile',
  },

  'default-regex-logout': {
    name: 'default-regex-logout',
    profileType: PROFILE_TYPE.REGEX,
    eventString: 'Authentication Logout',
    eventType: EVENT_TYPE.LOGOUT,
    username: { pattern: 'Username:([^ ]+)' },
    address: { pattern: 'Address:([^ ]+)' },
    description: 'Default regex-based logout profile',
  },

  // Windows Security Event Log (Event ID 4624)
  'windows-security-login': {
    name: 'windows-security-login',
    profileType: PROFILE_TYPE.REGEX,
    eventString: 'An account was successfully logged on',
    eventType: EVENT_TYPE.LOGIN,
    username: { pattern: 'Account Name:\\s*(\\S+)' },
    address: { pattern: 'Source Network Address:\\s*(\\S+)' },
    description: 'Windows Security Event Log format (Event ID 4624)',
  },

  'windows-security-logout': {
    name: 'windows-security-logout',
    profileType: PROFILE_TYPE.REGEX,
    eventString: 'An account was logged off',
    eventType: EVENT_TYPE.LOGOUT,
    username: { pattern: 'Account Name:\\s*(\\S+)' },
    address: { pattern: 'Source Network Address:\\s*(\\S+)' },
    description: 'Windows Security Event Log format (Event ID 4634)',
  },

  // Cisco ISE
  'cisco-ise-login': {
    name: 'cisco-ise-login',
    profileType: PROFILE_TYPE.REGEX,
    eventString: 'Authentication succeeded',
    eventType: EVENT_TYPE.LOGIN,
    username: { pattern: 'UserName=([^,]+)' },
    address: { pattern: 'FramedIPAddress=([^,]+)' },
    description: 'Cisco ISE authentication success format',
  },
};


module.exports = {
  PREDEFINED_PROFILES,
  formatProfileMessage,
};
