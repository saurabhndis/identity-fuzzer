// Message generator for syslog sender simulator
// Port of: AI-Agent/anton/apps/useridd/syslogsender/src/syslog_sender_sim/messages/generator.py
//
// PAN-OS Reference:
//   - syslog_test.c: Expected format "Username:Amro Address:192.1.1.110 Authentication Success"
//   - proxyServerStressTest.py: Generates unique usernames like "user_<server>_<seq>"

const { getTemplate, renderTemplate } = require('./templates');
const { PREDEFINED_PROFILES, formatProfileMessage } = require('./profiles');
const { IPGenerator } = require('./ip-generator');

/**
 * @typedef {Object} GeneratedMessage
 * @property {string} message - Formatted syslog message string (with \r\n terminator)
 * @property {string} username - Username embedded in the message
 * @property {string} ipAddress - IP address embedded in the message
 * @property {string|null} domain - Domain prefix (if any)
 * @property {string} eventType - "login" or "logout"
 * @property {string} templateName - Name of the template used
 * @property {string} profileName - Name of the compatible parse profile
 */

class MessageGenerator {
  /**
   * @param {Object} [opts]
   * @param {string} [opts.defaultTemplate='field-login']
   * @param {string|null} [opts.defaultDomain=null]
   * @param {string} [opts.defaultHostname='syslog-sim']
   */
  constructor(opts = {}) {
    this._defaultTemplate = opts.defaultTemplate || 'field-login';
    this._defaultDomain = opts.defaultDomain || null;
    this._defaultHostname = opts.defaultHostname || 'syslog-sim';
    this._generatedCount = 0;
  }

  /**
   * Generate a login event message.
   * @param {string} username
   * @param {string} ipAddress
   * @param {Object} [opts]
   * @param {string} [opts.domain]
   * @param {string} [opts.template]
   * @param {string} [opts.hostname]
   * @returns {GeneratedMessage}
   */
  login(username, ipAddress, opts = {}) {
    return this._generate({
      username,
      ipAddress,
      eventType: 'login',
      domain: opts.domain,
      templateName: opts.template || this._defaultTemplate,
      hostname: opts.hostname || this._defaultHostname,
    });
  }

  /**
   * Generate a logout event message.
   * @param {string} username
   * @param {string} ipAddress
   * @param {Object} [opts]
   * @param {string} [opts.domain]
   * @param {string} [opts.template]
   * @param {string} [opts.hostname]
   * @returns {GeneratedMessage}
   */
  logout(username, ipAddress, opts = {}) {
    let template = opts.template;
    if (!template) {
      // Auto-select logout template variant
      template = this._defaultTemplate.replace('login', 'logout');
      if (template === this._defaultTemplate) {
        template = 'field-logout';
      }
    }
    return this._generate({
      username,
      ipAddress,
      eventType: 'logout',
      domain: opts.domain,
      templateName: template,
      hostname: opts.hostname || this._defaultHostname,
    });
  }

  /**
   * Generate a message using a specific parse profile.
   * @param {string} profileName
   * @param {string} username
   * @param {string} ipAddress
   * @param {Object} [opts]
   * @param {string} [opts.domain]
   * @returns {GeneratedMessage}
   */
  fromProfile(profileName, username, ipAddress, opts = {}) {
    if (!PREDEFINED_PROFILES[profileName]) {
      const available = Object.keys(PREDEFINED_PROFILES).sort().join(', ');
      throw new Error(`Profile '${profileName}' not found. Available: ${available}`);
    }

    const profile = PREDEFINED_PROFILES[profileName];
    const useDomain = opts.domain || this._defaultDomain;
    const rawMessage = formatProfileMessage(profile, username, ipAddress, useDomain);
    const message = rawMessage + '\r\n';

    this._generatedCount++;

    return {
      message,
      username,
      ipAddress,
      domain: useDomain,
      eventType: profile.eventType,
      templateName: `profile:${profileName}`,
      profileName,
    };
  }

  /**
   * Generate a batch of login event messages with unique users and IPs.
   * @param {Object} [opts]
   * @param {string} [opts.usernamePattern='user_{n}']
   * @param {number} [opts.count=10]
   * @param {string} [opts.baseIP='192.168.1.1']
   * @param {string} [opts.domain]
   * @param {string} [opts.template]
   * @param {string} [opts.hostname]
   * @returns {GeneratedMessage[]}
   */
  batchLogin(opts = {}) {
    const pattern = opts.usernamePattern || 'user_{n}';
    const count = opts.count || 10;
    const baseIP = opts.baseIP || '192.168.1.1';
    const ipGen = new IPGenerator(baseIP);
    const messages = [];

    for (let i = 0; i < count; i++) {
      const username = pattern.replace('{n}', String(i));
      const ip = ipGen.next();
      messages.push(this.login(username, ip, {
        domain: opts.domain,
        template: opts.template,
        hostname: opts.hostname,
      }));
    }

    return messages;
  }

  /**
   * Generate a batch of logout event messages.
   * @param {Object} [opts] - Same as batchLogin
   * @returns {GeneratedMessage[]}
   */
  batchLogout(opts = {}) {
    const pattern = opts.usernamePattern || 'user_{n}';
    const count = opts.count || 10;
    const baseIP = opts.baseIP || '192.168.1.1';
    const ipGen = new IPGenerator(baseIP);
    const messages = [];

    for (let i = 0; i < count; i++) {
      const username = pattern.replace('{n}', String(i));
      const ip = ipGen.next();
      messages.push(this.logout(username, ip, {
        domain: opts.domain,
        template: opts.template,
        hostname: opts.hostname,
      }));
    }

    return messages;
  }

  /**
   * Generate a matching login/logout pair for the same user.
   * @param {string} username
   * @param {string} ipAddress
   * @param {Object} [opts]
   * @returns {[GeneratedMessage, GeneratedMessage]}
   */
  loginLogoutPair(username, ipAddress, opts = {}) {
    const loginMsg = this.login(username, ipAddress, {
      domain: opts.domain,
      template: opts.loginTemplate,
    });
    const logoutMsg = this.logout(username, ipAddress, {
      domain: opts.domain,
      template: opts.logoutTemplate,
    });
    return [loginMsg, logoutMsg];
  }

  /**
   * Generate a custom message (bypass templates).
   * @param {string} message
   * @param {Object} [opts]
   * @param {string} [opts.username='']
   * @param {string} [opts.ipAddress='']
   * @param {string} [opts.eventType='login']
   * @returns {GeneratedMessage}
   */
  custom(message, opts = {}) {
    if (!message.endsWith('\n')) {
      message += '\r\n';
    }
    this._generatedCount++;
    return {
      message,
      username: opts.username || '',
      ipAddress: opts.ipAddress || '',
      domain: null,
      eventType: opts.eventType || 'login',
      templateName: 'custom',
      profileName: '',
    };
  }

  /** Total number of messages generated. */
  get generatedCount() {
    return this._generatedCount;
  }

  /**
   * Internal message generation using a template.
   * @private
   */
  _generate({ username, ipAddress, eventType, domain, templateName, hostname }) {
    const tmpl = getTemplate(templateName);
    const useDomain = domain || this._defaultDomain;

    const rawMessage = renderTemplate(tmpl, {
      username,
      ip: ipAddress,
      domain: useDomain,
      hostname,
    });
    const message = rawMessage + '\r\n';

    this._generatedCount++;

    return {
      message,
      username,
      ipAddress,
      domain: useDomain,
      eventType,
      templateName,
      profileName: tmpl.compatibleProfile,
    };
  }
}

module.exports = { MessageGenerator };
