// Syslog message templates for PAN-OS User-ID server-monitor testing
// Port of: AI-Agent/anton/apps/useridd/syslogsender/src/syslog_sender_sim/messages/templates.py
//
// PAN-OS Reference:
//   - syslog_test.c: "Username:Amro Address:192.1.1.110 Authentication Success"
//   - proxyServerStressTest.py: Uses #username and #address placeholders

/**
 * @typedef {Object} MessageTemplate
 * @property {string} name - Unique template identifier
 * @property {string} template - Format string with {username}, {ip}, {domain}, {hostname}, {timestamp}, {priority}
 * @property {string} eventType - "login" or "logout"
 * @property {string} description - Human-readable description
 * @property {string} compatibleProfile - Name of matching ParseProfile
 * @property {number} syslogFacility - Syslog facility code (default: 1 = user-level)
 * @property {number} syslogSeverity - Syslog severity code (default: 6 = informational)
 */

/**
 * Format a template string by replacing {placeholders}.
 * @param {string} tmpl
 * @param {Object} vars
 * @returns {string}
 */
function formatTemplate(tmpl, vars) {
  return tmpl.replace(/\{(\w+)\}/g, (_, key) => {
    return vars[key] !== undefined ? vars[key] : `{${key}}`;
  });
}

/**
 * Get current timestamp in syslog format.
 * @returns {string} e.g. "Jan 15 14:30:05"
 */
function syslogTimestamp() {
  const d = new Date();
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const month = months[d.getMonth()];
  const day = String(d.getDate()).padStart(2, ' ');
  const time = d.toTimeString().split(' ')[0];
  return `${month} ${day} ${time}`;
}

/**
 * Format a message from a template.
 * @param {MessageTemplate} template
 * @param {Object} opts
 * @param {string} opts.username
 * @param {string} opts.ip
 * @param {string} [opts.domain]
 * @param {string} [opts.hostname='syslog-sim']
 * @param {string} [opts.timestamp]
 * @returns {string}
 */
function renderTemplate(template, opts) {
  const fullUsername = opts.domain ? `${opts.domain}\\${opts.username}` : opts.username;
  const priority = template.syslogFacility * 8 + template.syslogSeverity;

  return formatTemplate(template.template, {
    username: fullUsername,
    ip: opts.ip,
    domain: opts.domain || '',
    hostname: opts.hostname || 'syslog-sim',
    timestamp: opts.timestamp || syslogTimestamp(),
    priority: String(priority),
  });
}


// ═══════════════════════════════════════════════════════════════════════════════
//  TEMPLATE REGISTRY
// ═══════════════════════════════════════════════════════════════════════════════

const TEMPLATES = {};

function register(t) {
  TEMPLATES[t.name] = t;
  return t;
}

// --- Field-based templates (match default PAN-OS parse profile) ---

register({
  name: 'field-login',
  template: 'Username:{username} Address:{ip} Authentication Success',
  eventType: 'login',
  description: 'Default field-based login (matches PAN-OS unit test format from syslog_test.c)',
  compatibleProfile: 'default-field-login',
  syslogFacility: 1,
  syslogSeverity: 6,
});

register({
  name: 'field-logout',
  template: 'Username:{username} Address:{ip} Authentication Logout',
  eventType: 'logout',
  description: 'Default field-based logout',
  compatibleProfile: 'default-field-logout',
  syslogFacility: 1,
  syslogSeverity: 6,
});

// --- Regex-compatible templates ---

register({
  name: 'regex-login',
  template: 'Authentication Success: Username:{username} Address:{ip}',
  eventType: 'login',
  description: 'Regex-compatible login (event string first)',
  compatibleProfile: 'default-regex-login',
  syslogFacility: 1,
  syslogSeverity: 6,
});

register({
  name: 'regex-logout',
  template: 'Authentication Logout: Username:{username} Address:{ip}',
  eventType: 'logout',
  description: 'Regex-compatible logout',
  compatibleProfile: 'default-regex-logout',
  syslogFacility: 1,
  syslogSeverity: 6,
});

// --- RFC 5424 syslog format templates ---

register({
  name: 'rfc5424-login',
  template: '<{priority}>{timestamp} {hostname} auth: Username:{username} Address:{ip} Authentication Success',
  eventType: 'login',
  description: 'RFC 5424 syslog format with priority header',
  compatibleProfile: 'default-field-login',
  syslogFacility: 1,
  syslogSeverity: 6,
});

register({
  name: 'rfc5424-logout',
  template: '<{priority}>{timestamp} {hostname} auth: Username:{username} Address:{ip} Authentication Logout',
  eventType: 'logout',
  description: 'RFC 5424 syslog format with priority header',
  compatibleProfile: 'default-field-logout',
  syslogFacility: 1,
  syslogSeverity: 6,
});

// --- Windows Security Event Log templates ---

register({
  name: 'windows-login',
  template: '<14>{timestamp} DC1 Microsoft-Windows-Security-Auditing[4624]: An account was successfully logged on. Account Name: {username} Source Network Address: {ip}',
  eventType: 'login',
  description: 'Windows Security Event Log format (Event ID 4624)',
  compatibleProfile: 'windows-security-login',
  syslogFacility: 1,
  syslogSeverity: 6,
});

register({
  name: 'windows-logout',
  template: '<14>{timestamp} DC1 Microsoft-Windows-Security-Auditing[4634]: An account was logged off. Account Name: {username} Source Network Address: {ip}',
  eventType: 'logout',
  description: 'Windows Security Event Log format (Event ID 4634)',
  compatibleProfile: 'windows-security-logout',
  syslogFacility: 1,
  syslogSeverity: 6,
});

// --- Cisco ISE templates ---

register({
  name: 'cisco-ise-login',
  template: '<14>{timestamp} ISE CISE_Passed_Authentications: UserName={username}, FramedIPAddress={ip}, Authentication succeeded',
  eventType: 'login',
  description: 'Cisco ISE authentication success format',
  compatibleProfile: 'cisco-ise-login',
  syslogFacility: 1,
  syslogSeverity: 6,
});

// --- Domain-prefixed templates ---

register({
  name: 'domain-login',
  template: 'Username:{username} Address:{ip} Authentication Success',
  eventType: 'login',
  description: 'Login with domain prefix (pass domain="CORP" to include CORP\\user)',
  compatibleProfile: 'default-field-login',
  syslogFacility: 1,
  syslogSeverity: 6,
});

// --- Stress test template (minimal, fast to parse) ---

register({
  name: 'minimal-login',
  template: 'Username:{username} Address:{ip} Authentication Success',
  eventType: 'login',
  description: 'Minimal login message for stress testing (no syslog header)',
  compatibleProfile: 'default-field-login',
  syslogFacility: 1,
  syslogSeverity: 6,
});

register({
  name: 'minimal-logout',
  template: 'Username:{username} Address:{ip} Authentication Logout',
  eventType: 'logout',
  description: 'Minimal logout message for stress testing',
  compatibleProfile: 'default-field-logout',
  syslogFacility: 1,
  syslogSeverity: 6,
});

// --- White noise / garbage template ---

register({
  name: 'white-noise',
  template: 'Random system message from {hostname} at {timestamp} - no auth data here',
  eventType: 'login', // Won't match any profile
  description: 'Non-auth message for testing that PAN-OS correctly ignores it',
  compatibleProfile: '',
  syslogFacility: 1,
  syslogSeverity: 6,
});


// ═══════════════════════════════════════════════════════════════════════════════
//  PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get a message template by name.
 * @param {string} name
 * @returns {MessageTemplate}
 * @throws {Error} If template not found
 */
function getTemplate(name) {
  if (!TEMPLATES[name]) {
    const available = Object.keys(TEMPLATES).sort().join(', ');
    throw new Error(`Template '${name}' not found. Available: ${available}`);
  }
  return TEMPLATES[name];
}

/**
 * List all available templates, optionally filtered by event type.
 * @param {string} [eventType] - Filter by "login" or "logout"
 * @returns {MessageTemplate[]}
 */
function listTemplates(eventType) {
  let templates = Object.values(TEMPLATES);
  if (eventType) {
    templates = templates.filter(t => t.eventType === eventType);
  }
  return templates.sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = {
  TEMPLATES,
  getTemplate,
  listTemplates,
  renderTemplate,
  syslogTimestamp,
};
