// Syslog Sender Constants — ports, buffer sizes, enums
// Reference: PAN-OS pan_user_id_syslog_service.h, pan_user_id_syslog.h

// ─── Transport Types ──────────────────────────────────────────────────────────
const TRANSPORT_TYPE = {
  SSL: 'ssl',
  UDP: 'udp',
  BOTH: 'both',
};

// ─── Default Ports (matching PAN-OS syslog listener service) ──────────────────
const DEFAULT_SSL_PORT = 6514;  // PAN_USER_ID_SL_SERVICE_SSL_PORT_V6
const DEFAULT_UDP_PORT = 514;   // PAN_USER_ID_SL_SERVICE_UDP_PORT_V6

// ─── Buffer Sizes (matching PAN-OS) ───────────────────────────────────────────
const MAX_SSL_MESSAGE_SIZE = 8192;   // PAN_USER_ID_SL_SERVICE_MAX_SSL_SIZE
const MAX_UDP_MESSAGE_SIZE = 65535;  // PAN_USER_ID_SL_SERVICE_MAX_UDP_SIZE

// ─── PAN-OS Limits ────────────────────────────────────────────────────────────
const MAX_SYSLOG_SENDERS = 50;  // PAN_USER_ID_SYSLOG_SERVER_MAX

// ─── Transport State ──────────────────────────────────────────────────────────
const TRANSPORT_STATE = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  ERROR: 'error',
};

// ─── Scenario Status ──────────────────────────────────────────────────────────
const SCENARIO_STATUS = {
  PENDING: 'pending',
  RUNNING: 'running',
  PASSED: 'passed',
  FAILED: 'failed',
  ERROR: 'error',
};

// ─── Event Types ──────────────────────────────────────────────────────────────
const EVENT_TYPE = {
  LOGIN: 'login',
  LOGOUT: 'logout',
};

// ─── Parse Profile Types ──────────────────────────────────────────────────────
const PROFILE_TYPE = {
  FIELD: 'field',
  REGEX: 'regex',
};

module.exports = {
  TRANSPORT_TYPE,
  DEFAULT_SSL_PORT,
  DEFAULT_UDP_PORT,
  MAX_SSL_MESSAGE_SIZE,
  MAX_UDP_MESSAGE_SIZE,
  MAX_SYSLOG_SENDERS,
  TRANSPORT_STATE,
  SCENARIO_STATUS,
  EVENT_TYPE,
  PROFILE_TYPE,
};
