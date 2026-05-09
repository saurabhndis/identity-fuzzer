// Traffic Module Constants — DSCP, ports, HTTP methods, defaults
// Reference: RFC 2474 (DSCP), RFC 4594 (QoS), RFC 7540 (HTTP/2), RFC 9113 (HTTP/2 rev)

'use strict';

// ─── DSCP Values (RFC 2474 / RFC 4594) ──────────────────────────────────────
// Values are the full TOS byte (DSCP in upper 6 bits, ECN in lower 2 bits = 0)
const DSCP = {
  DEFAULT:  0x00,  // Best Effort (BE)        - 000000 00
  CS1:      0x20,  // Class Selector 1        - 001000 00  (scavenger/background)
  AF11:     0x28,  // Assured Forwarding 11   - 001010 00
  AF12:     0x30,  // Assured Forwarding 12   - 001100 00
  AF13:     0x38,  // Assured Forwarding 13   - 001110 00
  CS2:      0x40,  // Class Selector 2        - 010000 00
  AF21:     0x48,  // Assured Forwarding 21   - 010010 00
  AF22:     0x50,  // Assured Forwarding 22   - 010100 00
  AF23:     0x58,  // Assured Forwarding 23   - 010110 00
  CS3:      0x60,  // Class Selector 3        - 011000 00
  AF31:     0x68,  // Assured Forwarding 31   - 011010 00
  AF32:     0x70,  // Assured Forwarding 32   - 011100 00
  AF33:     0x78,  // Assured Forwarding 33   - 011110 00
  CS4:      0x80,  // Class Selector 4        - 100000 00
  AF41:     0x88,  // Assured Forwarding 41   - 100010 00
  AF42:     0x90,  // Assured Forwarding 42   - 100100 00
  AF43:     0x98,  // Assured Forwarding 43   - 100110 00
  CS5:      0xA0,  // Class Selector 5        - 101000 00  (voice bearer)
  EF:       0xB8,  // Expedited Forwarding    - 101110 00  (voice/video)
  CS6:      0xC0,  // Class Selector 6        - 110000 00  (network control)
  CS7:      0xE0,  // Class Selector 7        - 111000 00  (network control)
};

// Reverse map: TOS byte → human-readable name
const DSCP_NAME = {};
for (const [name, val] of Object.entries(DSCP)) {
  DSCP_NAME[val] = name;
}

// Parse a DSCP string (name or numeric) to TOS byte value
function parseDSCP(input) {
  if (input === undefined || input === null) return 0;
  if (typeof input === 'number') return input & 0xFF;
  const upper = String(input).toUpperCase().trim();
  if (DSCP[upper] !== undefined) return DSCP[upper];
  const num = parseInt(input, 0); // supports 0x hex prefix
  if (!isNaN(num)) return num & 0xFF;
  return 0;
}

// ─── Default Ports ──────────────────────────────────────────────────────────
const DEFAULT_TCP_PORT = 8080;
const DEFAULT_HTTP_PORT = 8080;
const DEFAULT_HTTPS_PORT = 8443;
const DEFAULT_HTTP2_PORT = 8443;

// ─── Default Endpoints ──────────────────────────────────────────────────────
const DEFAULT_HTTP_ENDPOINT = '/api/v1/health';
const DEFAULT_HTTP2_ENDPOINT = '/api/v2/status';
const DEFAULT_HOST = 'testserver.local';

// ─── HTTP Methods ───────────────────────────────────────────────────────────
const HTTP_METHOD = {
  GET:     'GET',
  POST:    'POST',
  PUT:     'PUT',
  DELETE:  'DELETE',
  PATCH:   'PATCH',
  HEAD:    'HEAD',
  OPTIONS: 'OPTIONS',
  TRACE:   'TRACE',
  CONNECT: 'CONNECT',
};

// ─── HTTP Status Codes ──────────────────────────────────────────────────────
const HTTP_STATUS = {
  200: 'OK',
  201: 'Created',
  204: 'No Content',
  301: 'Moved Permanently',
  302: 'Found',
  304: 'Not Modified',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  408: 'Request Timeout',
  413: 'Payload Too Large',
  414: 'URI Too Long',
  431: 'Request Header Fields Too Large',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
};

// ─── HTTP/2 Frame Types (RFC 7540 Section 6) ────────────────────────────────
const H2_FRAME_TYPE = {
  DATA:          0x00,
  HEADERS:       0x01,
  PRIORITY:      0x02,
  RST_STREAM:    0x03,
  SETTINGS:      0x04,
  PUSH_PROMISE:  0x05,
  PING:          0x06,
  GOAWAY:        0x07,
  WINDOW_UPDATE: 0x08,
  CONTINUATION:  0x09,
};

const H2_FRAME_TYPE_NAME = {};
for (const [name, val] of Object.entries(H2_FRAME_TYPE)) {
  H2_FRAME_TYPE_NAME[val] = name;
}

// ─── HTTP/2 Flags ───────────────────────────────────────────────────────────
const H2_FLAGS = {
  END_STREAM:  0x01,
  ACK:         0x01,  // for SETTINGS and PING
  END_HEADERS: 0x04,
  PADDED:      0x08,
  PRIORITY:    0x20,
};

// ─── HTTP/2 Settings IDs (RFC 7540 Section 6.5.2) ──────────────────────────
const H2_SETTINGS = {
  HEADER_TABLE_SIZE:      0x01,
  ENABLE_PUSH:            0x02,
  MAX_CONCURRENT_STREAMS: 0x03,
  INITIAL_WINDOW_SIZE:    0x04,
  MAX_FRAME_SIZE:         0x05,
  MAX_HEADER_LIST_SIZE:   0x06,
};

// ─── HTTP/2 Error Codes (RFC 7540 Section 7) ────────────────────────────────
const H2_ERROR = {
  NO_ERROR:            0x00,
  PROTOCOL_ERROR:      0x01,
  INTERNAL_ERROR:      0x02,
  FLOW_CONTROL_ERROR:  0x03,
  SETTINGS_TIMEOUT:    0x04,
  STREAM_CLOSED:       0x05,
  FRAME_SIZE_ERROR:    0x06,
  REFUSED_STREAM:      0x07,
  CANCEL:              0x08,
  COMPRESSION_ERROR:   0x09,
  CONNECT_ERROR:       0x0A,
  ENHANCE_YOUR_CALM:   0x0B,
  INADEQUATE_SECURITY: 0x0C,
  HTTP_1_1_REQUIRED:   0x0D,
};

// ─── Transport State ────────────────────────────────────────────────────────
const TRANSPORT_STATE = {
  DISCONNECTED: 'disconnected',
  CONNECTING:   'connecting',
  CONNECTED:    'connected',
  ERROR:        'error',
};

// ─── Scenario Status ────────────────────────────────────────────────────────
const SCENARIO_STATUS = {
  PENDING:  'pending',
  RUNNING:  'running',
  PASSED:   'passed',
  FAILED:   'failed',
  TIMEOUT:  'timeout',
  ERROR:    'error',
  DROPPED:  'dropped',
};

// ─── HTTP/2 Connection Preface ──────────────────────────────────────────────
const H2_PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';

module.exports = {
  // DSCP
  DSCP,
  DSCP_NAME,
  parseDSCP,

  // Ports
  DEFAULT_TCP_PORT,
  DEFAULT_HTTP_PORT,
  DEFAULT_HTTPS_PORT,
  DEFAULT_HTTP2_PORT,

  // Endpoints
  DEFAULT_HTTP_ENDPOINT,
  DEFAULT_HTTP2_ENDPOINT,
  DEFAULT_HOST,

  // HTTP
  HTTP_METHOD,
  HTTP_STATUS,

  // HTTP/2
  H2_FRAME_TYPE,
  H2_FRAME_TYPE_NAME,
  H2_FLAGS,
  H2_SETTINGS,
  H2_ERROR,
  H2_PREFACE,

  // State
  TRANSPORT_STATE,
  SCENARIO_STATUS,
};
