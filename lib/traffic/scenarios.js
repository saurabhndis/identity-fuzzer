// Traffic Fuzzer Scenarios — TCP, HTTP/1.1, and HTTP/2 fuzzing scenarios
// Follows the same category/scenario pattern as the LDAP fuzzer module

'use strict';

const {
  DSCP, DSCP_NAME,
  DEFAULT_TCP_PORT, DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT, DEFAULT_HTTP2_PORT,
  DEFAULT_HTTP_ENDPOINT, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST,
  HTTP_METHOD, HTTP_STATUS,
  H2_FRAME_TYPE, H2_FLAGS, H2_SETTINGS, H2_ERROR,
} = require('./constants');

const {
  buildHTTPRequest,
  buildHTTPResponse,
  buildChunkedBody,
} = require('./http-builder');

const {
  buildH2Preface,
  buildH2Frame,
  buildH2Settings,
  buildH2DefaultSettings,
  buildH2Headers,
  buildH2GetRequest,
  buildH2PostRequest,
  buildH2Data,
  buildH2Ping,
  buildH2Goaway,
  buildH2RstStream,
  buildH2WindowUpdate,
  buildH2Priority,
  buildH2PushPromise,
  hpackEncodeLiteral,
} = require('./http2-builder');


// ═══════════════════════════════════════════════════════════════════════════════
//  CATEGORY DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

const TRAFFIC_CATEGORIES = {
  TA: { name: 'TCP Connection Basics',       description: 'Connect, disconnect, half-close, RST' },
  TB: { name: 'TCP DSCP/TOS Marking',        description: 'Send traffic with various DSCP values' },
  TC: { name: 'TCP Edge Cases',              description: 'Zero-window, Nagle, keepalive, large segments' },
  HD: { name: 'HTTP Request Basics',         description: 'Standard GET/POST/PUT/DELETE requests' },
  HE: { name: 'HTTP Host Header Fuzzing',    description: 'Missing, duplicate, oversized Host headers' },
  HF: { name: 'HTTP Endpoint Fuzzing',       description: 'Path traversal, encoded paths, long URIs' },
  HG: { name: 'HTTP Header Fuzzing',         description: 'Malformed headers, header injection, oversized' },
  HH: { name: 'HTTP Body Fuzzing',           description: 'Chunked encoding, content-length mismatch' },
  HI: { name: 'HTTP Server Responses',       description: 'Server sends malformed/edge-case responses' },
  H2A: { name: 'HTTP/2 Connection Setup',    description: 'Preface, SETTINGS, GOAWAY' },
  H2B: { name: 'HTTP/2 Stream Management',   description: 'Stream creation, priority, RST_STREAM' },
  H2C: { name: 'HTTP/2 Header Fuzzing',      description: 'HPACK bombs, pseudo-header abuse, oversized' },
  H2D: { name: 'HTTP/2 Data Frames',         description: 'Flow control, padding, DATA after END_STREAM' },
  H2E: { name: 'HTTP/2 Server Push',         description: 'PUSH_PROMISE handling, server-initiated streams' },
  H2F: { name: 'HTTP/2 Protocol Violations', description: 'Invalid frames, wrong stream states' },
};

const TRAFFIC_CATEGORY_SEVERITY = {
  TA: 'info',
  TB: 'info',
  TC: 'medium',
  HD: 'info',
  HE: 'high',
  HF: 'high',
  HG: 'high',
  HH: 'high',
  HI: 'medium',
  H2A: 'info',
  H2B: 'medium',
  H2C: 'high',
  H2D: 'medium',
  H2E: 'medium',
  H2F: 'high',
};

const TRAFFIC_CATEGORY_DEFAULT_DISABLED = new Set([
  // None disabled by default — all categories run
]);


// ═══════════════════════════════════════════════════════════════════════════════
//  SCENARIO DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

const TRAFFIC_SCENARIOS = [];

// ─────────────────────────────────────────────────────────────────────────────
//  TA — TCP Connection Basics (~10 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'TA-001-normal-connect-disconnect',
    category: 'TA',
    description: 'Normal TCP connect and graceful FIN disconnect',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('PING\r\n'), label: 'Ping' },
      { type: 'recv', timeout: 5000, label: 'Pong' },
      { type: 'fin', label: 'GracefulClose' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept connection and respond to data',
  },
  {
    name: 'TA-002-connect-rst',
    category: 'TA',
    description: 'Connect then immediately send RST (abrupt close)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('HELLO'), label: 'Hello' },
      { type: 'rst', label: 'AbruptRST' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle RST without crashing',
  },
  {
    name: 'TA-003-connect-no-data',
    category: 'TA',
    description: 'Connect then close without sending any data',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'sleep', ms: 1000 },
      { type: 'fin', label: 'CloseNoData' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle idle connections gracefully',
  },
  {
    name: 'TA-004-half-close-read',
    category: 'TA',
    description: 'Half-close write side, continue reading',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('HALF-CLOSE-TEST\r\n'), label: 'Request' },
      { type: 'fin', label: 'HalfClose' },
      { type: 'recv', timeout: 5000, label: 'ServerResponse' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should still send data after client half-close',
  },
  {
    name: 'TA-005-multiple-sends',
    category: 'TA',
    description: 'Send multiple small messages on same connection',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('MSG1\r\n'), label: 'Msg1' },
      { type: 'send', data: () => Buffer.from('MSG2\r\n'), label: 'Msg2' },
      { type: 'send', data: () => Buffer.from('MSG3\r\n'), label: 'Msg3' },
      { type: 'recv', timeout: 5000, label: 'Responses' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle multiple messages on one connection',
  },
  {
    name: 'TA-006-rapid-reconnect',
    category: 'TA',
    description: 'Rapidly connect, send, disconnect, repeat 5 times',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('CYCLE-1\r\n'), label: 'Cycle1' },
      { type: 'close' },
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('CYCLE-2\r\n'), label: 'Cycle2' },
      { type: 'close' },
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('CYCLE-3\r\n'), label: 'Cycle3' },
      { type: 'close' },
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('CYCLE-4\r\n'), label: 'Cycle4' },
      { type: 'close' },
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('CYCLE-5\r\n'), label: 'Cycle5' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle rapid reconnections',
  },
  {
    name: 'TA-007-tls-connect',
    category: 'TA',
    description: 'TLS connection with default settings',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTPS_PORT },
      { type: 'send', data: () => Buffer.from('SECURE-PING\r\n'), label: 'SecurePing' },
      { type: 'recv', timeout: 5000, label: 'SecurePong' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept TLS connections',
  },
  {
    name: 'TA-008-connect-send-1byte',
    category: 'TA',
    description: 'Send a single byte then close',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from([0x41]), label: 'SingleByte' },
      { type: 'sleep', ms: 500 },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle minimal data',
  },
  {
    name: 'TA-009-simultaneous-close',
    category: 'TA',
    description: 'Send FIN immediately after data (no wait)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('IMMEDIATE-CLOSE\r\n'), label: 'Data' },
      { type: 'fin', label: 'ImmediateFIN' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle data+FIN in quick succession',
  },
  {
    name: 'TA-010-large-payload',
    category: 'TA',
    description: 'Send 1MB of data in a single write',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.alloc(1024 * 1024, 0x42), label: 'LargePayload' },
      { type: 'recv', timeout: 10000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle large payloads',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  TB — TCP DSCP/TOS Marking (~15 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

// Generate a DSCP scenario for each well-known DSCP value
for (const [dscpName, dscpValue] of Object.entries(DSCP)) {
  TRAFFIC_SCENARIOS.push({
    name: `TB-${String(TRAFFIC_SCENARIOS.filter(s => s.category === 'TB').length + 1).padStart(3, '0')}-dscp-${dscpName.toLowerCase()}`,
    category: 'TB',
    description: `Send TCP traffic with DSCP ${dscpName} (TOS 0x${dscpValue.toString(16).padStart(2, '0')}) marking`,
    side: 'client',
    dscp: dscpValue,
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT, dscp: dscpValue },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET',
        path: DEFAULT_HTTP_ENDPOINT,
        host: DEFAULT_HOST,
        headers: { 'X-DSCP-Test': dscpName },
      }), label: `DSCP-${dscpName}` },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: `Traffic should be accepted regardless of DSCP ${dscpName} marking`,
  });
}


// ─────────────────────────────────────────────────────────────────────────────
//  TC — TCP Edge Cases (~10 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'TC-001-zero-length-write',
    category: 'TC',
    description: 'Send zero-length data (empty buffer)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.alloc(0), label: 'EmptyWrite' },
      { type: 'sleep', ms: 1000 },
      { type: 'send', data: () => Buffer.from('AFTER-EMPTY\r\n'), label: 'AfterEmpty' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle zero-length writes',
  },
  {
    name: 'TC-002-byte-at-a-time',
    category: 'TC',
    description: 'Send HTTP request one byte at a time',
    side: 'client',
    steps: (() => {
      const req = buildHTTPRequest({ method: 'GET', path: DEFAULT_HTTP_ENDPOINT });
      const steps = [{ type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT }];
      // Send first 50 bytes one at a time (enough to test reassembly)
      const limit = Math.min(req.length, 50);
      for (let i = 0; i < limit; i++) {
        steps.push({ type: 'send', data: () => Buffer.from([req[i]]), label: `Byte${i}` });
      }
      // Send the rest in one chunk
      if (req.length > 50) {
        steps.push({ type: 'send', data: () => req.slice(50), label: 'Remainder' });
      }
      steps.push({ type: 'recv', timeout: 10000, label: 'Response' });
      steps.push({ type: 'close' });
      return steps;
    })(),
    expected: 'PASSED',
    expectedReason: 'Server should reassemble TCP segments',
  },
  {
    name: 'TC-003-nagle-disabled',
    category: 'TC',
    description: 'Send with TCP_NODELAY (Nagle disabled) — many small packets',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT, noDelay: true },
      { type: 'send', data: () => Buffer.from('A'), label: 'Pkt1' },
      { type: 'send', data: () => Buffer.from('B'), label: 'Pkt2' },
      { type: 'send', data: () => Buffer.from('C'), label: 'Pkt3' },
      { type: 'send', data: () => Buffer.from('D'), label: 'Pkt4' },
      { type: 'send', data: () => Buffer.from('\r\n'), label: 'CRLF' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle many small TCP segments',
  },
  {
    name: 'TC-004-keepalive-idle',
    category: 'TC',
    description: 'Connect, send data, then idle for 30 seconds',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('KEEPALIVE-TEST\r\n'), label: 'Initial' },
      { type: 'recv', timeout: 5000, label: 'InitialResponse' },
      { type: 'sleep', ms: 30000 },
      { type: 'send', data: () => Buffer.from('STILL-ALIVE\r\n'), label: 'AfterIdle' },
      { type: 'recv', timeout: 5000, label: 'AfterIdleResponse' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should keep connection alive during idle period',
  },
  {
    name: 'TC-005-binary-data',
    category: 'TC',
    description: 'Send binary data with all byte values 0x00-0xFF',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => {
        const buf = Buffer.alloc(256);
        for (let i = 0; i < 256; i++) buf[i] = i;
        return buf;
      }, label: 'AllBytes' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle arbitrary binary data',
  },
  {
    name: 'TC-006-urgent-data',
    category: 'TC',
    description: 'Send data with TCP urgent pointer (OOB data)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('NORMAL-DATA\r\n'), label: 'Normal' },
      { type: 'send-oob', data: () => Buffer.from('!'), label: 'UrgentByte' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle OOB/urgent data',
  },
  {
    name: 'TC-007-max-segment-size',
    category: 'TC',
    description: 'Send exactly 65535 bytes (max TCP segment payload)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.alloc(65535, 0x58), label: 'MaxSegment' },
      { type: 'recv', timeout: 10000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle maximum-size segments',
  },
  {
    name: 'TC-008-null-bytes',
    category: 'TC',
    description: 'Send data consisting entirely of null bytes',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.alloc(1024, 0x00), label: 'NullBytes' },
      { type: 'sleep', ms: 1000 },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle null byte streams',
  },
  {
    name: 'TC-009-interleaved-fin',
    category: 'TC',
    description: 'Send data interleaved with FIN (write after half-close attempt)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'send', data: () => Buffer.from('BEFORE-FIN\r\n'), label: 'BeforeFIN' },
      { type: 'fin', label: 'HalfClose' },
      // After FIN, writes should fail — test error handling
      { type: 'recv', timeout: 5000, label: 'ServerData' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle half-close correctly',
  },
  {
    name: 'TC-010-connection-flood',
    category: 'TC',
    description: 'Open 10 simultaneous connections',
    side: 'client',
    steps: [
      { type: 'parallel-connect', count: 10, mode: 'plain', port: DEFAULT_TCP_PORT },
      { type: 'sleep', ms: 2000 },
      { type: 'close-all' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle multiple simultaneous connections',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  HD — HTTP Request Basics (~12 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'HD-001-simple-get',
    category: 'HD',
    description: 'Simple HTTP GET to /api/v1/health',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/api/v1/health', host: DEFAULT_HOST,
      }), label: 'GET-Health' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respond with 200 OK',
  },
  {
    name: 'HD-002-post-json',
    category: 'HD',
    description: 'HTTP POST with JSON body to /api/v1/data',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: 'value', test: true }),
      }), label: 'POST-JSON' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept POST with JSON body',
  },
  {
    name: 'HD-003-put-request',
    category: 'HD',
    description: 'HTTP PUT request to /api/v1/data/1',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'PUT', path: '/api/v1/data/1', host: DEFAULT_HOST,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ updated: true }),
      }), label: 'PUT-Data' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept PUT requests',
  },
  {
    name: 'HD-004-delete-request',
    category: 'HD',
    description: 'HTTP DELETE request to /api/v1/data/1',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'DELETE', path: '/api/v1/data/1', host: DEFAULT_HOST,
      }), label: 'DELETE-Data' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept DELETE requests',
  },
  {
    name: 'HD-005-head-request',
    category: 'HD',
    description: 'HTTP HEAD request (no body in response)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'HEAD', path: '/api/v1/health', host: DEFAULT_HOST,
      }), label: 'HEAD-Health' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respond with headers only (no body)',
  },
  {
    name: 'HD-006-options-request',
    category: 'HD',
    description: 'HTTP OPTIONS request (CORS preflight)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'OPTIONS', path: '/api/v1/health', host: DEFAULT_HOST,
        headers: {
          'Origin': 'http://evil.com',
          'Access-Control-Request-Method': 'POST',
        },
      }), label: 'OPTIONS-CORS' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respond to OPTIONS request',
  },
  {
    name: 'HD-007-patch-request',
    category: 'HD',
    description: 'HTTP PATCH request with partial update',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'PATCH', path: '/api/v1/data/1', host: DEFAULT_HOST,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ field: 'patched' }),
      }), label: 'PATCH-Data' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept PATCH requests',
  },
  {
    name: 'HD-008-echo-endpoint',
    category: 'HD',
    description: 'HTTP GET to /api/v1/echo — should echo request details',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/api/v1/echo', host: DEFAULT_HOST,
        headers: { 'X-Custom-Header': 'test-value' },
      }), label: 'GET-Echo' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should echo request details',
  },
  {
    name: 'HD-009-404-not-found',
    category: 'HD',
    description: 'HTTP GET to non-existent path — expect 404',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/nonexistent/path/that/does/not/exist', host: DEFAULT_HOST,
      }), label: 'GET-404' },
      { type: 'recv', timeout: 5000, label: 'Response', expectStatus: 404 },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should return 404 for unknown paths',
  },
  {
    name: 'HD-010-http10-request',
    category: 'HD',
    description: 'HTTP/1.0 request (no persistent connection)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/api/v1/health', host: DEFAULT_HOST,
        version: 'HTTP/1.0',
      }), label: 'HTTP10-GET' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle HTTP/1.0 requests',
  },
  {
    name: 'HD-011-pipelined-requests',
    category: 'HD',
    description: 'Send two HTTP requests back-to-back (pipelining)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.concat([
        buildHTTPRequest({ method: 'GET', path: '/api/v1/health', host: DEFAULT_HOST }),
        buildHTTPRequest({ method: 'GET', path: '/api/v1/echo', host: DEFAULT_HOST }),
      ]), label: 'PipelinedRequests' },
      { type: 'recv', timeout: 5000, label: 'Responses' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle pipelined requests',
  },
  {
    name: 'HD-012-custom-endpoint',
    category: 'HD',
    description: 'HTTP GET to user-configured custom endpoint',
    side: 'client',
    useCustomEndpoint: true,
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: (ctx) => buildHTTPRequest({
        method: 'GET',
        path: ctx.httpEndpoint || DEFAULT_HTTP_ENDPOINT,
        host: ctx.httpHost || DEFAULT_HOST,
      }), label: 'CustomEndpoint' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respond to custom endpoint',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  HE — HTTP Host Header Fuzzing (~10 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'HE-001-missing-host',
    category: 'HE',
    description: 'HTTP/1.1 request without Host header',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/api/v1/health',
        includeHost: false,
      }), label: 'NoHost' },
      { type: 'recv', timeout: 5000, label: 'Response', expectStatus: 400 },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject HTTP/1.1 request without Host header (RFC 7230)',
  },
  {
    name: 'HE-002-empty-host',
    category: 'HE',
    description: 'Host header with empty value',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/api/v1/health', host: '',
      }), label: 'EmptyHost' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle empty Host header',
  },
  {
    name: 'HE-003-crlf-injection',
    category: 'HE',
    description: 'Host header with CRLF injection attempt',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        host: 'evil.com\r\nX-Injected: true',
        path: '/api/v1/health',
      }), label: 'CRLF-Host' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject CRLF injection in Host header',
  },
  {
    name: 'HE-004-oversized-host',
    category: 'HE',
    description: 'Host header with 10KB value',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        host: 'A'.repeat(10240) + '.example.com',
        path: '/api/v1/health',
      }), label: 'OversizedHost' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject or handle oversized Host header',
  },
  {
    name: 'HE-005-duplicate-host',
    category: 'HE',
    description: 'Two Host headers in same request',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        // Build raw request with duplicate Host
        const raw = `GET /api/v1/health HTTP/1.1\r\nHost: good.com\r\nHost: evil.com\r\n\r\n`;
        return Buffer.from(raw);
      }, label: 'DuplicateHost' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject requests with duplicate Host headers (RFC 7230)',
  },
  {
    name: 'HE-006-host-with-port',
    category: 'HE',
    description: 'Host header with explicit port number',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        host: `${DEFAULT_HOST}:${DEFAULT_HTTP_PORT}`,
        path: '/api/v1/health',
      }), label: 'HostWithPort' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept Host header with port',
  },
  {
    name: 'HE-007-host-ip-address',
    category: 'HE',
    description: 'Host header with IP address instead of hostname',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        host: '127.0.0.1',
        path: '/api/v1/health',
      }), label: 'HostIP' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept IP address as Host',
  },
  {
    name: 'HE-008-host-ipv6',
    category: 'HE',
    description: 'Host header with IPv6 address',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        host: '[::1]',
        path: '/api/v1/health',
      }), label: 'HostIPv6' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept IPv6 address as Host',
  },
  {
    name: 'HE-009-host-unicode',
    category: 'HE',
    description: 'Host header with Unicode/IDN characters',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        host: 'tëst-sërvér.example.com',
        path: '/api/v1/health',
      }), label: 'UnicodeHost' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle Unicode in Host header',
  },
  {
    name: 'HE-010-host-null-byte',
    category: 'HE',
    description: 'Host header with embedded null byte',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        host: 'good.com\x00evil.com',
        path: '/api/v1/health',
      }), label: 'NullByteHost' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject null bytes in Host header',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  HF — HTTP Endpoint Fuzzing (~12 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'HF-001-path-traversal',
    category: 'HF',
    description: 'Path traversal attempt with ../../etc/passwd',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/../../etc/passwd', host: DEFAULT_HOST,
      }), label: 'PathTraversal' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject or sanitize path traversal',
  },
  {
    name: 'HF-002-encoded-traversal',
    category: 'HF',
    description: 'URL-encoded path traversal (%2e%2e%2f)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/%2e%2e/%2e%2e/etc/passwd', host: DEFAULT_HOST,
      }), label: 'EncodedTraversal' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject encoded path traversal',
  },
  {
    name: 'HF-003-double-encoded',
    category: 'HF',
    description: 'Double URL-encoded path traversal (%252e%252e)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/%252e%252e/%252e%252e/etc/passwd', host: DEFAULT_HOST,
      }), label: 'DoubleEncoded' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject double-encoded traversal',
  },
  {
    name: 'HF-004-long-uri',
    category: 'HF',
    description: 'URI with 8192 characters',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/' + 'a'.repeat(8192), host: DEFAULT_HOST,
      }), label: 'LongURI' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle or reject very long URIs (414)',
  },
  {
    name: 'HF-005-query-string-injection',
    category: 'HF',
    description: 'Query string with SQL injection attempt',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: "/api/v1/data?id=1' OR '1'='1", host: DEFAULT_HOST,
      }), label: 'SQLi-Query' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should sanitize query parameters',
  },
  {
    name: 'HF-006-fragment-in-request',
    category: 'HF',
    description: 'URI with fragment identifier (should not be sent to server)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/health#fragment', host: DEFAULT_HOST,
      }), label: 'FragmentURI' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle fragment in URI',
  },
  {
    name: 'HF-007-null-byte-path',
    category: 'HF',
    description: 'Path with embedded null byte',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/health\x00.html', host: DEFAULT_HOST,
      }), label: 'NullBytePath' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject null bytes in path',
  },
  {
    name: 'HF-008-backslash-path',
    category: 'HF',
    description: 'Path with backslashes instead of forward slashes',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '\\api\\v1\\health', host: DEFAULT_HOST,
      }), label: 'BackslashPath' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle or reject backslash paths',
  },
  {
    name: 'HF-009-absolute-uri',
    category: 'HF',
    description: 'Absolute URI in request line (proxy-style)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: `http://${DEFAULT_HOST}/api/v1/health`, host: DEFAULT_HOST,
      }), label: 'AbsoluteURI' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle absolute URI form',
  },
  {
    name: 'HF-010-unicode-path',
    category: 'HF',
    description: 'Path with Unicode characters',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/données/résumé', host: DEFAULT_HOST,
      }), label: 'UnicodePath' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle Unicode in path',
  },
  {
    name: 'HF-011-dot-segments',
    category: 'HF',
    description: 'Path with excessive dot segments /./././',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/./././api/./v1/./health/./', host: DEFAULT_HOST,
      }), label: 'DotSegments' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should normalize dot segments',
  },
  {
    name: 'HF-012-asterisk-form',
    category: 'HF',
    description: 'OPTIONS * HTTP/1.1 (asterisk-form request target)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'OPTIONS', path: '*', host: DEFAULT_HOST,
      }), label: 'AsteriskForm' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle asterisk-form OPTIONS',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  HG — HTTP Header Fuzzing (~15 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'HG-001-no-headers',
    category: 'HG',
    description: 'HTTP request with no headers at all',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from('GET /api/v1/health HTTP/1.1\r\n\r\n'), label: 'NoHeaders' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle request with no headers',
  },
  {
    name: 'HG-002-oversized-header-value',
    category: 'HG',
    description: 'Single header with 64KB value',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/health', host: DEFAULT_HOST,
        headers: { 'X-Large-Header': 'X'.repeat(65536) },
      }), label: 'OversizedHeader' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject or handle oversized headers (431)',
  },
  {
    name: 'HG-003-many-headers',
    category: 'HG',
    description: 'Request with 200 custom headers',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const headers = {};
        for (let i = 0; i < 200; i++) {
          headers[`X-Custom-${i}`] = `value-${i}`;
        }
        return buildHTTPRequest({ path: '/api/v1/health', host: DEFAULT_HOST, headers });
      }, label: 'ManyHeaders' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle many headers',
  },
  {
    name: 'HG-004-header-without-value',
    category: 'HG',
    description: 'Header with name but no value (just colon)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'GET /api/v1/health HTTP/1.1\r\nHost: ' + DEFAULT_HOST + '\r\nX-Empty:\r\n\r\n'
      ), label: 'EmptyHeaderValue' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle headers with empty values',
  },
  {
    name: 'HG-005-header-no-colon',
    category: 'HG',
    description: 'Malformed header line without colon separator',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'GET /api/v1/health HTTP/1.1\r\nHost: ' + DEFAULT_HOST + '\r\nMalformedHeaderNoColon\r\n\r\n'
      ), label: 'NoColonHeader' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject malformed header lines',
  },
  {
    name: 'HG-006-header-space-before-colon',
    category: 'HG',
    description: 'Header with space before colon (obsolete line folding)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'GET /api/v1/health HTTP/1.1\r\nHost: ' + DEFAULT_HOST + '\r\nX-Bad : value\r\n\r\n'
      ), label: 'SpaceBeforeColon' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject space before colon in header name',
  },
  {
    name: 'HG-007-header-line-folding',
    category: 'HG',
    description: 'Obsolete header line folding (continuation with whitespace)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'GET /api/v1/health HTTP/1.1\r\nHost: ' + DEFAULT_HOST + '\r\nX-Folded: line1\r\n line2\r\n\tline3\r\n\r\n'
      ), label: 'LineFolding' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject obsolete line folding (RFC 7230)',
  },
  {
    name: 'HG-008-transfer-encoding-smuggling',
    category: 'HG',
    description: 'Both Transfer-Encoding and Content-Length (request smuggling)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'POST /api/v1/data HTTP/1.1\r\nHost: ' + DEFAULT_HOST +
        '\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX'
      ), label: 'TECLSmuggle' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject conflicting TE and CL headers',
  },
  {
    name: 'HG-009-content-length-negative',
    category: 'HG',
    description: 'Negative Content-Length value',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'POST /api/v1/data HTTP/1.1\r\nHost: ' + DEFAULT_HOST +
        '\r\nContent-Length: -1\r\n\r\ntest'
      ), label: 'NegativeCL' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject negative Content-Length',
  },
  {
    name: 'HG-010-duplicate-content-length',
    category: 'HG',
    description: 'Two different Content-Length headers',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'POST /api/v1/data HTTP/1.1\r\nHost: ' + DEFAULT_HOST +
        '\r\nContent-Length: 4\r\nContent-Length: 100\r\n\r\ntest'
      ), label: 'DuplicateCL' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject conflicting Content-Length values',
  },
  {
    name: 'HG-011-unknown-method',
    category: 'HG',
    description: 'Request with unknown HTTP method',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'FUZZ', path: '/api/v1/health', host: DEFAULT_HOST,
      }), label: 'UnknownMethod' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should return 405 or handle unknown methods',
  },
  {
    name: 'HG-012-invalid-http-version',
    category: 'HG',
    description: 'Request with invalid HTTP version string',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/api/v1/health', host: DEFAULT_HOST,
        version: 'HTTP/9.9',
      }), label: 'BadVersion' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should reject unsupported HTTP version',
  },
  {
    name: 'HG-013-header-injection-newline',
    category: 'HG',
    description: 'Header value with bare LF (not CRLF)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/health', host: DEFAULT_HOST,
        headers: { 'X-Inject': 'value\nX-Injected: true' },
      }), label: 'BareLFInjection' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject bare LF in header values',
  },
  {
    name: 'HG-014-connection-header-abuse',
    category: 'HG',
    description: 'Connection header listing hop-by-hop headers to strip',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/health', host: DEFAULT_HOST,
        headers: {
          'Connection': 'X-Secret-Internal, close',
          'X-Secret-Internal': 'should-be-stripped',
        },
      }), label: 'ConnectionAbuse' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should strip hop-by-hop headers listed in Connection',
  },
  {
    name: 'HG-015-request-line-only-lf',
    category: 'HG',
    description: 'Request using bare LF instead of CRLF line endings',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        path: '/api/v1/health', host: DEFAULT_HOST,
        lineEnding: '\n',
      }), label: 'BareLFRequest' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server may accept bare LF (lenient parsing) or reject',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  HH — HTTP Body Fuzzing (~10 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'HH-001-chunked-normal',
    category: 'HH',
    description: 'Normal chunked transfer encoding',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const chunkedBody = buildChunkedBody(['Hello, ', 'World!']);
        return buildHTTPRequest({
          method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
          headers: { 'Transfer-Encoding': 'chunked' },
          body: chunkedBody,
          includeContentLength: false,
        });
      }, label: 'ChunkedNormal' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle chunked transfer encoding',
  },
  {
    name: 'HH-002-chunked-zero-size',
    category: 'HH',
    description: 'Chunked encoding with zero-size chunks interspersed',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const body = Buffer.from('5\r\nHello\r\n0\r\n\r\n');
        return buildHTTPRequest({
          method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
          headers: { 'Transfer-Encoding': 'chunked' },
          body,
          includeContentLength: false,
        });
      }, label: 'ChunkedZero' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle chunked encoding correctly',
  },
  {
    name: 'HH-003-content-length-mismatch-short',
    category: 'HH',
    description: 'Content-Length larger than actual body',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'POST /api/v1/data HTTP/1.1\r\nHost: ' + DEFAULT_HOST +
        '\r\nContent-Length: 1000\r\n\r\nshort'
      ), label: 'CLMismatchShort' },
      { type: 'recv', timeout: 10000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should timeout waiting for remaining body',
  },
  {
    name: 'HH-004-content-length-mismatch-long',
    category: 'HH',
    description: 'Content-Length smaller than actual body',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => Buffer.from(
        'POST /api/v1/data HTTP/1.1\r\nHost: ' + DEFAULT_HOST +
        '\r\nContent-Length: 4\r\n\r\ntestEXTRA_DATA_BEYOND_CL'
      ), label: 'CLMismatchLong' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should only read Content-Length bytes',
  },
  {
    name: 'HH-005-empty-body-with-cl',
    category: 'HH',
    description: 'POST with Content-Length: 0',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
        headers: { 'Content-Length': '0', 'Content-Type': 'application/json' },
        body: '',
        includeContentLength: false,
      }), label: 'EmptyBodyCL0' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle empty body with CL: 0',
  },
  {
    name: 'HH-006-large-json-body',
    category: 'HH',
    description: 'POST with 1MB JSON body',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const largeArray = Array.from({ length: 10000 }, (_, i) => ({ id: i, data: 'x'.repeat(100) }));
        return buildHTTPRequest({
          method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(largeArray),
        });
      }, label: 'LargeJSON' },
      { type: 'recv', timeout: 15000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle large JSON bodies',
  },
  {
    name: 'HH-007-multipart-form',
    category: 'HH',
    description: 'Multipart form data upload',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const boundary = '----FuzzerBoundary123';
        const body = `--${boundary}\r\nContent-Disposition: form-data; name="field1"\r\n\r\nvalue1\r\n` +
          `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="test.txt"\r\nContent-Type: text/plain\r\n\r\nfile content here\r\n` +
          `--${boundary}--\r\n`;
        return buildHTTPRequest({
          method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
          headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
          body,
        });
      }, label: 'MultipartForm' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle multipart form data',
  },
  {
    name: 'HH-008-chunked-extension',
    category: 'HH',
    description: 'Chunked encoding with chunk extensions',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const body = Buffer.from('5;ext=val\r\nHello\r\n6;name="test"\r\n World\r\n0\r\n\r\n');
        return buildHTTPRequest({
          method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
          headers: { 'Transfer-Encoding': 'chunked' },
          body,
          includeContentLength: false,
        });
      }, label: 'ChunkedExtension' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle chunk extensions',
  },
  {
    name: 'HH-009-chunked-trailers',
    category: 'HH',
    description: 'Chunked encoding with trailer headers',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const chunkedBody = buildChunkedBody(['test data'], { trailers: { 'X-Checksum': 'abc123' } });
        return buildHTTPRequest({
          method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
          headers: { 'Transfer-Encoding': 'chunked', 'Trailer': 'X-Checksum' },
          body: chunkedBody,
          includeContentLength: false,
        });
      }, label: 'ChunkedTrailers' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle chunked trailers',
  },
  {
    name: 'HH-010-invalid-chunked-size',
    category: 'HH',
    description: 'Chunked encoding with invalid (non-hex) chunk size',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'plain', port: DEFAULT_HTTP_PORT },
      { type: 'send', data: () => {
        const body = Buffer.from('ZZZZ\r\nHello\r\n0\r\n\r\n');
        return buildHTTPRequest({
          method: 'POST', path: '/api/v1/data', host: DEFAULT_HOST,
          headers: { 'Transfer-Encoding': 'chunked' },
          body,
          includeContentLength: false,
        });
      }, label: 'InvalidChunkSize' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject invalid chunk size',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  HI — HTTP Server Responses (~12 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'HI-001-normal-200',
    category: 'HI',
    description: 'Server sends normal 200 OK response',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          log('Received request, sending 200 OK');
          const resp = buildHTTPResponse({
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'ok' }),
          });
          socket.write(resp);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: '200 OK sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should accept normal 200 response',
  },
  {
    name: 'HI-002-slow-headers',
    category: 'HI',
    description: 'Server sends response headers one byte at a time',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending response headers byte-by-byte');
          const resp = buildHTTPResponse({
            statusCode: 200,
            body: 'slow-headers-test',
          });
          let i = 0;
          const interval = setInterval(() => {
            if (i < resp.length) {
              socket.write(Buffer.from([resp[i++]]));
            } else {
              clearInterval(interval);
              setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Slow headers sent' }); }, 500);
            }
          }, 10);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reassemble slow response headers',
  },
  {
    name: 'HI-003-incomplete-response',
    category: 'HI',
    description: 'Server sends partial response then closes',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending incomplete response');
          socket.write(Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial'));
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Incomplete response sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should detect incomplete response',
  },
  {
    name: 'HI-004-invalid-status-line',
    category: 'HI',
    description: 'Server sends invalid status line',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending invalid status line');
          socket.write(Buffer.from('INVALID STATUS LINE\r\nContent-Length: 0\r\n\r\n'));
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Invalid status sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle invalid status line',
  },
  {
    name: 'HI-005-100-continue',
    category: 'HI',
    description: 'Server sends 100 Continue then 200 OK',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending 100 Continue');
          socket.write(Buffer.from('HTTP/1.1 100 Continue\r\n\r\n'));
          setTimeout(() => {
            const resp = buildHTTPResponse({ statusCode: 200, body: 'after-continue' });
            socket.write(resp);
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: '100+200 sent' }); }, 500);
          }, 200);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle 100 Continue followed by final response',
  },
  {
    name: 'HI-006-response-no-content-length',
    category: 'HI',
    description: 'Server sends response without Content-Length (close-delimited)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending response without Content-Length');
          socket.write(Buffer.from('HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-delimited-body'));
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Close-delimited sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should read until connection close',
  },
  {
    name: 'HI-007-chunked-response',
    category: 'HI',
    description: 'Server sends chunked transfer-encoded response',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending chunked response');
          const headers = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n';
          socket.write(Buffer.from(headers));
          setTimeout(() => socket.write(Buffer.from('5\r\nHello\r\n')), 100);
          setTimeout(() => socket.write(Buffer.from('7\r\n, World\r\n')), 200);
          setTimeout(() => {
            socket.write(Buffer.from('0\r\n\r\n'));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Chunked response sent' }); }, 500);
          }, 300);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle chunked response',
  },
  {
    name: 'HI-008-302-redirect',
    category: 'HI',
    description: 'Server sends 302 redirect',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending 302 redirect');
          const resp = buildHTTPResponse({
            statusCode: 302,
            headers: { 'Location': '/api/v1/new-location' },
            body: '',
          });
          socket.write(resp);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: '302 redirect sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle redirect response',
  },
  {
    name: 'HI-009-connection-close-mid-body',
    category: 'HI',
    description: 'Server closes connection mid-body',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending partial body then closing');
          socket.write(Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhalf'));
          setTimeout(() => { socket.destroy(); resolve({ status: 'PASSED', response: 'Connection closed mid-body' }); }, 200);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should detect premature connection close',
  },
  {
    name: 'HI-010-garbage-response',
    category: 'HI',
    description: 'Server sends random binary garbage',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending garbage data');
          const garbage = Buffer.alloc(256);
          for (let i = 0; i < 256; i++) garbage[i] = Math.floor(Math.random() * 256);
          socket.write(garbage);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Garbage sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle non-HTTP response data',
  },
  {
    name: 'HI-011-response-header-injection',
    category: 'HI',
    description: 'Server sends response with header injection attempt',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending response with injected headers');
          socket.write(Buffer.from(
            'HTTP/1.1 200 OK\r\nX-Normal: value\r\nSet-Cookie: session=hijacked\r\nContent-Length: 2\r\n\r\nok'
          ));
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Injected headers sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should be aware of unexpected Set-Cookie headers',
  },
  {
    name: 'HI-012-very-slow-response',
    category: 'HI',
    description: 'Server sends response with 5-second delay between header and body',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending headers, then delaying body');
          socket.write(Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n'));
          setTimeout(() => {
            socket.write(Buffer.from('slow-body!!'));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Slow response sent' }); }, 500);
          }, 5000);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should wait for slow response body',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  H2A — HTTP/2 Connection Setup (~8 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'H2A-001-valid-preface',
    category: 'H2A',
    description: 'Send valid HTTP/2 connection preface and SETTINGS',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'ClientSettings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept valid HTTP/2 preface',
  },
  {
    name: 'H2A-002-invalid-preface',
    category: 'H2A',
    description: 'Send invalid HTTP/2 connection preface',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => Buffer.from('NOT A VALID HTTP/2 PREFACE\r\n\r\n'), label: 'BadPreface' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject invalid preface with GOAWAY',
  },
  {
    name: 'H2A-003-preface-then-request',
    category: 'H2A',
    description: 'Full HTTP/2 handshake followed by GET request',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(1, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'GET-Request' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'send', data: () => buildH2Goaway(0, H2_ERROR.NO_ERROR), label: 'Goaway' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respond to HTTP/2 GET request',
  },
  {
    name: 'H2A-004-settings-max-frame-size',
    category: 'H2A',
    description: 'Send SETTINGS with very large MAX_FRAME_SIZE',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2Settings({
        [H2_SETTINGS.MAX_FRAME_SIZE]: 16777215,  // Maximum allowed
      }), label: 'LargeFrameSize' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept maximum MAX_FRAME_SIZE',
  },
  {
    name: 'H2A-005-settings-zero-window',
    category: 'H2A',
    description: 'Send SETTINGS with INITIAL_WINDOW_SIZE = 0',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2Settings({
        [H2_SETTINGS.INITIAL_WINDOW_SIZE]: 0,
      }), label: 'ZeroWindow' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept zero initial window size',
  },
  {
    name: 'H2A-006-settings-disable-push',
    category: 'H2A',
    description: 'Send SETTINGS disabling server push',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2Settings({
        [H2_SETTINGS.ENABLE_PUSH]: 0,
      }), label: 'DisablePush' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respect ENABLE_PUSH=0',
  },
  {
    name: 'H2A-007-ping-pong',
    category: 'H2A',
    description: 'Send PING frame and expect PING ACK',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Ping(Buffer.from('PINGTEST')), label: 'Ping' },
      { type: 'recv', timeout: 5000, label: 'PingACK' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respond with PING ACK',
  },
  {
    name: 'H2A-008-goaway-graceful',
    category: 'H2A',
    description: 'Send GOAWAY with NO_ERROR after request',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(1, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'Request' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'send', data: () => buildH2Goaway(1, H2_ERROR.NO_ERROR, 'graceful shutdown'), label: 'Goaway' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle graceful GOAWAY',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  H2B — HTTP/2 Stream Management (~10 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'H2B-001-multiple-streams',
    category: 'H2B',
    description: 'Open multiple concurrent streams',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(1, '/api/v2/status', DEFAULT_HOST), label: 'Stream1' },
      { type: 'send', data: () => buildH2GetRequest(3, '/api/v2/echo', DEFAULT_HOST), label: 'Stream3' },
      { type: 'send', data: () => buildH2GetRequest(5, '/api/v2/data', DEFAULT_HOST), label: 'Stream5' },
      { type: 'recv', timeout: 5000, label: 'Responses' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle multiple concurrent streams',
  },
  {
    name: 'H2B-002-stream-priority',
    category: 'H2B',
    description: 'Set stream priority with PRIORITY frame',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Priority(1, 0, 256, false), label: 'Priority' },
      { type: 'send', data: () => buildH2GetRequest(1, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'Request' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept PRIORITY frames',
  },
  {
    name: 'H2B-003-rst-stream',
    category: 'H2B',
    description: 'Cancel a stream with RST_STREAM',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(1, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'Request' },
      { type: 'send', data: () => buildH2RstStream(1, H2_ERROR.CANCEL), label: 'RST_STREAM' },
      { type: 'recv', timeout: 3000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle RST_STREAM gracefully',
  },
  {
    name: 'H2B-004-even-stream-id',
    category: 'H2B',
    description: 'Client sends request on even stream ID (protocol violation)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(2, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'EvenStreamID' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject even stream IDs from client',
  },
  {
    name: 'H2B-005-stream-id-zero-headers',
    category: 'H2B',
    description: 'Send HEADERS on stream 0 (connection-level, invalid)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(0, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'Stream0Headers' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject HEADERS on stream 0',
  },
  {
    name: 'H2B-006-decreasing-stream-ids',
    category: 'H2B',
    description: 'Send requests with decreasing stream IDs',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(5, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'Stream5' },
      { type: 'send', data: () => buildH2GetRequest(3, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'Stream3-Decreasing' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject decreasing stream IDs',
  },
  {
    name: 'H2B-007-max-concurrent-exceeded',
    category: 'H2B',
    description: 'Open more streams than MAX_CONCURRENT_STREAMS',
    side: 'client',
    steps: (() => {
      const steps = [
        { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
        { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
        { type: 'send', data: () => buildH2Settings({
          [H2_SETTINGS.MAX_CONCURRENT_STREAMS]: 1,
        }), label: 'Settings' },
        { type: 'recv', timeout: 5000, label: 'ServerSettings' },
        { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      ];
      // Open 5 streams (exceeding our stated max of 1)
      for (let i = 0; i < 5; i++) {
        const streamId = 1 + i * 2;
        steps.push({
          type: 'send',
          data: () => buildH2GetRequest(streamId, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST),
          label: `Stream${streamId}`,
        });
      }
      steps.push({ type: 'recv', timeout: 5000, label: 'Responses' });
      steps.push({ type: 'close' });
      return steps;
    })(),
    expected: 'PASSED',
    expectedReason: 'Server should handle or refuse excess streams',
  },
  {
    name: 'H2B-008-window-update',
    category: 'H2B',
    description: 'Send WINDOW_UPDATE to increase flow control window',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2WindowUpdate(0, 1048576), label: 'ConnWindowUpdate' },
      { type: 'send', data: () => buildH2GetRequest(1, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'Request' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should accept WINDOW_UPDATE',
  },
  {
    name: 'H2B-009-window-update-zero',
    category: 'H2B',
    description: 'Send WINDOW_UPDATE with zero increment (protocol error)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2WindowUpdate(0, 0), label: 'ZeroWindowUpdate' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should send GOAWAY for zero WINDOW_UPDATE',
  },
  {
    name: 'H2B-010-post-with-data',
    category: 'H2B',
    description: 'HTTP/2 POST with HEADERS + DATA frames',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'POST-Headers' },
      { type: 'send', data: () => buildH2Data(1, JSON.stringify({ key: 'value' }), { endStream: true }), label: 'POST-Data' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle POST with DATA frame',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  H2C — HTTP/2 Header Fuzzing (~12 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'H2C-001-missing-method',
    category: 'H2C',
    description: 'HEADERS without :method pseudo-header',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':scheme': 'https',
        ':path': DEFAULT_HTTP2_ENDPOINT,
        ':authority': DEFAULT_HOST,
      }, { endStream: true }), label: 'NoMethod' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject request without :method',
  },
  {
    name: 'H2C-002-missing-path',
    category: 'H2C',
    description: 'HEADERS without :path pseudo-header',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':scheme': 'https',
        ':authority': DEFAULT_HOST,
      }, { endStream: true }), label: 'NoPath' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject request without :path',
  },
  {
    name: 'H2C-003-missing-scheme',
    category: 'H2C',
    description: 'HEADERS without :scheme pseudo-header',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':path': DEFAULT_HTTP2_ENDPOINT,
        ':authority': DEFAULT_HOST,
      }, { endStream: true }), label: 'NoScheme' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject request without :scheme',
  },
  {
    name: 'H2C-004-uppercase-header',
    category: 'H2C',
    description: 'HEADERS with uppercase header name (forbidden in HTTP/2)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':scheme': 'https',
        ':path': DEFAULT_HTTP2_ENDPOINT,
        ':authority': DEFAULT_HOST,
        'X-UPPERCASE': 'value',
      }, { endStream: true }), label: 'UppercaseHeader' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject uppercase header names in HTTP/2',
  },
  {
    name: 'H2C-005-te-header',
    category: 'H2C',
    description: 'HEADERS with TE header (only "trailers" allowed in HTTP/2)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':scheme': 'https',
        ':path': DEFAULT_HTTP2_ENDPOINT,
        ':authority': DEFAULT_HOST,
        'te': 'chunked',
      }, { endStream: true }), label: 'TEChunked' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject TE header with value other than "trailers"',
  },
  {
    name: 'H2C-006-connection-header',
    category: 'H2C',
    description: 'HEADERS with Connection header (forbidden in HTTP/2)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':scheme': 'https',
        ':path': DEFAULT_HTTP2_ENDPOINT,
        ':authority': DEFAULT_HOST,
        'connection': 'keep-alive',
      }, { endStream: true }), label: 'ConnectionHeader' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject Connection header in HTTP/2',
  },
  {
    name: 'H2C-007-oversized-header-block',
    category: 'H2C',
    description: 'HEADERS with 64KB header block',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':scheme': 'https',
        ':path': DEFAULT_HTTP2_ENDPOINT,
        ':authority': DEFAULT_HOST,
        'x-large': 'X'.repeat(65536),
      }, { endStream: true }), label: 'OversizedHeaders' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle or reject oversized header blocks',
  },
  {
    name: 'H2C-008-duplicate-pseudo-header',
    category: 'H2C',
    description: 'HEADERS with duplicate :method pseudo-header',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => {
        // Manually build headers with duplicate :method
        const headerBlock = Buffer.concat([
          hpackEncodeLiteral(':method', 'GET'),
          hpackEncodeLiteral(':method', 'POST'),
          hpackEncodeLiteral(':scheme', 'https'),
          hpackEncodeLiteral(':path', DEFAULT_HTTP2_ENDPOINT),
          hpackEncodeLiteral(':authority', DEFAULT_HOST),
        ]);
        return buildH2Frame(H2_FRAME_TYPE.HEADERS, H2_FLAGS.END_HEADERS | H2_FLAGS.END_STREAM, 1, headerBlock);
      }, label: 'DuplicateMethod' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject duplicate pseudo-headers',
  },
  {
    name: 'H2C-009-pseudo-after-regular',
    category: 'H2C',
    description: 'Pseudo-header after regular header (invalid order)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => {
        const headerBlock = Buffer.concat([
          hpackEncodeLiteral(':method', 'GET'),
          hpackEncodeLiteral('x-custom', 'value'),
          hpackEncodeLiteral(':path', DEFAULT_HTTP2_ENDPOINT),  // pseudo after regular
          hpackEncodeLiteral(':scheme', 'https'),
          hpackEncodeLiteral(':authority', DEFAULT_HOST),
        ]);
        return buildH2Frame(H2_FRAME_TYPE.HEADERS, H2_FLAGS.END_HEADERS | H2_FLAGS.END_STREAM, 1, headerBlock);
      }, label: 'PseudoAfterRegular' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject pseudo-headers after regular headers',
  },
  {
    name: 'H2C-010-unknown-pseudo-header',
    category: 'H2C',
    description: 'HEADERS with unknown pseudo-header :foobar',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':scheme': 'https',
        ':path': DEFAULT_HTTP2_ENDPOINT,
        ':authority': DEFAULT_HOST,
        ':foobar': 'unknown',
      }, { endStream: true }), label: 'UnknownPseudo' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject unknown pseudo-headers',
  },
  {
    name: 'H2C-011-empty-path',
    category: 'H2C',
    description: 'HEADERS with empty :path',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Headers(1, {
        ':method': 'GET',
        ':scheme': 'https',
        ':path': '',
        ':authority': DEFAULT_HOST,
      }, { endStream: true }), label: 'EmptyPath' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject empty :path',
  },
  {
    name: 'H2C-012-custom-h2-endpoint',
    category: 'H2C',
    description: 'HTTP/2 GET to user-configured custom endpoint',
    side: 'client',
    useCustomEndpoint: true,
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: (ctx) => buildH2GetRequest(
        1,
        ctx.http2Endpoint || DEFAULT_HTTP2_ENDPOINT,
        ctx.httpHost || DEFAULT_HOST,
      ), label: 'CustomH2Request' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should respond to custom HTTP/2 endpoint',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  H2D — HTTP/2 Data Frames (~10 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'H2D-001-data-with-padding',
    category: 'H2D',
    description: 'DATA frame with padding',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'Headers' },
      { type: 'send', data: () => buildH2Data(1, 'padded data', { endStream: true, padLength: 64 }), label: 'PaddedData' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle padded DATA frames',
  },
  {
    name: 'H2D-002-empty-data',
    category: 'H2D',
    description: 'Empty DATA frame with END_STREAM',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'Headers' },
      { type: 'send', data: () => buildH2Data(1, '', { endStream: true }), label: 'EmptyData' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle empty DATA frame',
  },
  {
    name: 'H2D-003-data-after-end-stream',
    category: 'H2D',
    description: 'Send DATA after END_STREAM flag was set',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2GetRequest(1, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST), label: 'GET-EndStream' },
      { type: 'send', data: () => buildH2Data(1, 'extra data', { endStream: false }), label: 'DataAfterEnd' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject DATA on half-closed stream',
  },
  {
    name: 'H2D-004-data-on-stream-zero',
    category: 'H2D',
    description: 'Send DATA frame on stream 0 (invalid)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Data(0, 'stream-zero-data', { endStream: true }), label: 'DataStream0' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject DATA on stream 0',
  },
  {
    name: 'H2D-005-large-data-frame',
    category: 'H2D',
    description: 'DATA frame at maximum frame size (16384 bytes)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'Headers' },
      { type: 'send', data: () => buildH2Data(1, Buffer.alloc(16384, 0x42), { endStream: true }), label: 'MaxData' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle max-size DATA frames',
  },
  {
    name: 'H2D-006-oversized-data-frame',
    category: 'H2D',
    description: 'DATA frame exceeding MAX_FRAME_SIZE',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'Headers' },
      { type: 'send', data: () => buildH2Data(1, Buffer.alloc(16385, 0x42), { endStream: true }), label: 'OversizedData' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject DATA exceeding MAX_FRAME_SIZE',
  },
  {
    name: 'H2D-007-multiple-data-frames',
    category: 'H2D',
    description: 'Multiple DATA frames on same stream',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'Headers' },
      { type: 'send', data: () => buildH2Data(1, 'chunk1', { endStream: false }), label: 'Data1' },
      { type: 'send', data: () => buildH2Data(1, 'chunk2', { endStream: false }), label: 'Data2' },
      { type: 'send', data: () => buildH2Data(1, 'chunk3', { endStream: true }), label: 'Data3' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle multiple DATA frames',
  },
  {
    name: 'H2D-008-flow-control-exceeded',
    category: 'H2D',
    description: 'Send more data than flow control window allows',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2Settings({
        [H2_SETTINGS.INITIAL_WINDOW_SIZE]: 1024,
      }), label: 'SmallWindow' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'Headers' },
      { type: 'send', data: () => buildH2Data(1, Buffer.alloc(2048, 0x42), { endStream: true }), label: 'ExcessData' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle flow control correctly',
  },
  {
    name: 'H2D-009-data-only-padding',
    category: 'H2D',
    description: 'DATA frame with only padding (no actual data)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2PostRequest(1, '/api/v2/data', DEFAULT_HOST), label: 'Headers' },
      { type: 'send', data: () => buildH2Data(1, '', { endStream: true, padLength: 128 }), label: 'PaddingOnly' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server should handle DATA with only padding',
  },
  {
    name: 'H2D-010-data-no-headers',
    category: 'H2D',
    description: 'Send DATA frame without preceding HEADERS',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Data(1, 'no-headers-data', { endStream: true }), label: 'DataNoHeaders' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject DATA without preceding HEADERS',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  H2E — HTTP/2 Server Push (~8 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'H2E-001-push-promise',
    category: 'H2E',
    description: 'Server sends PUSH_PROMISE for a resource',
    side: 'server',
    serverHandler: (socket, log, h2Session) => {
      return new Promise((resolve) => {
        // This scenario uses Node.js http2 server
        log('Waiting for HTTP/2 client request to send PUSH_PROMISE');
        setTimeout(() => {
          resolve({ status: 'PASSED', response: 'PUSH_PROMISE scenario (requires http2 session)' });
        }, 5000);
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle PUSH_PROMISE',
  },
  {
    name: 'H2E-002-push-after-disable',
    category: 'H2E',
    description: 'Server sends PUSH_PROMISE after client disabled push',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        log('Sending PUSH_PROMISE despite client ENABLE_PUSH=0');
        socket.on('data', () => {
          const pushPromise = buildH2PushPromise(1, 2, {
            ':method': 'GET',
            ':scheme': 'https',
            ':authority': DEFAULT_HOST,
            ':path': '/api/v2/pushed-resource',
          });
          socket.write(pushPromise);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Push after disable sent' }); }, 1000);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should send GOAWAY for unexpected PUSH_PROMISE',
  },
  {
    name: 'H2E-003-push-odd-stream',
    category: 'H2E',
    description: 'Server sends PUSH_PROMISE with odd promised stream ID (invalid)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending PUSH_PROMISE with odd stream ID');
          const pushPromise = buildH2PushPromise(1, 3, {
            ':method': 'GET',
            ':scheme': 'https',
            ':authority': DEFAULT_HOST,
            ':path': '/api/v2/odd-push',
          });
          socket.write(pushPromise);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Odd push stream sent' }); }, 1000);
        });
      });
    },
    expected: 'DROPPED',
    expectedReason: 'Client should reject PUSH_PROMISE with odd stream ID',
  },
  {
    name: 'H2E-004-goaway-with-error',
    category: 'H2E',
    description: 'Server sends GOAWAY with PROTOCOL_ERROR',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending GOAWAY with PROTOCOL_ERROR');
          const goaway = buildH2Goaway(0, H2_ERROR.PROTOCOL_ERROR, 'test error');
          socket.write(goaway);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'GOAWAY error sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle GOAWAY with error code',
  },
  {
    name: 'H2E-005-rst-stream-from-server',
    category: 'H2E',
    description: 'Server sends RST_STREAM on client request',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending RST_STREAM REFUSED_STREAM');
          const rst = buildH2RstStream(1, H2_ERROR.REFUSED_STREAM);
          socket.write(rst);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'RST_STREAM sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle RST_STREAM from server',
  },
  {
    name: 'H2E-006-settings-ack-timeout',
    category: 'H2E',
    description: 'Server never sends SETTINGS ACK',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        log('Sending SETTINGS but never ACKing client SETTINGS');
        const settings = buildH2Settings({
          [H2_SETTINGS.MAX_CONCURRENT_STREAMS]: 100,
        });
        socket.write(settings);
        // Never send ACK — client should timeout
        setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'No SETTINGS ACK sent' }); }, 10000);
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should timeout waiting for SETTINGS ACK',
  },
  {
    name: 'H2E-007-invalid-frame-type',
    category: 'H2E',
    description: 'Server sends frame with unknown type',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending unknown frame type 0xFF');
          const unknownFrame = buildH2Frame(0xFF, 0, 0, Buffer.from('unknown'));
          socket.write(unknownFrame);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Unknown frame type sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should ignore unknown frame types (RFC 7540 Section 4.1)',
  },
  {
    name: 'H2E-008-server-h2-response',
    category: 'H2E',
    description: 'Server sends normal HTTP/2 response with headers and data',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', () => {
          log('Sending HTTP/2 response');
          const respHeaders = buildH2Headers(1, {
            ':status': '200',
            'content-type': 'application/json',
          }, { endStream: false });
          const respData = buildH2Data(1, JSON.stringify({ status: 'ok', protocol: 'h2' }), { endStream: true });
          socket.write(Buffer.concat([respHeaders, respData]));
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'H2 response sent' }); }, 500);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should parse HTTP/2 response',
  },
);


// ─────────────────────────────────────────────────────────────────────────────
//  H2F — HTTP/2 Protocol Violations (~12 scenarios)
// ─────────────────────────────────────────────────────────────────────────────

TRAFFIC_SCENARIOS.push(
  {
    name: 'H2F-001-settings-on-stream',
    category: 'H2F',
    description: 'Send SETTINGS frame on non-zero stream (invalid)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2Frame(H2_FRAME_TYPE.SETTINGS, 0, 1, Buffer.alloc(0)), label: 'SettingsOnStream1' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject SETTINGS on non-zero stream',
  },
  {
    name: 'H2F-002-ping-wrong-length',
    category: 'H2F',
    description: 'Send PING frame with wrong payload length (not 8 bytes)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Frame(H2_FRAME_TYPE.PING, 0, 0, Buffer.alloc(4)), label: 'ShortPing' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject PING with wrong length (FRAME_SIZE_ERROR)',
  },
  {
    name: 'H2F-003-settings-odd-length',
    category: 'H2F',
    description: 'Send SETTINGS with payload not multiple of 6 bytes',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2Frame(H2_FRAME_TYPE.SETTINGS, 0, 0, Buffer.alloc(7)), label: 'OddSettings' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject SETTINGS with invalid length',
  },
  {
    name: 'H2F-004-settings-ack-with-payload',
    category: 'H2F',
    description: 'Send SETTINGS ACK with non-empty payload',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Frame(H2_FRAME_TYPE.SETTINGS, H2_FLAGS.ACK, 0, Buffer.alloc(6)), label: 'ACKWithPayload' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject SETTINGS ACK with payload',
  },
  {
    name: 'H2F-005-goaway-on-stream',
    category: 'H2F',
    description: 'Send GOAWAY on non-zero stream (invalid)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => {
        const payload = Buffer.alloc(8);
        return buildH2Frame(H2_FRAME_TYPE.GOAWAY, 0, 1, payload);
      }, label: 'GoawayOnStream1' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject GOAWAY on non-zero stream',
  },
  {
    name: 'H2F-006-window-update-on-idle',
    category: 'H2F',
    description: 'Send WINDOW_UPDATE on idle stream',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2WindowUpdate(99, 1024), label: 'WUIdleStream' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'PASSED',
    expectedReason: 'Server may accept or reject WINDOW_UPDATE on idle stream',
  },
  {
    name: 'H2F-007-continuation-without-headers',
    category: 'H2F',
    description: 'Send CONTINUATION frame without preceding HEADERS',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Frame(
        H2_FRAME_TYPE.CONTINUATION,
        H2_FLAGS.END_HEADERS,
        1,
        hpackEncodeLiteral(':method', 'GET'),
      ), label: 'OrphanContinuation' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject CONTINUATION without HEADERS',
  },
  {
    name: 'H2F-008-rst-stream-zero',
    category: 'H2F',
    description: 'Send RST_STREAM on stream 0 (invalid)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2RstStream(0, H2_ERROR.NO_ERROR), label: 'RSTStream0' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject RST_STREAM on stream 0',
  },
  {
    name: 'H2F-009-priority-on-stream-zero',
    category: 'H2F',
    description: 'Send PRIORITY on stream 0 (invalid)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2Priority(0, 1, 16, false), label: 'PriorityStream0' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject PRIORITY on stream 0',
  },
  {
    name: 'H2F-010-invalid-settings-value',
    category: 'H2F',
    description: 'Send SETTINGS with ENABLE_PUSH = 2 (invalid, must be 0 or 1)',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2Settings({
        [H2_SETTINGS.ENABLE_PUSH]: 2,
      }), label: 'InvalidPushValue' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject ENABLE_PUSH value other than 0 or 1',
  },
  {
    name: 'H2F-011-window-overflow',
    category: 'H2F',
    description: 'Send WINDOW_UPDATE causing flow control window overflow',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildH2Preface(), label: 'Preface' },
      { type: 'send', data: () => buildH2DefaultSettings(), label: 'Settings' },
      { type: 'recv', timeout: 5000, label: 'ServerSettings' },
      { type: 'send', data: () => buildH2Settings({}, true), label: 'SettingsACK' },
      { type: 'send', data: () => buildH2WindowUpdate(0, 0x7FFFFFFF), label: 'MaxWindowUpdate' },
      { type: 'send', data: () => buildH2WindowUpdate(0, 0x7FFFFFFF), label: 'OverflowWindowUpdate' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should send GOAWAY for flow control window overflow',
  },
  {
    name: 'H2F-012-http11-on-h2-port',
    category: 'H2F',
    description: 'Send HTTP/1.1 request on HTTP/2 port',
    side: 'client',
    steps: [
      { type: 'connect', mode: 'tls', port: DEFAULT_HTTP2_PORT, alpn: 'h2' },
      { type: 'send', data: () => buildHTTPRequest({
        method: 'GET', path: '/api/v1/health', host: DEFAULT_HOST,
      }), label: 'HTTP11onH2' },
      { type: 'recv', timeout: 5000, label: 'Response' },
      { type: 'close' },
    ],
    expected: 'DROPPED',
    expectedReason: 'Server should reject HTTP/1.1 on HTTP/2 connection',
  },
);


// ═══════════════════════════════════════════════════════════════════════════════
//  SCENARIO LOOKUP FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get a scenario by name.
 * @param {string} name - Scenario name
 * @returns {Object|null}
 */
function getTrafficScenario(name) {
  return TRAFFIC_SCENARIOS.find(s => s.name === name) || null;
}

/**
 * Get all scenarios in a category.
 * @param {string} category - Category code (e.g. 'TA', 'HD')
 * @returns {Array}
 */
function getTrafficScenariosByCategory(category) {
  return TRAFFIC_SCENARIOS.filter(s => s.category === category);
}

/**
 * List all scenarios grouped by category.
 * @returns {{ categories: Object, scenarios: Object, categorySeverity: Object, defaultDisabled: string[] }}
 */
function listTrafficScenarios() {
  const scenarios = {};
  for (const s of TRAFFIC_SCENARIOS) {
    if (!scenarios[s.category]) scenarios[s.category] = [];
    scenarios[s.category].push(s);
  }
  return {
    categories: TRAFFIC_CATEGORIES,
    scenarios,
    categorySeverity: TRAFFIC_CATEGORY_SEVERITY,
    defaultDisabled: [...TRAFFIC_CATEGORY_DEFAULT_DISABLED],
  };
}

/**
 * List only client-side scenarios.
 * @returns {Array}
 */
function listTrafficClientScenarios() {
  return TRAFFIC_SCENARIOS.filter(s => s.side === 'client');
}

/**
 * List only server-side scenarios.
 * @returns {Array}
 */
function listTrafficServerScenarios() {
  return TRAFFIC_SCENARIOS.filter(s => s.side === 'server');
}


module.exports = {
  // Category metadata
  TRAFFIC_CATEGORIES,
  TRAFFIC_CATEGORY_SEVERITY,
  TRAFFIC_CATEGORY_DEFAULT_DISABLED,

  // Scenarios
  TRAFFIC_SCENARIOS,

  // Lookup functions
  getTrafficScenario,
  getTrafficScenariosByCategory,
  listTrafficScenarios,
  listTrafficClientScenarios,
  listTrafficServerScenarios,
};
