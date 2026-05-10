// HTTP/1.1 Request/Response Builder — raw message construction for fuzzing
// Builds HTTP messages as raw buffers for precise control over headers and body

'use strict';

const {
  HTTP_METHOD,
  HTTP_STATUS,
  DEFAULT_HTTP_ENDPOINT,
  DEFAULT_HOST,
} = require('./constants');


// ═══════════════════════════════════════════════════════════════════════════════
//  REQUEST BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a raw HTTP/1.1 request as a Buffer.
 * Uses raw string construction (not Node.js http module) for fuzzing precision.
 *
 * @param {Object} [opts]
 * @param {string} [opts.method='GET'] - HTTP method
 * @param {string} [opts.path='/api/v1/health'] - Request path
 * @param {string} [opts.host='testserver.local'] - Host header value
 * @param {string} [opts.version='HTTP/1.1'] - HTTP version string
 * @param {Object} [opts.headers={}] - Additional headers (key-value pairs)
 * @param {string|Buffer} [opts.body=''] - Request body
 * @param {boolean} [opts.includeContentLength=true] - Auto-add Content-Length for body
 * @param {boolean} [opts.includeHost=true] - Auto-add Host header
 * @param {string} [opts.lineEnding='\r\n'] - Line ending (CRLF by default)
 * @returns {Buffer}
 */
function buildHTTPRequest(opts = {}) {
  const method = opts.method || HTTP_METHOD.GET;
  const path = opts.path || DEFAULT_HTTP_ENDPOINT;
  const host = opts.host || DEFAULT_HOST;
  const version = opts.version || 'HTTP/1.1';
  const headers = opts.headers || {};
  const body = opts.body || '';
  const le = opts.lineEnding || '\r\n';
  const includeHost = opts.includeHost !== false;
  const includeContentLength = opts.includeContentLength !== false;

  let req = `${method} ${path} ${version}${le}`;

  // Host header first (HTTP/1.1 requirement)
  if (includeHost && !hasHeader(headers, 'host')) {
    req += `Host: ${host}${le}`;
  }

  // User-supplied headers
  for (const [key, value] of Object.entries(headers)) {
    req += `${key}: ${value}${le}`;
  }

  // Content-Length for body
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  if (bodyBuf.length > 0 && includeContentLength && !hasHeader(headers, 'content-length')) {
    req += `Content-Length: ${bodyBuf.length}${le}`;
  }

  // End of headers
  req += le;

  // Combine request line + headers + body
  const headerBuf = Buffer.from(req);
  if (bodyBuf.length > 0) {
    return Buffer.concat([headerBuf, bodyBuf]);
  }
  return headerBuf;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  RESPONSE BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a raw HTTP/1.1 response as a Buffer.
 *
 * @param {Object} [opts]
 * @param {number} [opts.statusCode=200] - HTTP status code
 * @param {string} [opts.statusText] - Status text (auto-derived from code if omitted)
 * @param {string} [opts.version='HTTP/1.1'] - HTTP version string
 * @param {Object} [opts.headers={}] - Response headers
 * @param {string|Buffer} [opts.body=''] - Response body
 * @param {boolean} [opts.includeContentLength=true] - Auto-add Content-Length
 * @param {boolean} [opts.includeDate=true] - Auto-add Date header
 * @param {boolean} [opts.includeServer=true] - Auto-add Server header
 * @param {string} [opts.lineEnding='\r\n'] - Line ending
 * @returns {Buffer}
 */
function buildHTTPResponse(opts = {}) {
  const statusCode = opts.statusCode || 200;
  const statusText = opts.statusText || HTTP_STATUS[statusCode] || 'Unknown';
  const version = opts.version || 'HTTP/1.1';
  const headers = opts.headers || {};
  const body = opts.body || '';
  const le = opts.lineEnding || '\r\n';
  const includeContentLength = opts.includeContentLength !== false;
  const includeDate = opts.includeDate !== false;
  const includeServer = opts.includeServer !== false;

  let resp = `${version} ${statusCode} ${statusText}${le}`;

  // Standard headers
  if (includeDate && !hasHeader(headers, 'date')) {
    resp += `Date: ${new Date().toUTCString()}${le}`;
  }
  if (includeServer && !hasHeader(headers, 'server')) {
    resp += `Server: identity-fuzzer/1.0${le}`;
  }

  // User-supplied headers
  for (const [key, value] of Object.entries(headers)) {
    resp += `${key}: ${value}${le}`;
  }

  // Content-Length
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  if (includeContentLength && !hasHeader(headers, 'content-length')) {
    resp += `Content-Length: ${bodyBuf.length}${le}`;
  }

  // End of headers
  resp += le;

  const headerBuf = Buffer.from(resp);
  if (bodyBuf.length > 0) {
    return Buffer.concat([headerBuf, bodyBuf]);
  }
  return headerBuf;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  CHUNKED ENCODING BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encode a body using HTTP chunked transfer encoding.
 * @param {Array<string|Buffer>} chunks - Array of chunk data
 * @param {Object} [opts]
 * @param {Object} [opts.trailers] - Trailer headers
 * @returns {Buffer}
 */
function buildChunkedBody(chunks, opts = {}) {
  const parts = [];
  for (const chunk of chunks) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    parts.push(Buffer.from(`${buf.length.toString(16)}\r\n`));
    parts.push(buf);
    parts.push(Buffer.from('\r\n'));
  }
  // Terminal chunk
  parts.push(Buffer.from('0\r\n'));

  // Trailers
  if (opts.trailers) {
    for (const [key, value] of Object.entries(opts.trailers)) {
      parts.push(Buffer.from(`${key}: ${value}\r\n`));
    }
  }
  parts.push(Buffer.from('\r\n'));

  return Buffer.concat(parts);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PARSER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Parse a raw HTTP message (request or response) from a Buffer.
 * Returns structured data for inspection.
 *
 * @param {Buffer} buffer - Raw HTTP message
 * @returns {Object} Parsed message with { type, method, path, version, statusCode, statusText, headers, body, raw }
 */
function parseHTTPMessage(buffer) {
  const raw = buffer.toString('utf8');
  const headerEnd = raw.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    return { type: 'incomplete', raw, headers: {}, body: '' };
  }

  const headerSection = raw.substring(0, headerEnd);
  const bodySection = raw.substring(headerEnd + 4);
  const lines = headerSection.split('\r\n');
  const firstLine = lines[0] || '';

  const result = {
    type: 'unknown',
    raw,
    headers: {},
    body: bodySection,
    headerCount: 0,
  };

  // Parse first line — request or response?
  if (firstLine.startsWith('HTTP/')) {
    // Response: HTTP/1.1 200 OK
    result.type = 'response';
    const parts = firstLine.split(' ');
    result.version = parts[0];
    result.statusCode = parseInt(parts[1], 10) || 0;
    result.statusText = parts.slice(2).join(' ');
  } else {
    // Request: GET /path HTTP/1.1
    result.type = 'request';
    const parts = firstLine.split(' ');
    result.method = parts[0];
    result.path = parts[1];
    result.version = parts[2];
  }

  // Parse headers
  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(':');
    if (colonIdx > 0) {
      const key = lines[i].substring(0, colonIdx).trim();
      const value = lines[i].substring(colonIdx + 1).trim();
      // Support multiple headers with same name
      if (result.headers[key.toLowerCase()]) {
        if (Array.isArray(result.headers[key.toLowerCase()])) {
          result.headers[key.toLowerCase()].push(value);
        } else {
          result.headers[key.toLowerCase()] = [result.headers[key.toLowerCase()], value];
        }
      } else {
        result.headers[key.toLowerCase()] = value;
      }
      result.headerCount++;
    }
  }

  return result;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if a header exists (case-insensitive) in a headers object.
 */
function hasHeader(headers, name) {
  const lower = name.toLowerCase();
  return Object.keys(headers).some(k => k.toLowerCase() === lower);
}

/**
 * Build a JSON body string.
 * @param {Object} data - Data to serialize
 * @returns {string}
 */
function jsonBody(data) {
  return JSON.stringify(data);
}

/**
 * Build a standard health check response body.
 * @returns {string}
 */
function healthResponse() {
  return jsonBody({ status: 'healthy', version: '1.0.0', timestamp: new Date().toISOString() });
}

/**
 * Build an echo response body from request details.
 * @param {Object} reqInfo - Parsed request info
 * @returns {string}
 */
function echoResponse(reqInfo) {
  return jsonBody({
    method: reqInfo.method,
    path: reqInfo.path,
    headers: reqInfo.headers,
    body: reqInfo.body,
    timestamp: new Date().toISOString(),
  });
}


module.exports = {
  buildHTTPRequest,
  buildHTTPResponse,
  buildChunkedBody,
  parseHTTPMessage,
  hasHeader,
  jsonBody,
  healthResponse,
  echoResponse,
};
