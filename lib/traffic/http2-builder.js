// HTTP/2 Frame Builder — raw frame construction for fuzzing
// Builds HTTP/2 frames as raw buffers for precise protocol-level control
// Reference: RFC 7540 (HTTP/2), RFC 7541 (HPACK)

'use strict';

const {
  H2_FRAME_TYPE,
  H2_FLAGS,
  H2_SETTINGS,
  H2_ERROR,
  H2_PREFACE,
  DEFAULT_HTTP2_ENDPOINT,
  DEFAULT_HOST,
} = require('./constants');


// ═══════════════════════════════════════════════════════════════════════════════
//  CONNECTION PREFACE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build the HTTP/2 connection preface (magic octets).
 * Must be the first thing sent by the client.
 * @returns {Buffer}
 */
function buildH2Preface() {
  return Buffer.from(H2_PREFACE, 'ascii');
}


// ═══════════════════════════════════════════════════════════════════════════════
//  GENERIC FRAME BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a raw HTTP/2 frame.
 * Frame format (9-byte header + payload):
 *   Length (24 bits) | Type (8) | Flags (8) | Reserved (1) | Stream ID (31)
 *
 * @param {number} type - Frame type (H2_FRAME_TYPE.*)
 * @param {number} flags - Frame flags
 * @param {number} streamId - Stream identifier (0 for connection-level)
 * @param {Buffer} [payload=Buffer.alloc(0)] - Frame payload
 * @returns {Buffer}
 */
function buildH2Frame(type, flags, streamId, payload) {
  const data = payload || Buffer.alloc(0);
  const header = Buffer.alloc(9);

  // Length: 24-bit unsigned integer
  header[0] = (data.length >> 16) & 0xFF;
  header[1] = (data.length >> 8) & 0xFF;
  header[2] = data.length & 0xFF;

  // Type: 8-bit
  header[3] = type & 0xFF;

  // Flags: 8-bit
  header[4] = flags & 0xFF;

  // Stream ID: 31-bit (MSB reserved, must be 0)
  header.writeUInt32BE(streamId & 0x7FFFFFFF, 5);

  return Buffer.concat([header, data]);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SETTINGS FRAME
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a SETTINGS frame.
 * @param {Object} [settings={}] - Settings key-value pairs (H2_SETTINGS.* → value)
 * @param {boolean} [ack=false] - If true, build a SETTINGS ACK (empty payload)
 * @returns {Buffer}
 */
function buildH2Settings(settings = {}, ack = false) {
  if (ack) {
    return buildH2Frame(H2_FRAME_TYPE.SETTINGS, H2_FLAGS.ACK, 0, Buffer.alloc(0));
  }

  const entries = Object.entries(settings);
  const payload = Buffer.alloc(entries.length * 6);
  let offset = 0;

  for (const [id, value] of entries) {
    const settingId = typeof id === 'string' ? parseInt(id, 10) : id;
    payload.writeUInt16BE(settingId, offset);
    payload.writeUInt32BE(value, offset + 2);
    offset += 6;
  }

  return buildH2Frame(H2_FRAME_TYPE.SETTINGS, 0, 0, payload.slice(0, offset));
}

/**
 * Build default client SETTINGS frame.
 * @returns {Buffer}
 */
function buildH2DefaultSettings() {
  return buildH2Settings({
    [H2_SETTINGS.MAX_CONCURRENT_STREAMS]: 100,
    [H2_SETTINGS.INITIAL_WINDOW_SIZE]: 65535,
    [H2_SETTINGS.MAX_FRAME_SIZE]: 16384,
  });
}


// ═══════════════════════════════════════════════════════════════════════════════
//  HEADERS FRAME (simplified HPACK)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encode a header name-value pair using HPACK literal encoding (never indexed).
 * This is a simplified encoder — does NOT use the static/dynamic table for
 * compression. Suitable for fuzzing where we want explicit control.
 *
 * @param {string} name - Header name (lowercase)
 * @param {string} value - Header value
 * @returns {Buffer}
 */
function hpackEncodeLiteral(name, value) {
  const nameBuf = Buffer.from(name, 'utf8');
  const valueBuf = Buffer.from(value, 'utf8');
  const parts = [];

  // Literal Header Field without Indexing — New Name (0000 0000)
  parts.push(Buffer.from([0x00]));

  // Name length (7-bit prefix)
  parts.push(hpackEncodeInteger(nameBuf.length, 7));
  parts.push(nameBuf);

  // Value length (7-bit prefix)
  parts.push(hpackEncodeInteger(valueBuf.length, 7));
  parts.push(valueBuf);

  return Buffer.concat(parts);
}

/**
 * Encode an integer using HPACK integer encoding (RFC 7541 Section 5.1).
 * @param {number} value - Integer to encode
 * @param {number} prefixBits - Number of prefix bits (1-8)
 * @returns {Buffer}
 */
function hpackEncodeInteger(value, prefixBits) {
  const maxPrefix = (1 << prefixBits) - 1;
  if (value < maxPrefix) {
    return Buffer.from([value]);
  }

  const bytes = [maxPrefix];
  value -= maxPrefix;
  while (value >= 128) {
    bytes.push((value & 0x7F) | 0x80);
    value >>= 7;
  }
  bytes.push(value);
  return Buffer.from(bytes);
}

/**
 * Build a HEADERS frame with HPACK-encoded headers.
 *
 * @param {number} streamId - Stream identifier (must be odd for client-initiated)
 * @param {Object} headers - Headers to encode. Pseudo-headers (:method, :path, etc.) first.
 * @param {Object} [opts]
 * @param {boolean} [opts.endStream=false] - Set END_STREAM flag
 * @param {boolean} [opts.endHeaders=true] - Set END_HEADERS flag
 * @param {boolean} [opts.priority=false] - Include PRIORITY data
 * @param {number} [opts.weight=16] - Stream weight (1-256)
 * @param {number} [opts.dependency=0] - Stream dependency
 * @param {boolean} [opts.exclusive=false] - Exclusive dependency
 * @returns {Buffer}
 */
function buildH2Headers(streamId, headers, opts = {}) {
  const endStream = opts.endStream || false;
  const endHeaders = opts.endHeaders !== false;

  let flags = 0;
  if (endStream) flags |= H2_FLAGS.END_STREAM;
  if (endHeaders) flags |= H2_FLAGS.END_HEADERS;
  if (opts.priority) flags |= H2_FLAGS.PRIORITY;

  // Encode headers using HPACK literal encoding
  const headerBlocks = [];

  // Pseudo-headers first (required order per RFC 7540)
  const pseudoOrder = [':method', ':scheme', ':authority', ':path', ':status'];
  for (const name of pseudoOrder) {
    if (headers[name] !== undefined) {
      headerBlocks.push(hpackEncodeLiteral(name, String(headers[name])));
    }
  }

  // Regular headers
  for (const [name, value] of Object.entries(headers)) {
    if (!name.startsWith(':')) {
      headerBlocks.push(hpackEncodeLiteral(name, String(value)));
    }
  }

  let payload = Buffer.concat(headerBlocks);

  // Prepend PRIORITY data if requested
  if (opts.priority) {
    const priorityBuf = Buffer.alloc(5);
    let dep = (opts.dependency || 0) & 0x7FFFFFFF;
    if (opts.exclusive) dep |= 0x80000000;
    priorityBuf.writeUInt32BE(dep >>> 0, 0);
    priorityBuf[4] = ((opts.weight || 16) - 1) & 0xFF;
    payload = Buffer.concat([priorityBuf, payload]);
  }

  return buildH2Frame(H2_FRAME_TYPE.HEADERS, flags, streamId, payload);
}

/**
 * Build a HEADERS frame for a standard GET request.
 * @param {number} streamId - Stream ID
 * @param {string} [path='/api/v2/status'] - Request path
 * @param {string} [authority='testserver.local'] - Authority (host)
 * @param {Object} [extraHeaders={}] - Additional headers
 * @returns {Buffer}
 */
function buildH2GetRequest(streamId, path, authority, extraHeaders = {}) {
  const headers = {
    ':method': 'GET',
    ':scheme': 'https',
    ':authority': authority || DEFAULT_HOST,
    ':path': path || DEFAULT_HTTP2_ENDPOINT,
    ...extraHeaders,
  };
  return buildH2Headers(streamId, headers, { endStream: true });
}

/**
 * Build a HEADERS frame for a POST request (headers only, body sent as DATA).
 * @param {number} streamId - Stream ID
 * @param {string} [path='/api/v2/data'] - Request path
 * @param {string} [authority='testserver.local'] - Authority
 * @param {Object} [extraHeaders={}] - Additional headers
 * @returns {Buffer}
 */
function buildH2PostRequest(streamId, path, authority, extraHeaders = {}) {
  const headers = {
    ':method': 'POST',
    ':scheme': 'https',
    ':authority': authority || DEFAULT_HOST,
    ':path': path || '/api/v2/data',
    'content-type': 'application/json',
    ...extraHeaders,
  };
  return buildH2Headers(streamId, headers, { endStream: false });
}


// ═══════════════════════════════════════════════════════════════════════════════
//  DATA FRAME
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a DATA frame.
 * @param {number} streamId - Stream identifier
 * @param {Buffer|string} data - Payload data
 * @param {Object} [opts]
 * @param {boolean} [opts.endStream=true] - Set END_STREAM flag
 * @param {number} [opts.padLength=0] - Padding length (0-255)
 * @returns {Buffer}
 */
function buildH2Data(streamId, data, opts = {}) {
  const endStream = opts.endStream !== false;
  const padLength = opts.padLength || 0;
  let flags = 0;
  if (endStream) flags |= H2_FLAGS.END_STREAM;

  let payload = Buffer.isBuffer(data) ? data : Buffer.from(data);

  if (padLength > 0) {
    flags |= H2_FLAGS.PADDED;
    const padded = Buffer.alloc(1 + payload.length + padLength);
    padded[0] = padLength;
    payload.copy(padded, 1);
    // Padding bytes are zero (already from alloc)
    payload = padded;
  }

  return buildH2Frame(H2_FRAME_TYPE.DATA, flags, streamId, payload);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  CONTROL FRAMES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a PING frame.
 * @param {Buffer} [opaqueData] - 8 bytes of opaque data
 * @param {boolean} [ack=false] - ACK flag
 * @returns {Buffer}
 */
function buildH2Ping(opaqueData, ack = false) {
  const data = opaqueData || Buffer.alloc(8);
  if (data.length !== 8) {
    const padded = Buffer.alloc(8);
    data.copy(padded, 0, 0, Math.min(8, data.length));
    return buildH2Frame(H2_FRAME_TYPE.PING, ack ? H2_FLAGS.ACK : 0, 0, padded);
  }
  return buildH2Frame(H2_FRAME_TYPE.PING, ack ? H2_FLAGS.ACK : 0, 0, data);
}

/**
 * Build a GOAWAY frame.
 * @param {number} lastStreamId - Last stream ID the sender will accept
 * @param {number} [errorCode=0] - Error code (H2_ERROR.*)
 * @param {Buffer|string} [debugData] - Optional debug data
 * @returns {Buffer}
 */
function buildH2Goaway(lastStreamId, errorCode, debugData) {
  const debug = debugData ? (Buffer.isBuffer(debugData) ? debugData : Buffer.from(debugData)) : Buffer.alloc(0);
  const payload = Buffer.alloc(8 + debug.length);
  payload.writeUInt32BE(lastStreamId & 0x7FFFFFFF, 0);
  payload.writeUInt32BE((errorCode || H2_ERROR.NO_ERROR) >>> 0, 4);
  if (debug.length > 0) debug.copy(payload, 8);
  return buildH2Frame(H2_FRAME_TYPE.GOAWAY, 0, 0, payload);
}

/**
 * Build a RST_STREAM frame.
 * @param {number} streamId - Stream to reset
 * @param {number} [errorCode=0] - Error code
 * @returns {Buffer}
 */
function buildH2RstStream(streamId, errorCode) {
  const payload = Buffer.alloc(4);
  payload.writeUInt32BE((errorCode || H2_ERROR.NO_ERROR) >>> 0, 0);
  return buildH2Frame(H2_FRAME_TYPE.RST_STREAM, 0, streamId, payload);
}

/**
 * Build a WINDOW_UPDATE frame.
 * @param {number} streamId - Stream ID (0 for connection-level)
 * @param {number} increment - Window size increment (1 to 2^31-1)
 * @returns {Buffer}
 */
function buildH2WindowUpdate(streamId, increment) {
  const payload = Buffer.alloc(4);
  payload.writeUInt32BE(increment & 0x7FFFFFFF, 0);
  return buildH2Frame(H2_FRAME_TYPE.WINDOW_UPDATE, 0, streamId, payload);
}

/**
 * Build a PRIORITY frame.
 * @param {number} streamId - Stream ID
 * @param {number} dependency - Stream dependency
 * @param {number} [weight=16] - Weight (1-256)
 * @param {boolean} [exclusive=false] - Exclusive flag
 * @returns {Buffer}
 */
function buildH2Priority(streamId, dependency, weight, exclusive) {
  const payload = Buffer.alloc(5);
  let dep = dependency & 0x7FFFFFFF;
  if (exclusive) dep |= 0x80000000;
  payload.writeUInt32BE(dep >>> 0, 0);
  payload[4] = ((weight || 16) - 1) & 0xFF;
  return buildH2Frame(H2_FRAME_TYPE.PRIORITY, 0, streamId, payload);
}

/**
 * Build a PUSH_PROMISE frame.
 * @param {number} streamId - Associated stream ID
 * @param {number} promisedStreamId - Promised stream ID
 * @param {Object} headers - Headers for the promised request
 * @returns {Buffer}
 */
function buildH2PushPromise(streamId, promisedStreamId, headers) {
  // Encode headers
  const headerBlocks = [];
  const pseudoOrder = [':method', ':scheme', ':authority', ':path'];
  for (const name of pseudoOrder) {
    if (headers[name] !== undefined) {
      headerBlocks.push(hpackEncodeLiteral(name, String(headers[name])));
    }
  }
  for (const [name, value] of Object.entries(headers)) {
    if (!name.startsWith(':')) {
      headerBlocks.push(hpackEncodeLiteral(name, String(value)));
    }
  }

  const headerBlock = Buffer.concat(headerBlocks);
  const payload = Buffer.alloc(4 + headerBlock.length);
  payload.writeUInt32BE(promisedStreamId & 0x7FFFFFFF, 0);
  headerBlock.copy(payload, 4);

  return buildH2Frame(
    H2_FRAME_TYPE.PUSH_PROMISE,
    H2_FLAGS.END_HEADERS,
    streamId,
    payload
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FRAME PARSER (basic)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Parse an HTTP/2 frame header from a buffer.
 * @param {Buffer} buffer - At least 9 bytes
 * @returns {Object|null} { length, type, flags, streamId, typeName }
 */
function parseH2FrameHeader(buffer) {
  if (buffer.length < 9) return null;

  const length = (buffer[0] << 16) | (buffer[1] << 8) | buffer[2];
  const type = buffer[3];
  const flags = buffer[4];
  const streamId = buffer.readUInt32BE(5) & 0x7FFFFFFF;

  return {
    length,
    type,
    flags,
    streamId,
    typeName: require('./constants').H2_FRAME_TYPE_NAME[type] || `UNKNOWN(${type})`,
  };
}

/**
 * Parse all HTTP/2 frames from a buffer.
 * @param {Buffer} buffer - Raw data
 * @returns {Array<Object>} Array of { header, payload }
 */
function parseH2Frames(buffer) {
  const frames = [];
  let offset = 0;

  while (offset + 9 <= buffer.length) {
    const header = parseH2FrameHeader(buffer.slice(offset));
    if (!header) break;

    const frameEnd = offset + 9 + header.length;
    if (frameEnd > buffer.length) break;

    const payload = buffer.slice(offset + 9, frameEnd);
    frames.push({ header, payload });
    offset = frameEnd;
  }

  return frames;
}


module.exports = {
  // Preface
  buildH2Preface,

  // Generic frame
  buildH2Frame,

  // Settings
  buildH2Settings,
  buildH2DefaultSettings,

  // HPACK helpers
  hpackEncodeLiteral,
  hpackEncodeInteger,

  // Headers
  buildH2Headers,
  buildH2GetRequest,
  buildH2PostRequest,

  // Data
  buildH2Data,

  // Control frames
  buildH2Ping,
  buildH2Goaway,
  buildH2RstStream,
  buildH2WindowUpdate,
  buildH2Priority,
  buildH2PushPromise,

  // Parser
  parseH2FrameHeader,
  parseH2Frames,
};
