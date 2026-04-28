// HTTPS transport for PAN-OS User-ID XML API
// Sends uid-message payloads to the firewall management interface.
//
// PAN-OS Reference:
//   - POST /api/?type=user-id&key=<api-key>&cmd=<uid-message-xml>
//   - Response: <response status="success|error">...</response>

'use strict';

const https = require('https');
const fs = require('fs');
const { DEFAULT_API_PORT, API_ENDPOINT, TRANSPORT_STATE } = require('./constants');
const { parseResponse } = require('./xml-builder');


// ═══════════════════════════════════════════════════════════════════════════════
//  TRANSPORT STATS
// ═══════════════════════════════════════════════════════════════════════════════

class TransportStats {
  constructor() {
    this.requestsSent = 0;
    this.bytesSent = 0;
    this.bytesReceived = 0;
    this.successCount = 0;
    this.errorCount = 0;
    this.lastRequestTime = null;
  }

  recordSuccess(sentBytes, receivedBytes) {
    this.requestsSent++;
    this.successCount++;
    this.bytesSent += sentBytes || 0;
    this.bytesReceived += receivedBytes || 0;
    this.lastRequestTime = Date.now();
  }

  recordError(sentBytes) {
    this.requestsSent++;
    this.errorCount++;
    this.bytesSent += sentBytes || 0;
    this.lastRequestTime = Date.now();
  }

  get successRate() {
    if (this.requestsSent === 0) return 0;
    return (this.successCount / this.requestsSent) * 100;
  }

  toJSON() {
    return {
      requests_sent: this.requestsSent,
      bytes_sent: this.bytesSent,
      bytes_received: this.bytesReceived,
      success_count: this.successCount,
      error_count: this.errorCount,
      success_rate: Math.round(this.successRate * 10) / 10,
    };
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  XML API TRANSPORT
// ═══════════════════════════════════════════════════════════════════════════════

class XmlApiTransport {
  constructor() {
    this._state = TRANSPORT_STATE.DISCONNECTED;
    this._stats = new TransportStats();
    this._host = null;
    this._port = null;
    this._apiKey = null;
    this._tlsOptions = {};
  }

  get state() { return this._state; }
  get stats() { return this._stats; }
  get isConnected() { return this._state === TRANSPORT_STATE.CONNECTED; }
  get host() { return this._host; }
  get port() { return this._port; }

  /**
   * Configure the transport with connection parameters.
   * Unlike syslog, XML API is stateless HTTP — no persistent connection.
   * "connect" validates parameters and marks the transport as ready.
   *
   * @param {string} host - Firewall IP address or hostname
   * @param {number} [port] - HTTPS port (default: 443)
   * @param {Object} [opts]
   * @param {string} opts.apiKey - PAN-OS API key (required)
   * @param {boolean} [opts.verify=false] - Verify server certificate
   * @param {string} [opts.certFile] - Client certificate PEM file (mTLS)
   * @param {string} [opts.keyFile] - Client private key PEM file (mTLS)
   * @param {string} [opts.caFile] - CA certificate for server verification
   * @param {number} [opts.timeout=30000] - Request timeout in ms
   * @returns {Promise<void>}
   */
  async connect(host, port, opts = {}) {
    if (!host) throw new Error('Host is required');
    if (!opts.apiKey) throw new Error('API key is required');

    this._host = host;
    this._port = port || DEFAULT_API_PORT;
    this._apiKey = opts.apiKey;
    this._timeout = opts.timeout || 30000;

    // Build TLS options
    this._tlsOptions = {
      rejectUnauthorized: opts.verify === true,
    };

    if (opts.certFile) {
      this._tlsOptions.cert = fs.readFileSync(opts.certFile);
    }
    if (opts.keyFile) {
      this._tlsOptions.key = fs.readFileSync(opts.keyFile);
    }
    if (opts.caFile) {
      this._tlsOptions.ca = fs.readFileSync(opts.caFile);
    }

    this._state = TRANSPORT_STATE.CONNECTED;
  }

  /**
   * Send a uid-message XML payload to the PAN-OS XML API.
   *
   * @param {string} xmlPayload - Complete uid-message XML string
   * @returns {Promise<{status: string, message: string, code: string|null, raw: string}>}
   */
  send(xmlPayload) {
    if (this._state !== TRANSPORT_STATE.CONNECTED) {
      return Promise.reject(new Error('Transport not connected — call connect() first'));
    }

    return new Promise((resolve, reject) => {
      // Build the POST body: cmd=<xml>
      const body = `cmd=${encodeURIComponent(xmlPayload)}`;
      const bodyBytes = Buffer.from(body, 'utf-8');

      const url = `${API_ENDPOINT}?type=user-id&key=${encodeURIComponent(this._apiKey)}`;

      const requestOpts = {
        hostname: this._host,
        port: this._port,
        path: url,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': bodyBytes.length,
        },
        timeout: this._timeout,
        ...this._tlsOptions,
      };

      const req = https.request(requestOpts, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const responseBody = Buffer.concat(chunks).toString('utf-8');
          const parsed = parseResponse(responseBody);

          if (parsed.status === 'success') {
            this._stats.recordSuccess(bodyBytes.length, responseBody.length);
          } else {
            this._stats.recordError(bodyBytes.length);
          }

          resolve(parsed);
        });
      });

      req.on('error', (err) => {
        this._stats.recordError(bodyBytes.length);
        this._state = TRANSPORT_STATE.ERROR;
        reject(err);
      });

      req.on('timeout', () => {
        req.destroy();
        this._stats.recordError(bodyBytes.length);
        reject(new Error(`Request timed out after ${this._timeout}ms`));
      });

      req.write(bodyBytes);
      req.end();
    });
  }

  /**
   * Generate an API key from username/password via the keygen endpoint.
   *
   * @param {string} host - Firewall IP
   * @param {number} [port=443] - HTTPS port
   * @param {string} username - Admin username
   * @param {string} password - Admin password
   * @param {Object} [opts]
   * @param {boolean} [opts.verify=false] - Verify server certificate
   * @returns {Promise<string>} The API key
   */
  static keygen(host, port, username, password, opts = {}) {
    return new Promise((resolve, reject) => {
      const url = `${API_ENDPOINT}?type=keygen&user=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`;

      const requestOpts = {
        hostname: host,
        port: port || DEFAULT_API_PORT,
        path: url,
        method: 'GET',
        rejectUnauthorized: opts.verify === true,
        timeout: 15000,
      };

      const req = https.request(requestOpts, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8');
          // Extract key from: <response status="success"><result><key>APIKEY</key></result></response>
          const keyMatch = body.match(/<key>([^<]+)<\/key>/);
          if (keyMatch) {
            resolve(keyMatch[1]);
          } else {
            const parsed = parseResponse(body);
            reject(new Error(`Keygen failed: ${parsed.message || body}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Keygen request timed out'));
      });

      req.end();
    });
  }

  /**
   * Disconnect / reset the transport.
   */
  disconnect() {
    this._state = TRANSPORT_STATE.DISCONNECTED;
    this._host = null;
    this._port = null;
    this._apiKey = null;
    this._tlsOptions = {};
  }
}

module.exports = {
  XmlApiTransport,
  TransportStats,
};
