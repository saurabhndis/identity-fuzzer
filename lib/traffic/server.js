// Traffic Fuzzer Server — hosts HTTP/HTTP2 endpoints and runs server-side scenarios
// Follows the same pattern as LdapFuzzerServer

'use strict';

const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const crypto = require('crypto');
const { Logger } = require('../logger');
const { PcapWriter } = require('../pcap-writer');
const { generateServerCert } = require('../cert-gen');
const { parseHTTPMessage, buildHTTPResponse, healthResponse, echoResponse, jsonBody } = require('./http-builder');
const {
  DEFAULT_TCP_PORT, DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT, DEFAULT_HTTP2_PORT,
  DEFAULT_HTTP_ENDPOINT, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST,
  DSCP_NAME, parseDSCP,
} = require('./constants');


class TrafficFuzzerServer {
  /**
   * @param {Object} opts
   * @param {number} [opts.port=8080] - TCP/HTTP port
   * @param {number} [opts.httpsPort=8443] - HTTPS/HTTP2 port
   * @param {string} [opts.hostname='::'] - Bind hostname
   * @param {number} [opts.timeout=10000] - Timeout per scenario (ms)
   * @param {number} [opts.delay=100] - Delay between scenarios (ms)
   * @param {string} [opts.httpHost] - Expected Host header
   * @param {string} [opts.httpEndpoint] - HTTP endpoint path
   * @param {string} [opts.http2Endpoint] - HTTP/2 endpoint path
   * @param {Logger} [opts.logger] - Logger instance
   * @param {string} [opts.pcapFile] - PCAP output file path
   */
  constructor(opts = {}) {
    this.port = opts.port || DEFAULT_HTTP_PORT;
    this.httpsPort = opts.httpsPort || DEFAULT_HTTP2_PORT;
    this.hostname = opts.hostname || '::';
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.httpHost = opts.httpHost || DEFAULT_HOST;
    this.httpEndpoint = opts.httpEndpoint || DEFAULT_HTTP_ENDPOINT;
    this.http2Endpoint = opts.http2Endpoint || DEFAULT_HTTP2_ENDPOINT;
    this.logger = opts.logger || new Logger();
    this.pcapFile = opts.pcapFile || null;

    this._tcpServer = null;
    this._h2Server = null;
    this._tlsCerts = null;
    this.actualPort = null;
    this.actualHttpsPort = null;
  }

  /**
   * Start the TCP and HTTP/2 servers.
   * @returns {Promise<void>}
   */
  async start() {
    // Generate self-signed certs for TLS/HTTP2
    const certInfo = generateServerCert('localhost');
    // Convert DER cert to PEM format for Node.js TLS/HTTP2
    const certPEM = '-----BEGIN CERTIFICATE-----\n' +
      certInfo.certDER.toString('base64').match(/.{1,64}/g).join('\n') +
      '\n-----END CERTIFICATE-----\n';
    this._tlsCerts = {
      key: certInfo.privateKeyPEM,
      cert: certPEM,
    };

    // Start plain TCP/HTTP server
    await this._startTCPServer();

    // Start TLS/HTTP2 server
    await this._startH2Server();
  }

  /**
   * Start the plain TCP server that handles raw TCP and HTTP/1.1 requests.
   */
  _startTCPServer() {
    return new Promise((resolve, reject) => {
      this._tcpServer = net.createServer({ allowHalfOpen: true }, (socket) => {
        this._handleTCPConnection(socket);
      });

      this._tcpServer.on('error', (err) => {
        reject(new Error(`TCP server failed: ${err.message}`));
      });

      this._tcpServer.listen(this.port, this.hostname, () => {
        const addr = this._tcpServer.address();
        this.actualPort = addr.port;
        this.logger.info(`TCP/HTTP server listening on port ${this.actualPort}`);
        resolve();
      });
    });
  }

  /**
   * Start the TLS/HTTP2 server.
   */
  _startH2Server() {
    return new Promise((resolve, reject) => {
      this._h2Server = http2.createSecureServer({
        key: this._tlsCerts.key,
        cert: this._tlsCerts.cert,
        allowHTTP1: true, // Allow HTTP/1.1 over TLS too
      });

      this._h2Server.on('stream', (stream, headers) => {
        this._handleH2Stream(stream, headers);
      });

      this._h2Server.on('error', (err) => {
        this.logger.error(`HTTP/2 server error: ${err.message}`);
      });

      this._h2Server.on('sessionError', (err) => {
        this.logger.error(`HTTP/2 session error: ${err.message}`);
      });

      this._h2Server.listen(this.httpsPort, this.hostname, () => {
        const addr = this._h2Server.address();
        this.actualHttpsPort = addr.port;
        this.logger.info(`HTTPS/HTTP2 server listening on port ${this.actualHttpsPort}`);
        resolve();
      });
    });
  }

  /**
   * Handle an incoming TCP connection (raw TCP or HTTP/1.1).
   */
  _handleTCPConnection(socket) {
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    this.logger.info(`Client connected from ${remote}`);

    let buffer = Buffer.alloc(0);

    socket.on('data', (data) => {
      buffer = Buffer.concat([buffer, data]);
      this.logger.received(data);

      // Try to parse as HTTP request
      const parsed = parseHTTPMessage(buffer);
      if (parsed.type === 'request' && parsed.body !== undefined) {
        this._handleHTTPRequest(socket, parsed);
        buffer = Buffer.alloc(0);
      } else if (parsed.type === 'unknown' || parsed.type === 'incomplete') {
        // Raw TCP data — echo it back
        if (buffer.length > 0 && !buffer.toString().startsWith('GET ') &&
            !buffer.toString().startsWith('POST ') &&
            !buffer.toString().startsWith('PUT ') &&
            !buffer.toString().startsWith('DELETE ') &&
            !buffer.toString().startsWith('HEAD ') &&
            !buffer.toString().startsWith('OPTIONS ') &&
            !buffer.toString().startsWith('PATCH ')) {
          // Echo raw TCP data
          const echo = Buffer.concat([Buffer.from('ECHO: '), buffer]);
          socket.write(echo);
          this.logger.sent(echo);
          buffer = Buffer.alloc(0);
        }
      }
    });

    socket.on('end', () => {
      this.logger.tcpEvent('received', 'FIN');
    });

    socket.on('close', () => {
      this.logger.info(`Client disconnected: ${remote}`);
    });

    socket.on('error', (err) => {
      this.logger.error(`Client socket error (${remote}): ${err.message}`);
    });
  }

  /**
   * Handle a parsed HTTP/1.1 request.
   */
  _handleHTTPRequest(socket, req) {
    const method = req.method || 'GET';
    const path = req.path || '/';
    this.logger.info(`  HTTP ${method} ${path}`);

    let statusCode = 200;
    let body = '';
    let headers = { 'Content-Type': 'application/json' };

    // Route to handlers
    if (path === '/api/v1/health' || path === this.httpEndpoint) {
      body = healthResponse();
    } else if (path === '/api/v1/echo') {
      body = echoResponse(req);
    } else if (path.startsWith('/api/v1/data')) {
      if (method === 'POST') {
        statusCode = 201;
        body = jsonBody({ created: true, received: req.body, timestamp: new Date().toISOString() });
      } else if (method === 'PUT' || method === 'PATCH') {
        body = jsonBody({ updated: true, received: req.body, timestamp: new Date().toISOString() });
      } else if (method === 'DELETE') {
        statusCode = 204;
        body = '';
      } else {
        body = jsonBody({ data: 'sample', method, path, timestamp: new Date().toISOString() });
      }
    } else if (path.startsWith('/api/v1/')) {
      body = jsonBody({ method, path, timestamp: new Date().toISOString() });
    } else {
      statusCode = 404;
      body = jsonBody({ error: 'Not Found', path });
    }

    // Handle HEAD — no body
    if (method === 'HEAD') {
      const resp = buildHTTPResponse({ statusCode, headers, body: '' });
      socket.write(resp);
      this.logger.sent(resp);
      return;
    }

    const resp = buildHTTPResponse({ statusCode, headers, body });
    socket.write(resp);
    this.logger.sent(resp);
  }

  /**
   * Handle an HTTP/2 stream.
   */
  _handleH2Stream(stream, headers) {
    const method = headers[':method'] || 'GET';
    const path = headers[':path'] || '/';
    const streamId = stream.id || '?';
    this.logger.info(`  ← HTTP/2 stream ${streamId}: ${method} ${path}`);

    let statusCode = 200;
    let body = '';
    const respHeaders = { 'content-type': 'application/json' };
    let responded = false;

    const sendResponse = (reqBody) => {
      if (responded) return;
      responded = true;

      // Route to handlers
      if (path === '/api/v2/status' || path === this.http2Endpoint) {
        body = jsonBody({ status: 'running', protocol: 'h2', timestamp: new Date().toISOString() });
      } else if (path === '/api/v2/echo') {
        const reqHeaders = {};
        for (const [k, v] of Object.entries(headers)) {
          if (!k.startsWith(':')) reqHeaders[k] = v;
        }
        body = jsonBody({ method, path, headers: reqHeaders, body: reqBody, timestamp: new Date().toISOString() });
      } else if (path.startsWith('/api/v2/data')) {
        if (method === 'POST') {
          statusCode = 201;
          body = jsonBody({ created: true, received: reqBody, timestamp: new Date().toISOString() });
        } else if (method === 'PUT' || method === 'PATCH') {
          body = jsonBody({ updated: true, received: reqBody, timestamp: new Date().toISOString() });
        } else if (method === 'DELETE') {
          statusCode = 204;
          body = '';
        } else {
          body = jsonBody({ data: 'sample', method, path, protocol: 'h2', timestamp: new Date().toISOString() });
        }
      } else if (path.startsWith('/api/v2/')) {
        body = jsonBody({ method, path, protocol: 'h2', timestamp: new Date().toISOString() });
      } else {
        statusCode = 404;
        body = jsonBody({ error: 'Not Found', path, protocol: 'h2' });
      }

      try {
        if (stream.destroyed || stream.closed) return;
        this.logger.info(`  → HTTP/2 stream ${streamId}: responding ${statusCode} (${body.length} bytes)`);
        stream.respond({
          ':status': statusCode,
          ...respHeaders,
        });
        if (body && method !== 'HEAD') {
          stream.end(body);
        } else {
          stream.end();
        }
      } catch (err) {
        // Silently ignore if stream already closed (common with raw frame clients)
        if (!err.message.includes('already been initiated')) {
          this.logger.error(`HTTP/2 response error (stream ${streamId}): ${err.message}`);
        }
      }
    };

    // Collect body data for all methods (some clients send body with GET too)
    let reqBody = '';
    stream.on('data', (chunk) => {
      reqBody += chunk.toString();
      this.logger.info(`  ← HTTP/2 stream ${streamId}: received ${chunk.length} bytes data`);
    });
    stream.on('end', () => {
      sendResponse(reqBody);
    });

    // For methods without body, the 'end' event fires immediately when END_STREAM is set
    // No need to manually trigger — Node.js http2 handles this
  }

  /**
   * Run a server-side scenario.
   * Starts listening, waits for client, executes the scenario handler.
   *
   * @param {Object} scenario - Scenario definition
   * @returns {Promise<Object>} Result { scenario, status, response, duration }
   */
  async runScenario(scenario) {
    const startTime = Date.now();
    const result = {
      scenario: scenario.name,
      status: 'PENDING',
      response: '',
      duration: 0,
    };

    this.logger.info(`▶ ${scenario.name}: ${scenario.description}`);

    if (!scenario.serverHandler) {
      result.status = 'ERROR';
      result.response = 'No serverHandler defined for server-side scenario';
      result.duration = Date.now() - startTime;
      return result;
    }

    // For server-side scenarios, we create a temporary TCP server
    // that runs the scenario handler when a client connects
    const timeout = this.timeout;

    try {
      const scenarioResult = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve({ status: 'TIMEOUT', response: 'No client connected within timeout' });
        }, timeout);

        // Create a one-shot server for this scenario
        const server = net.createServer({ allowHalfOpen: true }, (socket) => {
          clearTimeout(timer);
          this.logger.info(`  Client connected from ${socket.remoteAddress}:${socket.remotePort}`);

          const log = (msg) => this.logger.info(`  [scenario] ${msg}`);

          socket.on('error', (err) => {
            this.logger.error(`  Client socket error: ${err.message}`);
          });

          scenario.serverHandler(socket, log)
            .then((res) => {
              server.close();
              resolve(res);
            })
            .catch((err) => {
              server.close();
              resolve({ status: 'ERROR', response: err.message });
            });
        });

        server.on('error', (err) => {
          clearTimeout(timer);
          reject(new Error(`Scenario server failed: ${err.message}`));
        });

        // Listen on the configured port
        server.listen(this.port, this.hostname, () => {
          const addr = server.address();
          this.logger.info(`  Scenario server listening on port ${addr.port} — waiting for client...`);
        });
      });

      result.status = scenarioResult.status || 'PASSED';
      result.response = scenarioResult.response || '';
    } catch (err) {
      result.status = 'ERROR';
      result.response = err.message;
      this.logger.error(`  ✗ ${err.message}`);
    }

    result.duration = Date.now() - startTime;
    const icon = result.status === 'PASSED' ? '✓' : result.status === 'ERROR' ? '✗' : '?';
    this.logger.info(`  ${icon} ${result.status} (${result.duration}ms) — ${result.response}`);

    return result;
  }

  /**
   * Stop all servers.
   */
  stop() {
    if (this._tcpServer) {
      this._tcpServer.close();
      this._tcpServer = null;
    }
    if (this._h2Server) {
      this._h2Server.close();
      this._h2Server = null;
    }
    this.logger.info('Traffic fuzzer servers stopped');
  }
}


module.exports = { TrafficFuzzerServer };
