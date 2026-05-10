// TCP/TLS Transport with DSCP/TOS support for traffic fuzzer
// Sets IP_TOS on real sockets via socket.setTOS() and records in PCAP

'use strict';

const net = require('net');
const tls = require('tls');
const { TRANSPORT_STATE, parseDSCP } = require('./constants');
const { trySetTOS } = require('./set-tos');


// ═══════════════════════════════════════════════════════════════════════════════
//  TRANSPORT STATS
// ═══════════════════════════════════════════════════════════════════════════════

class TransportStats {
  constructor() {
    this.messagesSent = 0;
    this.messagesReceived = 0;
    this.bytesSent = 0;
    this.bytesReceived = 0;
    this.sendErrors = 0;
    this.connectionsMade = 0;
    this.lastSendTime = null;
    this.connectTime = null;
  }

  recordSend(byteCount) {
    this.messagesSent++;
    this.bytesSent += byteCount;
    this.lastSendTime = Date.now();
  }

  recordReceive(byteCount) {
    this.messagesReceived++;
    this.bytesReceived += byteCount;
  }

  recordError() {
    this.sendErrors++;
  }

  recordConnect() {
    this.connectionsMade++;
    this.connectTime = Date.now();
  }

  get successRate() {
    const total = this.messagesSent + this.sendErrors;
    if (total === 0) return 0;
    return (this.messagesSent / total) * 100;
  }

  toJSON() {
    return {
      messages_sent: this.messagesSent,
      messages_received: this.messagesReceived,
      bytes_sent: this.bytesSent,
      bytes_received: this.bytesReceived,
      send_errors: this.sendErrors,
      connections_made: this.connectionsMade,
      success_rate: Math.round(this.successRate * 10) / 10,
    };
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  TCP TRANSPORT (plain)
// ═══════════════════════════════════════════════════════════════════════════════

class TCPTransport {
  constructor(opts = {}) {
    this._dscp = parseDSCP(opts.dscp);
    this._socket = null;
    this._server = null;
    this._state = TRANSPORT_STATE.DISCONNECTED;
    this._stats = new TransportStats();
    this._host = null;
    this._port = null;
  }

  get state() { return this._state; }
  get stats() { return this._stats; }
  get socket() { return this._socket; }
  get isConnected() { return this._state === TRANSPORT_STATE.CONNECTED; }
  get host() { return this._host; }
  get port() { return this._port; }
  get dscp() { return this._dscp; }

  /**
   * Set the DSCP/TOS value. Can be called before or after connect.
   * @param {number|string} value - DSCP name (e.g. 'EF') or TOS byte value
   */
  setDSCP(value) {
    this._dscp = parseDSCP(value);
    if (this._socket && !this._socket.destroyed && this._dscp) {
      const result = trySetTOS(this._socket, this._dscp);
      this._appliedTOS = result.readback || 0;
      this._tosMethod = result.method;
      this._tosError = result.success ? null : result.error;
    }
  }

  /**
   * Connect to a remote host as a TCP client.
   * @param {string} host - Remote host
   * @param {number} port - Remote port
   * @param {Object} [opts]
   * @param {number} [opts.timeout=10000] - Connection timeout in ms
   * @param {boolean} [opts.allowHalfOpen=true] - Allow half-open connections
   * @returns {Promise<net.Socket>}
   */
  connect(host, port, opts = {}) {
    return new Promise((resolve, reject) => {
      this._host = host;
      this._port = port;
      this._state = TRANSPORT_STATE.CONNECTING;

      const timeout = opts.timeout || 10000;

      this._socket = net.createConnection({
        host,
        port,
        allowHalfOpen: opts.allowHalfOpen !== false,
      });

      this._socket.setNoDelay(true);
      this._socket.setKeepAlive(false);

      const timer = setTimeout(() => {
        this._state = TRANSPORT_STATE.ERROR;
        this._socket.destroy(new Error('Connection timeout'));
        reject(new Error(`TCP connect timeout to ${host}:${port}`));
      }, timeout);

      this._socket.on('connect', () => {
        clearTimeout(timer);
        // Apply DSCP/TOS marking on the live socket
        this._appliedTOS = 0;
        this._tosError = null;
        this._tosMethod = 'none';
        if (this._dscp) {
          const tosResult = trySetTOS(this._socket, this._dscp);
          this._appliedTOS = tosResult.readback || 0;
          this._tosMethod = tosResult.method;
          if (!tosResult.success) {
            this._tosError = tosResult.error;
          }
        }
        // Read back local/remote address info
        this._localAddress = this._socket.localAddress;
        this._localPort = this._socket.localPort;
        this._remoteAddress = this._socket.remoteAddress;
        this._remotePort = this._socket.remotePort;
        this._state = TRANSPORT_STATE.CONNECTED;
        this._stats.recordConnect();
        resolve(this._socket);
      });

      this._socket.on('error', (err) => {
        clearTimeout(timer);
        if (this._state === TRANSPORT_STATE.CONNECTING) {
          this._state = TRANSPORT_STATE.ERROR;
          reject(new Error(`TCP connect failed to ${host}:${port}: ${err.message}`));
        }
      });
    });
  }

  /**
   * Start a TCP server.
   * @param {number} port - Port to listen on
   * @param {string} [hostname='::'] - Hostname to bind to
   * @returns {Promise<net.Server>}
   */
  listen(port, hostname = '::') {
    return new Promise((resolve, reject) => {
      this._port = port;
      this._server = net.createServer({ allowHalfOpen: true });

      this._server.on('error', (err) => {
        reject(new Error(`TCP server failed to start on port ${port}: ${err.message}`));
      });

      this._server.listen(port, hostname, () => {
        const addr = this._server.address();
        this._port = addr.port;
        this._state = TRANSPORT_STATE.CONNECTED;
        resolve(this._server);
      });
    });
  }

  /**
   * Send data on the connected socket.
   * @param {Buffer|string} data - Data to send
   * @returns {Promise<void>}
   */
  send(data) {
    return new Promise((resolve, reject) => {
      if (!this._socket || this._socket.destroyed) {
        this._stats.recordError();
        return reject(new Error('Socket not connected'));
      }
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      this._socket.write(buf, (err) => {
        if (err) {
          this._stats.recordError();
          reject(err);
        } else {
          this._stats.recordSend(buf.length);
          resolve();
        }
      });
    });
  }

  /**
   * Wait for data from the socket.
   * @param {number} [timeout=5000] - Timeout in ms
   * @returns {Promise<Buffer>}
   */
  waitForData(timeout = 5000) {
    return new Promise((resolve, reject) => {
      if (!this._socket || this._socket.destroyed) {
        return reject(new Error('Socket not connected'));
      }

      let received = Buffer.alloc(0);
      let timer;
      let settled = false;

      const onData = (chunk) => {
        received = Buffer.concat([received, chunk]);
        this._stats.recordReceive(chunk.length);
        // Reset timer on each chunk — wait for silence
        clearTimeout(timer);
        timer = setTimeout(() => {
          settled = true;
          cleanup();
          resolve(received);
        }, Math.min(timeout, 500));
      };

      const onEnd = () => {
        if (!settled) {
          settled = true;
          cleanup();
          resolve(received);
        }
      };

      const onError = (err) => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(err);
        }
      };

      const onTimeout = () => {
        if (!settled) {
          settled = true;
          cleanup();
          if (received.length > 0) {
            resolve(received);
          } else {
            reject(new Error('Receive timeout'));
          }
        }
      };

      const cleanup = () => {
        clearTimeout(timer);
        this._socket.removeListener('data', onData);
        this._socket.removeListener('end', onEnd);
        this._socket.removeListener('error', onError);
      };

      this._socket.on('data', onData);
      this._socket.on('end', onEnd);
      this._socket.on('error', onError);

      timer = setTimeout(onTimeout, timeout);
    });
  }

  /**
   * Send FIN (graceful half-close).
   * @returns {Promise<void>}
   */
  sendFIN() {
    return new Promise((resolve) => {
      if (this._socket && !this._socket.destroyed) {
        this._socket.end(() => resolve());
      } else {
        resolve();
      }
    });
  }

  /**
   * Send RST (abrupt close).
   */
  sendRST() {
    if (this._socket) {
      if (typeof this._socket.resetAndDestroy === 'function') {
        this._socket.resetAndDestroy();
      } else {
        this._socket.destroy();
      }
    }
  }

  /**
   * Close the transport.
   */
  close() {
    if (this._socket && !this._socket.destroyed) {
      this._socket.destroy();
    }
    if (this._server) {
      this._server.close();
      this._server = null;
    }
    this._state = TRANSPORT_STATE.DISCONNECTED;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  TLS TRANSPORT
// ═══════════════════════════════════════════════════════════════════════════════

class TLSTransport extends TCPTransport {
  /**
   * Connect to a remote host over TLS.
   * @param {string} host - Remote host
   * @param {number} port - Remote port
   * @param {Object} [opts]
   * @param {boolean} [opts.rejectUnauthorized=false] - Verify server cert
   * @param {string} [opts.certFile] - Client certificate PEM
   * @param {string} [opts.keyFile] - Client private key PEM
   * @param {string} [opts.caFile] - CA certificate PEM
   * @param {string} [opts.alpn] - ALPN protocol (e.g. 'h2', 'http/1.1')
   * @param {number} [opts.timeout=10000] - Connection timeout
   * @returns {Promise<tls.TLSSocket>}
   */
  connect(host, port, opts = {}) {
    return new Promise((resolve, reject) => {
      this._host = host;
      this._port = port;
      this._state = TRANSPORT_STATE.CONNECTING;

      const timeout = opts.timeout || 10000;
      const fs = require('fs');

      const tlsOpts = {
        host,
        port,
        rejectUnauthorized: opts.rejectUnauthorized === true,
        allowHalfOpen: opts.allowHalfOpen !== false,
      };

      if (opts.certFile) {
        tlsOpts.cert = fs.readFileSync(opts.certFile);
      }
      if (opts.keyFile) {
        tlsOpts.key = fs.readFileSync(opts.keyFile);
      }
      if (opts.caFile) {
        tlsOpts.ca = fs.readFileSync(opts.caFile);
      }
      if (opts.alpn) {
        tlsOpts.ALPNProtocols = Array.isArray(opts.alpn) ? opts.alpn : [opts.alpn];
      }

      const timer = setTimeout(() => {
        this._state = TRANSPORT_STATE.ERROR;
        reject(new Error(`TLS connect timeout to ${host}:${port}`));
      }, timeout);

      this._socket = tls.connect(tlsOpts, () => {
        clearTimeout(timer);
        // Apply DSCP/TOS marking after TLS handshake
        this._appliedTOS = 0;
        this._tosError = null;
        this._tosMethod = 'none';
        if (this._dscp) {
          const tosResult = trySetTOS(this._socket, this._dscp);
          this._appliedTOS = tosResult.readback || 0;
          this._tosMethod = tosResult.method;
          if (!tosResult.success) {
            this._tosError = tosResult.error;
          }
        }
        this._localAddress = this._socket.localAddress;
        this._localPort = this._socket.localPort;
        this._remoteAddress = this._socket.remoteAddress;
        this._remotePort = this._socket.remotePort;
        this._state = TRANSPORT_STATE.CONNECTED;
        this._stats.recordConnect();
        resolve(this._socket);
      });

      this._socket.setNoDelay(true);

      this._socket.on('error', (err) => {
        clearTimeout(timer);
        if (this._state === TRANSPORT_STATE.CONNECTING) {
          this._state = TRANSPORT_STATE.ERROR;
          reject(new Error(`TLS connect failed to ${host}:${port}: ${err.message}`));
        }
      });
    });
  }

  /**
   * Get the negotiated TLS protocol version.
   * @returns {string|null}
   */
  get tlsVersion() {
    if (this._socket && this._state === TRANSPORT_STATE.CONNECTED) {
      return this._socket.getProtocol();
    }
    return null;
  }

  /**
   * Get the negotiated ALPN protocol.
   * @returns {string|null}
   */
  get alpnProtocol() {
    if (this._socket && this._state === TRANSPORT_STATE.CONNECTED) {
      return this._socket.alpnProtocol || null;
    }
    return null;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FACTORY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a transport instance.
 * @param {'tcp'|'tls'} type - Transport type
 * @param {Object} [opts] - Transport options (dscp, etc.)
 * @returns {TCPTransport|TLSTransport}
 */
function createTransport(type, opts = {}) {
  switch (type) {
    case 'tls':
    case 'ssl':
      return new TLSTransport(opts);
    case 'tcp':
    case 'plain':
    default:
      return new TCPTransport(opts);
  }
}


module.exports = {
  TransportStats,
  TCPTransport,
  TLSTransport,
  createTransport,
};
