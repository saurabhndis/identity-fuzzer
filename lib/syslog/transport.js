// SSL and UDP transport for syslog sender simulator
// Port of: AI-Agent/anton/apps/useridd/syslogsender/src/syslog_sender_sim/transport/
//
// PAN-OS Reference:
//   - pan_user_id_syslog_service.h: SSL port 6514, UDP port 514
//   - pan_user_id_syslog_service.c: pan_user_id_sl_service_accept_ssl_conn_proc_fd()
//   - pan_user_id_syslog_service.c: pan_user_id_sl_service_read_ssl_msgs() — 8192-byte chunks

const net = require('net');
const tls = require('tls');
const dgram = require('dgram');
const fs = require('fs');
const {
  DEFAULT_SSL_PORT, DEFAULT_UDP_PORT,
  MAX_SSL_MESSAGE_SIZE, MAX_UDP_MESSAGE_SIZE,
  TRANSPORT_STATE,
} = require('./constants');


// ═══════════════════════════════════════════════════════════════════════════════
//  TRANSPORT STATS
// ═══════════════════════════════════════════════════════════════════════════════

class TransportStats {
  constructor() {
    this.messagesSent = 0;
    this.bytesSent = 0;
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
      bytes_sent: this.bytesSent,
      send_errors: this.sendErrors,
      connections_made: this.connectionsMade,
      success_rate: Math.round(this.successRate * 10) / 10,
    };
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SSL TRANSPORT
// ═══════════════════════════════════════════════════════════════════════════════

class SSLTransport {
  constructor() {
    this._state = TRANSPORT_STATE.DISCONNECTED;
    this._stats = new TransportStats();
    this._host = null;
    this._port = null;
    this._socket = null;
  }

  get state() { return this._state; }
  get stats() { return this._stats; }
  get isConnected() { return this._state === TRANSPORT_STATE.CONNECTED; }
  get host() { return this._host; }
  get port() { return this._port; }

  /**
   * Establish an SSL/TLS connection to the PAN-OS firewall.
   * @param {string} host - Firewall IP address or hostname
   * @param {number} [port] - SSL port (default: 6514)
   * @param {Object} [opts]
   * @param {string} [opts.certFile] - Client certificate PEM file
   * @param {string} [opts.keyFile] - Client private key PEM file
   * @param {string} [opts.caFile] - CA certificate for server verification
   * @param {boolean} [opts.verify=false] - Verify server certificate
   * @param {string} [opts.sourceIP] - Source IP to bind to
   * @param {number} [opts.timeout=10000] - Connection timeout in ms
   * @returns {Promise<void>}
   */
  connect(host, port, opts = {}) {
    return new Promise((resolve, reject) => {
      if (this._state === TRANSPORT_STATE.CONNECTED) {
        this.close();
      }

      this._host = host;
      this._port = port || DEFAULT_SSL_PORT;
      this._state = TRANSPORT_STATE.CONNECTING;

      const tlsOpts = {
        host: this._host,
        port: this._port,
        rejectUnauthorized: opts.verify || false,
        timeout: opts.timeout || 10000,
      };

      // Client certificate
      if (opts.certFile) {
        tlsOpts.cert = fs.readFileSync(opts.certFile);
      }
      if (opts.keyFile) {
        tlsOpts.key = fs.readFileSync(opts.keyFile);
      }
      if (opts.caFile) {
        tlsOpts.ca = fs.readFileSync(opts.caFile);
      }

      // Source IP binding
      if (opts.sourceIP) {
        tlsOpts.localAddress = opts.sourceIP;
      }

      this._socket = tls.connect(tlsOpts, () => {
        this._state = TRANSPORT_STATE.CONNECTED;
        this._stats.recordConnect();
        resolve();
      });

      this._socket.on('error', (err) => {
        if (this._state === TRANSPORT_STATE.CONNECTING) {
          this._state = TRANSPORT_STATE.ERROR;
          reject(new Error(`SSL connection failed to ${host}:${this._port}: ${err.message}`));
        }
      });

      this._socket.on('timeout', () => {
        if (this._state === TRANSPORT_STATE.CONNECTING) {
          this._state = TRANSPORT_STATE.ERROR;
          this._socket.destroy();
          reject(new Error(`SSL connection timed out to ${host}:${this._port}`));
        }
      });

      this._socket.on('close', () => {
        this._state = TRANSPORT_STATE.DISCONNECTED;
      });
    });
  }

  /**
   * Send a syslog message over the SSL connection.
   * @param {string} message - Syslog message string
   * @returns {Promise<number>} Number of bytes sent
   */
  send(message) {
    return new Promise((resolve, reject) => {
      if (this._state !== TRANSPORT_STATE.CONNECTED || !this._socket) {
        return reject(new Error('SSL transport not connected. Call connect() first.'));
      }

      message = _ensureTerminated(message);
      const data = Buffer.from(message, 'utf8');

      if (data.length > MAX_SSL_MESSAGE_SIZE) {
        // Warning only — PAN-OS may truncate
      }

      this._socket.write(data, (err) => {
        if (err) {
          this._stats.recordError();
          this._state = TRANSPORT_STATE.ERROR;
          reject(new Error(`SSL send failed: ${err.message}`));
        } else {
          this._stats.recordSend(data.length);
          resolve(data.length);
        }
      });
    });
  }

  /**
   * Send multiple messages with optional interval.
   * @param {string[]} messages
   * @param {number} [interval=0] - Seconds between messages
   * @returns {Promise<number>} Total bytes sent
   */
  async sendBatch(messages, interval = 0) {
    let totalBytes = 0;
    for (let i = 0; i < messages.length; i++) {
      totalBytes += await this.send(messages[i]);
      if (interval > 0 && i < messages.length - 1) {
        await _sleep(interval * 1000);
      }
    }
    return totalBytes;
  }

  /** Close the SSL connection. */
  close() {
    if (this._state === TRANSPORT_STATE.DISCONNECTED) return;
    if (this._socket) {
      try { this._socket.destroy(); } catch (_) {}
      this._socket = null;
    }
    this._state = TRANSPORT_STATE.DISCONNECTED;
  }

  /** Current SSL cipher in use. */
  get cipher() {
    if (this._socket && this._state === TRANSPORT_STATE.CONNECTED) {
      const info = this._socket.getCipher();
      return info ? info.name : null;
    }
    return null;
  }

  /** Current TLS version. */
  get tlsVersion() {
    if (this._socket && this._state === TRANSPORT_STATE.CONNECTED) {
      return this._socket.getProtocol();
    }
    return null;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  UDP TRANSPORT
// ═══════════════════════════════════════════════════════════════════════════════

class UDPTransport {
  constructor() {
    this._state = TRANSPORT_STATE.DISCONNECTED;
    this._stats = new TransportStats();
    this._host = null;
    this._port = null;
    this._socket = null;
  }

  get state() { return this._state; }
  get stats() { return this._stats; }
  get isConnected() { return this._state === TRANSPORT_STATE.CONNECTED; }
  get host() { return this._host; }
  get port() { return this._port; }

  /**
   * Configure UDP socket for sending to PAN-OS firewall.
   * @param {string} host - Firewall IP address or hostname
   * @param {number} [port] - UDP port (default: 514)
   * @param {Object} [opts]
   * @param {string} [opts.sourceIP] - Source IP to bind to
   * @param {number} [opts.timeout=5000] - Socket timeout in ms
   * @returns {Promise<void>}
   */
  connect(host, port, opts = {}) {
    return new Promise((resolve, reject) => {
      if (this._state === TRANSPORT_STATE.CONNECTED) {
        this.close();
      }

      this._host = host;
      this._port = port || DEFAULT_UDP_PORT;
      this._state = TRANSPORT_STATE.CONNECTING;

      try {
        this._socket = dgram.createSocket('udp4');

        if (opts.sourceIP) {
          this._socket.bind({ address: opts.sourceIP }, () => {
            this._state = TRANSPORT_STATE.CONNECTED;
            this._stats.recordConnect();
            resolve();
          });
        } else {
          this._state = TRANSPORT_STATE.CONNECTED;
          this._stats.recordConnect();
          resolve();
        }

        this._socket.on('error', (err) => {
          if (this._state === TRANSPORT_STATE.CONNECTING) {
            this._state = TRANSPORT_STATE.ERROR;
            reject(new Error(`UDP socket error: ${err.message}`));
          }
        });
      } catch (err) {
        this._state = TRANSPORT_STATE.ERROR;
        reject(new Error(`Failed to create UDP socket: ${err.message}`));
      }
    });
  }

  /**
   * Send a syslog message as a UDP datagram.
   * @param {string} message - Syslog message string
   * @returns {Promise<number>} Number of bytes sent
   */
  send(message) {
    return new Promise((resolve, reject) => {
      if (this._state !== TRANSPORT_STATE.CONNECTED || !this._socket) {
        return reject(new Error('UDP transport not connected. Call connect() first.'));
      }

      message = _ensureTerminated(message);
      const data = Buffer.from(message, 'utf8');

      if (data.length > MAX_UDP_MESSAGE_SIZE) {
        return reject(new Error(
          `Message size (${data.length} bytes) exceeds PAN-OS UDP buffer (${MAX_UDP_MESSAGE_SIZE} bytes).`
        ));
      }

      this._socket.send(data, 0, data.length, this._port, this._host, (err) => {
        if (err) {
          this._stats.recordError();
          reject(new Error(`UDP send failed to ${this._host}:${this._port}: ${err.message}`));
        } else {
          this._stats.recordSend(data.length);
          resolve(data.length);
        }
      });
    });
  }

  /**
   * Send multiple messages with optional interval.
   * @param {string[]} messages
   * @param {number} [interval=0] - Seconds between messages
   * @returns {Promise<number>} Total bytes sent
   */
  async sendBatch(messages, interval = 0) {
    let totalBytes = 0;
    for (let i = 0; i < messages.length; i++) {
      totalBytes += await this.send(messages[i]);
      if (interval > 0 && i < messages.length - 1) {
        await _sleep(interval * 1000);
      }
    }
    return totalBytes;
  }

  /** Close the UDP socket. */
  close() {
    if (this._state === TRANSPORT_STATE.DISCONNECTED) return;
    if (this._socket) {
      try { this._socket.close(); } catch (_) {}
      this._socket = null;
    }
    this._state = TRANSPORT_STATE.DISCONNECTED;
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FACTORY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a transport instance by type.
 * @param {string} type - 'ssl' or 'udp'
 * @returns {SSLTransport|UDPTransport}
 */
function createTransport(type) {
  if (type === 'ssl') return new SSLTransport();
  if (type === 'udp') return new UDPTransport();
  throw new Error(`Unknown transport type: ${type}`);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Ensure message ends with newline (PAN-OS requirement).
 * @param {string} message
 * @returns {string}
 */
function _ensureTerminated(message) {
  if (!message.endsWith('\n')) {
    message += '\r\n';
  }
  return message;
}

function _sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}


module.exports = {
  SSLTransport,
  UDPTransport,
  TransportStats,
  createTransport,
};
