// Well-behaved LDAP client — sends valid LDAP operations for server-mode testing
const net = require('net');

class WellBehavedClient {
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || 389;
    this.logger = opts.logger || null;
    this._connection = null;
    this._stopped = false;
    this.activeSockets = new Set();
  }

  connectLDAP() {
    const pkt = require('./ldap/packet');
    const maxRetries = 70;
    const retryDelay = 500;

    const attempt = (retryCount) => {
      return new Promise((resolve) => {
        let retrying = false;
        const socket = net.createConnection({
          host: this.host,
          port: this.port,
          allowHalfOpen: true,
        });

        this._connection = socket;
        this.activeSockets.add(socket);

        const cleanup = () => { this.activeSockets.delete(socket); };
        socket.on('close', cleanup);

        socket.on('connect', () => {
          if (this.logger) this.logger.info('[local-client] LDAP TCP connected');
          // Send anonymous bind
          try {
            socket.write(pkt.buildBindRequest(1, { dn: '', password: '' }));
          } catch (_) {}
        });

        socket.on('data', (data) => {
          // After bind response, send a simple RootDSE search
          try {
            const msg = pkt.parseLDAPMessage(data);
            if (msg && msg.protocolOp === 0x61) { // BindResponse
              socket.write(pkt.buildSearchRequest(2, {
                baseDN: '', scope: 0,
                filter: { type: 'present', attr: 'objectClass' },
                attributes: ['namingContexts'],
              }));
            }
          } catch (_) {}
        });

        socket.on('error', (err) => {
          if ((err.code === 'ECONNREFUSED' || err.message.includes('ECONNREFUSED')) && retryCount < maxRetries && !this._stopped) {
            retrying = true;
            this.activeSockets.delete(socket);
            try { socket.destroy(); } catch (_) {}
            if (this.logger) this.logger.info(`[local-client] LDAP connection refused, retrying (${retryCount + 1}/${maxRetries})...`);
            setTimeout(() => attempt(retryCount + 1).then(resolve), retryDelay);
            return;
          }
          if (this.logger) this.logger.info(`[local-client] LDAP error (expected): ${err.message}`);
          resolve();
        });

        socket.on('close', () => { if (!retrying) resolve(); });

        socket.setTimeout(10000, () => {
          socket.destroy();
          resolve();
        });
      });
    };

    return attempt(0);
  }

  stop() {
    this._stopped = true;
    if (this._connection) {
      try { this._connection.destroy(); } catch (_) {}
      this._connection = null;
    }
    for (const socket of this.activeSockets) {
      try { socket.destroy(); } catch (_) {}
    }
    this.activeSockets.clear();
  }
}

module.exports = { WellBehavedClient };
