// Well-Behaved LDAP Echo Server — responds to all basic LDAP operations
// Used as local target for client-mode fuzzer testing.
// Responds with proper LDAP messages so scenarios get PASSED status.

const net = require('net');
const pkt = require('./ldap/packet');
const { LDAP_OP, LDAP_RESULT } = require('./ldap/constants');

const MAX_BUFFER_SIZE = 256 * 1024; // 256KB — reject oversize payloads
const INCOMPLETE_MSG_TIMEOUT = 3000; // 3s — flush incomplete buffers

class LdapEchoServer {
  constructor(opts = {}) {
    this.port = opts.port || 389;
    this.hostname = opts.hostname || '::';
    this.logger = opts.logger || null;
    this._server = null;
  }

  async start() {
    return new Promise((resolve, reject) => {
      this._server = net.createServer({ allowHalfOpen: true }, (socket) => {
        this._handleConnection(socket);
      });

      this._server.on('error', (err) => reject(err));

      this._server.listen(this.port, this.hostname, () => {
        if (this.logger) this.logger.info(`LDAP echo server listening on ${this.hostname}:${this.port}`);
        resolve();
      });
    });
  }

  stop() {
    if (this._server) {
      this._server.close();
      this._server = null;
    }
  }

  _handleConnection(socket) {
    let recvBuf = Buffer.alloc(0);
    let incompleteTimer = null;

    const clearIncompleteTimer = () => {
      if (incompleteTimer) { clearTimeout(incompleteTimer); incompleteTimer = null; }
    };

    socket.on('data', (data) => {
      clearIncompleteTimer();
      recvBuf = Buffer.concat([recvBuf, data]);

      // Guard against oversized payloads (e.g., 1MB+ fuzzing payloads)
      if (recvBuf.length > MAX_BUFFER_SIZE) {
        try {
          const errResp = pkt.buildExtendedResponse(0, LDAP_RESULT.protocolError, '', 'Message too large');
          if (!socket.destroyed && !socket.writableEnded) socket.write(errResp);
        } catch (_) {}
        recvBuf = Buffer.alloc(0);
        return;
      }

      const consumed = this._processBuffer(socket, recvBuf);
      // Keep unconsumed bytes for next data event (handles split TCP segments)
      if (consumed > 0 && consumed < recvBuf.length) {
        recvBuf = recvBuf.slice(consumed);
      } else if (consumed >= recvBuf.length) {
        recvBuf = Buffer.alloc(0);
      }

      // If we have leftover bytes (incomplete message), set a timer.
      // If no new data arrives within the timeout, flush with protocolError.
      if (recvBuf.length > 0) {
        incompleteTimer = setTimeout(() => {
          if (recvBuf.length > 0) {
            try {
              const errResp = pkt.buildExtendedResponse(0, LDAP_RESULT.protocolError, '', 'Incomplete message timeout');
              if (!socket.destroyed && !socket.writableEnded) socket.write(errResp);
            } catch (_) {}
            recvBuf = Buffer.alloc(0);
          }
        }, INCOMPLETE_MSG_TIMEOUT);
      }
    });

    socket.on('error', () => { clearIncompleteTimer(); });
    socket.on('end', () => {
      clearIncompleteTimer();
      if (!socket.destroyed) socket.end();
    });
    socket.on('close', () => { clearIncompleteTimer(); });
  }

  _processBuffer(socket, buf) {
    // Try to parse one or more LDAP messages from the buffer.
    // Returns the number of bytes consumed.
    let offset = 0;
    while (offset < buf.length) {
      try {
        const msg = pkt.parseLDAPMessage(buf.slice(offset));
        if (!msg || !msg.totalLength || msg.totalLength <= 0) break; // incomplete or unparseable

        this._respond(socket, msg);
        offset += msg.totalLength;
      } catch (_) {
        // Malformed data — send protocolError and skip remaining bytes
        try {
          const errResp = pkt.buildExtendedResponse(0, LDAP_RESULT.protocolError, '', 'Malformed request');
          if (!socket.destroyed && !socket.writableEnded) socket.write(errResp);
        } catch (__) {}
        // Skip past what we can't parse — consume all remaining bytes
        offset = buf.length;
        break;
      }
    }
    return offset;
  }

  _respond(socket, msg) {
    if (socket.destroyed || socket.writableEnded) return;

    const id = msg.messageID || 0;
    const op = msg.protocolOp;

    try {
      switch (op) {
        case LDAP_OP.BindRequest:
          socket.write(pkt.buildBindResponse(id, LDAP_RESULT.success));
          break;

        case LDAP_OP.UnbindRequest:
          // UnbindRequest: no response required per RFC 4511.
          // Delay close to let client read pending data and send follow-up requests.
          setTimeout(() => {
            if (!socket.destroyed) socket.end();
          }, 2000);
          break;

        case LDAP_OP.SearchRequest:
          // Send SearchResultEntry, then delay SearchResultDone slightly
          // so they arrive in separate TCP reads for scenarios with 2 recv calls.
          socket.write(pkt.buildSearchResultEntry(id, 'cn=test,dc=example,dc=com', {
            cn: ['test'],
            objectClass: ['top', 'organizationalUnit'],
          }));
          // Use setTimeout to send SearchResultDone in next event loop tick
          // This ensures they arrive as separate TCP segments on localhost
          setTimeout(() => {
            if (!socket.destroyed && !socket.writableEnded) {
              socket.write(pkt.buildSearchResultDone(id, LDAP_RESULT.success));
            }
          }, 30);
          break;

        case LDAP_OP.ModifyRequest:
          socket.write(pkt.buildModifyResponse(id, LDAP_RESULT.success));
          break;

        case LDAP_OP.AddRequest:
          socket.write(pkt.buildAddResponse(id, LDAP_RESULT.success));
          break;

        case LDAP_OP.DelRequest:
          socket.write(pkt.buildDelResponse(id, LDAP_RESULT.success));
          break;

        case LDAP_OP.ModifyDNRequest:
          socket.write(pkt.buildModifyDNResponse(id, LDAP_RESULT.success));
          break;

        case LDAP_OP.CompareRequest:
          socket.write(pkt.buildCompareResponse(id, LDAP_RESULT.compareTrue));
          break;

        case LDAP_OP.AbandonRequest:
          // No response for Abandon
          break;

        case LDAP_OP.ExtendedRequest:
          // Respond with success for known OIDs, unwillingToPerform for others
          socket.write(pkt.buildExtendedResponse(id, LDAP_RESULT.success, '', ''));
          break;

        default:
          // Unknown op — send a generic protocolError via ExtendedResponse
          socket.write(pkt.buildExtendedResponse(id, LDAP_RESULT.protocolError, '', 'Unsupported operation'));
          break;
      }
    } catch (_) {
      // Write failed (socket closed, etc.) — ignore
    }
  }
}

module.exports = { LdapEchoServer };
