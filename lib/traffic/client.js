// Traffic Fuzzer Client — executes client-side scenarios against a remote server
// Follows the same pattern as LdapFuzzerClient

'use strict';

const { Logger } = require('../logger');
const { PcapWriter } = require('../pcap-writer');
const { TCPTransport, TLSTransport, createTransport } = require('./transport');
const { parseHTTPMessage } = require('./http-builder');
const {
  DEFAULT_TCP_PORT, DEFAULT_HTTP_PORT, DEFAULT_HTTP2_PORT,
  DEFAULT_HTTP_ENDPOINT, DEFAULT_HTTP2_ENDPOINT, DEFAULT_HOST,
  DSCP_NAME, parseDSCP,
} = require('./constants');


class TrafficFuzzerClient {
  /**
   * @param {Object} opts
   * @param {string} [opts.host='localhost'] - Target host
   * @param {number} [opts.port=8080] - Target port
   * @param {number} [opts.timeout=10000] - Timeout per scenario (ms)
   * @param {number} [opts.delay=100] - Delay between scenarios (ms)
   * @param {number|string} [opts.dscp=0] - Default DSCP/TOS value
   * @param {string} [opts.httpHost] - Custom HTTP Host header
   * @param {string} [opts.httpEndpoint] - Custom HTTP endpoint path
   * @param {string} [opts.http2Endpoint] - Custom HTTP/2 endpoint path
   * @param {Logger} [opts.logger] - Logger instance
   * @param {string} [opts.pcapFile] - PCAP output file path
   */
  constructor(opts = {}) {
    this.host = opts.host || 'localhost';
    this.port = opts.port || DEFAULT_TCP_PORT;
    this.timeout = opts.timeout || 10000;
    this.delay = opts.delay || 100;
    this.dscp = parseDSCP(opts.dscp);
    this.httpHost = opts.httpHost || DEFAULT_HOST;
    this.httpEndpoint = opts.httpEndpoint || DEFAULT_HTTP_ENDPOINT;
    this.http2Endpoint = opts.http2Endpoint || DEFAULT_HTTP2_ENDPOINT;
    this.logger = opts.logger || new Logger();
    this.pcapFile = opts.pcapFile || null;
    this.pcap = null;
  }

  /**
   * Run a single client-side scenario.
   * @param {Object} scenario - Scenario definition from scenarios.js
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

    // Initialize PCAP writer for this scenario if configured
    if (this.pcapFile) {
      try {
        const pcapPath = this.pcapFile.replace(/\.pcap$/, '') + `-${scenario.name}.pcap`;
        this.pcap = new PcapWriter(pcapPath, {
          role: 'client',
          clientPort: 49152 + Math.floor(Math.random() * 16000),
          serverPort: this.port,
          tos: scenario.dscp || this.dscp,
        });
      } catch (err) {
        this.logger.error(`PCAP init failed: ${err.message}`);
      }
    }

    this.logger.info(`▶ ${scenario.name}: ${scenario.description}`);

    // Context object passed to step data functions
    const ctx = {
      httpHost: this.httpHost,
      httpEndpoint: this.httpEndpoint,
      http2Endpoint: this.http2Endpoint,
      dscp: scenario.dscp || this.dscp,
    };

    let transport = null;
    let transports = []; // for parallel-connect scenarios

    let stepNum = 0;
    const totalSteps = scenario.steps.length;

    try {
      for (const step of scenario.steps) {
        stepNum++;
        const stepPrefix = `  [${stepNum}/${totalSteps}]`;

        switch (step.type) {
          case 'connect': {
            const mode = step.mode || 'plain';
            const port = step.port || this.port;
            const dscp = step.dscp || scenario.dscp || this.dscp;
            const dscpLabel = DSCP_NAME[dscp] || '0x' + dscp.toString(16);
            const alpnLabel = step.alpn ? `, ALPN=${step.alpn}` : '';

            transport = createTransport(mode, { dscp });
            this.logger.info(`${stepPrefix} CONNECT → ${this.host}:${port} (${mode.toUpperCase()}${alpnLabel}, DSCP=${dscpLabel})`);

            const connectOpts = { timeout: this.timeout };
            if (step.alpn) connectOpts.alpn = step.alpn;

            await transport.connect(this.host, port, connectOpts);

            if (this.pcap) {
              this.pcap.setTOS(dscp);
              this.pcap.writeTCPHandshake();
            }

            // Log connection details with IP/TCP header info
            const srcAddr = transport._localAddress || '?';
            const srcPort = transport._localPort || '?';
            const dstAddr = transport._remoteAddress || this.host;
            const dstPort = transport._remotePort || port;
            const appliedTOS = transport._appliedTOS || 0;
            const tosErr = transport._tosError;
            const tosMethod = transport._tosMethod || 'none';

            this.logger.info(`${stepPrefix} ✓ Connected: ${srcAddr}:${srcPort} → ${dstAddr}:${dstPort}`);
            this.logger.info(`${stepPrefix}   IP Header: Version=4, TOS=0x${dscp.toString(16).padStart(2, '0')} (DSCP=${dscpLabel}), TTL=64, Protocol=TCP(6)`);
            this.logger.info(`${stepPrefix}   TCP Header: SrcPort=${srcPort}, DstPort=${dstPort}, Flags=[SYN→SYN,ACK→ACK]`);
            if (dscp) {
              if (tosMethod !== 'none' && tosMethod !== 'pcap-only (not on wire)') {
                this.logger.info(`${stepPrefix}   ✓ DSCP/TOS 0x${appliedTOS.toString(16).padStart(2, '0')} applied on wire via ${tosMethod} (readback=0x${appliedTOS.toString(16).padStart(2, '0')})`);
              } else if (tosErr) {
                this.logger.error(`${stepPrefix}   ⚠ DSCP not applied on wire: ${tosErr}`);
                this.logger.info(`${stepPrefix}   ℹ DSCP 0x${dscp.toString(16).padStart(2, '0')} will be recorded in PCAP only`);
              } else {
                this.logger.info(`${stepPrefix}   ℹ DSCP 0x${dscp.toString(16).padStart(2, '0')} recorded in PCAP capture`);
              }
            }
            break;
          }

          case 'send': {
            if (!transport || !transport.isConnected) {
              throw new Error('Not connected — cannot send');
            }
            const data = typeof step.data === 'function' ? step.data(ctx) : step.data;
            if (data && data.length > 0) {
              // Describe what we're sending
              const label = step.label || 'Data';
              const preview = _describePayload(data);
              this.logger.info(`${stepPrefix} SEND → ${label} (${data.length} bytes): ${preview}`);

              await transport.send(data);
              this.logger.sent(data);
              if (this.pcap) this.pcap.writeTLSData(data, 'sent');
            }
            break;
          }

          case 'send-oob': {
            if (!transport || !transport.socket) break;
            const data = typeof step.data === 'function' ? step.data(ctx) : step.data;
            if (data && data.length > 0) {
              this.logger.info(`${stepPrefix} SEND-OOB → Urgent data (${data.length} bytes)`);
              await new Promise((resolve, reject) => {
                transport.socket.write(data, undefined, (err) => {
                  if (err) reject(err); else resolve();
                });
              });
            }
            break;
          }

          case 'recv': {
            if (!transport) break;
            const timeout = step.timeout || this.timeout;
            const label = step.label || 'Response';
            this.logger.info(`${stepPrefix} RECV ← Waiting for ${label} (timeout=${timeout}ms)...`);
            try {
              const data = await transport.waitForData(timeout);
              if (data && data.length > 0) {
                this.logger.received(data);
                if (this.pcap) this.pcap.writeTLSData(data, 'received');

                // Try to parse as HTTP response for status checking
                const parsed = parseHTTPMessage(data);
                if (parsed.type === 'response') {
                  result.response = `${parsed.statusCode} ${parsed.statusText}`;
                  this.logger.info(`${stepPrefix} ✓ Received HTTP ${parsed.statusCode} ${parsed.statusText} (${data.length} bytes)`);
                  if (step.expectStatus && parsed.statusCode !== step.expectStatus) {
                    result.response += ` (expected ${step.expectStatus})`;
                    this.logger.info(`${stepPrefix} ⚠ Expected HTTP ${step.expectStatus}`);
                  }
                } else {
                  result.response = `${data.length} bytes received`;
                  const preview = _describePayload(data);
                  this.logger.info(`${stepPrefix} ✓ Received ${data.length} bytes: ${preview}`);
                }
              } else {
                result.response = 'No data received';
                this.logger.info(`${stepPrefix} ⚠ No data received`);
              }
            } catch (err) {
              if (err.message === 'Receive timeout') {
                result.response = 'Timeout waiting for response';
                this.logger.info(`${stepPrefix} ⏳ Timeout — no response within ${timeout}ms`);
              } else {
                throw err;
              }
            }
            break;
          }

          case 'fin': {
            if (transport) {
              this.logger.info(`${stepPrefix} FIN → Graceful half-close (${step.label || 'FIN'})`);
              this.logger.tcpEvent('sent', step.label || 'FIN');
              if (this.pcap) this.pcap.writeFIN('sent');
              await transport.sendFIN();
            }
            break;
          }

          case 'rst': {
            if (transport) {
              this.logger.info(`${stepPrefix} RST → Abrupt connection reset (${step.label || 'RST'})`);
              this.logger.tcpEvent('sent', step.label || 'RST');
              if (this.pcap) this.pcap.writeRST('sent');
              transport.sendRST();
            }
            break;
          }

          case 'close': {
            if (transport) {
              this.logger.info(`${stepPrefix} CLOSE → Connection closed`);
              this.logger.tcpEvent('sent', step.label || 'Close');
              transport.close();
              transport = null;
            }
            break;
          }

          case 'sleep': {
            const ms = step.ms || 1000;
            this.logger.info(`${stepPrefix} SLEEP ⏳ Waiting ${ms}ms...`);
            await sleep(ms);
            break;
          }

          case 'parallel-connect': {
            const count = step.count || 5;
            const mode = step.mode || 'plain';
            const port = step.port || this.port;
            this.logger.info(`${stepPrefix} PARALLEL-CONNECT → Opening ${count} connections to ${this.host}:${port} (${mode.toUpperCase()})`);
            const promises = [];
            for (let i = 0; i < count; i++) {
              const t = createTransport(mode, { dscp: this.dscp });
              promises.push(
                t.connect(this.host, port, { timeout: this.timeout })
                  .then(() => { transports.push(t); })
                  .catch(err => { this.logger.error(`${stepPrefix}   Connection ${i + 1} failed: ${err.message}`); })
              );
            }
            await Promise.allSettled(promises);
            this.logger.info(`${stepPrefix} ✓ ${transports.length}/${count} connections established`);
            break;
          }

          case 'close-all': {
            this.logger.info(`${stepPrefix} CLOSE-ALL → Closing ${transports.length} connections`);
            for (const t of transports) {
              try { t.close(); } catch (_) {}
            }
            transports = [];
            if (transport) {
              transport.close();
              transport = null;
            }
            break;
          }

          default:
            this.logger.info(`${stepPrefix} ⚠ Unknown step type: ${step.type}`);
        }
      }

      result.status = 'PASSED';
    } catch (err) {
      result.status = 'ERROR';
      result.response = err.message;
      this.logger.error(`  ✗ ${err.message}`);
    } finally {
      // Cleanup
      if (transport) {
        try { transport.close(); } catch (_) {}
      }
      for (const t of transports) {
        try { t.close(); } catch (_) {}
      }
      if (this.pcap) {
        try { this.pcap.close(); } catch (_) {}
        this.pcap = null;
      }
    }

    result.duration = Date.now() - startTime;
    const icon = result.status === 'PASSED' ? '✓' : result.status === 'ERROR' ? '✗' : '?';
    this.logger.info(`  ${icon} ${result.status} (${result.duration}ms) — ${result.response}`);

    return result;
  }
}


function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Describe a payload buffer for human-readable logging.
 * Detects HTTP/1.1 requests, HTTP/2 frames, and raw data.
 */
function _describePayload(data) {
  if (!data || data.length === 0) return '(empty)';

  const str = data.toString('utf8', 0, Math.min(data.length, 200));

  // HTTP/1.1 request
  if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) /.test(str)) {
    const firstLine = str.split('\r\n')[0] || str.split('\n')[0];
    return `HTTP/1.1 "${firstLine}"`;
  }

  // HTTP/1.1 response
  if (/^HTTP\/\d\.\d \d{3}/.test(str)) {
    const firstLine = str.split('\r\n')[0] || str.split('\n')[0];
    return `HTTP Response "${firstLine}"`;
  }

  // HTTP/2 connection preface
  if (str.startsWith('PRI * HTTP/2.0')) {
    return 'HTTP/2 Connection Preface (magic octets)';
  }

  // HTTP/2 frame (9-byte header)
  if (data.length >= 9) {
    const frameLen = (data[0] << 16) | (data[1] << 8) | data[2];
    const frameType = data[3];
    const frameTypes = { 0: 'DATA', 1: 'HEADERS', 2: 'PRIORITY', 3: 'RST_STREAM', 4: 'SETTINGS', 5: 'PUSH_PROMISE', 6: 'PING', 7: 'GOAWAY', 8: 'WINDOW_UPDATE', 9: 'CONTINUATION' };
    const typeName = frameTypes[frameType];
    if (typeName && frameLen <= data.length) {
      const streamId = data.readUInt32BE(5) & 0x7FFFFFFF;
      const flags = data[4];
      return `HTTP/2 ${typeName} frame (stream=${streamId}, flags=0x${flags.toString(16)}, len=${frameLen})`;
    }
  }

  // Raw text
  if (/^[\x20-\x7E\r\n\t]+$/.test(str.substring(0, 50))) {
    return `"${str.substring(0, 80).replace(/\r\n/g, '\\r\\n').replace(/\n/g, '\\n')}"`;
  }

  // Binary
  return `binary [${data.slice(0, 16).toString('hex').match(/../g).join(' ')}${data.length > 16 ? '...' : ''}]`;
}


module.exports = { TrafficFuzzerClient };
