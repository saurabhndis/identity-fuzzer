// Sequential IPv4 address generator for syslog sender simulator
// Port of: AI-Agent/anton/apps/useridd/syslogsender/src/syslog_sender_sim/utils/ip_generator.py

/**
 * Generates sequential unique IPv4 addresses from a base address.
 * Used to create unique IP-to-user mappings for syslog login events.
 *
 * Usage:
 *   const gen = new IPGenerator('192.168.1.1');
 *   for (let i = 0; i < 10; i++) {
 *     console.log(gen.next()); // 192.168.1.1, 192.168.1.2, ...
 *   }
 */
class IPGenerator {
  /**
   * @param {string} baseIP - Starting IPv4 address
   * @param {Object} [opts]
   * @param {boolean} [opts.skipNetwork=true] - Skip .0 addresses
   * @param {boolean} [opts.skipBroadcast=true] - Skip .255 addresses
   */
  constructor(baseIP = '192.168.1.1', opts = {}) {
    this._base = IPGenerator.ipToInt(baseIP);
    this._current = this._base;
    this._skipNetwork = opts.skipNetwork !== false;
    this._skipBroadcast = opts.skipBroadcast !== false;
    this._count = 0;
  }

  /**
   * Get the next IP address in the sequence.
   * @returns {string} Next IPv4 address
   * @throws {Error} If address space is exhausted
   */
  next() {
    while (true) {
      if (this._current > 0xFFFFFFFE) { // 255.255.255.254
        throw new Error('IPv4 address space exhausted');
      }

      const addr = this._current;
      this._current++;

      const lastOctet = addr & 0xFF;
      if (this._skipNetwork && lastOctet === 0) continue;
      if (this._skipBroadcast && lastOctet === 255) continue;

      this._count++;
      return IPGenerator.intToIP(addr);
    }
  }

  /**
   * Generate a batch of sequential IP addresses.
   * @param {number} count
   * @returns {string[]}
   */
  batch(count) {
    const ips = [];
    for (let i = 0; i < count; i++) {
      ips.push(this.next());
    }
    return ips;
  }

  /** Reset to the base IP address. */
  reset() {
    this._current = this._base;
    this._count = 0;
  }

  /** Number of IPs generated so far. */
  get generatedCount() {
    return this._count;
  }

  /** The next IP that will be generated. */
  get currentIP() {
    return IPGenerator.intToIP(this._current);
  }

  /**
   * Convert dotted IPv4 string to 32-bit integer.
   * @param {string} ip
   * @returns {number}
   */
  static ipToInt(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      throw new Error(`Invalid IPv4 address: ${ip}`);
    }
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }

  /**
   * Convert 32-bit integer to dotted IPv4 string.
   * @param {number} n
   * @returns {string}
   */
  static intToIP(n) {
    return [
      (n >>> 24) & 0xFF,
      (n >>> 16) & 0xFF,
      (n >>> 8) & 0xFF,
      n & 0xFF,
    ].join('.');
  }
}

module.exports = { IPGenerator };
