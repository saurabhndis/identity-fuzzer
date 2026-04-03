// PCAP File Writer — write standard pcap format readable by Wireshark
const fs = require('fs');

// TCP flags — inlined to avoid external dependency
const TCPFlags = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
};

// PCAP magic number and header constants
const PCAP_MAGIC = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR = 2;
const PCAP_VERSION_MINOR = 4;
const PCAP_SNAPLEN = 65535;
const PCAP_LINKTYPE_ETHERNET = 1;

// Ethernet + IP + TCP header sizes
const ETH_HEADER_SIZE = 14;
const IP_HEADER_SIZE = 20;
const TCP_HEADER_SIZE = 20;
const TOTAL_HEADER_SIZE = ETH_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE;

class PcapWriter {
  constructor(filepath, opts = {}) {
    if (!filepath || typeof filepath !== 'string') {
      throw new Error('Valid filepath is required for PCAP writer');
    }

    const path = require('path');
    const normalizedPath = path.normalize(filepath);
    if (!normalizedPath.toLowerCase().endsWith('.pcap')) {
      throw new Error('PCAP filepath must end with .pcap');
    }

    this.filepath = normalizedPath;
    this.role = opts.role || 'client';

    this.clientIP = opts.clientIP || '10.0.0.1';
    this.serverIP = opts.serverIP || '10.0.0.2';
    this.clientPort = opts.clientPort || opts.srcPort || 49152;
    this.serverPort = opts.serverPort || opts.dstPort || 389;
    this.protocol = opts.protocol || 'tcp';

    if (opts.srcIP || opts.dstIP) {
      if (this.role === 'client') {
        this.clientIP = opts.srcIP || this.clientIP;
        this.serverIP = opts.dstIP || this.serverIP;
      } else {
        this.serverIP = opts.srcIP || this.serverIP;
        this.clientIP = opts.dstIP || this.clientIP;
      }
    }

    this.clientSeq = Math.floor(Math.random() * 0xffffffff);
    this.serverSeq = Math.floor(Math.random() * 0xffffffff);

    this.fd = opts.append && fs.existsSync(this.filepath)
      ? fs.openSync(this.filepath, 'a')
      : fs.openSync(this.filepath, 'w');

    if (!opts.append || !fs.statSync(this.filepath).size) {
      this._writeGlobalHeader();
    }
    this.packetCount = 0;
  }

  _writeGlobalHeader() {
    const buf = Buffer.alloc(24);
    buf.writeUInt32LE(PCAP_MAGIC, 0);
    buf.writeUInt16LE(PCAP_VERSION_MAJOR, 4);
    buf.writeUInt16LE(PCAP_VERSION_MINOR, 6);
    buf.writeInt32LE(0, 8);
    buf.writeUInt32LE(0, 12);
    buf.writeUInt32LE(PCAP_SNAPLEN, 16);
    buf.writeUInt32LE(PCAP_LINKTYPE_ETHERNET, 20);
    fs.writeSync(this.fd, buf);
    try { fs.fsyncSync(this.fd); } catch (_) {}
  }

  _ipToBytes(ip) {
    return ip.split('.').map(n => parseInt(n, 10));
  }

  _resolveDirection(direction) {
    if (direction === 'outbound') {
      if (this.role === 'client') {
        return { srcIP: this.clientIP, dstIP: this.serverIP, srcPort: this.clientPort, dstPort: this.serverPort, seqOwner: 'client' };
      } else {
        return { srcIP: this.serverIP, dstIP: this.clientIP, srcPort: this.serverPort, dstPort: this.clientPort, seqOwner: 'server' };
      }
    } else {
      if (this.role === 'client') {
        return { srcIP: this.serverIP, dstIP: this.clientIP, srcPort: this.serverPort, dstPort: this.clientPort, seqOwner: 'server' };
      } else {
        return { srcIP: this.clientIP, dstIP: this.serverIP, srcPort: this.clientPort, dstPort: this.serverPort, seqOwner: 'client' };
      }
    }
  }

  _buildEthernetHeader(dir) {
    const buf = Buffer.alloc(ETH_HEADER_SIZE);
    const dstMAC = dir.seqOwner === 'client'
      ? [0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
      : [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    const srcMAC = dir.seqOwner === 'client'
      ? [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
      : [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
    for (let i = 0; i < 6; i++) { buf[i] = dstMAC[i]; buf[i + 6] = srcMAC[i]; }
    buf.writeUInt16BE(0x0800, 12);
    return buf;
  }

  _buildIPHeader(dir, payloadLength) {
    const transportHeaderSize = this.protocol === 'udp' ? 8 : 20;
    const totalLength = IP_HEADER_SIZE + transportHeaderSize + payloadLength;
    const buf = Buffer.alloc(IP_HEADER_SIZE);

    buf[0] = 0x45;
    buf[1] = 0x00;
    buf.writeUInt16BE(totalLength, 2);
    buf.writeUInt16BE(this.packetCount & 0xffff, 4);
    buf.writeUInt16BE(0x4000, 6);
    buf[8] = 64;
    buf[9] = this.protocol === 'udp' ? 17 : 6;
    buf.writeUInt16BE(0, 10);

    const srcIP = this._ipToBytes(dir.srcIP);
    const dstIP = this._ipToBytes(dir.dstIP);
    buf[12] = srcIP[0]; buf[13] = srcIP[1]; buf[14] = srcIP[2]; buf[15] = srcIP[3];
    buf[16] = dstIP[0]; buf[17] = dstIP[1]; buf[18] = dstIP[2]; buf[19] = dstIP[3];

    let sum = 0;
    for (let i = 0; i < 20; i += 2) sum += buf.readUInt16BE(i);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    buf.writeUInt16BE(~sum & 0xffff, 10);

    return buf;
  }

  _buildTCPHeader(dir, flags, payloadLength) {
    const buf = Buffer.alloc(TCP_HEADER_SIZE);
    buf.writeUInt16BE(dir.srcPort, 0);
    buf.writeUInt16BE(dir.dstPort, 2);

    if (dir.seqOwner === 'client') {
      buf.writeUInt32BE(this.clientSeq >>> 0, 4);
      buf.writeUInt32BE((flags & TCPFlags.ACK) ? (this.serverSeq >>> 0) : 0, 8);
      this.clientSeq = (this.clientSeq + payloadLength) >>> 0;
      if (flags & TCPFlags.SYN) this.clientSeq = (this.clientSeq + 1) >>> 0;
      if (flags & TCPFlags.FIN) this.clientSeq = (this.clientSeq + 1) >>> 0;
    } else {
      buf.writeUInt32BE(this.serverSeq >>> 0, 4);
      buf.writeUInt32BE((flags & TCPFlags.ACK) ? (this.clientSeq >>> 0) : 0, 8);
      this.serverSeq = (this.serverSeq + payloadLength) >>> 0;
      if (flags & TCPFlags.SYN) this.serverSeq = (this.serverSeq + 1) >>> 0;
      if (flags & TCPFlags.FIN) this.serverSeq = (this.serverSeq + 1) >>> 0;
    }

    buf[12] = 0x50;
    buf[13] = flags & 0xff;
    buf.writeUInt16BE(65535, 14);
    buf.writeUInt16BE(0, 16);
    buf.writeUInt16BE(0, 18);

    return buf;
  }

  _computeTCPChecksum(dir, tcpHeader, payload) {
    const srcIP = this._ipToBytes(dir.srcIP);
    const dstIP = this._ipToBytes(dir.dstIP);
    const tcpLen = tcpHeader.length + payload.length;

    const pseudo = Buffer.alloc(12);
    pseudo[0] = srcIP[0]; pseudo[1] = srcIP[1]; pseudo[2] = srcIP[2]; pseudo[3] = srcIP[3];
    pseudo[4] = dstIP[0]; pseudo[5] = dstIP[1]; pseudo[6] = dstIP[2]; pseudo[7] = dstIP[3];
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo.writeUInt16BE(tcpLen, 10);

    let sum = 0;
    const parts = [pseudo, tcpHeader, payload];
    for (const part of parts) {
      for (let i = 0; i < part.length - 1; i += 2) {
        sum += part.readUInt16BE(i);
      }
      if (part.length % 2 !== 0) {
        sum += part[part.length - 1] << 8;
      }
    }
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum & 0xffff;
  }

  _toBuffer(data) {
    if (!data) return Buffer.alloc(0);
    if (Buffer.isBuffer(data)) return data;
    if (typeof data === 'string') return Buffer.from(data, 'binary');
    if (data instanceof Uint8Array || Array.isArray(data)) return Buffer.from(data);
    return Buffer.alloc(0);
  }

  writePacket(payload, direction, flags = TCPFlags.PSH | TCPFlags.ACK) {
    let data = this._toBuffer(payload);
    const dir = this._resolveDirection(direction);

    const origLen = data.length;
    const maxPayload = PCAP_SNAPLEN - TOTAL_HEADER_SIZE;
    if (data.length > maxPayload) {
      data = data.slice(0, maxPayload);
    }

    const eth = this._buildEthernetHeader(dir);
    const ip = this._buildIPHeader(dir, data.length);
    const tcp = this._buildTCPHeader(dir, flags, data.length);

    const checksum = this._computeTCPChecksum(dir, tcp, data);
    tcp.writeUInt16BE(checksum, 16);

    const packet = Buffer.concat([eth, ip, tcp, data]);

    const now = Date.now();
    const tsSec = Math.floor(now / 1000);
    const tsUsec = (now % 1000) * 1000;

    const packetHeader = Buffer.alloc(16);
    packetHeader.writeUInt32LE(tsSec, 0);
    packetHeader.writeUInt32LE(tsUsec, 4);
    packetHeader.writeUInt32LE(packet.length, 8);
    const totalOrigLen = ETH_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE + origLen;
    packetHeader.writeUInt32LE(Math.min(totalOrigLen, 0xFFFFFF), 12);

    const finalBuffer = Buffer.concat([packetHeader, packet]);
    fs.writeSync(this.fd, finalBuffer);
    try { fs.fsyncSync(this.fd); } catch (_) {}
    this.packetCount++;
  }

  writeTCPHandshake() {
    const clientSends = this.role === 'client' ? 'outbound' : 'inbound';
    const serverSends = this.role === 'client' ? 'inbound' : 'outbound';
    this.writePacket(Buffer.alloc(0), clientSends, TCPFlags.SYN);
    this.writePacket(Buffer.alloc(0), serverSends, TCPFlags.SYN | TCPFlags.ACK);
    this.writePacket(Buffer.alloc(0), clientSends, TCPFlags.ACK);
  }

  writeTLSData(data, direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(data, dir, TCPFlags.PSH | TCPFlags.ACK);
  }

  writeFIN(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.FIN | TCPFlags.ACK);
  }

  writeRST(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.RST);
  }

  writeACK(direction) {
    const dir = direction === 'sent' ? 'outbound' : 'inbound';
    this.writePacket(Buffer.alloc(0), dir, TCPFlags.ACK);
  }

  close() {
    try {
      fs.closeSync(this.fd);
    } catch (_) {}
  }
}

module.exports = { PcapWriter };
