// set-tos.js — Set IP_TOS/DSCP on a TCP socket file descriptor
// Node.js doesn't expose setsockopt for TCP sockets, so we use a Python helper
// to call setsockopt(fd, IPPROTO_IP, IP_TOS, value) on the socket's fd.
//
// This works because:
// 1. Node.js TCP sockets have an internal _handle with an fd property
// 2. We spawn a Python process that inherits the fd (via stdio: 'inherit')
// 3. Python calls setsockopt on the inherited fd
// 4. The kernel applies the TOS value to all subsequent packets on that socket

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Platform-specific IP_TOS constant
// macOS: 3, Linux: 1
const IP_TOS = process.platform === 'darwin' ? 3 : 1;
const IPPROTO_IP = 0;

/**
 * Set IP_TOS on a TCP socket using a Python helper.
 * @param {net.Socket} socket - Node.js TCP socket
 * @param {number} tosValue - TOS byte value (0-255)
 * @returns {{ success: boolean, readback: number|null, error: string|null }}
 */
function setSocketTOS(socket, tosValue) {
  if (!socket || !socket._handle) {
    return { success: false, readback: null, error: 'No socket handle' };
  }

  const fd = socket._handle.fd;
  if (fd === undefined || fd < 0) {
    return { success: false, readback: null, error: 'Invalid fd' };
  }

  // Write a temp Python script that sets TOS via setsockopt
  const scriptPath = path.join(require('os').tmpdir(), `set_tos_${process.pid}.py`);
  const script = `
import socket, struct, sys, os

fd = int(sys.argv[1])
tos = int(sys.argv[2])
ip_tos = int(sys.argv[3])

try:
    # Use fcntl to duplicate the fd so Python can use it
    new_fd = os.dup(fd)
    s = socket.fromfd(new_fd, socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, ip_tos, tos)
    readback = s.getsockopt(socket.IPPROTO_IP, ip_tos)
    print(readback)
    s.detach()
    os.close(new_fd)
except Exception as e:
    print("ERROR:" + str(e), file=sys.stderr)
    sys.exit(1)
`;

  try {
    fs.writeFileSync(scriptPath, script);

    const result = spawnSync('python3', [scriptPath, String(fd), String(tosValue), String(IP_TOS)], {
      timeout: 5000,
      stdio: ['inherit', 'pipe', 'pipe'],
    });

    // Cleanup
    try { fs.unlinkSync(scriptPath); } catch (_) {}

    if (result.status === 0) {
      const readback = parseInt(result.stdout.toString().trim(), 10);
      return { success: true, readback, error: null };
    } else {
      const stderr = result.stderr ? result.stderr.toString().trim() : 'Unknown error';
      return { success: false, readback: null, error: stderr };
    }
  } catch (e) {
    try { fs.unlinkSync(scriptPath); } catch (_) {}
    return { success: false, readback: null, error: e.message };
  }
}

/**
 * Try to set TOS on a socket. Falls back gracefully if Python is not available.
 * @param {net.Socket} socket
 * @param {number} tosValue
 * @returns {{ success: boolean, readback: number|null, error: string|null, method: string }}
 */
function trySetTOS(socket, tosValue) {
  if (!tosValue || tosValue === 0) {
    return { success: true, readback: 0, error: null, method: 'default' };
  }

  // Method 1: Try socket.setTOS (works on dgram/UDP, may work on some Node versions)
  if (typeof socket.setTOS === 'function') {
    try {
      socket.setTOS(tosValue);
      return { success: true, readback: tosValue, error: null, method: 'socket.setTOS()' };
    } catch (_) {}
  }

  // Method 2: Try Python setsockopt helper
  const result = setSocketTOS(socket, tosValue);
  if (result.success) {
    return { ...result, method: 'setsockopt via python3' };
  }

  // Method 3: Fallback — DSCP only in PCAP, not on wire
  return {
    success: false,
    readback: null,
    error: result.error || 'No method available to set IP_TOS on TCP socket',
    method: 'pcap-only (not on wire)',
  };
}


module.exports = { setSocketTOS, trySetTOS };
