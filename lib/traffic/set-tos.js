// set-tos.js — Set IP_TOS/DSCP on a TCP socket
// Uses a native N-API addon (set_tos_napi.node) to call setsockopt directly
// Falls back to Python helper if addon not available

'use strict';

const path = require('path');
const { spawnSync } = require('child_process');

// Platform-specific IP_TOS constant
const IP_TOS = process.platform === 'darwin' ? 3 : 1;

// Try to load the native addon
let nativeAddon = null;
try {
  // In packaged Electron app, native addons must be in app.asar.unpacked/
  // Electron automatically redirects require() from app.asar to app.asar.unpacked
  const addonPaths = [
    // Same directory as this file (works when in app.asar.unpacked)
    path.join(__dirname, 'set_tos_napi.node'),
    // Electron's app.asar.unpacked directory
    path.join(__dirname.replace('app.asar', 'app.asar.unpacked'), 'set_tos_napi.node'),
    // process.resourcesPath (Electron-specific)
    path.join(process.resourcesPath || '', 'set_tos_napi.node'),
    // app.asar.unpacked lib/traffic
    path.join(process.resourcesPath || '', 'app.asar.unpacked', 'lib', 'traffic', 'set_tos_napi.node'),
    // Relative paths from lib/traffic/
    path.join(__dirname, '..', '..', 'resources', 'set_tos_napi.node'),
    // Fallback: /tmp (for development/testing)
    '/tmp/set_tos_napi.node',
  ];
  for (const p of addonPaths) {
    try {
      nativeAddon = require(p);
      if (nativeAddon && typeof nativeAddon.setTOS === 'function') break;
      nativeAddon = null;
    } catch (_) {
      nativeAddon = null;
    }
  }
} catch (_) {
  nativeAddon = null;
}

/**
 * Get the raw TCP socket from a potentially wrapped socket (TLS, etc.)
 * @param {net.Socket|tls.TLSSocket} socket
 * @returns {net.Socket}
 */
function getRawSocket(socket) {
  if (!socket) return null;
  if (socket._parent && socket._parent._handle) return socket._parent;
  if (socket.socket && socket.socket._handle) return socket.socket;
  if (socket._handle) return socket;
  return null;
}

/**
 * Get the file descriptor from a socket.
 * @param {net.Socket} socket
 * @returns {number} fd or -1
 */
function getSocketFd(socket) {
  const raw = getRawSocket(socket);
  if (!raw || !raw._handle) return -1;
  const fd = raw._handle.fd;
  if (fd === undefined || fd === null || fd < 0) return -1;
  return fd;
}

/**
 * Set IP_TOS on a TCP socket using the native addon.
 * @param {net.Socket} socket - Node.js TCP or TLS socket
 * @param {number} tosValue - TOS byte value (0-255)
 * @returns {{ success: boolean, readback: number|null, error: string|null }}
 */
function setSocketTOS(socket, tosValue) {
  const fd = getSocketFd(socket);
  if (fd < 0) {
    return { success: false, readback: null, error: `Cannot get socket fd (fd=${fd})` };
  }

  // Method 1: Native addon (in-process setsockopt)
  if (nativeAddon) {
    try {
      const readback = nativeAddon.setTOS(fd, tosValue);
      if (readback >= 0) {
        return { success: true, readback, error: null };
      }
      return { success: false, readback: null, error: `setsockopt returned error (readback=${readback})` };
    } catch (e) {
      return { success: false, readback: null, error: `Native addon error: ${e.message}` };
    }
  }

  // Method 2: Python fallback (won't work due to CLOEXEC, but try anyway)
  try {
    const script = `import socket,os,sys;fd=int(sys.argv[1]);s=socket.fromfd(os.dup(fd),socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.IPPROTO_IP,${IP_TOS},int(sys.argv[2]));r=s.getsockopt(socket.IPPROTO_IP,${IP_TOS});print(r);s.detach()`;
    const result = spawnSync('python3', ['-c', script, String(fd), String(tosValue)], {
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (result.status === 0 && result.stdout) {
      const readback = parseInt(result.stdout.toString().trim(), 10);
      if (!isNaN(readback)) {
        return { success: true, readback, error: null };
      }
    }
  } catch (_) {}

  return { success: false, readback: null, error: 'No method available (native addon not loaded, python failed)' };
}

/**
 * Try to set TOS on a socket. Falls back gracefully if methods fail.
 * @param {net.Socket|tls.TLSSocket} socket
 * @param {number} tosValue
 * @returns {{ success: boolean, readback: number|null, error: string|null, method: string }}
 */
function trySetTOS(socket, tosValue) {
  if (!tosValue || tosValue === 0) {
    return { success: true, readback: 0, error: null, method: 'default' };
  }

  const rawSocket = getRawSocket(socket);

  // Method 1: Try Node.js native socket.setTOS() (available on some builds)
  if (rawSocket && typeof rawSocket.setTOS === 'function') {
    try {
      rawSocket.setTOS(tosValue);
      return { success: true, readback: tosValue, error: null, method: 'socket.setTOS()' };
    } catch (_) {}
  }

  // Method 2: Native addon setsockopt (in-process, works with CLOEXEC fds)
  if (nativeAddon) {
    const fd = getSocketFd(socket);
    if (fd >= 0) {
      try {
        const readback = nativeAddon.setTOS(fd, tosValue);
        if (readback >= 0) {
          return { success: true, readback, error: null, method: 'native setsockopt addon' };
        }
      } catch (e) {
        // Fall through to next method
      }
    }
  }

  // Method 3: Python setsockopt helper (fallback)
  const result = setSocketTOS(socket, tosValue);
  if (result.success) {
    return { ...result, method: 'setsockopt via python3' };
  }

  // Method 4: Fallback — DSCP only in PCAP, not on wire
  return {
    success: false,
    readback: null,
    error: result.error || 'No method available to set IP_TOS on TCP socket',
    method: 'pcap-only (not on wire)',
  };
}


/**
 * Get the native addon instance (for direct use by transport layer).
 * @returns {Object|null} The native addon with setTOS() and createSocketWithTOS()
 */
function getNativeAddon() {
  return nativeAddon;
}

module.exports = { setSocketTOS, trySetTOS, getNativeAddon };
