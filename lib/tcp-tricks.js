// TCP-level manipulation helpers for LDAP fuzzing

/**
 * Send TCP FIN (half-close the write side)
 */
function sendFIN(socket) {
  return new Promise((resolve) => {
    socket.end(() => resolve());
  });
}

/**
 * Send TCP RST (abruptly destroy the connection)
 */
function sendRST(socket) {
  if (typeof socket.resetAndDestroy === 'function') {
    socket.resetAndDestroy();
  } else {
    // Fallback: set linger to 0 then destroy (sends RST)
    try {
      socket.setKeepAlive(false);
    } catch (_) {}
    socket.destroy();
  }
}

/**
 * Configure socket for fuzzing
 */
function configureSocket(socket) {
  socket.setNoDelay(true); // disable Nagle's for precise packet control
  socket.setKeepAlive(false);
}

module.exports = {
  sendFIN,
  sendRST,
  configureSocket,
};
