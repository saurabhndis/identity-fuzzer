"""Server runner for the AD Simulator LDAP server.

Provides functions to start and stop the Twisted-based LDAP server,
both in the foreground (blocking) and in a background thread (for
GUI integration or testing).

Note: The Twisted reactor is imported lazily to avoid interfering with
test frameworks like pytest-twisted.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

from ad_simulator.server.ldap_server import ADSimulatorFactory
from ad_simulator.server.ssl_config import get_ssl_context

if TYPE_CHECKING:
    from ad_simulator.ad.domain import ADDomain

logger = logging.getLogger(__name__)

# Module-level state for background server management
_server_thread: threading.Thread | None = None
_listening_ports: list[Any] = []
_factory: ADSimulatorFactory | None = None


def _get_reactor() -> Any:
    """Lazily import the Twisted reactor.

    This avoids importing the reactor at module level, which would
    interfere with pytest-twisted and other test frameworks.

    Returns:
        The Twisted reactor instance.
    """
    from twisted.internet import reactor

    return reactor


def run_server(
    domain: ADDomain,
    host: str = "0.0.0.0",
    port: int = 389,
    ssl_port: int | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
) -> None:
    """Start the LDAP server in the foreground (blocking).

    Starts the Twisted reactor, which blocks until :func:`stop_server`
    is called or the process is interrupted.

    Args:
        domain: The :class:`ADDomain` to serve.
        host: The interface to bind to (default ``"0.0.0.0"``).
        port: The LDAP port (default ``389``).
        ssl_port: Optional LDAPS port (default ``None`` — no SSL).
        cert_file: Path to PEM certificate for LDAPS.
        key_file: Path to PEM private key for LDAPS.
    """
    global _factory, _listening_ports

    reactor = _get_reactor()
    _factory = ADSimulatorFactory(domain)
    _listening_ports = []

    # LDAP (plaintext)
    ldap_port = reactor.listenTCP(port, _factory, interface=host)
    _listening_ports.append(ldap_port)
    logger.info("LDAP server listening on %s:%d", host, port)

    # LDAPS (SSL/TLS)
    if ssl_port is not None and cert_file and key_file:
        ssl_ctx = get_ssl_context(cert_file, key_file)
        ldaps_port = reactor.listenSSL(ssl_port, _factory, ssl_ctx, interface=host)
        _listening_ports.append(ldaps_port)
        logger.info("LDAPS server listening on %s:%d", host, ssl_port)

    reactor.run()


def start_server_background(
    domain: ADDomain,
    host: str = "0.0.0.0",
    port: int = 10389,
    ssl_port: int | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    on_log: Any = None,
) -> ADSimulatorFactory:
    """Start the LDAP server in a background thread.

    Useful for GUI integration or testing. The server runs in a daemon
    thread and can be stopped with :func:`stop_server`.

    Args:
        domain: The :class:`ADDomain` to serve.
        host: The interface to bind to (default ``"0.0.0.0"``).
        port: The LDAP port (default ``10389`` for non-root testing).
        ssl_port: Optional LDAPS port.
        cert_file: Path to PEM certificate for LDAPS.
        key_file: Path to PEM private key for LDAPS.

    Returns:
        The :class:`ADSimulatorFactory` instance managing connections.

    Raises:
        RuntimeError: If a server is already running.
    """
    global _server_thread, _factory, _listening_ports

    if _server_thread is not None and _server_thread.is_alive():
        raise RuntimeError("Server is already running in background")

    reactor = _get_reactor()
    _factory = ADSimulatorFactory(domain, on_log=on_log)
    _listening_ports = []

    # Schedule the listener setup on the reactor thread
    def _setup_listeners() -> None:
        global _listening_ports
        ldap_port = reactor.listenTCP(port, _factory, interface=host)
        _listening_ports.append(ldap_port)
        logger.info("LDAP server (background) listening on %s:%d", host, port)

        if ssl_port is not None and cert_file and key_file:
            ssl_ctx = get_ssl_context(cert_file, key_file)
            ldaps_port = reactor.listenSSL(ssl_port, _factory, ssl_ctx, interface=host)
            _listening_ports.append(ldaps_port)
            logger.info("LDAPS server (background) listening on %s:%d", host, ssl_port)

    reactor.callFromThread(_setup_listeners)

    def _run_reactor() -> None:
        """Run the reactor if it's not already running."""
        if not reactor.running:
            reactor.run(installSignalHandlers=False)

    _server_thread = threading.Thread(target=_run_reactor, daemon=True)
    _server_thread.start()

    return _factory


def stop_server() -> None:
    """Stop the LDAP server and clean up resources.

    Stops all listening ports and the Twisted reactor if it's running.
    Safe to call even if no server is running.
    """
    global _server_thread, _listening_ports, _factory

    if not _listening_ports and _factory is None and _server_thread is None:
        # Nothing to stop
        return

    for port_obj in _listening_ports:
        try:
            port_obj.stopListening()
        except Exception:
            pass

    _listening_ports = []

    # Only touch the reactor if we actually started something
    if _server_thread is not None:
        reactor = _get_reactor()
        if reactor.running:
            try:
                reactor.callFromThread(reactor.stop)
            except Exception:
                pass
        _server_thread.join(timeout=5.0)
        _server_thread = None

    _factory = None
    logger.info("LDAP server stopped")


def get_factory() -> ADSimulatorFactory | None:
    """Return the current server factory, or None if not running.

    Returns:
        The active :class:`ADSimulatorFactory` or ``None``.
    """
    return _factory
