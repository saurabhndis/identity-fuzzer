"""LDAP server components for the AD Simulator (Phase 3).

Exports the LDAP server protocol, factory, runner functions, and SSL utilities.
"""

from ad_simulator.server.ldap_server import (
    ADSimulatorFactory,
    ADSimulatorLDAPServer,
    ldaptor_filter_to_string,
)
from ad_simulator.server.runner import (
    get_factory,
    run_server,
    start_server_background,
    stop_server,
)
from ad_simulator.server.ssl_config import generate_server_certs, get_ssl_context

__all__ = [
    "ADSimulatorFactory",
    "ADSimulatorLDAPServer",
    "ldaptor_filter_to_string",
    "run_server",
    "start_server_background",
    "stop_server",
    "get_factory",
    "generate_server_certs",
    "get_ssl_context",
]
