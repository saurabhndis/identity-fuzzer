"""PAN-OS compatible LDAP server built on ldaptor/Twisted.

Provides :class:`ADSimulatorLDAPServer` (the per-connection protocol) and
:class:`ADSimulatorFactory` (the Twisted server factory) that together
simulate an Active Directory LDAP endpoint for PAN-OS firewall testing.

Handles:
- Bind (service account + user authentication)
- Search (group mapping, user lookup, email lookup)
- Unbind
"""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapserver import BaseLDAPServer
from twisted.internet import protocol

from ad_simulator.directory.dit import SearchScope
from ad_simulator.directory.filters import parse_filter

if TYPE_CHECKING:
    from ad_simulator.ad.domain import ADDomain


def _ensure_bytes(value: str | bytes) -> bytes:
    """Ensure a value is bytes, encoding from UTF-8 if necessary."""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _ensure_str(value: str | bytes) -> str:
    """Ensure a value is a string, decoding from UTF-8 if necessary."""
    if isinstance(value, str):
        return value
    return value.decode("utf-8")


def ldaptor_filter_to_string(ldap_filter: Any) -> str:
    """Convert an ldaptor filter object to an RFC 4515 filter string.

    Manually converts each ldaptor filter type to its RFC 4515 string
    representation. We cannot rely on ldaptor's ``asText()`` method
    because it has str/bytes incompatibilities in Python 3.

    Args:
        ldap_filter: An ldaptor filter object (e.g. ``LDAPFilter_equalityMatch``).

    Returns:
        The RFC 4515 filter string representation.

    Raises:
        ValueError: If the filter type is not recognized.
    """
    if isinstance(ldap_filter, pureldap.LDAPFilter_and):
        children = "".join(ldaptor_filter_to_string(child) for child in ldap_filter)
        return f"(&{children})"

    if isinstance(ldap_filter, pureldap.LDAPFilter_or):
        children = "".join(ldaptor_filter_to_string(child) for child in ldap_filter)
        return f"(|{children})"

    if isinstance(ldap_filter, pureldap.LDAPFilter_not):
        child = ldaptor_filter_to_string(ldap_filter.value)
        return f"(!{child})"

    if isinstance(ldap_filter, pureldap.LDAPFilter_equalityMatch):
        attr = _ensure_str(ldap_filter.attributeDesc.value)
        val = _ensure_str(ldap_filter.assertionValue.value)
        return f"({attr}={val})"

    if isinstance(ldap_filter, pureldap.LDAPFilter_substrings):
        attr = _ensure_str(ldap_filter.type)
        initial = ""
        final = ""
        any_parts: list[str] = []

        for sub in ldap_filter.substrings:
            if isinstance(sub, pureldap.LDAPFilter_substrings_initial):
                initial = _ensure_str(sub.value)
            elif isinstance(sub, pureldap.LDAPFilter_substrings_final):
                final = _ensure_str(sub.value)
            elif isinstance(sub, pureldap.LDAPFilter_substrings_any):
                any_parts.append(_ensure_str(sub.value))

        parts = [initial] + any_parts + [final]
        return f"({attr}={'*'.join(parts)})"

    if isinstance(ldap_filter, pureldap.LDAPFilter_present):
        attr = _ensure_str(ldap_filter.value)
        return f"({attr}=*)"

    if isinstance(ldap_filter, pureldap.LDAPFilter_greaterOrEqual):
        attr = _ensure_str(ldap_filter.attributeDesc.value)
        val = _ensure_str(ldap_filter.assertionValue.value)
        return f"({attr}>={val})"

    if isinstance(ldap_filter, pureldap.LDAPFilter_lessOrEqual):
        attr = _ensure_str(ldap_filter.attributeDesc.value)
        val = _ensure_str(ldap_filter.assertionValue.value)
        return f"({attr}<={val})"

    if isinstance(ldap_filter, pureldap.LDAPFilter_extensibleMatch):
        # Extensible match: attr[:dn]:matchingRule:=value
        attr_part = _ensure_str(ldap_filter.type.value) if ldap_filter.type else ""
        dn_part = ":dn" if ldap_filter.dnAttributes and ldap_filter.dnAttributes.value else ""
        rule_part = f":{_ensure_str(ldap_filter.matchingRule.value)}" if ldap_filter.matchingRule else ""
        val = _ensure_str(ldap_filter.matchValue.value)
        return f"({attr_part}{dn_part}{rule_part}:={val})"

    raise ValueError(f"Unsupported ldaptor filter type: {type(ldap_filter).__name__}")


class ADSimulatorLDAPServer(BaseLDAPServer):
    """LDAP server protocol that simulates Active Directory for PAN-OS testing.

    Each instance handles a single client connection. The :attr:`domain`
    attribute is set by the factory and provides access to the directory
    information tree (DIT) for bind and search operations.

    Attributes:
        domain: The :class:`ADDomain` backing this server.
        connection_log: Per-connection log of LDAP operations.
    """

    def __init__(self) -> None:
        super().__init__()
        self.domain: ADDomain | None = None  # Set by factory
        self.connection_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Bind
    # ------------------------------------------------------------------

    def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Any,
        reply: Any,
    ) -> None:
        """Handle LDAP bind requests.

        PAN-OS sends:
        1. Service account bind: ``DN=CN=svc-panos,CN=Users,DC=testlab,DC=local``
        2. User auth bind: ``DN=CN=John Doe,CN=Users,DC=testlab,DC=local``

        Anonymous binds (empty DN) are allowed.
        """
        dn = _ensure_str(request.dn) if request.dn else ""
        password = _ensure_str(request.auth) if request.auth else ""

        if not dn:
            # Anonymous bind — allow
            self._log_operation("BIND", dn="", success=True, anonymous=True)
            reply(pureldap.LDAPBindResponse(resultCode=0))
            return

        # Try to authenticate against the DIT
        assert self.domain is not None
        if self.domain.dit.bind(dn, password):
            self._log_operation("BIND", dn=dn, success=True)
            reply(pureldap.LDAPBindResponse(resultCode=0))
        else:
            self._log_operation("BIND", dn=dn, success=False, error="Invalid credentials")
            reply(
                pureldap.LDAPBindResponse(
                    resultCode=49,  # invalidCredentials
                    errorMessage="Invalid credentials",
                )
            )

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def handle_LDAPSearchRequest(
        self,
        request: pureldap.LDAPSearchRequest,
        controls: Any,
        reply: Any,
    ) -> None:
        """Handle LDAP search requests.

        PAN-OS sends these searches:
        - ``(objectClass=group)`` — group membership query
        - ``(sAMAccountName=username)`` — user lookup
        - ``(|(mail=...)(proxyAddresses=...))`` — email lookup
        - ``(&(objectClass=group)(whenChanged>=...))`` — incremental sync
        """
        base_dn = _ensure_str(request.baseObject) if request.baseObject else ""
        scope_map = {0: SearchScope.BASE, 1: SearchScope.ONELEVEL, 2: SearchScope.SUBTREE}
        scope = scope_map.get(request.scope, SearchScope.SUBTREE)

        # Convert ldaptor filter to our filter string, then parse it
        filter_str = ldaptor_filter_to_string(request.filter)
        filter_node = parse_filter(filter_str)

        # Get requested attributes
        attrs: list[str] | None = None
        if request.attributes:
            attrs = [_ensure_str(a) for a in request.attributes]

        # Search the DIT
        assert self.domain is not None
        results = self.domain.dit.search(base_dn, scope, filter_node, attrs)

        self._log_operation(
            "SEARCH",
            base_dn=base_dn,
            scope=scope.name,
            filter=filter_str,
            results=len(results),
        )

        # Send each result entry
        for entry in results:
            selected = entry.get_selected_attributes(attrs) if attrs else entry.to_ldap_attributes()
            ldap_attrs: list[tuple[bytes, list[bytes]]] = []
            for attr_name, values in selected.items():
                ldap_attrs.append(
                    (
                        _ensure_bytes(attr_name),
                        [_ensure_bytes(v) for v in values],
                    )
                )
            reply(
                pureldap.LDAPSearchResultEntry(
                    objectName=_ensure_bytes(entry.dn),
                    attributes=ldap_attrs,
                )
            )

        # Send search done
        reply(pureldap.LDAPSearchResultDone(resultCode=0))

    # ------------------------------------------------------------------
    # Unbind
    # ------------------------------------------------------------------

    def handle_LDAPUnbindRequest(
        self,
        request: pureldap.LDAPUnbindRequest,
        controls: Any,
        reply: Any,
    ) -> None:
        """Handle unbind — log and close connection."""
        self._log_operation("UNBIND")

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def connectionLost(self, reason=None):
        """Called when the client disconnects."""
        super().connectionLost(reason)
        if hasattr(self, "factory") and hasattr(self.factory, "active_connections"):
            self.factory.active_connections = max(0, self.factory.active_connections - 1)
            client = "unknown"
            if self.transport is not None:
                try:
                    client = str(self.transport.getPeer())
                except Exception:
                    pass
            if hasattr(self.factory, "_emit_log"):
                self.factory._emit_log({
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "operation": "DISCONNECT",
                    "client": client,
                    "active_connections": self.factory.active_connections,
                })

    def _log_operation(self, op_type: str, **kwargs: Any) -> None:
        """Log an LDAP operation for the connection log.

        Also appends to the factory's shared operation log via _emit_log.

        Args:
            op_type: The operation type (``"BIND"``, ``"SEARCH"``, ``"UNBIND"``).
            **kwargs: Additional key-value pairs to include in the log entry.
        """
        client = "unknown"
        if self.transport is not None:
            try:
                client = str(self.transport.getPeer())
            except Exception:
                pass

        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "operation": op_type,
            "client": client,
            **kwargs,
        }
        self.connection_log.append(entry)

        # Forward to factory's shared log with real-time callback
        if hasattr(self, "factory") and hasattr(self.factory, "_emit_log"):
            self.factory._emit_log(entry)


class ADSimulatorFactory(protocol.ServerFactory):
    """Factory that creates LDAP server protocol instances.

    Each connection gets its own :class:`ADSimulatorLDAPServer` instance
    backed by the shared :class:`ADDomain`.

    Attributes:
        domain: The :class:`ADDomain` backing all connections.
        operation_log: Shared log across all connections.
        connection_count: Total number of connections created.
        on_log: Optional callback invoked for each log entry.
    """

    protocol = ADSimulatorLDAPServer

    def __init__(self, domain: ADDomain, on_log: Any = None) -> None:
        self.domain = domain
        self.operation_log: list[dict[str, Any]] = []
        self.connection_count: int = 0
        self.active_connections: int = 0
        self.on_log = on_log  # callback(entry_dict) for real-time log forwarding

    def _emit_log(self, entry: dict[str, Any]) -> None:
        """Append to operation_log and invoke callback if set."""
        self.operation_log.append(entry)
        if self.on_log:
            try:
                self.on_log(entry)
            except Exception:
                pass

    def buildProtocol(self, addr: Any) -> ADSimulatorLDAPServer:
        """Create a new protocol instance for an incoming connection.

        Args:
            addr: The address of the connecting client.

        Returns:
            A configured :class:`ADSimulatorLDAPServer` instance.
        """
        proto = ADSimulatorLDAPServer()
        proto.factory = self  # type: ignore[attr-defined]
        proto.domain = self.domain
        self.connection_count += 1
        self.active_connections += 1

        # Log the new connection
        client_addr = str(addr) if addr else "unknown"
        self._emit_log({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "operation": "CONNECT",
            "client": client_addr,
            "connection_number": self.connection_count,
            "active_connections": self.active_connections,
        })
        return proto
