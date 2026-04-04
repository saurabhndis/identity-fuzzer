"""Organizational Unit (OU) management for the AD Simulator.

Provides CRUD operations for OUs within the simulated Active Directory
domain structure.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ad_simulator.directory.dit import DirectoryInformationTree, SearchScope
from ad_simulator.directory.entry import LDAPEntry
from ad_simulator.directory.filters import parse_filter


def _ad_timestamp() -> str:
    """Return the current time in AD generalized time format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S.0Z")


class OUManager:
    """Manages Organizational Unit entries in the directory.

    Provides create, read, list, and delete operations for OUs.
    """

    def __init__(self, dit: DirectoryInformationTree, base_dn: str) -> None:
        self._dit = dit
        self._base_dn = base_dn

    def create_ou(self, name: str, parent_dn: str | None = None) -> LDAPEntry:
        """Create an Organizational Unit entry.

        Args:
            name: The OU name (e.g. ``"Engineering"``).
            parent_dn: Parent DN under which to create the OU.
                If ``None``, creates directly under the domain base DN.

        Returns:
            The created :class:`LDAPEntry`.
        """
        parent = parent_dn if parent_dn is not None else self._base_dn
        dn = f"OU={name},{parent}"
        now = _ad_timestamp()

        entry = LDAPEntry(
            dn=dn,
            attributes={
                "objectClass": ["top", "organizationalUnit"],
                "ou": [name],
                "name": [name],
                "distinguishedName": [dn],
                "whenCreated": [now],
                "whenChanged": [now],
            },
        )
        self._dit.add_entry(entry)
        return entry

    def get_ou(self, name: str) -> LDAPEntry | None:
        """Look up an OU by name via subtree search.

        Args:
            name: The OU name to find.

        Returns:
            The :class:`LDAPEntry` if found, or ``None``.
        """
        filter_node = parse_filter(
            f"(&(objectClass=organizationalUnit)(ou={name}))"
        )
        results = self._dit.search(self._base_dn, SearchScope.SUBTREE, filter_node)
        return results[0] if results else None

    def list_ous(self) -> list[LDAPEntry]:
        """Return all OU entries under the base DN.

        Returns:
            A list of :class:`LDAPEntry` objects with objectClass ``organizationalUnit``.
        """
        filter_node = parse_filter("(objectClass=organizationalUnit)")
        return self._dit.search(self._base_dn, SearchScope.SUBTREE, filter_node)

    def delete_ou(self, name: str) -> bool:
        """Delete an OU by name.

        Args:
            name: The OU name to delete.

        Returns:
            ``True`` if the OU was found and deleted, ``False`` otherwise.
        """
        entry = self.get_ou(name)
        if entry is None:
            return False
        return self._dit.delete_entry(entry.dn)
