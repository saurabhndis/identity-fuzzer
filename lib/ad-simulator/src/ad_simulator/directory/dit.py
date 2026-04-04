"""Directory Information Tree (DIT) — the in-memory LDAP directory store.

Provides the core data structure for the AD Simulator: a dict-based tree
of LDAPEntry objects keyed by normalized (lowercase) DN. Supports LDAP
operations: add, get, delete, modify, search (with BASE/ONELEVEL/SUBTREE
scopes), and bind authentication.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from ad_simulator.directory.dn import (
    is_descendant_of,
    normalize_dn,
    parent_dn,
)
from ad_simulator.directory.entry import LDAPEntry

if TYPE_CHECKING:
    from ad_simulator.directory.filters import FilterNode


class SearchScope(Enum):
    """LDAP search scope as defined in RFC 4511."""

    BASE = 0  # Search only the base object
    ONELEVEL = 1  # Search immediate children of the base
    SUBTREE = 2  # Search the base and all descendants


class DirectoryInformationTree:
    """In-memory LDAP directory store.

    All DN lookups are case-insensitive. The DIT maintains a flat dict
    mapping normalized DNs to LDAPEntry objects, with scope-based search
    implemented via DN string comparison.
    """

    def __init__(self) -> None:
        self._entries: dict[str, LDAPEntry] = {}  # normalized_dn → LDAPEntry

    @property
    def entry_count(self) -> int:
        """Return the number of entries in the DIT."""
        return len(self._entries)

    def add_entry(self, entry: LDAPEntry) -> None:
        """Add an entry to the directory.

        If an entry with the same DN already exists, it is replaced.

        Args:
            entry: The LDAP entry to add.
        """
        key = normalize_dn(entry.dn)
        self._entries[key] = entry

    def get_entry(self, dn: str) -> LDAPEntry | None:
        """Retrieve an entry by its DN (case-insensitive).

        Args:
            dn: The Distinguished Name to look up.

        Returns:
            The LDAPEntry if found, or None.
        """
        key = normalize_dn(dn)
        return self._entries.get(key)

    def delete_entry(self, dn: str) -> bool:
        """Delete an entry by its DN.

        Args:
            dn: The Distinguished Name of the entry to delete.

        Returns:
            True if the entry was found and deleted, False otherwise.
        """
        key = normalize_dn(dn)
        if key in self._entries:
            del self._entries[key]
            return True
        return False

    def modify_entry(self, dn: str, modifications: dict[str, list[str]]) -> bool:
        """Modify an existing entry's attributes.

        Each key in ``modifications`` is an attribute name; the value is the
        new list of values for that attribute. To delete an attribute, pass
        an empty list.

        Args:
            dn: The DN of the entry to modify.
            modifications: Dict of attribute_name → new values.

        Returns:
            True if the entry was found and modified, False otherwise.
        """
        entry = self.get_entry(dn)
        if entry is None:
            return False

        for attr_name, values in modifications.items():
            if values:
                entry.set_attr(attr_name, values)
            else:
                entry.delete_attr(attr_name)

        return True

    def search(
        self,
        base_dn: str,
        scope: SearchScope,
        filter_node: FilterNode,
        attributes: list[str] | None = None,
    ) -> list[LDAPEntry]:
        """Search the directory for entries matching the filter.

        Args:
            base_dn: The base DN for the search.
            scope: The search scope (BASE, ONELEVEL, SUBTREE).
            filter_node: The parsed search filter.
            attributes: Optional list of attribute names to return.
                If None or contains ``"*"``, all attributes are returned.
                This parameter is informational — the caller should use
                ``entry.get_selected_attributes()`` to filter the response.

        Returns:
            A list of matching LDAPEntry objects.
        """
        base_norm = normalize_dn(base_dn)
        results: list[LDAPEntry] = []

        for entry_dn_norm, entry in self._entries.items():
            if not self._in_scope(entry_dn_norm, base_norm, scope):
                continue

            if filter_node.matches(entry):
                results.append(entry)

        return results

    def bind(self, dn: str, password: str) -> bool:
        """Authenticate a bind request.

        Looks up the entry by DN and compares the password.

        Args:
            dn: The bind DN.
            password: The bind password.

        Returns:
            True if the DN exists and the password matches.
        """
        entry = self.get_entry(dn)
        if entry is None:
            return False

        if entry.password is None:
            return False

        return entry.password == password

    def list_entries(self) -> list[LDAPEntry]:
        """Return all entries in the DIT.

        Returns:
            A list of all LDAPEntry objects.
        """
        return list(self._entries.values())

    def _in_scope(
        self,
        entry_dn: str,
        base_dn: str,
        scope: SearchScope,
    ) -> bool:
        """Check if an entry DN falls within the search scope.

        Args:
            entry_dn: Normalized DN of the candidate entry.
            base_dn: Normalized DN of the search base.
            scope: The search scope.

        Returns:
            True if the entry is within scope.
        """
        if scope == SearchScope.BASE:
            return entry_dn == base_dn

        if scope == SearchScope.ONELEVEL:
            # Entry must be a direct child of base_dn
            entry_parent = normalize_dn(parent_dn(entry_dn))
            return entry_parent == base_dn

        if scope == SearchScope.SUBTREE:
            return is_descendant_of(entry_dn, base_dn)

        return False

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def export_entries(self) -> list[dict]:
        """Serialise all entries to a list of JSON-compatible dicts.

        Returns:
            A list of dicts, each produced by :meth:`LDAPEntry.to_dict`.
        """
        return [entry.to_dict() for entry in self._entries.values()]

    def import_entries(self, entries: list[dict]) -> int:
        """Import entries from a list of serialised dicts, replacing all
        existing entries.

        Args:
            entries: List of dicts as produced by :meth:`export_entries`.

        Returns:
            The number of entries imported.
        """
        self._entries.clear()
        for entry_data in entries:
            entry = LDAPEntry.from_dict(entry_data)
            self.add_entry(entry)
        return len(self._entries)
