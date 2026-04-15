"""LDAP Entry model for the AD Simulator.

Represents a single entry in the Directory Information Tree with
multi-valued attributes, password storage for bind authentication,
and filter matching support.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ad_simulator.directory.dn import normalize_dn

if TYPE_CHECKING:
    from ad_simulator.directory.filters import FilterNode


class LDAPEntry:
    """An entry in the LDAP directory.

    Attributes:
        dn: The Distinguished Name of this entry.
        attributes: Multi-valued attribute dict (attr_name → list of string values).
        password: Optional password for bind authentication.
        created_at: Timestamp when the entry was created.
        modified_at: Timestamp when the entry was last modified.
    """

    def __init__(
        self,
        dn: str,
        attributes: dict[str, list[str]] | None = None,
        password: str | None = None,
    ) -> None:
        self.dn = dn
        self._attributes: dict[str, list[str]] = {}
        self.password = password
        self.created_at = datetime.now(timezone.utc)
        self.modified_at = datetime.now(timezone.utc)

        # Store attributes with case-insensitive key lookup
        if attributes:
            for name, values in attributes.items():
                self._attributes[name.lower()] = (name, list(values))  # type: ignore[assignment]

        # Internal storage is actually dict[str_lower, tuple[original_name, list[str]]]
        # We re-type the internal structure properly
        self._attr_store: dict[str, tuple[str, list[str]]] = {}
        if attributes:
            for name, values in attributes.items():
                self._attr_store[name.lower()] = (name, list(values))

        # Reset _attributes — we use _attr_store instead
        self._attributes = {}  # unused, kept for clarity

    def get_attr(self, name: str) -> list[str]:
        """Get attribute values by name (case-insensitive).

        Args:
            name: Attribute name.

        Returns:
            List of attribute values, or empty list if not present.
        """
        entry = self._attr_store.get(name.lower())
        if entry is None:
            return []
        return list(entry[1])

    def get_attr_first(self, name: str) -> str | None:
        """Get the first value of an attribute, or None.

        Args:
            name: Attribute name.

        Returns:
            First value string, or None if attribute is absent or empty.
        """
        values = self.get_attr(name)
        return values[0] if values else None

    def set_attr(self, name: str, values: list[str]) -> None:
        """Set attribute values, replacing any existing values.

        Args:
            name: Attribute name.
            values: List of values to set.
        """
        key = name.lower()
        # Preserve original casing if already stored
        existing = self._attr_store.get(key)
        original_name = existing[0] if existing else name
        self._attr_store[key] = (original_name, list(values))
        self._touch()

    def add_attr_value(self, name: str, value: str) -> None:
        """Add a single value to a multi-valued attribute.

        If the attribute doesn't exist, it is created. Duplicate values
        are not added (case-insensitive comparison).

        Args:
            name: Attribute name.
            value: Value to add.
        """
        key = name.lower()
        existing = self._attr_store.get(key)
        if existing is None:
            self._attr_store[key] = (name, [value])
        else:
            original_name, current_values = existing
            # Check for duplicate (case-insensitive for string attrs)
            if value.lower() not in {v.lower() for v in current_values}:
                current_values.append(value)
        self._touch()

    def remove_attr_value(self, name: str, value: str) -> bool:
        """Remove a single value from a multi-valued attribute.

        Args:
            name: Attribute name.
            value: Value to remove (case-insensitive match).

        Returns:
            True if the value was found and removed, False otherwise.
        """
        key = name.lower()
        existing = self._attr_store.get(key)
        if existing is None:
            return False

        original_name, current_values = existing
        value_lower = value.lower()
        new_values = [v for v in current_values if v.lower() != value_lower]

        if len(new_values) == len(current_values):
            return False  # Nothing removed

        if new_values:
            self._attr_store[key] = (original_name, new_values)
        else:
            # Remove the attribute entirely if no values remain
            del self._attr_store[key]

        self._touch()
        return True

    def delete_attr(self, name: str) -> bool:
        """Delete an entire attribute.

        Args:
            name: Attribute name.

        Returns:
            True if the attribute existed and was deleted.
        """
        key = name.lower()
        if key in self._attr_store:
            del self._attr_store[key]
            self._touch()
            return True
        return False

    def has_attr(self, name: str) -> bool:
        """Check if an attribute exists on this entry.

        Args:
            name: Attribute name (case-insensitive).

        Returns:
            True if the attribute exists with at least one value.
        """
        entry = self._attr_store.get(name.lower())
        return entry is not None and len(entry[1]) > 0

    def has_object_class(self, cls: str) -> bool:
        """Check if this entry has a specific objectClass value.

        Args:
            cls: The objectClass name to check (case-insensitive).

        Returns:
            True if the objectClass is present.
        """
        oc_values = self.get_attr("objectClass")
        return cls.lower() in {v.lower() for v in oc_values}

    def matches_filter(self, filter_node: FilterNode) -> bool:
        """Test whether this entry matches an LDAP search filter.

        Args:
            filter_node: A parsed filter tree node.

        Returns:
            True if the entry matches the filter.
        """
        return filter_node.matches(self)

    def to_ldap_attributes(self) -> dict[str, list[str]]:
        """Convert entry attributes to a dict suitable for LDAP response.

        Returns original-cased attribute names as keys. Always includes
        ``distinguishedName`` with the entry's DN.

        Returns:
            Dict mapping attribute names to lists of string values.
        """
        result: dict[str, list[str]] = {}
        for _key, (original_name, values) in self._attr_store.items():
            result[original_name] = list(values)

        # Always include distinguishedName
        if "distinguishedname" not in self._attr_store:
            result["distinguishedName"] = [self.dn]

        return result

    def get_selected_attributes(self, requested: list[str]) -> dict[str, list[str]]:
        """Get only the requested attributes for an LDAP search response.

        If ``requested`` contains ``"*"`` or is empty, all attributes are returned.

        Args:
            requested: List of attribute names to return.

        Returns:
            Dict of selected attributes.
        """
        if not requested or "*" in requested:
            return self.to_ldap_attributes()

        result: dict[str, list[str]] = {}
        for attr_name in requested:
            key = attr_name.lower()
            if key == "distinguishedname" or key == "dn":
                result["distinguishedName"] = [self.dn]
            elif key in self._attr_store:
                original_name, values = self._attr_store[key]
                result[original_name] = list(values)

        return result

    @property
    def normalized_dn(self) -> str:
        """Return the normalized (lowercase) DN for comparison."""
        return normalize_dn(self.dn)

    def _touch(self) -> None:
        """Update the modified_at timestamp."""
        self.modified_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        oc = self.get_attr("objectClass")
        return f"LDAPEntry(dn={self.dn!r}, objectClass={oc!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LDAPEntry):
            return NotImplemented
        return normalize_dn(self.dn) == normalize_dn(other.dn)

    def __hash__(self) -> int:
        return hash(normalize_dn(self.dn))

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise the entry to a JSON-compatible dict.

        Returns:
            A dict with ``dn``, ``password``, and ``attributes`` keys.
        """
        attrs: dict[str, list[str]] = {}
        for _key, (original_name, values) in self._attr_store.items():
            attrs[original_name] = list(values)
        return {
            "dn": self.dn,
            "password": self.password,
            "attributes": attrs,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LDAPEntry":
        """Reconstruct an :class:`LDAPEntry` from a serialised dict.

        Args:
            data: Dict produced by :meth:`to_dict`.

        Returns:
            A new :class:`LDAPEntry` instance.
        """
        return cls(
            dn=data["dn"],
            attributes=data.get("attributes", {}),
            password=data.get("password"),
        )
