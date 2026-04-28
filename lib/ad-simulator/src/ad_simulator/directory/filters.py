"""LDAP Search Filter Parser (RFC 4515).

Parses LDAP filter strings into a tree of FilterNode objects that can be
evaluated against LDAPEntry instances. Supports the filter types used by
PAN-OS LDAP client code:

- Equality:    ``(sAMAccountName=jdoe)``
- Substring:   ``(cn=test*)``
- Presence:    ``(objectClass=*)``
- AND:         ``(&(objectClass=user)(memberOf=CN=...))``
- OR:          ``(|(mail=...)(proxyAddresses=...))``
- NOT:         ``(!(userAccountControl=514))``
- GTE:         ``(whenChanged>=20240101000000.0Z)``
- LTE:         ``(userAccountControl<=512)``
- Extensible:  ``(userAccountControl:1.2.840.113556.1.4.803:=2)``
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ad_simulator.directory.entry import LDAPEntry


class FilterParseError(Exception):
    """Raised when an LDAP filter string cannot be parsed."""


# ---------------------------------------------------------------------------
# Filter Node hierarchy
# ---------------------------------------------------------------------------


class FilterNode(ABC):
    """Base class for LDAP search filter nodes."""

    @abstractmethod
    def matches(self, entry: LDAPEntry) -> bool:
        """Test whether an LDAP entry matches this filter.

        Args:
            entry: The LDAP entry to test.

        Returns:
            True if the entry matches.
        """

    @abstractmethod
    def __repr__(self) -> str: ...


class AndFilter(FilterNode):
    """Logical AND of multiple sub-filters: ``(&(f1)(f2)...)``."""

    def __init__(self, children: list[FilterNode]) -> None:
        self.children = children

    def matches(self, entry: LDAPEntry) -> bool:
        return all(child.matches(entry) for child in self.children)

    def __repr__(self) -> str:
        children_repr = "".join(repr(c) for c in self.children)
        return f"(&{children_repr})"


class OrFilter(FilterNode):
    """Logical OR of multiple sub-filters: ``(|(f1)(f2)...)``."""

    def __init__(self, children: list[FilterNode]) -> None:
        self.children = children

    def matches(self, entry: LDAPEntry) -> bool:
        return any(child.matches(entry) for child in self.children)

    def __repr__(self) -> str:
        children_repr = "".join(repr(c) for c in self.children)
        return f"(|{children_repr})"


class NotFilter(FilterNode):
    """Logical NOT of a single sub-filter: ``(!(f))``."""

    def __init__(self, child: FilterNode) -> None:
        self.child = child

    def matches(self, entry: LDAPEntry) -> bool:
        return not self.child.matches(entry)

    def __repr__(self) -> str:
        return f"(!{self.child!r})"


class EqualityFilter(FilterNode):
    """Equality match: ``(attr=value)``.

    Comparison is case-insensitive for both attribute name and value,
    matching AD behavior.
    """

    def __init__(self, attribute: str, value: str) -> None:
        self.attribute = attribute
        self.value = value

    def matches(self, entry: LDAPEntry) -> bool:
        # Special handling for DN attribute
        if self.attribute.lower() in ("dn", "distinguishedname"):
            from ad_simulator.directory.dn import normalize_dn

            return normalize_dn(entry.dn) == normalize_dn(self.value)

        values = entry.get_attr(self.attribute)
        target = self.value.lower()
        return any(v.lower() == target for v in values)

    def __repr__(self) -> str:
        return f"({self.attribute}={self.value})"


class SubstringFilter(FilterNode):
    """Substring match: ``(attr=init*any*final)``.

    Supports initial, any, and final substring components.
    """

    def __init__(
        self,
        attribute: str,
        initial: str | None = None,
        any_parts: list[str] | None = None,
        final: str | None = None,
    ) -> None:
        self.attribute = attribute
        self.initial = initial
        self.any_parts = any_parts or []
        self.final = final

    def matches(self, entry: LDAPEntry) -> bool:
        values = entry.get_attr(self.attribute)
        for val in values:
            if self._matches_value(val.lower()):
                return True
        return False

    def _matches_value(self, value: str) -> bool:
        """Test a single value against the substring pattern."""
        pos = 0

        if self.initial is not None:
            initial_lower = self.initial.lower()
            if not value.startswith(initial_lower):
                return False
            pos = len(initial_lower)

        for part in self.any_parts:
            part_lower = part.lower()
            idx = value.find(part_lower, pos)
            if idx < 0:
                return False
            pos = idx + len(part_lower)

        if self.final is not None:
            final_lower = self.final.lower()
            if not value.endswith(final_lower):
                return False
            # Ensure final doesn't overlap with what we've already matched
            if len(value) - len(final_lower) < pos:
                return False

        return True

    def __repr__(self) -> str:
        parts: list[str] = []
        if self.initial is not None:
            parts.append(self.initial)
        else:
            parts.append("")
        for p in self.any_parts:
            parts.append(p)
        if self.final is not None:
            parts.append(self.final)
        else:
            parts.append("")
        return f"({self.attribute}={'*'.join(parts)})"


class PresenceFilter(FilterNode):
    """Presence test: ``(attr=*)``.

    Matches if the attribute exists on the entry with any value.
    """

    def __init__(self, attribute: str) -> None:
        self.attribute = attribute

    def matches(self, entry: LDAPEntry) -> bool:
        # objectClass is always present on valid entries
        if self.attribute.lower() == "objectclass":
            return True
        return entry.has_attr(self.attribute)

    def __repr__(self) -> str:
        return f"({self.attribute}=*)"


class GreaterOrEqualFilter(FilterNode):
    """Greater-than-or-equal match: ``(attr>=value)``.

    Used by PAN-OS for incremental sync with ``whenChanged`` timestamps.
    Comparison is lexicographic (string-based), which works correctly
    for AD generalized time format ``20240101000000.0Z``.
    """

    def __init__(self, attribute: str, value: str) -> None:
        self.attribute = attribute
        self.value = value

    def matches(self, entry: LDAPEntry) -> bool:
        values = entry.get_attr(self.attribute)
        target = self.value.lower()
        return any(v.lower() >= target for v in values)

    def __repr__(self) -> str:
        return f"({self.attribute}>={self.value})"


class LessOrEqualFilter(FilterNode):
    """Less-than-or-equal match: ``(attr<=value)``."""

    def __init__(self, attribute: str, value: str) -> None:
        self.attribute = attribute
        self.value = value

    def matches(self, entry: LDAPEntry) -> bool:
        values = entry.get_attr(self.attribute)
        target = self.value.lower()
        return any(v.lower() <= target for v in values)

    def __repr__(self) -> str:
        return f"({self.attribute}<={self.value})"


class ExtensibleMatchFilter(FilterNode):
    """Extensible match filter: ``(attr:oid:=value)``.

    Supports the AD-specific bitwise matching rules used by PAN-OS:

    - ``1.2.840.113556.1.4.803`` — LDAP_MATCHING_RULE_BIT_AND
      True when ``(entry_value & assertion_value) == assertion_value``
    - ``1.2.840.113556.1.4.804`` — LDAP_MATCHING_RULE_BIT_OR
      True when ``(entry_value & assertion_value) != 0``

    For unrecognised OIDs the filter falls back to simple equality.
    """

    # AD bitwise matching rule OIDs
    LDAP_MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"
    LDAP_MATCHING_RULE_BIT_OR = "1.2.840.113556.1.4.804"

    def __init__(self, attribute: str, matching_rule: str, value: str, dn_flag: bool = False) -> None:
        self.attribute = attribute
        self.matching_rule = matching_rule
        self.value = value
        self.dn_flag = dn_flag

    def matches(self, entry: LDAPEntry) -> bool:
        values = entry.get_attr(self.attribute)
        if not values:
            return False

        try:
            assertion = int(self.value)
        except ValueError:
            # Non-integer value — fall back to equality
            target = self.value.lower()
            return any(v.lower() == target for v in values)

        for v in values:
            try:
                entry_val = int(v)
            except ValueError:
                continue

            if self.matching_rule == self.LDAP_MATCHING_RULE_BIT_AND:
                if (entry_val & assertion) == assertion:
                    return True
            elif self.matching_rule == self.LDAP_MATCHING_RULE_BIT_OR:
                if (entry_val & assertion) != 0:
                    return True
            else:
                # Unknown OID — treat as equality
                if entry_val == assertion:
                    return True

        return False

    def __repr__(self) -> str:
        dn_part = ":dn" if self.dn_flag else ""
        return f"({self.attribute}{dn_part}:{self.matching_rule}:={self.value})"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_filter(filter_string: str) -> FilterNode:
    """Parse an RFC 4515 LDAP search filter string into a FilterNode tree.

    Args:
        filter_string: The filter string, e.g. ``"(&(objectClass=user)(cn=test*))"``

    Returns:
        A FilterNode tree that can be evaluated against LDAPEntry objects.

    Raises:
        FilterParseError: If the filter string is malformed.
    """
    filter_string = filter_string.strip()
    if not filter_string:
        raise FilterParseError("Empty filter string")

    node, pos = _parse_filter_expr(filter_string, 0)

    if pos != len(filter_string):
        raise FilterParseError(
            f"Unexpected content after filter at position {pos}: "
            f"{filter_string[pos:]!r}"
        )

    return node


def _parse_filter_expr(s: str, pos: int) -> tuple[FilterNode, int]:
    """Parse a single filter expression starting at pos.

    A filter expression is always wrapped in parentheses: ``(content)``.
    """
    if pos >= len(s):
        raise FilterParseError("Unexpected end of filter string")

    if s[pos] != "(":
        raise FilterParseError(
            f"Expected '(' at position {pos}, got {s[pos]!r}"
        )

    pos += 1  # skip '('

    if pos >= len(s):
        raise FilterParseError("Unexpected end of filter after '('")

    ch = s[pos]

    if ch == "&":
        node, pos = _parse_composite(s, pos + 1, "and")
    elif ch == "|":
        node, pos = _parse_composite(s, pos + 1, "or")
    elif ch == "!":
        node, pos = _parse_not(s, pos + 1)
    else:
        node, pos = _parse_simple(s, pos)

    if pos >= len(s) or s[pos] != ")":
        raise FilterParseError(
            f"Expected ')' at position {pos}"
        )

    pos += 1  # skip ')'
    return node, pos


def _parse_composite(s: str, pos: int, op: str) -> tuple[FilterNode, int]:
    """Parse AND or OR composite filter: children until closing ')'."""
    children: list[FilterNode] = []

    while pos < len(s) and s[pos] == "(":
        child, pos = _parse_filter_expr(s, pos)
        children.append(child)

    if not children:
        raise FilterParseError(f"Empty {op.upper()} filter — no children")

    if op == "and":
        return AndFilter(children), pos
    else:
        return OrFilter(children), pos


def _parse_not(s: str, pos: int) -> tuple[FilterNode, int]:
    """Parse NOT filter: exactly one child."""
    if pos >= len(s) or s[pos] != "(":
        raise FilterParseError(f"Expected '(' after '!' at position {pos}")

    child, pos = _parse_filter_expr(s, pos)
    return NotFilter(child), pos


# Regex for extensible match: attr[:dn]:matchingRule:=value
_EXTENSIBLE_RE = re.compile(
    r"^(?P<attr>[a-zA-Z][a-zA-Z0-9-]*)"       # attribute name
    r"(?P<dn>:dn)?"                             # optional :dn flag
    r":(?P<oid>[0-9]+(?:\.[0-9]+)*)"            # :matchingRuleOID
    r":=(?P<value>.*)$"                         # :=assertionValue
)


def _parse_simple(s: str, pos: int) -> tuple[FilterNode, int]:
    """Parse a simple (non-composite) filter: equality, substring, presence,
    GTE, LTE, or extensible match."""
    # Find the closing ')' — but handle escaped characters
    end = _find_closing_paren_content(s, pos)
    content = s[pos:end]

    # Check for extensible match first: attr:OID:=value
    # Must be checked before ':=' is misinterpreted by other branches
    ext_match = _EXTENSIBLE_RE.match(content)
    if ext_match:
        return ExtensibleMatchFilter(
            attribute=ext_match.group("attr"),
            matching_rule=ext_match.group("oid"),
            value=ext_match.group("value"),
            dn_flag=ext_match.group("dn") is not None,
        ), end

    # Check for >= (greaterOrEqual)
    gte_idx = content.find(">=")
    if gte_idx > 0:
        attr = content[:gte_idx]
        value = content[gte_idx + 2:]
        return GreaterOrEqualFilter(attr, value), end

    # Check for <= (lessOrEqual)
    lte_idx = content.find("<=")
    if lte_idx > 0:
        attr = content[:lte_idx]
        value = content[lte_idx + 2:]
        return LessOrEqualFilter(attr, value), end

    # Check for ~= (approxMatch) — treat as equality
    approx_idx = content.find("~=")
    if approx_idx > 0:
        attr = content[:approx_idx]
        value = content[approx_idx + 2:]
        return EqualityFilter(attr, value), end

    # Must be = (equality, substring, or presence)
    eq_idx = content.find("=")
    if eq_idx < 0:
        raise FilterParseError(f"No operator found in filter item: {content!r}")

    attr = content[:eq_idx]
    value = content[eq_idx + 1:]

    if not attr:
        raise FilterParseError(f"Empty attribute name in filter: {content!r}")

    # Presence filter: (attr=*)
    if value == "*":
        return PresenceFilter(attr), end

    # Substring filter: contains '*'
    if "*" in value:
        return _parse_substring(attr, value), end

    # Simple equality
    return EqualityFilter(attr, value), end


def _find_closing_paren_content(s: str, pos: int) -> int:
    """Find the end position of simple filter content (before the closing ')')."""
    i = pos
    while i < len(s):
        if s[i] == ")":
            return i
        if s[i] == "\\" and i + 1 < len(s):
            i += 2  # skip escaped char
        else:
            i += 1
    raise FilterParseError(f"Unterminated filter starting at position {pos}")


def _parse_substring(attr: str, value: str) -> SubstringFilter:
    """Parse a substring filter value like ``init*any*final``."""
    parts = value.split("*")

    # parts[0] is initial (empty string if value starts with *)
    # parts[-1] is final (empty string if value ends with *)
    # parts[1:-1] are 'any' components

    initial: str | None = parts[0] if parts[0] else None
    final: str | None = parts[-1] if parts[-1] else None
    any_parts = [p for p in parts[1:-1] if p]

    return SubstringFilter(attr, initial=initial, any_parts=any_parts, final=final)
