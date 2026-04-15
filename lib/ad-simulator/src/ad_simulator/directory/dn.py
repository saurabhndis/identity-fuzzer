"""Distinguished Name (DN) parsing and manipulation utilities.

Handles the RFC 4514 DN format used by Microsoft Active Directory:
    CN=John Doe,CN=Users,DC=testlab,DC=local

All comparison operations are case-insensitive to match AD behavior.
"""

from __future__ import annotations

import re


def parse_dn(dn_string: str) -> list[tuple[str, str, str]]:
    """Parse a DN string into a list of (attribute, value, separator) tuples.

    Args:
        dn_string: A distinguished name string, e.g. ``"CN=John Doe,CN=Users,DC=testlab,DC=local"``.

    Returns:
        A list of ``(attr, value, separator)`` tuples. The separator is ``","``
        between components and ``""`` for the last component.
        Returns an empty list for empty/whitespace-only input.

    Examples:
        >>> parse_dn("CN=John Doe,CN=Users,DC=testlab,DC=local")
        [('CN', 'John Doe', ','), ('CN', 'Users', ','), ('DC', 'testlab', ','), ('DC', 'local', '')]
        >>> parse_dn("")
        []
    """
    dn_string = dn_string.strip()
    if not dn_string:
        return []

    result: list[tuple[str, str, str]] = []

    # Split on commas that are not escaped
    # AD DNs use backslash-escaping for special chars: \, \+ \; etc.
    components = _split_dn(dn_string)

    for i, component in enumerate(components):
        component = component.strip()
        if not component:
            continue

        eq_pos = component.find("=")
        if eq_pos < 0:
            # Malformed component — treat entire thing as CN value
            attr = "CN"
            value = component
        else:
            attr = component[:eq_pos].strip()
            value = component[eq_pos + 1:].strip()

        separator = "," if i < len(components) - 1 else ""
        result.append((attr, value, separator))

    return result


def _split_dn(dn_string: str) -> list[str]:
    """Split a DN string on unescaped commas.

    Handles backslash-escaped commas (``\\,``) within attribute values.
    """
    components: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(dn_string):
        ch = dn_string[i]
        if ch == "\\" and i + 1 < len(dn_string):
            # Escaped character — consume both
            current.append(ch)
            current.append(dn_string[i + 1])
            i += 2
        elif ch == ",":
            components.append("".join(current))
            current = []
            i += 1
        else:
            current.append(ch)
            i += 1

    if current:
        components.append("".join(current))

    return components


def normalize_dn(dn_string: str) -> str:
    """Normalize a DN to a canonical lowercase form for comparison.

    Lowercases attribute names and values, trims whitespace around ``=`` and ``,``.

    Args:
        dn_string: The DN string to normalize.

    Returns:
        A normalized, lowercase DN string.

    Examples:
        >>> normalize_dn("CN=John Doe,CN=Users,DC=TestLab,DC=Local")
        'cn=john doe,cn=users,dc=testlab,dc=local'
        >>> normalize_dn("")
        ''
    """
    parts = parse_dn(dn_string)
    if not parts:
        return ""

    components: list[str] = []
    for attr, value, _ in parts:
        components.append(f"{attr.lower()}={value.lower()}")

    return ",".join(components)


def dn_to_domain(dn_string: str) -> str:
    """Extract the domain name from DC components of a DN.

    Args:
        dn_string: A DN string containing DC components.

    Returns:
        A dotted domain name, e.g. ``"testlab.local"``.
        Returns an empty string if no DC components are found.

    Examples:
        >>> dn_to_domain("CN=John Doe,CN=Users,DC=testlab,DC=local")
        'testlab.local'
        >>> dn_to_domain("CN=Users")
        ''
    """
    parts = parse_dn(dn_string)
    dc_values = [value for attr, value, _ in parts if attr.upper() == "DC"]
    return ".".join(dc_values)


def parent_dn(dn_string: str) -> str:
    """Get the parent DN by removing the first (leftmost) RDN component.

    Args:
        dn_string: A DN string.

    Returns:
        The parent DN string, or an empty string if the DN has zero or one component.

    Examples:
        >>> parent_dn("CN=John Doe,CN=Users,DC=testlab,DC=local")
        'CN=Users,DC=testlab,DC=local'
        >>> parent_dn("DC=local")
        ''
    """
    parts = parse_dn(dn_string)
    if len(parts) <= 1:
        return ""

    # Reconstruct from the second component onward
    components: list[str] = []
    for attr, value, _ in parts[1:]:
        components.append(f"{attr}={value}")

    return ",".join(components)


def rdn(dn_string: str) -> str:
    """Get the first (leftmost) Relative Distinguished Name component.

    Args:
        dn_string: A DN string.

    Returns:
        The first RDN as ``"ATTR=value"``, or an empty string if the DN is empty.

    Examples:
        >>> rdn("CN=John Doe,CN=Users,DC=testlab,DC=local")
        'CN=John Doe'
        >>> rdn("")
        ''
    """
    parts = parse_dn(dn_string)
    if not parts:
        return ""

    attr, value, _ = parts[0]
    return f"{attr}={value}"


def is_descendant_of(child_dn: str, ancestor_dn: str) -> bool:
    """Check if child_dn is a descendant of (or equal to) ancestor_dn.

    Comparison is case-insensitive.

    Args:
        child_dn: The potential descendant DN.
        ancestor_dn: The potential ancestor DN.

    Returns:
        True if child_dn ends with ancestor_dn (case-insensitive).
    """
    child_norm = normalize_dn(child_dn)
    ancestor_norm = normalize_dn(ancestor_dn)

    if not ancestor_norm:
        return True  # Everything is under the empty root

    if child_norm == ancestor_norm:
        return True

    return child_norm.endswith("," + ancestor_norm)


def is_direct_child_of(child_dn: str, parent_dn_str: str) -> bool:
    """Check if child_dn is a direct child (one level below) parent_dn.

    Args:
        child_dn: The potential child DN.
        parent_dn_str: The potential parent DN.

    Returns:
        True if the parent of child_dn equals parent_dn_str (case-insensitive).
    """
    actual_parent = normalize_dn(parent_dn(child_dn))
    expected_parent = normalize_dn(parent_dn_str)
    return actual_parent == expected_parent
