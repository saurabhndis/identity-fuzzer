"""Fuzz data generators for the AD Simulator.

Produces adversarial, edge-case, and stress-test data for LDAP protocol
testing against PAN-OS and other LDAP consumers.
"""

from __future__ import annotations

import random
import string


def generate_oversized_dn(length: int = 4096) -> str:
    """Generate a very long Distinguished Name string.

    Creates a chain of ``OU=xxxx`` components until the total DN length
    exceeds *length* characters.

    Args:
        length: Minimum total length of the resulting DN string.

    Returns:
        A DN string of at least *length* characters.
    """
    parts: list[str] = []
    current_length = 0
    i = 0
    while current_length < length:
        ou_name = f"ou{i:06d}_{'x' * 50}"
        part = f"OU={ou_name}"
        parts.append(part)
        current_length += len(part) + 1  # +1 for comma
        i += 1
    parts.append("DC=testlab,DC=local")
    return ",".join(parts)


def generate_unicode_value(length: int = 100) -> str:
    """Generate a string with mixed unicode characters.

    Includes Latin, CJK, Arabic, Cyrillic, and emoji characters.

    Args:
        length: Approximate length of the resulting string.

    Returns:
        A string containing diverse unicode characters.
    """
    pools = [
        # CJK Unified Ideographs
        [chr(c) for c in range(0x4E00, 0x4E00 + 20)],
        # Arabic
        [chr(c) for c in range(0x0621, 0x0621 + 20)],
        # Cyrillic
        [chr(c) for c in range(0x0410, 0x0410 + 20)],
        # Emoji
        [chr(c) for c in range(0x1F600, 0x1F600 + 20)],
        # Latin Extended
        [chr(c) for c in range(0x00C0, 0x00C0 + 20)],
        # Devanagari
        [chr(c) for c in range(0x0905, 0x0905 + 20)],
    ]
    result: list[str] = []
    for i in range(length):
        pool = pools[i % len(pools)]
        result.append(random.choice(pool))
    return "".join(result)


def generate_null_bytes_value(length: int = 50) -> str:
    """Generate a string with embedded null bytes.

    Alternates between printable ASCII characters and null bytes.

    Args:
        length: Total length of the resulting string.

    Returns:
        A string containing embedded ``\\x00`` characters.
    """
    result: list[str] = []
    for i in range(length):
        if i % 5 == 0:
            result.append("\x00")
        else:
            result.append(random.choice(string.ascii_letters))
    return "".join(result)


def generate_oversized_attribute(size_kb: int = 64) -> str:
    """Generate a very large attribute value.

    Args:
        size_kb: Size of the value in kilobytes.

    Returns:
        A string of approximately *size_kb* × 1024 characters.
    """
    return "A" * (size_kb * 1024)


def generate_many_members(count: int = 10000) -> list[str]:
    """Generate a list of fake member DNs.

    Args:
        count: Number of member DNs to generate.

    Returns:
        A list of DN strings like ``CN=user0001,CN=Users,DC=testlab,DC=local``.
    """
    return [
        f"CN=fuzzuser{i:06d},CN=Users,DC=testlab,DC=local"
        for i in range(count)
    ]


def generate_deeply_nested_filter(depth: int = 50) -> str:
    """Generate a deeply nested LDAP filter string.

    Creates nested ``(&(...))`` filters to stress-test filter parsers.

    Args:
        depth: Number of nesting levels.

    Returns:
        A deeply nested LDAP filter string.
    """
    # Build from inside out
    inner = "(cn=test)"
    for _ in range(depth):
        inner = f"(&{inner}(objectClass=*))"
    return inner


def generate_special_chars_dn() -> str:
    """Generate a DN containing special LDAP characters.

    Includes characters that require escaping in LDAP DNs:
    ``=``, ``+``, ``<``, ``>``, ``#``, ``;``, ``\\``, and commas.

    Returns:
        A DN string with special characters in the CN value.
    """
    special_cn = r"test\+user\=1\<2\>3\#4\;5"
    return f"CN={special_cn},CN=Users,DC=testlab,DC=local"


def generate_wildcard_heavy_filter() -> str:
    """Generate an LDAP filter with many wildcard patterns.

    Returns:
        A filter string like ``(cn=*a*b*c*d*e*)``.
    """
    chars = list(string.ascii_lowercase[:10])
    pattern = "*".join(chars)
    return f"(cn=*{pattern}*)"


def generate_many_objectclasses(count: int = 50) -> list[str]:
    """Generate a list of many objectClass values.

    Args:
        count: Number of objectClass values to generate.

    Returns:
        A list of objectClass strings.
    """
    base_classes = ["top", "person", "organizationalPerson", "user"]
    extra = [f"auxClass{i:03d}" for i in range(count - len(base_classes))]
    return base_classes + extra
