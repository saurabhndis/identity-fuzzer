"""Predefined fuzz scenarios for the AD Simulator.

Each scenario exercises an edge case or adversarial condition that may
reveal bugs in LDAP consumers such as PAN-OS User-ID agents.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from ad_simulator.fuzzer.generators import (
    generate_deeply_nested_filter,
    generate_many_members,
    generate_many_objectclasses,
    generate_null_bytes_value,
    generate_oversized_attribute,
    generate_oversized_dn,
    generate_special_chars_dn,
    generate_unicode_value,
    generate_wildcard_heavy_filter,
)

if TYPE_CHECKING:
    from ad_simulator.ad.domain import ADDomain


@dataclass
class FuzzResult:
    """Result of running a single fuzz scenario.

    Attributes:
        scenario_name: Name of the scenario that was run.
        success: Whether the scenario completed without errors.
        details: Human-readable description of the outcome.
        duration_ms: Wall-clock time in milliseconds.
        error: Optional exception message if the scenario failed.
    """

    scenario_name: str
    success: bool
    details: str
    duration_ms: float
    error: str | None = None


@dataclass
class FuzzScenario:
    """A predefined fuzz test scenario.

    Attributes:
        name: Short identifier for the scenario.
        description: Human-readable description of what the scenario tests.
        category: Category grouping (e.g. ``"protocol"``, ``"data"``, ``"membership"``).
        setup_fn: Callable that sets up the scenario on a domain.
        verify_fn: Optional callable that verifies the result.
    """

    name: str
    description: str
    category: str
    setup_fn: Callable[[ADDomain], str]
    verify_fn: Callable[[ADDomain], bool] | None = None


# ---------------------------------------------------------------------------
# Scenario setup functions
# ---------------------------------------------------------------------------


def _setup_oversized_dn(domain: ADDomain) -> str:
    """Create a user with a 4096+ character DN."""
    long_dn = generate_oversized_dn(4096)
    from ad_simulator.directory.entry import LDAPEntry

    entry = LDAPEntry(
        dn=long_dn,
        attributes={
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": ["oversized-dn-user"],
            "sAMAccountName": ["oversized-dn-user"],
            "distinguishedName": [long_dn],
        },
    )
    domain.dit.add_entry(entry)
    return f"Created entry with DN length {len(long_dn)}"


def _setup_unicode_attributes(domain: ADDomain) -> str:
    """Create users with unicode names and attributes."""
    unicode_cn = generate_unicode_value(30)
    domain.user_manager.create_user(
        cn=unicode_cn,
        sam_account_name="unicode-user",
        password="password",
        extra_attrs={
            "description": [generate_unicode_value(100)],
            "displayName": [generate_unicode_value(50)],
        },
    )
    return f"Created user with unicode CN: {unicode_cn[:20]}..."


def _setup_null_bytes(domain: ADDomain) -> str:
    """Create attributes containing null bytes."""
    null_value = generate_null_bytes_value(50)
    domain.user_manager.create_user(
        cn="null-bytes-user",
        sam_account_name="null-bytes-user",
        password="password",
        extra_attrs={
            "description": [null_value],
        },
    )
    return f"Created user with null bytes in description (length {len(null_value)})"


def _setup_oversized_group_membership(domain: ADDomain) -> str:
    """Create a group with 10K+ members."""
    group = domain.group_manager.create_group(cn="fuzz-large-group", ou="CN=Users")
    members = generate_many_members(10000)
    # Directly set the member attribute to avoid creating 10K user entries
    group.set_attr("member", members)
    return f"Created group with {len(members)} members"


def _setup_deeply_nested_groups(domain: ADDomain) -> str:
    """Create a 20-level nested group chain."""
    groups = domain.group_manager.create_nested_groups(
        depth=20, base_name="fuzz-nested"
    )
    return f"Created {len(groups)} nested groups"


def _setup_empty_group_name(domain: ADDomain) -> str:
    """Create a group with an empty CN."""
    from ad_simulator.directory.entry import LDAPEntry

    dn = f"CN=,CN=Users,{domain.base_dn}"
    entry = LDAPEntry(
        dn=dn,
        attributes={
            "objectClass": ["top", "group"],
            "cn": [""],
            "name": [""],
            "distinguishedName": [dn],
        },
    )
    domain.dit.add_entry(entry)
    return "Created group with empty CN"


def _setup_special_chars_dn(domain: ADDomain) -> str:
    """Create an entry with special LDAP characters in the DN."""
    special_dn = generate_special_chars_dn()
    from ad_simulator.directory.entry import LDAPEntry

    entry = LDAPEntry(
        dn=special_dn,
        attributes={
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": [r"test\+user\=1\<2\>3\#4\;5"],
            "sAMAccountName": ["special-chars-user"],
            "distinguishedName": [special_dn],
        },
    )
    domain.dit.add_entry(entry)
    return f"Created entry with special chars DN: {special_dn}"


def _setup_many_objectclasses(domain: ADDomain) -> str:
    """Create an entry with 50+ objectClass values."""
    classes = generate_many_objectclasses(50)
    from ad_simulator.directory.entry import LDAPEntry

    dn = f"CN=many-oc-user,CN=Users,{domain.base_dn}"
    entry = LDAPEntry(
        dn=dn,
        attributes={
            "objectClass": classes,
            "cn": ["many-oc-user"],
            "sAMAccountName": ["many-oc-user"],
            "distinguishedName": [dn],
        },
    )
    domain.dit.add_entry(entry)
    return f"Created entry with {len(classes)} objectClass values"


def _setup_duplicate_members(domain: ADDomain) -> str:
    """Create a group with duplicate member entries."""
    group = domain.group_manager.create_group(cn="fuzz-dup-members", ou="CN=Users")
    dup_dn = f"CN=dupuser,CN=Users,{domain.base_dn}"
    # Add the same member multiple times directly
    group.set_attr("member", [dup_dn, dup_dn, dup_dn])
    return f"Created group with 3 duplicate member entries for {dup_dn}"


def _setup_circular_group_membership(domain: ADDomain) -> str:
    """Create circular group membership: A → B → A."""
    group_a = domain.group_manager.create_group(cn="fuzz-circular-A", ou="CN=Users")
    group_b = domain.group_manager.create_group(cn="fuzz-circular-B", ou="CN=Users")
    # A contains B
    domain.group_manager.add_member("fuzz-circular-A", group_b.dn)
    # B contains A (circular)
    domain.group_manager.add_member("fuzz-circular-B", group_a.dn)
    return "Created circular group membership: A → B → A"


def _setup_very_long_attribute_value(domain: ADDomain) -> str:
    """Create an entry with a 64KB+ attribute value."""
    big_value = generate_oversized_attribute(64)
    domain.user_manager.create_user(
        cn="big-attr-user",
        sam_account_name="big-attr-user",
        password="password",
        extra_attrs={
            "description": [big_value],
        },
    )
    return f"Created user with {len(big_value)} byte description"


def _setup_many_groups_per_user(domain: ADDomain) -> str:
    """Create a user that belongs to 500+ groups."""
    user = domain.user_manager.create_user(
        cn="many-groups-user",
        sam_account_name="many-groups-user",
        password="password",
    )
    # Create groups and add user to each
    group_dns: list[str] = []
    for i in range(500):
        group = domain.group_manager.create_group(
            cn=f"fuzz-mg-{i:04d}", ou="CN=Users"
        )
        group.add_attr_value("member", user.dn)
        group_dns.append(group.dn)
    # Set memberOf on the user directly for efficiency
    user.set_attr("memberOf", group_dns)
    return f"Created user in {len(group_dns)} groups"


def _setup_empty_search_base(domain: ADDomain) -> str:
    """Attempt a search with an empty base DN."""
    from ad_simulator.directory.dit import SearchScope
    from ad_simulator.directory.filters import parse_filter

    filter_node = parse_filter("(objectClass=*)")
    results = domain.dit.search("", SearchScope.SUBTREE, filter_node)
    return f"Search with empty base returned {len(results)} results"


def _setup_wildcard_heavy_filter(domain: ADDomain) -> str:
    """Execute a filter with many wildcards."""
    filter_str = generate_wildcard_heavy_filter()
    from ad_simulator.directory.dit import SearchScope
    from ad_simulator.directory.filters import parse_filter

    filter_node = parse_filter(filter_str)
    results = domain.dit.search(domain.base_dn, SearchScope.SUBTREE, filter_node)
    return f"Wildcard filter '{filter_str}' returned {len(results)} results"


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

_SCENARIOS: list[FuzzScenario] = [
    FuzzScenario(
        name="oversized_dn",
        description="Create user with 4096+ character DN",
        category="protocol",
        setup_fn=_setup_oversized_dn,
    ),
    FuzzScenario(
        name="unicode_attributes",
        description="Users with unicode names/attributes (CJK, Arabic, emoji)",
        category="data",
        setup_fn=_setup_unicode_attributes,
    ),
    FuzzScenario(
        name="null_bytes_in_values",
        description="Attributes containing embedded null bytes",
        category="data",
        setup_fn=_setup_null_bytes,
    ),
    FuzzScenario(
        name="oversized_group_membership",
        description="Group with 10K+ members",
        category="membership",
        setup_fn=_setup_oversized_group_membership,
    ),
    FuzzScenario(
        name="deeply_nested_groups",
        description="20-level nested group chain",
        category="membership",
        setup_fn=_setup_deeply_nested_groups,
    ),
    FuzzScenario(
        name="empty_group_name",
        description="Group with empty CN",
        category="data",
        setup_fn=_setup_empty_group_name,
    ),
    FuzzScenario(
        name="special_chars_in_dn",
        description="DN with special LDAP characters (=, +, <, >, #, ;, \\)",
        category="protocol",
        setup_fn=_setup_special_chars_dn,
    ),
    FuzzScenario(
        name="many_objectclasses",
        description="Entry with 50+ objectClass values",
        category="data",
        setup_fn=_setup_many_objectclasses,
    ),
    FuzzScenario(
        name="duplicate_members",
        description="Group with duplicate member entries",
        category="membership",
        setup_fn=_setup_duplicate_members,
    ),
    FuzzScenario(
        name="circular_group_membership",
        description="Circular group membership: A → B → A",
        category="membership",
        setup_fn=_setup_circular_group_membership,
    ),
    FuzzScenario(
        name="very_long_attribute_value",
        description="64KB+ attribute value",
        category="data",
        setup_fn=_setup_very_long_attribute_value,
    ),
    FuzzScenario(
        name="many_groups_per_user",
        description="User in 500+ groups (large memberOf)",
        category="membership",
        setup_fn=_setup_many_groups_per_user,
    ),
    FuzzScenario(
        name="empty_search_base",
        description="Search with empty base DN",
        category="protocol",
        setup_fn=_setup_empty_search_base,
    ),
    FuzzScenario(
        name="wildcard_heavy_filter",
        description="Filter with many wildcards: (cn=*a*b*c*d*e*)",
        category="protocol",
        setup_fn=_setup_wildcard_heavy_filter,
    ),
]


def get_all_scenarios() -> list[FuzzScenario]:
    """Return all registered fuzz scenarios.

    Returns:
        A list of :class:`FuzzScenario` objects.
    """
    return list(_SCENARIOS)


def get_scenario_by_name(name: str) -> FuzzScenario | None:
    """Look up a scenario by its name.

    Args:
        name: The scenario name (e.g. ``"oversized_dn"``).

    Returns:
        The :class:`FuzzScenario` if found, or ``None``.
    """
    for s in _SCENARIOS:
        if s.name == name:
            return s
    return None


def get_scenarios_by_category(category: str) -> list[FuzzScenario]:
    """Return all scenarios in a given category.

    Args:
        category: The category to filter by (e.g. ``"protocol"``).

    Returns:
        A list of matching :class:`FuzzScenario` objects.
    """
    return [s for s in _SCENARIOS if s.category == category]


def run_scenario(scenario: FuzzScenario, domain: ADDomain) -> FuzzResult:
    """Execute a single fuzz scenario against a domain.

    Creates a fresh domain context and runs the scenario's setup function.

    Args:
        scenario: The scenario to run.
        domain: The :class:`ADDomain` to run against.

    Returns:
        A :class:`FuzzResult` with success/failure and timing information.
    """
    start = time.monotonic()
    try:
        details = scenario.setup_fn(domain)
        duration_ms = (time.monotonic() - start) * 1000

        # Run verify if present
        if scenario.verify_fn is not None:
            verified = scenario.verify_fn(domain)
            if not verified:
                return FuzzResult(
                    scenario_name=scenario.name,
                    success=False,
                    details=f"{details} — verification failed",
                    duration_ms=duration_ms,
                    error="Verification function returned False",
                )

        return FuzzResult(
            scenario_name=scenario.name,
            success=True,
            details=details,
            duration_ms=duration_ms,
        )
    except Exception as exc:
        duration_ms = (time.monotonic() - start) * 1000
        return FuzzResult(
            scenario_name=scenario.name,
            success=False,
            details=f"Exception: {exc}",
            duration_ms=duration_ms,
            error=str(exc),
        )
