"""LDAP fuzzer components for PAN-OS testing (Phase 4).

Exports generators, scenarios, engine, and result types for fuzz testing
the AD Simulator's LDAP directory against edge cases and adversarial inputs.
"""

from ad_simulator.fuzzer.engine import FuzzerEngine
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
from ad_simulator.fuzzer.scenarios import (
    FuzzResult,
    FuzzScenario,
    get_all_scenarios,
    get_scenario_by_name,
    get_scenarios_by_category,
    run_scenario,
)

__all__ = [
    "FuzzerEngine",
    "FuzzResult",
    "FuzzScenario",
    "generate_deeply_nested_filter",
    "generate_many_members",
    "generate_many_objectclasses",
    "generate_null_bytes_value",
    "generate_oversized_attribute",
    "generate_oversized_dn",
    "generate_special_chars_dn",
    "generate_unicode_value",
    "generate_wildcard_heavy_filter",
    "get_all_scenarios",
    "get_scenario_by_name",
    "get_scenarios_by_category",
    "run_scenario",
]
