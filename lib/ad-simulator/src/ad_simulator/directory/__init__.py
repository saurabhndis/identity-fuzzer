"""Directory components for the AD Simulator.

Exports the core directory classes: DIT, LDAPEntry, filter parser, DN utilities,
and SearchScope enum.
"""

from ad_simulator.directory.dit import DirectoryInformationTree, SearchScope
from ad_simulator.directory.dn import dn_to_domain, normalize_dn, parent_dn, parse_dn, rdn
from ad_simulator.directory.entry import LDAPEntry
from ad_simulator.directory.filters import parse_filter

__all__ = [
    "DirectoryInformationTree",
    "SearchScope",
    "LDAPEntry",
    "parse_filter",
    "parse_dn",
    "normalize_dn",
    "dn_to_domain",
    "parent_dn",
    "rdn",
]
