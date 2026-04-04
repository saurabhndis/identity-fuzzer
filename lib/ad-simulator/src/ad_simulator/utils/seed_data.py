"""Seed data generator for the AD Simulator.

Populates an :class:`ADDomain` with a realistic Active Directory structure
including OUs, groups, users with realistic names, and group memberships.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ad_simulator.ad.domain import ADDomain

# Realistic first/last name pools
_FIRST_NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Eve",
    "Frank", "Grace", "Hank", "Irene", "Jack",
    "Karen", "Leo", "Mona", "Nick", "Olivia",
    "Paul", "Quinn", "Rachel", "Steve", "Tina",
    "Uma", "Victor", "Wendy", "Xavier", "Yolanda",
    "Zach", "Amber", "Brian", "Cathy", "Derek",
]

_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones",
    "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
    "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris",
    "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
]

# OU → list of group names that belong in that OU's functional area
_OU_GROUPS: dict[str, list[str]] = {
    "Engineering": ["Engineering"],
    "Sales": ["Sales"],
    "IT": ["IT Support"],
    "HR": ["HR Team"],
    "Management": [],
}

# Global groups (created under CN=Users, matching real AD convention)
_GLOBAL_GROUPS = ["VPN Users"]


def seed_directory(
    domain: ADDomain,
    num_users: int = 10,
    num_groups: int = 5,
) -> None:
    """Populate a domain with realistic seed data.

    Creates:
    - OUs: Engineering, Sales, IT, HR, Management
    - Groups: Domain Admins, VPN Users, Engineering, Sales, IT Support, HR Team
    - Users distributed across OUs with realistic names
    - Users assigned to appropriate groups
    - Service account ``svc-panos`` with password ``"paloalto"``

    Args:
        domain: The :class:`ADDomain` to populate (should already have
            :meth:`ADDomain.setup` called).
        num_users: Number of regular users to create.
        num_groups: Ignored (kept for API compatibility); the standard
            set of groups is always created.
    """
    om = domain.ou_manager
    gm = domain.group_manager
    um = domain.user_manager

    # 1. Create departmental OUs
    ou_names = list(_OU_GROUPS.keys())
    for ou_name in ou_names:
        om.create_ou(ou_name)

    # 2. Create global groups (in CN=Users, matching real AD convention)
    for group_name in _GLOBAL_GROUPS:
        gm.create_group(cn=group_name, ou="CN=Users")

    # 3. Create departmental groups
    for _ou, group_names in _OU_GROUPS.items():
        for group_name in group_names:
            gm.create_group(cn=group_name, ou="CN=Users")

    # 4. Create users distributed across OUs
    total_first = len(_FIRST_NAMES)
    total_last = len(_LAST_NAMES)

    for i in range(num_users):
        first = _FIRST_NAMES[i % total_first]
        last = _LAST_NAMES[i % total_last]
        cn = f"{first} {last}"
        sam = f"{first[0].lower()}{last.lower()}"

        # Distribute users across OUs round-robin
        ou_name = ou_names[i % len(ou_names)]
        ou_path = f"OU={ou_name}"

        email = f"{sam}@{domain.domain_name}"

        # Determine group memberships
        user_groups: list[str] = ["VPN Users"]
        # Add departmental group if one exists for this OU
        dept_groups = _OU_GROUPS.get(ou_name, [])
        user_groups.extend(dept_groups)

        # First user also gets Domain Admins
        if i == 0:
            user_groups.append("Domain Admins")

        um.create_user(
            cn=cn,
            sam_account_name=sam,
            password="password",  # noqa: S106
            ou=ou_path,
            groups=user_groups,
            email=email,
        )

    # 5. Ensure svc-panos service account exists with the expected password
    svc_pw = os.environ.get("AD_SIM_SVC_PASSWORD", "password")  # noqa: S105
    existing_svc = um.get_user("svc-panos")
    if existing_svc is None:
        um.create_user(
            cn="svc-panos",
            sam_account_name="svc-panos",
            password=svc_pw,
            ou="CN=Users",
        )
    else:
        # Update password to the seed-expected value
        um.set_password("svc-panos", svc_pw)
