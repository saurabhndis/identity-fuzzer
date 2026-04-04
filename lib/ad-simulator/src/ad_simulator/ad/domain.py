"""AD Domain setup and orchestration for the AD Simulator.

Provides the top-level :class:`ADDomain` class that wires together the
directory tree, OU/user/group managers, and creates the default Active
Directory structure (containers, OUs, built-in accounts).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from ad_simulator.ad.groups import GroupManager
from ad_simulator.ad.ous import OUManager
from ad_simulator.ad.users import UserManager
from ad_simulator.directory.dit import DirectoryInformationTree, SearchScope
from ad_simulator.directory.entry import LDAPEntry
from ad_simulator.directory.filters import parse_filter


def _ad_timestamp() -> str:
    """Return the current time in AD generalized time format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S.0Z")


def _domain_to_base_dn(domain_name: str) -> str:
    """Convert a dotted domain name to a base DN.

    Example:
        >>> _domain_to_base_dn("testlab.local")
        'DC=testlab,DC=local'
    """
    parts = domain_name.split(".")
    return ",".join(f"DC={p}" for p in parts)


class ADDomain:
    """Represents a simulated Active Directory domain.

    Orchestrates the directory tree and the OU, user, and group managers.
    Call :meth:`setup` to populate the default AD structure (domain root,
    standard containers, built-in admin account, service account).

    Attributes:
        domain_name: The DNS domain name (e.g. ``"testlab.local"``).
        base_dn: The base Distinguished Name derived from the domain name.
        dit: The underlying :class:`DirectoryInformationTree`.
        ou_manager: Manager for Organizational Units.
        user_manager: Manager for user accounts.
        group_manager: Manager for security/distribution groups.
    """

    def __init__(
        self,
        domain_name: str = "testlab.local",
        dit: DirectoryInformationTree | None = None,
    ) -> None:
        self.domain_name = domain_name
        self.base_dn = _domain_to_base_dn(domain_name)
        self.dit = dit if dit is not None else DirectoryInformationTree()

        # Managers
        self.ou_manager = OUManager(self.dit, self.base_dn)
        self.group_manager = GroupManager(self.dit, self.base_dn, self.domain_name)
        self.user_manager = UserManager(self.dit, self.base_dn, self.domain_name)

        # Wire up cross-references
        self.user_manager.set_group_manager(self.group_manager)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Create the default AD domain structure.

        Populates the directory with the standard containers, OUs,
        built-in accounts, and groups that a real Microsoft Active
        Directory domain controller creates during ``dcpromo``.

        This includes:
        - Domain root entry
        - Standard CN containers (Users, Computers, Builtin,
          ForeignSecurityPrincipals, Managed Service Accounts,
          Program Data, System, NTDS Quotas, Keys,
          Infrastructure, LostAndFound)
        - Standard OUs (Domain Controllers)
        - Built-in user accounts (Administrator, Guest, krbtgt)
        - Built-in security groups (Domain Admins, Domain Users,
          Domain Computers, Domain Controllers, Domain Guests,
          Enterprise Admins, Schema Admins, Administrators,
          Account Operators, Backup Operators, Print Operators,
          Server Operators, Remote Desktop Users, etc.)
        - Default service account for PAN-OS testing
        """
        now = _ad_timestamp()

        # ── 1. Domain root entry ──────────────────────────────────────
        root_entry = LDAPEntry(
            dn=self.base_dn,
            attributes={
                "objectClass": ["top", "domain", "domainDNS"],
                "dc": [self.domain_name.split(".")[0]],
                "distinguishedName": [self.base_dn],
                "name": [self.domain_name.split(".")[0]],
                "whenCreated": [now],
                "whenChanged": [now],
            },
        )
        self.dit.add_entry(root_entry)

        # ── 2. Standard CN containers (matches real AD) ──────────────
        standard_containers = [
            "Users",
            "Computers",
            "Builtin",
            "ForeignSecurityPrincipals",
            "Managed Service Accounts",
            "Program Data",
            "System",
            "NTDS Quotas",
            "Keys",
            "Infrastructure",
            "LostAndFound",
        ]
        for container_name in standard_containers:
            container_dn = f"CN={container_name},{self.base_dn}"
            container = LDAPEntry(
                dn=container_dn,
                attributes={
                    "objectClass": ["top", "container"],
                    "cn": [container_name],
                    "name": [container_name],
                    "distinguishedName": [container_dn],
                    "description": [f"Default container for {container_name}"],
                    "whenCreated": [now],
                    "whenChanged": [now],
                },
            )
            self.dit.add_entry(container)

        # ── 3. Standard OUs ───────────────────────────────────────────
        self.ou_manager.create_ou("Domain Controllers")

        # ── 4. Built-in user accounts ─────────────────────────────────
        admin_pw = os.environ.get("AD_SIM_ADMIN_PASSWORD", "password")  # noqa: S105
        self.user_manager.create_user(
            cn="Administrator",
            sam_account_name="Administrator",
            password=admin_pw,
            ou="CN=Users",
        )
        self.user_manager.create_user(
            cn="Guest",
            sam_account_name="Guest",
            password="",
            ou="CN=Users",
        )
        self.user_manager.create_user(
            cn="krbtgt",
            sam_account_name="krbtgt",
            password="krbtgt-disabled",
            ou="CN=Users",
        )

        # ── 5. Built-in domain security groups (CN=Users) ─────────────
        domain_groups = [
            ("Domain Admins", "Designated administrators of the domain"),
            ("Domain Users", "All domain users"),
            ("Domain Computers", "All workstations and servers joined to the domain"),
            ("Domain Controllers", "All domain controllers in the domain"),
            ("Domain Guests", "All domain guests"),
            ("Enterprise Admins", "Designated administrators of the enterprise"),
            ("Schema Admins", "Designated administrators of the schema"),
            ("Group Policy Creator Owners", "Members can modify group policy for the domain"),
            ("Cert Publishers", "Members are permitted to publish certificates to the directory"),
            ("DnsAdmins", "DNS Administrators Group"),
            ("DnsUpdateProxy", "DNS clients who are permitted to perform dynamic updates"),
            ("Allowed RODC Password Replication Group", "Members can have passwords replicated to all read-only domain controllers"),
            ("Denied RODC Password Replication Group", "Members cannot have passwords replicated to any read-only domain controllers"),
            ("Read-only Domain Controllers", "Members are Read-Only Domain Controllers in the domain"),
            ("Cloneable Domain Controllers", "Members that can be cloned"),
            ("RAS and IAS Servers", "Servers can access remote access properties of users"),
        ]
        for group_name, description in domain_groups:
            self.group_manager.create_group(
                cn=group_name,
                ou="CN=Users",
                description=description,
            )

        # ── 6. Built-in local groups (CN=Builtin) ─────────────────────
        builtin_groups = [
            ("Administrators", "Built-in account for administering the computer/domain"),
            ("Account Operators", "Members can administer domain user and group accounts"),
            ("Backup Operators", "Members can bypass file security to back up files"),
            ("Guests", "Guests have the same access as members of the Users group by default"),
            ("Print Operators", "Members can administer printers installed on domain controllers"),
            ("Server Operators", "Members can administer domain servers"),
            ("Users", "Users are prevented from making accidental or intentional system-wide changes"),
            ("Remote Desktop Users", "Members are granted the right to logon remotely"),
            ("Network Configuration Operators", "Members can have some administrative privileges to manage configuration of networking features"),
            ("Performance Monitor Users", "Members can access performance counter data locally and remotely"),
            ("Performance Log Users", "Members can schedule logging of performance counters"),
            ("Distributed COM Users", "Members are allowed to launch, activate and use Distributed COM objects"),
            ("IIS_IUSRS", "Built-in group used by Internet Information Services"),
            ("Cryptographic Operators", "Members are authorized to perform cryptographic operations"),
            ("Event Log Readers", "Members can read event logs from local machine"),
            ("Certificate Service DCOM Access", "Members are allowed to connect to Certification Authorities in the enterprise"),
            ("Pre-Windows 2000 Compatible Access", "A backward compatibility group"),
            ("Incoming Forest Trust Builders", "Members can create incoming, one-way trusts to this forest"),
            ("Windows Authorization Access Group", "Members have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects"),
            ("Terminal Server License Servers", "Members can update user accounts in Active Directory with information about license issuance"),
            ("Access Control Assistance Operators", "Members can remotely query authorization attributes and permissions for resources"),
            ("Remote Management Users", "Members can access WMI resources over management protocols"),
            ("Hyper-V Administrators", "Members have complete and unrestricted access to all features of Hyper-V"),
            ("Storage Replica Administrators", "Members have complete and unrestricted access to all features of Storage Replica"),
        ]
        for group_name, description in builtin_groups:
            self.group_manager.create_group(
                cn=group_name,
                ou="CN=Builtin",
                description=description,
            )

        # ── 7. Add Administrator to key groups ────────────────────────
        admin_dn = f"CN=Administrator,CN=Users,{self.base_dn}"
        for group_name in ("Domain Admins", "Enterprise Admins", "Schema Admins"):
            try:
                self.group_manager.add_member(group_name, admin_dn)
            except Exception:
                pass  # Ignore if already a member

        # ── 8. Default service account for PAN-OS testing ─────────────
        svc_pw = os.environ.get("AD_SIM_SVC_PASSWORD", "password")  # noqa: S105
        self.user_manager.create_user(
            cn="svc-panos",
            sam_account_name="svc-panos",
            password=svc_pw,
            ou="CN=Users",
        )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, int]:
        """Return counts of users, groups, and OUs in the directory.

        Returns:
            A dict with keys ``"users"``, ``"groups"``, and ``"ous"``.
        """
        return {
            "users": self.user_manager.user_count(),
            "groups": self.group_manager.group_count(),
            "ous": len(self.ou_manager.list_ous()),
        }
