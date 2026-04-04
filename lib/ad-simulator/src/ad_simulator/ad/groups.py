"""Group management for the AD Simulator.

Provides CRUD operations for security and distribution groups, including
bidirectional member/memberOf synchronisation that mirrors real Active
Directory behaviour.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ad_simulator.directory.dit import DirectoryInformationTree, SearchScope
from ad_simulator.directory.entry import LDAPEntry
from ad_simulator.directory.filters import parse_filter


def _ad_timestamp() -> str:
    """Return the current time in AD generalized time format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S.0Z")


class GroupManager:
    """Manages group entries in the directory.

    Handles group creation, membership (with bidirectional ``member`` /
    ``memberOf`` updates), nested group chains, and deletion.
    """

    def __init__(
        self,
        dit: DirectoryInformationTree,
        base_dn: str,
        domain_name: str,
    ) -> None:
        self._dit = dit
        self._base_dn = base_dn
        self._domain_name = domain_name

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_group(
        self,
        cn: str,
        ou: str = "CN=Users",
        description: str = "",
        group_type: str = "security",
        email: str | None = None,
        group_member_attr: str | None = None,
    ) -> LDAPEntry:
        """Create a group entry in the directory.

        Args:
            cn: Common Name of the group (also used as ``sAMAccountName``).
            ou: Relative container/OU path (e.g. ``"CN=Users"``).
            description: Optional group description.
            group_type: ``"security"`` or ``"distribution"``.
            email: Optional group email address (stored as ``mail``).
            group_member_attr: Optional custom attribute name to use for
                group membership instead of the default ``member``.
                For example, ``"uniqueMember"`` for eDirectory compatibility.
                When set, this attribute name is stored on the group entry
                as ``groupMemberAttr`` so the server knows which attribute
                to use for membership queries.

        Returns:
            The created :class:`LDAPEntry`.
        """
        dn = f"CN={cn},{ou},{self._base_dn}"
        now = _ad_timestamp()
        object_category = (
            f"CN=Group,CN=Schema,CN=Configuration,{self._base_dn}"
        )

        # groupType flag: -2147483646 = security global, 8 = distribution
        group_type_val = "-2147483646" if group_type == "security" else "8"

        attrs: dict[str, list[str]] = {
            "objectClass": ["top", "group"],
            "cn": [cn],
            "name": [cn],
            "sAMAccountName": [cn],
            "distinguishedName": [dn],
            "objectCategory": [object_category],
            "groupType": [group_type_val],
            "whenCreated": [now],
            "whenChanged": [now],
        }
        if description:
            attrs["description"] = [description]
        if email:
            attrs["mail"] = [email]
        if group_member_attr:
            attrs["groupMemberAttr"] = [group_member_attr]

        entry = LDAPEntry(dn=dn, attributes=attrs)
        self._dit.add_entry(entry)
        return entry

    def get_group(self, cn: str) -> LDAPEntry | None:
        """Look up a group by its CN.

        Args:
            cn: The common name of the group.

        Returns:
            The :class:`LDAPEntry` if found, or ``None``.
        """
        filter_node = parse_filter(
            f"(&(objectClass=group)(cn={cn}))"
        )
        results = self._dit.search(self._base_dn, SearchScope.SUBTREE, filter_node)
        return results[0] if results else None

    def list_groups(self) -> list[LDAPEntry]:
        """Return all group entries under the base DN.

        Returns:
            A list of group :class:`LDAPEntry` objects.
        """
        filter_node = parse_filter("(objectClass=group)")
        return self._dit.search(self._base_dn, SearchScope.SUBTREE, filter_node)

    def delete_group(self, cn: str) -> bool:
        """Delete a group and clean up memberOf references on its members.

        Args:
            cn: The common name of the group to delete.

        Returns:
            ``True`` if the group was found and deleted, ``False`` otherwise.
        """
        group = self.get_group(cn)
        if group is None:
            return False

        group_dn = group.dn

        # Remove this group's DN from every member's memberOf attribute
        for member_dn in group.get_attr("member"):
            member_entry = self._dit.get_entry(member_dn)
            if member_entry is not None:
                member_entry.remove_attr_value("memberOf", group_dn)

        return self._dit.delete_entry(group_dn)

    # ------------------------------------------------------------------
    # Membership
    # ------------------------------------------------------------------

    def add_member(self, group_cn: str, member_dn: str) -> bool:
        """Add a member to a group (bidirectional update).

        Adds ``member_dn`` to the group's ``member`` attribute **and** adds
        the group's DN to the member's ``memberOf`` attribute.

        Args:
            group_cn: The CN of the group.
            member_dn: The DN of the member to add.

        Returns:
            ``True`` if the operation succeeded, ``False`` if the group
            was not found.
        """
        group = self.get_group(group_cn)
        if group is None:
            return False

        now = _ad_timestamp()

        # Add member DN to group's member attribute
        group.add_attr_value("member", member_dn)
        group.set_attr("whenChanged", [now])

        # Add group DN to member's memberOf attribute
        member_entry = self._dit.get_entry(member_dn)
        if member_entry is not None:
            member_entry.add_attr_value("memberOf", group.dn)
            member_entry.set_attr("whenChanged", [now])

        return True

    def remove_member(self, group_cn: str, member_dn: str) -> bool:
        """Remove a member from a group (bidirectional update).

        Args:
            group_cn: The CN of the group.
            member_dn: The DN of the member to remove.

        Returns:
            ``True`` if the member was removed, ``False`` if the group
            was not found or the member was not in the group.
        """
        group = self.get_group(group_cn)
        if group is None:
            return False

        now = _ad_timestamp()

        removed = group.remove_attr_value("member", member_dn)
        if removed:
            group.set_attr("whenChanged", [now])

        # Remove group DN from member's memberOf
        member_entry = self._dit.get_entry(member_dn)
        if member_entry is not None:
            member_entry.remove_attr_value("memberOf", group.dn)
            member_entry.set_attr("whenChanged", [now])

        return removed

    def get_members(self, group_cn: str) -> list[str]:
        """Return the list of member DNs for a group.

        Args:
            group_cn: The CN of the group.

        Returns:
            A list of member DN strings, or an empty list if the group
            is not found or has no members.
        """
        group = self.get_group(group_cn)
        if group is None:
            return []
        return group.get_attr("member")

    # ------------------------------------------------------------------
    # Nested groups
    # ------------------------------------------------------------------

    def create_nested_groups(
        self,
        depth: int,
        base_name: str = "nested-group",
        ou: str = "CN=Users",
    ) -> list[LDAPEntry]:
        """Create a chain of nested groups.

        Creates ``depth`` groups where each group (except the last) contains
        the next group as a member:
        ``group-L1 → group-L2 → … → group-L{depth}``.

        Args:
            depth: Number of groups in the chain.
            base_name: Prefix for group names.
            ou: The OU in which to create the groups.

        Returns:
            A list of the created :class:`LDAPEntry` objects, ordered from
            outermost to innermost.
        """
        groups: list[LDAPEntry] = []
        for level in range(1, depth + 1):
            cn = f"{base_name}-L{level}"
            group = self.create_group(cn=cn, ou=ou)
            groups.append(group)

        # Wire up nesting: each group contains the next
        for i in range(len(groups) - 1):
            parent_cn = f"{base_name}-L{i + 1}"
            child_dn = groups[i + 1].dn
            self.add_member(parent_cn, child_dn)

        return groups

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def group_count(self) -> int:
        """Return the total number of groups in the directory.

        Returns:
            Integer count of group entries.
        """
        return len(self.list_groups())
