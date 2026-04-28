"""User management for the AD Simulator.

Provides CRUD operations for user accounts, bulk creation, authentication,
and password management within the simulated Active Directory.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ad_simulator.directory.dit import DirectoryInformationTree, SearchScope
from ad_simulator.directory.entry import LDAPEntry
from ad_simulator.directory.filters import parse_filter

if TYPE_CHECKING:
    from ad_simulator.ad.groups import GroupManager


def _ad_timestamp() -> str:
    """Return the current time in AD generalized time format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S.0Z")


class UserManager:
    """Manages user entries in the directory.

    Handles user creation (including auto-generated AD attributes),
    lookup, deletion, bulk creation, authentication, and password changes.
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
        self._group_manager: GroupManager | None = None

    def set_group_manager(self, gm: GroupManager) -> None:
        """Inject the :class:`GroupManager` for group membership operations.

        Called by :class:`ADDomain` after both managers are constructed.
        """
        self._group_manager = gm

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_user(
        self,
        cn: str,
        sam_account_name: str,
        password: str,
        ou: str = "CN=Users",
        groups: list[str] | None = None,
        email: str | None = None,
        upn_format: str | None = None,
        custom_attr1: tuple[str, str] | None = None,
        custom_attr2: tuple[str, str] | None = None,
        custom_attr3: tuple[str, str] | None = None,
        extra_attrs: dict[str, list[str]] | None = None,
    ) -> LDAPEntry:
        """Create a user entry in the directory.

        Auto-generates standard AD attributes such as ``userPrincipalName``,
        ``objectCategory``, ``userAccountControl``, and ``whenChanged``.

        Args:
            cn: Common Name (display name) of the user.
            sam_account_name: The ``sAMAccountName`` (logon name).
            password: The user's password (stored in plaintext for simulation).
            ou: Relative container/OU path (e.g. ``"CN=Users"`` or
                ``"OU=Engineering"``).
            groups: Optional list of group CNs to add the user to.
            email: Optional email address.
            upn_format: Optional custom UPN format string. Use ``{sam}`` for
                sAMAccountName and ``{domain}`` for domain name.
                Default: ``"{sam}@{domain}"``.
                Example: ``"{sam}@subdomain.{domain}"``
            custom_attr1: Optional tuple of (attribute_name, value) for a
                custom LDAP attribute on the user.
            custom_attr2: Optional tuple of (attribute_name, value) for a
                second custom LDAP attribute.
            custom_attr3: Optional tuple of (attribute_name, value) for a
                third custom LDAP attribute.
            extra_attrs: Optional dict of additional attributes to set.

        Returns:
            The created :class:`LDAPEntry`.
        """
        dn = f"CN={cn},{ou},{self._base_dn}"
        if upn_format:
            upn = upn_format.format(sam=sam_account_name, domain=self._domain_name)
        else:
            upn = f"{sam_account_name}@{self._domain_name}"
        now = _ad_timestamp()
        object_category = (
            f"CN=Person,CN=Schema,CN=Configuration,{self._base_dn}"
        )

        attrs: dict[str, list[str]] = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": [cn],
            "name": [cn],
            "sAMAccountName": [sam_account_name],
            "userPrincipalName": [upn],
            "distinguishedName": [dn],
            "objectCategory": [object_category],
            "userAccountControl": ["512"],
            "primaryGroupID": ["513"],
            "whenCreated": [now],
            "whenChanged": [now],
        }

        if email:
            attrs["mail"] = [email]

        # Apply custom attributes (name, value tuples)
        for custom in (custom_attr1, custom_attr2, custom_attr3):
            if custom is not None:
                attr_name, attr_value = custom
                if attr_name:
                    attrs[attr_name] = [attr_value]

        if extra_attrs:
            for key, values in extra_attrs.items():
                attrs[key] = list(values)

        entry = LDAPEntry(dn=dn, attributes=attrs, password=password)
        self._dit.add_entry(entry)

        # Add user to requested groups
        if groups and self._group_manager is not None:
            for group_cn in groups:
                self._group_manager.add_member(group_cn, dn)

        return entry

    def get_user(self, sam_account_name: str) -> LDAPEntry | None:
        """Look up a user by ``sAMAccountName``.

        Args:
            sam_account_name: The logon name to search for.

        Returns:
            The :class:`LDAPEntry` if found, or ``None``.
        """
        filter_node = parse_filter(
            f"(&(objectClass=user)(sAMAccountName={sam_account_name}))"
        )
        results = self._dit.search(self._base_dn, SearchScope.SUBTREE, filter_node)
        return results[0] if results else None

    def get_user_by_dn(self, dn: str) -> LDAPEntry | None:
        """Look up a user by DN.

        Args:
            dn: The Distinguished Name of the user.

        Returns:
            The :class:`LDAPEntry` if found and is a user, or ``None``.
        """
        entry = self._dit.get_entry(dn)
        if entry is None:
            return None
        if not entry.has_object_class("user"):
            return None
        return entry

    def delete_user(self, sam_account_name: str) -> bool:
        """Delete a user by ``sAMAccountName``.

        Also removes the user's DN from any group ``member`` attributes
        and cleans up the corresponding ``memberOf`` references.

        Args:
            sam_account_name: The logon name of the user to delete.

        Returns:
            ``True`` if the user was found and deleted, ``False`` otherwise.
        """
        user = self.get_user(sam_account_name)
        if user is None:
            return False

        user_dn = user.dn

        # Remove user from all groups they belong to
        if self._group_manager is not None:
            for group_dn in user.get_attr("memberOf"):
                group_entry = self._dit.get_entry(group_dn)
                if group_entry is not None:
                    group_cn = group_entry.get_attr_first("cn")
                    if group_cn:
                        # Use remove_attr_value directly to avoid re-lookup
                        group_entry.remove_attr_value("member", user_dn)

        return self._dit.delete_entry(user_dn)

    def list_users(self) -> list[LDAPEntry]:
        """Return all user entries under the base DN.

        Returns:
            A list of user :class:`LDAPEntry` objects.
        """
        filter_node = parse_filter(
            "(&(objectClass=user)(objectCategory=*))"
        )
        results = self._dit.search(self._base_dn, SearchScope.SUBTREE, filter_node)
        return results

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def bulk_create_users(
        self,
        count: int,
        pattern: str = "user{:04d}",
        ou: str = "CN=Users",
        password: str = "P@ssw0rd",
        base_groups: list[str] | None = None,
    ) -> list[LDAPEntry]:
        """Create multiple users following a naming pattern.

        Args:
            count: Number of users to create.
            pattern: A format string with one ``{}`` placeholder for the
                index (1-based). Defaults to ``"user{:04d}"``.
            ou: Container/OU for the users.
            password: Password assigned to every user.
            base_groups: Optional list of group CNs to add each user to.

        Returns:
            A list of the created :class:`LDAPEntry` objects.
        """
        users: list[LDAPEntry] = []
        for i in range(1, count + 1):
            name = pattern.format(i)
            user = self.create_user(
                cn=name,
                sam_account_name=name,
                password=password,
                ou=ou,
                groups=base_groups,
            )
            users.append(user)
        return users

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self, sam_account_name: str, password: str) -> bool:
        """Authenticate a user by ``sAMAccountName`` and password.

        Finds the user's DN and delegates to :meth:`DirectoryInformationTree.bind`.

        Args:
            sam_account_name: The logon name.
            password: The password to verify.

        Returns:
            ``True`` if authentication succeeds.
        """
        user = self.get_user(sam_account_name)
        if user is None:
            return False
        return self._dit.bind(user.dn, password)

    def set_password(self, sam_account_name: str, new_password: str) -> bool:
        """Change a user's password.

        Args:
            sam_account_name: The logon name.
            new_password: The new password.

        Returns:
            ``True`` if the user was found and the password was changed.
        """
        user = self.get_user(sam_account_name)
        if user is None:
            return False
        user.password = new_password
        now = _ad_timestamp()
        user.set_attr("whenChanged", [now])
        return True

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def user_count(self) -> int:
        """Return the total number of user entries in the directory.

        Returns:
            Integer count of user entries.
        """
        return len(self.list_users())
