"""Active Directory schema definitions.

Defines AD objectClass hierarchy and attribute metadata used by the simulator
to validate entries and provide schema-aware behavior matching Microsoft AD.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AttributeSyntax(Enum):
    """LDAP attribute syntax types relevant to AD simulation."""

    DIRECTORY_STRING = "2.5.5.12"  # Unicode string
    DN = "2.5.5.1"  # Distinguished Name
    INTEGER = "2.5.5.9"  # Integer
    BOOLEAN = "2.5.5.8"  # Boolean
    GENERALIZED_TIME = "2.5.5.11"  # Generalized Time (e.g., 20240101000000.0Z)
    OCTET_STRING = "2.5.5.10"  # Binary / octet string
    OID = "2.5.5.2"  # Object Identifier
    LARGE_INTEGER = "2.5.5.16"  # 64-bit integer (e.g., lastLogon)
    SID = "2.5.5.17"  # Security Identifier
    NT_SECURITY_DESCRIPTOR = "2.5.5.15"  # NT Security Descriptor


@dataclass(frozen=True)
class AttributeDef:
    """Definition of an LDAP attribute."""

    name: str
    syntax: AttributeSyntax = AttributeSyntax.DIRECTORY_STRING
    single_valued: bool = False
    case_insensitive: bool = True
    description: str = ""


@dataclass(frozen=True)
class ObjectClassDef:
    """Definition of an AD objectClass."""

    name: str
    oid: str = ""
    superior: str = ""  # Parent objectClass
    required_attrs: frozenset[str] = field(default_factory=frozenset)
    optional_attrs: frozenset[str] = field(default_factory=frozenset)
    description: str = ""


# ---------------------------------------------------------------------------
# AD Attribute Definitions
# ---------------------------------------------------------------------------

AD_ATTRIBUTES: dict[str, AttributeDef] = {
    # Core identity attributes
    "cn": AttributeDef(
        name="cn",
        description="Common Name",
    ),
    "name": AttributeDef(
        name="name",
        single_valued=True,
        description="RDN display name",
    ),
    "distinguishedName": AttributeDef(
        name="distinguishedName",
        syntax=AttributeSyntax.DN,
        single_valued=True,
        description="Full DN of the entry",
    ),
    "objectClass": AttributeDef(
        name="objectClass",
        syntax=AttributeSyntax.OID,
        description="Object class membership",
    ),
    "objectCategory": AttributeDef(
        name="objectCategory",
        syntax=AttributeSyntax.DN,
        single_valued=True,
        description="AD object category DN",
    ),
    "objectGUID": AttributeDef(
        name="objectGUID",
        syntax=AttributeSyntax.OCTET_STRING,
        single_valued=True,
        description="Globally unique identifier",
    ),
    "objectSid": AttributeDef(
        name="objectSid",
        syntax=AttributeSyntax.SID,
        single_valued=True,
        description="Security identifier",
    ),
    "instanceType": AttributeDef(
        name="instanceType",
        syntax=AttributeSyntax.INTEGER,
        single_valued=True,
        description="Instance type flags",
    ),
    # User attributes
    "sAMAccountName": AttributeDef(
        name="sAMAccountName",
        single_valued=True,
        description="Pre-Windows 2000 logon name",
    ),
    "sAMAccountType": AttributeDef(
        name="sAMAccountType",
        syntax=AttributeSyntax.INTEGER,
        single_valued=True,
        description="SAM account type",
    ),
    "userPrincipalName": AttributeDef(
        name="userPrincipalName",
        single_valued=True,
        description="UPN (user@domain.local)",
    ),
    "userAccountControl": AttributeDef(
        name="userAccountControl",
        syntax=AttributeSyntax.INTEGER,
        single_valued=True,
        description="Account control flags (512=normal, 514=disabled)",
    ),
    "givenName": AttributeDef(
        name="givenName",
        single_valued=True,
        description="First name",
    ),
    "sn": AttributeDef(
        name="sn",
        single_valued=True,
        description="Surname / last name",
    ),
    "displayName": AttributeDef(
        name="displayName",
        single_valued=True,
        description="Display name",
    ),
    "mail": AttributeDef(
        name="mail",
        single_valued=True,
        description="Email address",
    ),
    "proxyAddresses": AttributeDef(
        name="proxyAddresses",
        description="Proxy email addresses (multi-valued)",
    ),
    "description": AttributeDef(
        name="description",
        description="Description",
    ),
    # Group attributes
    "member": AttributeDef(
        name="member",
        syntax=AttributeSyntax.DN,
        description="Group members (DNs)",
    ),
    "memberOf": AttributeDef(
        name="memberOf",
        syntax=AttributeSyntax.DN,
        description="Groups this entry belongs to (DNs)",
    ),
    "groupType": AttributeDef(
        name="groupType",
        syntax=AttributeSyntax.INTEGER,
        single_valued=True,
        description="Group type flags",
    ),
    # OU / Container attributes
    "ou": AttributeDef(
        name="ou",
        description="Organizational Unit name",
    ),
    # Timestamps
    "whenCreated": AttributeDef(
        name="whenCreated",
        syntax=AttributeSyntax.GENERALIZED_TIME,
        single_valued=True,
        description="Creation timestamp",
    ),
    "whenChanged": AttributeDef(
        name="whenChanged",
        syntax=AttributeSyntax.GENERALIZED_TIME,
        single_valued=True,
        description="Last modification timestamp",
    ),
    "modifyTimestamp": AttributeDef(
        name="modifyTimestamp",
        syntax=AttributeSyntax.GENERALIZED_TIME,
        single_valued=True,
        description="LDAP standard modify timestamp",
    ),
    # Domain attributes
    "dc": AttributeDef(
        name="dc",
        single_valued=True,
        description="Domain Component",
    ),
    # Misc
    "dSCorePropagationData": AttributeDef(
        name="dSCorePropagationData",
        syntax=AttributeSyntax.GENERALIZED_TIME,
        description="DS core propagation data",
    ),
    "uSNCreated": AttributeDef(
        name="uSNCreated",
        syntax=AttributeSyntax.LARGE_INTEGER,
        single_valued=True,
        description="Update sequence number at creation",
    ),
    "uSNChanged": AttributeDef(
        name="uSNChanged",
        syntax=AttributeSyntax.LARGE_INTEGER,
        single_valued=True,
        description="Update sequence number at last change",
    ),
    "primaryGroupID": AttributeDef(
        name="primaryGroupID",
        syntax=AttributeSyntax.INTEGER,
        single_valued=True,
        description="Primary group RID",
    ),
}


# ---------------------------------------------------------------------------
# AD objectClass Definitions
# ---------------------------------------------------------------------------

OBJECT_CLASSES: dict[str, ObjectClassDef] = {
    "top": ObjectClassDef(
        name="top",
        oid="2.5.6.0",
        required_attrs=frozenset({"objectClass"}),
        optional_attrs=frozenset({
            "cn",
            "description",
            "distinguishedName",
            "name",
            "objectCategory",
            "objectGUID",
            "objectSid",
            "whenCreated",
            "whenChanged",
            "instanceType",
            "uSNCreated",
            "uSNChanged",
        }),
        description="Top-level abstract class",
    ),
    "domain": ObjectClassDef(
        name="domain",
        oid="1.2.840.113556.1.5.67",
        superior="top",
        required_attrs=frozenset({"dc"}),
        optional_attrs=frozenset({
            "description",
            "objectCategory",
        }),
        description="AD domain root",
    ),
    "organizationalUnit": ObjectClassDef(
        name="organizationalUnit",
        oid="2.5.6.5",
        superior="top",
        required_attrs=frozenset({"ou"}),
        optional_attrs=frozenset({
            "description",
            "objectCategory",
        }),
        description="Organizational Unit",
    ),
    "container": ObjectClassDef(
        name="container",
        oid="2.5.6.11",
        superior="top",
        required_attrs=frozenset({"cn"}),
        optional_attrs=frozenset({
            "description",
            "objectCategory",
        }),
        description="Generic container",
    ),
    "person": ObjectClassDef(
        name="person",
        oid="2.5.6.6",
        superior="top",
        required_attrs=frozenset({"cn", "sn"}),
        optional_attrs=frozenset({
            "description",
            "userAccountControl",
        }),
        description="Person",
    ),
    "organizationalPerson": ObjectClassDef(
        name="organizationalPerson",
        oid="2.5.6.7",
        superior="person",
        required_attrs=frozenset(),
        optional_attrs=frozenset({
            "givenName",
            "displayName",
            "mail",
        }),
        description="Organizational Person",
    ),
    "user": ObjectClassDef(
        name="user",
        oid="1.2.840.113556.1.5.9",
        superior="organizationalPerson",
        required_attrs=frozenset(),
        optional_attrs=frozenset({
            "sAMAccountName",
            "sAMAccountType",
            "userPrincipalName",
            "userAccountControl",
            "memberOf",
            "primaryGroupID",
            "proxyAddresses",
        }),
        description="AD User account",
    ),
    "group": ObjectClassDef(
        name="group",
        oid="1.2.840.113556.1.5.8",
        superior="top",
        required_attrs=frozenset({"cn"}),
        optional_attrs=frozenset({
            "sAMAccountName",
            "sAMAccountType",
            "member",
            "memberOf",
            "groupType",
            "mail",
            "description",
            "objectCategory",
        }),
        description="AD Security/Distribution Group",
    ),
}


def get_all_attrs_for_class(class_name: str) -> tuple[frozenset[str], frozenset[str]]:
    """Get all required and optional attributes for an objectClass, including inherited.

    Walks the objectClass hierarchy (via ``superior``) and collects attributes
    from each ancestor class.

    Args:
        class_name: The objectClass name (case-sensitive key in OBJECT_CLASSES).

    Returns:
        A tuple of (required_attrs, optional_attrs) frozensets.
    """
    required: set[str] = set()
    optional: set[str] = set()
    visited: set[str] = set()

    current = class_name
    while current and current not in visited:
        visited.add(current)
        cls_def = OBJECT_CLASSES.get(current)
        if cls_def is None:
            break
        required.update(cls_def.required_attrs)
        optional.update(cls_def.optional_attrs)
        current = cls_def.superior

    return frozenset(required), frozenset(optional)


def validate_entry_schema(object_classes: list[str], attributes: dict[str, list[str]]) -> list[str]:
    """Validate that an entry's attributes satisfy its objectClass requirements.

    Args:
        object_classes: List of objectClass values on the entry.
        attributes: The entry's attribute dict.

    Returns:
        A list of validation error strings (empty if valid).
    """
    errors: list[str] = []
    attr_names_lower = {k.lower() for k in attributes}

    for oc in object_classes:
        cls_def = OBJECT_CLASSES.get(oc)
        if cls_def is None:
            continue  # Unknown objectClass — skip validation
        required, _ = get_all_attrs_for_class(oc)
        for req_attr in required:
            if req_attr.lower() not in attr_names_lower and req_attr != "objectClass":
                errors.append(f"objectClass '{oc}' requires attribute '{req_attr}'")

    return errors
