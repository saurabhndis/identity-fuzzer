"""Click CLI for the AD Simulator.

Provides the ``ad-sim`` command-line interface for managing the simulated
Active Directory server, users, groups, OUs, fuzzer, and certificates.
"""

from __future__ import annotations

import json
import logging
import sys

import click

from ad_simulator.ad.domain import ADDomain
from ad_simulator.fuzzer.engine import FuzzerEngine
from ad_simulator.fuzzer.scenarios import get_all_scenarios, get_scenario_by_name
from ad_simulator.server.ssl_config import generate_server_certs
from ad_simulator.utils.seed_data import seed_directory

# Module-level domain for commands that need shared state
_domain: ADDomain | None = None


def _get_or_create_domain(domain_name: str = "testlab.local") -> ADDomain:
    """Get the current domain or create and set up a new one.

    Args:
        domain_name: DNS domain name.

    Returns:
        A configured :class:`ADDomain`.
    """
    global _domain
    if _domain is None or _domain.domain_name != domain_name:
        _domain = ADDomain(domain_name)
        _domain.setup()
    return _domain


# ---------------------------------------------------------------------------
# Root CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def cli(verbose: bool) -> None:
    """AD Simulator — Active Directory simulator for PAN-OS testing."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


# ---------------------------------------------------------------------------
# start command
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--port", default=389, show_default=True, help="LDAP port.")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
@click.option("--seed-users", default=10, show_default=True, help="Number of seed users.")
@click.option("--seed-groups", default=5, show_default=True, help="Number of seed groups.")
@click.option("--ssl", "use_ssl", is_flag=True, help="Enable LDAPS.")
@click.option("--ssl-port", default=636, show_default=True, help="LDAPS port.")
def start(
    port: int,
    domain_name: str,
    seed_users: int,
    seed_groups: int,
    use_ssl: bool,
    ssl_port: int,
) -> None:
    """Start the AD Simulator LDAP server."""
    from ad_simulator.server.runner import run_server

    domain = _get_or_create_domain(domain_name)
    seed_directory(domain, num_users=seed_users, num_groups=seed_groups)

    stats = domain.get_stats()
    click.echo(f"Domain: {domain_name}")
    click.echo(f"Base DN: {domain.base_dn}")
    click.echo(f"Users: {stats['users']}, Groups: {stats['groups']}, OUs: {stats['ous']}")
    click.echo(f"Starting LDAP server on port {port}...")

    ssl_port_val = ssl_port if use_ssl else None
    cert_file = None
    key_file = None

    if use_ssl:
        cert_file_path, key_file_path = generate_server_certs(domain_name, "./certs")
        cert_file = cert_file_path
        key_file = key_file_path
        click.echo(f"LDAPS enabled on port {ssl_port}")

    run_server(
        domain,
        host="0.0.0.0",
        port=port,
        ssl_port=ssl_port_val,
        cert_file=cert_file,
        key_file=key_file,
    )


# ---------------------------------------------------------------------------
# user commands
# ---------------------------------------------------------------------------


@cli.group()
def user() -> None:
    """Manage users in the directory."""


@user.command("add")
@click.option("--name", required=True, help="User display name (CN).")
@click.option("--sam", required=True, help="sAMAccountName (logon name).")
@click.option("--password", required=True, help="User password.")
@click.option("--ou", default="CN=Users", show_default=True, help="OU or container path.")
@click.option("--email", default=None, help="Email address.")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def user_add(
    name: str,
    sam: str,
    password: str,
    ou: str,
    email: str | None,
    domain_name: str,
) -> None:
    """Add a single user to the directory."""
    domain = _get_or_create_domain(domain_name)

    # Normalize OU: if just a name like "Engineering", prefix with OU=
    if not ou.upper().startswith(("CN=", "OU=")):
        ou = f"OU={ou}"

    entry = domain.user_manager.create_user(
        cn=name,
        sam_account_name=sam,
        password=password,
        ou=ou,
        email=email,
    )
    click.echo(f"Created user: {entry.dn}")


@user.command("list")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def user_list(domain_name: str) -> None:
    """List all users in the directory."""
    domain = _get_or_create_domain(domain_name)
    users = domain.user_manager.list_users()
    if not users:
        click.echo("No users found.")
        return
    click.echo(f"{'sAMAccountName':<25} {'CN':<30} {'DN'}")
    click.echo("-" * 100)
    for u in users:
        sam = u.get_attr_first("sAMAccountName") or "?"
        cn = u.get_attr_first("cn") or "?"
        click.echo(f"{sam:<25} {cn:<30} {u.dn}")
    click.echo(f"\nTotal: {len(users)} users")


@user.command("bulk-add")
@click.option("--count", required=True, type=int, help="Number of users to create.")
@click.option("--pattern", default="user{:04d}", show_default=True, help="Name pattern.")
@click.option("--ou", default="CN=Users", show_default=True, help="OU or container path.")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def user_bulk_add(count: int, pattern: str, ou: str, domain_name: str) -> None:
    """Bulk-create users in the directory."""
    domain = _get_or_create_domain(domain_name)

    if not ou.upper().startswith(("CN=", "OU=")):
        ou = f"OU={ou}"

    entries = domain.user_manager.bulk_create_users(
        count=count, pattern=pattern, ou=ou
    )
    click.echo(f"Created {len(entries)} users in {ou}")


# ---------------------------------------------------------------------------
# group commands
# ---------------------------------------------------------------------------


@cli.group()
def group() -> None:
    """Manage groups in the directory."""


@group.command("add")
@click.option("--name", required=True, help="Group name (CN).")
@click.option("--ou", default="CN=Users", show_default=True, help="OU/container path.")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def group_add(name: str, ou: str, domain_name: str) -> None:
    """Create a new group."""
    domain = _get_or_create_domain(domain_name)

    if not ou.upper().startswith(("CN=", "OU=")):
        ou = f"OU={ou}"

    entry = domain.group_manager.create_group(cn=name, ou=ou)
    click.echo(f"Created group: {entry.dn}")


@group.command("add-member")
@click.option("--group", "group_name", required=True, help="Group CN.")
@click.option("--member-dn", required=True, help="Member DN to add.")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def group_add_member(group_name: str, member_dn: str, domain_name: str) -> None:
    """Add a member to a group."""
    domain = _get_or_create_domain(domain_name)
    success = domain.group_manager.add_member(group_name, member_dn)
    if success:
        click.echo(f"Added {member_dn} to group {group_name}")
    else:
        click.echo(f"Failed to add member (group '{group_name}' not found?)", err=True)
        sys.exit(1)


@group.command("list")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def group_list(domain_name: str) -> None:
    """List all groups in the directory."""
    domain = _get_or_create_domain(domain_name)
    groups = domain.group_manager.list_groups()
    if not groups:
        click.echo("No groups found.")
        return
    click.echo(f"{'CN':<30} {'Members':<10} {'DN'}")
    click.echo("-" * 90)
    for g in groups:
        cn = g.get_attr_first("cn") or "?"
        members = len(g.get_attr("member"))
        click.echo(f"{cn:<30} {members:<10} {g.dn}")
    click.echo(f"\nTotal: {len(groups)} groups")


# ---------------------------------------------------------------------------
# ou commands
# ---------------------------------------------------------------------------


@cli.group()
def ou() -> None:
    """Manage Organizational Units."""


@ou.command("add")
@click.option("--name", required=True, help="OU name.")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def ou_add(name: str, domain_name: str) -> None:
    """Create a new Organizational Unit."""
    domain = _get_or_create_domain(domain_name)
    entry = domain.ou_manager.create_ou(name)
    click.echo(f"Created OU: {entry.dn}")


@ou.command("list")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def ou_list(domain_name: str) -> None:
    """List all Organizational Units."""
    domain = _get_or_create_domain(domain_name)
    ous = domain.ou_manager.list_ous()
    if not ous:
        click.echo("No OUs found.")
        return
    for o in ous:
        name = o.get_attr_first("ou") or "?"
        click.echo(f"  {name:<30} {o.dn}")
    click.echo(f"\nTotal: {len(ous)} OUs")


# ---------------------------------------------------------------------------
# fuzz commands
# ---------------------------------------------------------------------------


@cli.command("fuzz")
@click.option("--scenario", "scenario_name", default=None, help="Run a specific scenario by name.")
@click.option("--all", "run_all", is_flag=True, help="Run all fuzz scenarios.")
@click.option("--category", default=None, help="Run scenarios in a category.")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def fuzz(
    scenario_name: str | None,
    run_all: bool,
    category: str | None,
    domain_name: str,
) -> None:
    """Run fuzzer scenarios against the directory."""
    domain = ADDomain(domain_name)
    domain.setup()
    engine = FuzzerEngine(domain)

    if scenario_name:
        # Normalize: allow hyphens or underscores
        normalized = scenario_name.replace("-", "_")
        result = engine.run_by_name(normalized)
        _print_fuzz_result(result)
    elif category:
        results = engine.run_by_category(category)
        _print_fuzz_results(results)
    elif run_all:
        results = engine.run_all()
        _print_fuzz_results(results)
    else:
        click.echo("Specify --scenario, --category, or --all. Use 'ad-sim fuzz list-scenarios' to see available scenarios.")


@cli.command("fuzz-list")
def fuzz_list_scenarios() -> None:
    """List all available fuzz scenarios."""
    scenarios = get_all_scenarios()
    click.echo(f"{'Name':<35} {'Category':<15} {'Description'}")
    click.echo("-" * 100)
    for s in scenarios:
        click.echo(f"{s.name:<35} {s.category:<15} {s.description}")
    click.echo(f"\nTotal: {len(scenarios)} scenarios")


def _print_fuzz_result(result: object) -> None:
    """Print a single fuzz result."""
    from ad_simulator.fuzzer.scenarios import FuzzResult

    r: FuzzResult = result  # type: ignore[assignment]
    status = click.style("PASS", fg="green") if r.success else click.style("FAIL", fg="red")
    click.echo(f"  {status} {r.scenario_name} ({r.duration_ms:.1f}ms)")
    click.echo(f"       {r.details}")
    if r.error:
        click.echo(f"       Error: {r.error}")


def _print_fuzz_results(results: list) -> None:
    """Print a list of fuzz results with summary."""
    passed = sum(1 for r in results if r.success)
    failed = len(results) - passed
    click.echo(f"\nFuzz Results ({len(results)} scenarios):")
    click.echo("-" * 60)
    for r in results:
        _print_fuzz_result(r)
    click.echo("-" * 60)
    click.echo(f"Passed: {passed}, Failed: {failed}")


# ---------------------------------------------------------------------------
# generate-certs command
# ---------------------------------------------------------------------------


@cli.command("generate-certs")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name for cert CN/SAN.")
@click.option("--output-dir", default="./certs", show_default=True, help="Output directory for cert files.")
def generate_certs(domain_name: str, output_dir: str) -> None:
    """Generate self-signed SSL certificates for LDAPS."""
    cert_path, key_path = generate_server_certs(domain_name, output_dir)
    click.echo(f"Certificate: {cert_path}")
    click.echo(f"Private key: {key_path}")


# ---------------------------------------------------------------------------
# info command
# ---------------------------------------------------------------------------


@cli.command("info")
@click.option("--domain", "domain_name", default="testlab.local", show_default=True, help="Domain name.")
def info(domain_name: str) -> None:
    """Show domain information and statistics."""
    domain = _get_or_create_domain(domain_name)
    stats = domain.get_stats()

    click.echo(f"Domain:   {domain.domain_name}")
    click.echo(f"Base DN:  {domain.base_dn}")
    click.echo(f"Users:    {stats['users']}")
    click.echo(f"Groups:   {stats['groups']}")
    click.echo(f"OUs:      {stats['ous']}")
    click.echo(f"Entries:  {domain.dit.entry_count}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
