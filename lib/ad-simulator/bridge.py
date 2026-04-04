#!/usr/bin/env python3
"""
bridge.py - JSON stdin/stdout bridge for AD Simulator
Spawned by Electron as a child process.

Protocol:
  - Reads one JSON object per line from stdin
  - Writes one JSON object per line to stdout
  - Uses stderr for debug/error logging (never stdout)

Request format:
  {"id": "uuid", "cmd": "start", "args": {"domain": "testlab.local", "port": 10389}}

Response format:
  {"id": "uuid", "ok": true, "data": {...}}

Error format:
  {"id": "uuid", "ok": false, "error": "message"}

Async event (no request id):
  {"event": "log", "data": {"op": "bind", "dn": "cn=admin", "success": true, "ts": "..."}}
  {"event": "status", "data": {"running": true, "port": 10389}}
"""

import sys
import json
import threading
import traceback
import os
from dataclasses import asdict

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Thread-safe lock for writing to stdout
_write_lock = threading.Lock()


def _first(values):
    """Return the first element of a list, or empty string if None/empty."""
    if values and isinstance(values, list) and len(values) > 0:
        return values[0]
    return ""


def send_response(response):
    """Write a JSON response to stdout (thread-safe)."""
    with _write_lock:
        line = json.dumps(response, default=str)
        sys.stdout.write(line + '\n')
        sys.stdout.flush()


def send_event(event_type, data):
    """Send an async event to Electron."""
    send_response({"event": event_type, "data": data})


def log(msg):
    """Log to stderr (doesn't interfere with JSON protocol on stdout)."""
    sys.stderr.write(f"[bridge] {msg}\n")
    sys.stderr.flush()


class ADSimBridge:
    """Bridge between Electron JSON protocol and the AD Simulator Python API."""

    def __init__(self):
        self.domain = None
        self.factory = None
        self.running = False
        self._config = None
        self._lock = threading.Lock()

    def handle_command(self, msg):
        """Route a command to the appropriate handler."""
        cmd = msg.get('cmd', '')
        args = msg.get('args', {})
        msg_id = msg.get('id')

        try:
            handler = getattr(self, f'cmd_{cmd.replace("-", "_")}', None)
            if handler is None:
                return {"id": msg_id, "ok": False, "error": f"Unknown command: {cmd}"}

            result = handler(args)
            return {"id": msg_id, "ok": True, "data": result}
        except Exception as e:
            log(f"Error handling {cmd}: {traceback.format_exc()}")
            return {"id": msg_id, "ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def cmd_start(self, args):
        """Start the AD Simulator LDAP server."""
        if self.running:
            return {"message": "Server already running"}

        try:
            from ad_simulator.config import ServerConfig
            from ad_simulator.ad.domain import ADDomain
            from ad_simulator.server.runner import start_server_background, get_factory
        except ImportError as e:
            raise RuntimeError(
                f"AD Simulator dependencies not installed. "
                f"Run: pip install -r lib/ad-simulator/requirements.txt\n"
                f"Import error: {e}"
            )

        domain_name = args.get('domain', 'testlab.local')
        port = args.get('port', 10389)
        ssl_port = args.get('ssl_port', 10636)
        admin_password = args.get('admin_password', 'FuzzerAdmin123!')
        bind_password = args.get('bind_password', admin_password)

        # Set up the domain
        self.domain = ADDomain(domain_name=domain_name)
        self.domain.setup()

        # Override admin/svc passwords via environment before setup
        # (setup already called, so update passwords directly)
        self.domain.user_manager.set_password('Administrator', admin_password)
        self.domain.user_manager.set_password('svc-panos', bind_password)

        # Determine cert paths
        cert_dir = os.path.join(os.path.dirname(__file__), 'certs')
        cert_file = os.path.join(cert_dir, 'testlab.local.crt')
        key_file = os.path.join(cert_dir, 'testlab.local.key')

        ssl_cert = cert_file if os.path.exists(cert_file) else None
        ssl_key = key_file if os.path.exists(key_file) else None
        effective_ssl_port = ssl_port if (ssl_cert and ssl_key) else None

        # Store config for status queries
        self._config = {
            'domain': domain_name,
            'base_dn': self.domain.base_dn,
            'port': port,
            'ssl_port': effective_ssl_port,
        }

        # Set up real-time log forwarding callback
        def on_ldap_log(entry):
            """Forward LDAP operation logs to Electron as events."""
            send_event("log", entry)

        # Start server in background thread
        try:
            self.factory = start_server_background(
                domain=self.domain,
                host='0.0.0.0',
                port=port,
                ssl_port=effective_ssl_port,
                cert_file=ssl_cert,
                key_file=ssl_key,
                on_log=on_ldap_log,
            )
            self.running = True
        except RuntimeError as e:
            # Server might already be running from a previous start
            self.factory = get_factory()
            if self.factory is not None:
                self.running = True
            else:
                raise

        send_event("status", {"running": True, "port": port})
        return {
            "message": "Server started",
            "port": port,
            "ssl_port": effective_ssl_port,
            "domain": domain_name,
            "base_dn": self.domain.base_dn,
        }

    def cmd_stop(self, args):
        """Stop the AD Simulator LDAP server."""
        if not self.running:
            return {"message": "Server not running"}

        try:
            from ad_simulator.server.runner import stop_server
            stop_server()
        except Exception as e:
            log(f"Error stopping server: {e}")

        self.running = False
        self.factory = None
        self.domain = None
        self._config = None
        send_event("status", {"running": False})
        return {"message": "Server stopped"}

    def cmd_status(self, args):
        """Get server status."""
        if self.domain and self.running:
            stats = self.domain.get_stats()
            return {
                "running": True,
                "domain": self._config.get('domain') if self._config else None,
                "base_dn": self.domain.base_dn,
                "port": self._config.get('port') if self._config else None,
                "ssl_port": self._config.get('ssl_port') if self._config else None,
                "users": stats.get('users', 0),
                "groups": stats.get('groups', 0),
                "ous": stats.get('ous', 0),
                "connections": self.factory.connection_count if self.factory else 0,
            }
        return {
            "running": False,
            "domain": None,
            "port": None,
        }

    def cmd_seed(self, args):
        """Seed directory with test users and groups."""
        if not self.domain:
            raise RuntimeError("Server not started")

        from ad_simulator.utils.seed_data import seed_directory

        count = args.get('count', 50)
        seed_directory(self.domain, num_users=count)
        stats = self.domain.get_stats()
        return {
            "message": f"Seeded {count} users",
            "users": stats['users'],
            "groups": stats['groups'],
            "ous": stats['ous'],
        }

    def cmd_list_users(self, args):
        """List all users in the directory."""
        if not self.domain:
            raise RuntimeError("Server not started")

        users = self.domain.user_manager.list_users()
        result = []
        for u in users:
            d = u.to_dict()
            attrs = d.get("attributes", {})
            result.append({
                "dn": d.get("dn", ""),
                "cn": _first(attrs.get("cn")),
                "display_name": _first(attrs.get("displayName")) or _first(attrs.get("cn")),
                "sam_account_name": _first(attrs.get("sAMAccountName")),
                "upn": _first(attrs.get("userPrincipalName")),
                "email": _first(attrs.get("mail")),
                "object_class": attrs.get("objectClass", []),
            })
        return {
            "users": result,
            "count": len(result),
        }

    def cmd_add_user(self, args):
        """Add a user to the directory."""
        if not self.domain:
            raise RuntimeError("Server not started")

        cn = args.get('cn')
        if not cn:
            raise ValueError("'cn' is required")

        # Build custom attribute tuples if provided
        custom_attr1 = None
        custom_attr2 = None
        ca1_name = args.get('custom_attr1_name', '').strip()
        ca1_val = args.get('custom_attr1_value', '').strip()
        if ca1_name and ca1_val:
            custom_attr1 = (ca1_name, ca1_val)
        ca2_name = args.get('custom_attr2_name', '').strip()
        ca2_val = args.get('custom_attr2_value', '').strip()
        if ca2_name and ca2_val:
            custom_attr2 = (ca2_name, ca2_val)

        entry = self.domain.user_manager.create_user(
            cn=cn,
            sam_account_name=args.get('sam_account_name', cn),
            password=args.get('password', 'Password123!'),
            ou=args.get('ou', 'CN=Users'),
            groups=args.get('groups'),
            email=args.get('email'),
            upn_format=args.get('upn_format') or None,
            custom_attr1=custom_attr1,
            custom_attr2=custom_attr2,
        )
        return {
            "message": f"User {cn} created",
            "dn": entry.dn,
        }

    def cmd_delete_user(self, args):
        """Delete a user from the directory.

        Accepts either 'dn' (for backwards compat with the command table)
        or 'sam_account_name'. If 'dn' is provided, we extract the CN
        and look up by sAMAccountName.
        """
        if not self.domain:
            raise RuntimeError("Server not started")

        sam = args.get('sam_account_name')
        dn = args.get('dn')

        if not sam and dn:
            # Try to extract CN from DN to use as sAMAccountName lookup
            # DN format: CN=username,OU=...,DC=...,DC=...
            for part in dn.split(','):
                part = part.strip()
                if part.upper().startswith('CN='):
                    sam = part[3:]
                    break

        if not sam:
            raise ValueError("'sam_account_name' or 'dn' is required")

        deleted = self.domain.user_manager.delete_user(sam)
        if not deleted:
            raise RuntimeError(f"User not found: {sam}")
        return {"message": f"User deleted: {sam}"}

    def cmd_set_password(self, args):
        """Change a user's password."""
        if not self.domain:
            raise RuntimeError("Server not started")

        sam = args.get('sam_account_name')
        dn = args.get('dn')
        new_password = args.get('password', '')

        if not sam and dn:
            for part in dn.split(','):
                part = part.strip()
                if part.upper().startswith('CN='):
                    sam = part[3:]
                    break

        if not sam:
            raise ValueError("'sam_account_name' or 'dn' is required")
        if not new_password:
            raise ValueError("'password' is required")

        success = self.domain.user_manager.set_password(sam, new_password)
        if not success:
            raise RuntimeError(f"User not found: {sam}")
        return {"message": f"Password changed for {sam}"}

    def cmd_list_groups(self, args):
        """List all groups."""
        if not self.domain:
            raise RuntimeError("Server not started")

        groups = self.domain.group_manager.list_groups()
        result = []
        for g in groups:
            d = g.to_dict()
            attrs = d.get("attributes", {})
            members = attrs.get("member", [])
            result.append({
                "dn": d.get("dn", ""),
                "cn": _first(attrs.get("cn")),
                "name": _first(attrs.get("cn")),
                "sam_account_name": _first(attrs.get("sAMAccountName")),
                "member_count": len(members),
                "members": members,
                "group_type": _first(attrs.get("groupType")),
                "object_class": attrs.get("objectClass", []),
            })
        return {
            "groups": result,
            "count": len(result),
        }

    def cmd_list_tree(self, args):
        """Return the full directory tree for visualization.

        Builds a hierarchical tree from the flat DIT entries by
        grouping each entry under its parent DN. Each node includes:
        - dn: the full distinguished name
        - name: the display name (RDN value or domain name for root)
        - type: 'domain', 'ou', 'container', 'user', 'group', or 'other'
        - children: list of child nodes
        """
        if not self.domain:
            raise RuntimeError("Server not started")

        from ad_simulator.directory.dn import parent_dn, rdn, parse_dn, normalize_dn

        entries = self.domain.dit.list_entries()

        # Build a lookup: normalized_dn -> node dict
        nodes = {}
        for entry in entries:
            dn_str = entry.dn
            dn_norm = normalize_dn(dn_str)

            # Determine the entry type from objectClass
            oc_values = [v.lower() for v in entry.get_attr("objectClass")]
            if "organizationalunit" in oc_values:
                entry_type = "ou"
            elif "container" in oc_values:
                entry_type = "container"
            elif "user" in oc_values or "person" in oc_values:
                entry_type = "user"
            elif "group" in oc_values:
                entry_type = "group"
            elif "domaindns" in oc_values or "domain" in oc_values:
                entry_type = "domain"
            else:
                entry_type = "other"

            # Extract display name from the RDN
            rdn_str = rdn(dn_str)
            if "=" in rdn_str:
                name = rdn_str.split("=", 1)[1]
            else:
                name = rdn_str or dn_str

            # For domain root, show the domain name
            if entry_type == "domain":
                parts = parse_dn(dn_str)
                dc_values = [v for a, v, _ in parts if a.upper() == "DC"]
                if dc_values:
                    name = ".".join(dc_values)

            # Extra attributes for detail display
            attrs = entry.to_dict().get("attributes", {})
            node_info = {
                "dn": dn_str,
                "name": name,
                "type": entry_type,
                "children": [],
            }

            # Add useful metadata based on type
            if entry_type == "user":
                node_info["sam_account_name"] = _first(attrs.get("sAMAccountName"))
                node_info["display_name"] = _first(attrs.get("displayName")) or name
                node_info["email"] = _first(attrs.get("mail"))
            elif entry_type == "group":
                members = attrs.get("member", [])
                node_info["sam_account_name"] = _first(attrs.get("sAMAccountName"))
                node_info["member_count"] = len(members)

            nodes[dn_norm] = node_info

        # Build the tree by linking children to parents
        root_nodes = []
        for dn_norm, node in nodes.items():
            p_dn = parent_dn(node["dn"])
            p_norm = normalize_dn(p_dn) if p_dn else ""

            if p_norm and p_norm in nodes:
                nodes[p_norm]["children"].append(node)
            else:
                root_nodes.append(node)

        # Sort children: containers/OUs first, then groups, then users
        type_order = {"domain": 0, "ou": 1, "container": 2, "group": 3, "user": 4, "other": 5}

        def sort_tree(node):
            node["children"].sort(key=lambda c: (type_order.get(c["type"], 9), c["name"].lower()))
            for child in node["children"]:
                sort_tree(child)

        for root in root_nodes:
            sort_tree(root)

        # If there's exactly one root, return it directly; otherwise wrap
        if len(root_nodes) == 1:
            return {"tree": root_nodes[0]}
        else:
            return {"tree": {
                "dn": self.domain.base_dn,
                "name": self.domain.domain_name,
                "type": "domain",
                "children": root_nodes,
            }}

    def cmd_add_group(self, args):
        """Add a group."""
        if not self.domain:
            raise RuntimeError("Server not started")

        name = args.get('name')
        if not name:
            raise ValueError("'name' is required")

        entry = self.domain.group_manager.create_group(
            cn=name,
            ou=args.get('ou', 'CN=Users'),
            description=args.get('description', ''),
            email=args.get('email') or None,
        )
        return {
            "message": f"Group {name} created",
            "dn": entry.dn,
        }

    def cmd_add_member(self, args):
        """Add a member to a group.

        Accepts 'group_dn' or 'group_cn' for the group, and 'member_dn'
        for the member. The GroupManager.add_member() takes a group CN,
        so we extract it from the DN if needed.
        """
        if not self.domain:
            raise RuntimeError("Server not started")

        group_cn = args.get('group_cn')
        group_dn = args.get('group_dn')
        member_dn = args.get('member_dn')

        if not member_dn:
            raise ValueError("'member_dn' is required")

        if not group_cn and group_dn:
            # Extract CN from group DN
            for part in group_dn.split(','):
                part = part.strip()
                if part.upper().startswith('CN='):
                    group_cn = part[3:]
                    break

        if not group_cn:
            raise ValueError("'group_cn' or 'group_dn' is required")

        success = self.domain.group_manager.add_member(group_cn, member_dn)
        if not success:
            raise RuntimeError(f"Group not found: {group_cn}")
        return {"message": "Member added to group"}

    def cmd_remove_member(self, args):
        """Remove a member from a group.

        Same CN extraction logic as cmd_add_member.
        """
        if not self.domain:
            raise RuntimeError("Server not started")

        group_cn = args.get('group_cn')
        group_dn = args.get('group_dn')
        member_dn = args.get('member_dn')

        if not member_dn:
            raise ValueError("'member_dn' is required")

        if not group_cn and group_dn:
            for part in group_dn.split(','):
                part = part.strip()
                if part.upper().startswith('CN='):
                    group_cn = part[3:]
                    break

        if not group_cn:
            raise ValueError("'group_cn' or 'group_dn' is required")

        success = self.domain.group_manager.remove_member(group_cn, member_dn)
        if not success:
            raise RuntimeError(f"Group not found or member not in group: {group_cn}")
        return {"message": "Member removed from group"}

    def cmd_fuzz_list(self, args):
        """List available fuzz scenarios."""
        try:
            from ad_simulator.fuzzer.scenarios import get_all_scenarios
            scenarios = get_all_scenarios()
            return {
                "scenarios": [
                    {
                        "name": s.name,
                        "description": s.description,
                        "category": s.category,
                    }
                    for s in scenarios
                ]
            }
        except ImportError:
            return {"scenarios": []}

    def cmd_fuzz_run(self, args):
        """Run fuzz scenarios."""
        if not self.domain:
            raise RuntimeError("Server not started")

        from ad_simulator.fuzzer.engine import FuzzerEngine

        engine = FuzzerEngine(self.domain)
        scenario_names = args.get('scenarios')

        if scenario_names:
            # Run specific scenarios by name
            results = []
            for name in scenario_names:
                result = engine.run_by_name(name)
                results.append(result)
        else:
            # Run all scenarios
            results = engine.run_all()

        return {
            "results": [
                {
                    "scenario_name": r.scenario_name,
                    "success": r.success,
                    "details": r.details,
                    "duration_ms": r.duration_ms,
                    "error": r.error,
                }
                for r in results
            ],
            "total": len(results),
            "passed": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
        }

    def cmd_save(self, args):
        """Save directory state to a JSON file."""
        if not self.domain:
            raise RuntimeError("Server not started")

        from ad_simulator.utils.persistence import save_directory

        path = args.get('path', 'ad_state.json')
        saved_path = save_directory(self.domain, path)
        return {"message": f"State saved to {saved_path}", "path": str(saved_path)}

    def cmd_load(self, args):
        """Load directory state from a JSON file.

        Replaces the current domain with the loaded one. If the server
        is running, the factory's domain reference is updated in-place.
        """
        from ad_simulator.utils.persistence import load_directory

        path = args.get('path', 'ad_state.json')
        loaded_domain = load_directory(path)

        if self.domain and self.factory:
            # Update the factory's domain reference so the running server
            # uses the loaded data
            self.domain = loaded_domain
            self.factory.domain = loaded_domain
        else:
            self.domain = loaded_domain

        stats = self.domain.get_stats()
        return {
            "message": f"State loaded from {path}",
            "domain": self.domain.domain_name,
            "base_dn": self.domain.base_dn,
            "users": stats['users'],
            "groups": stats['groups'],
            "ous": stats['ous'],
        }

    def cmd_get_log(self, args):
        """Get recent LDAP operation log from the server factory."""
        if not self.factory:
            return {"log": [], "count": 0}

        limit = args.get('limit', 100)
        all_entries = self.factory.operation_log
        # Return the most recent entries up to the limit
        entries = all_entries[-limit:] if len(all_entries) > limit else all_entries
        return {
            "log": entries,
            "count": len(entries),
            "total": len(all_entries),
        }


def main():
    """Main loop: read JSON commands from stdin, dispatch, write responses to stdout."""
    log("AD Simulator bridge starting...")
    bridge = ADSimBridge()

    # Signal ready
    send_response({"event": "ready", "data": {"version": "1.0.0"}})

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                send_response({"ok": False, "error": f"Invalid JSON: {e}"})
                continue

            response = bridge.handle_command(msg)
            send_response(response)
    except KeyboardInterrupt:
        log("Bridge interrupted")
    except EOFError:
        log("Bridge stdin closed")
    finally:
        # Cleanup
        if bridge.running:
            try:
                bridge.cmd_stop({})
            except Exception:
                pass
        log("Bridge exiting")


if __name__ == '__main__':
    main()
