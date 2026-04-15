"""Directory persistence — save and restore the DIT to/from a JSON file.

Provides functions to serialise the entire directory state (all entries
including users, groups, OUs) to a local JSON file and restore it later.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ad_simulator.ad.domain import ADDomain

# Default save file location (relative to working directory)
DEFAULT_SAVE_FILE = "ad_simulator_directory.json"


def save_directory(domain: ADDomain, path: str | Path | None = None) -> Path:
    """Save the entire directory state to a JSON file.

    Args:
        domain: The :class:`ADDomain` instance to save.
        path: File path to save to. Defaults to :data:`DEFAULT_SAVE_FILE`.

    Returns:
        The :class:`Path` where the file was saved.
    """
    save_path = Path(path) if path else Path(DEFAULT_SAVE_FILE)

    data = {
        "version": 1,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "domain_name": domain.domain_name,
        "base_dn": domain.base_dn,
        "entry_count": domain.dit.entry_count,
        "entries": domain.dit.export_entries(),
    }

    save_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return save_path


def load_directory(path: str | Path | None = None) -> ADDomain:
    """Load a directory state from a JSON file.

    Creates a new :class:`ADDomain` and populates its DIT with the
    saved entries. Does **not** call :meth:`ADDomain.setup` — the
    saved entries already include the domain structure.

    Args:
        path: File path to load from. Defaults to :data:`DEFAULT_SAVE_FILE`.

    Returns:
        A new :class:`ADDomain` with the restored directory.

    Raises:
        FileNotFoundError: If the save file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    load_path = Path(path) if path else Path(DEFAULT_SAVE_FILE)

    raw = load_path.read_text(encoding="utf-8")
    data = json.loads(raw)

    domain_name = data.get("domain_name", "testlab.local")
    domain = ADDomain(domain_name=domain_name)

    # Import entries into the DIT (replaces any existing entries)
    entries = data.get("entries", [])
    domain.dit.import_entries(entries)

    return domain


def save_file_exists(path: str | Path | None = None) -> bool:
    """Check whether a save file exists.

    Args:
        path: File path to check. Defaults to :data:`DEFAULT_SAVE_FILE`.

    Returns:
        ``True`` if the file exists, ``False`` otherwise.
    """
    check_path = Path(path) if path else Path(DEFAULT_SAVE_FILE)
    return check_path.is_file()


def get_save_file_info(path: str | Path | None = None) -> dict | None:
    """Get metadata about a save file without loading all entries.

    Args:
        path: File path to inspect. Defaults to :data:`DEFAULT_SAVE_FILE`.

    Returns:
        A dict with ``saved_at``, ``domain_name``, ``entry_count`` keys,
        or ``None`` if the file doesn't exist or is invalid.
    """
    check_path = Path(path) if path else Path(DEFAULT_SAVE_FILE)
    if not check_path.is_file():
        return None

    try:
        raw = check_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return {
            "saved_at": data.get("saved_at", "unknown"),
            "domain_name": data.get("domain_name", "unknown"),
            "entry_count": data.get("entry_count", 0),
            "file_path": str(check_path.resolve()),
        }
    except (json.JSONDecodeError, OSError):
        return None
