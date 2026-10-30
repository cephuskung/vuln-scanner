"""Provider-neutral installed-software inventory contract.

SentriX's Software Scan assesses an *inventory*: a list of installed
applications plus an honest description of how complete that list is. This
module defines that contract so the collection mechanism can change without
touching the assessment code:

  * ``LocalWindowsInventory`` (scanner/windows_inventory.py) reads the Windows
    registry of the computer that is running the SentriX server process.
  * A future authenticated endpoint agent, or a remote-inventory integration,
    only has to implement ``InventoryProvider.collect()`` and return an
    ``InventoryResult``. ``host.scope`` says whose software it is, so the UI and
    reports never claim that the browser user's machine (or any other machine)
    was inspected when it was not.

Nothing in here talks to the registry, the network or the database.
"""
from __future__ import annotations

import platform
from dataclasses import dataclass, field, asdict
from typing import Optional, Protocol, runtime_checkable

# host.scope values. Only SERVER_LOCAL is implemented today.
SCOPE_SERVER_LOCAL = "server-local"      # the computer running the SentriX server process
SCOPE_AGENT = "agent"                    # reserved: an authenticated endpoint agent reporting for its own machine

# InventoryResult.status values
STATUS_COMPLETE = "complete"             # every registry location was readable (or legitimately absent)
STATUS_PARTIAL = "partial"               # some locations were inaccessible or failed - the list may be incomplete
STATUS_FAILED = "failed"                 # nothing could be read
STATUS_UNSUPPORTED = "unsupported"       # wrong operating system for this provider

# LocationStatus.status values
LOC_OK = "ok"
LOC_NOT_FOUND = "not_found"
LOC_ACCESS_DENIED = "access_denied"
LOC_ERROR = "error"


@dataclass
class InventoryEntry:
    """One distinct installed application (after de-duplication)."""
    name: str
    publisher: Optional[str] = None
    version: Optional[str] = None
    install_date: Optional[str] = None            # ISO date (YYYY-MM-DD) when the source held a valid one
    sources: list = field(default_factory=list)   # e.g. ["HKLM 64-bit", "HKLM 32-bit (WOW6432Node)"]
    missing: list = field(default_factory=list)   # fields the source did not provide: "version", "publisher"
    system_component: bool = False                # flagged hidden from Programs and Features by its installer

    @property
    def collection_status(self):
        return "partial" if self.missing else "complete"


@dataclass
class LocationStatus:
    """What happened when one inventory source (registry location) was read."""
    label: str
    status: str                                   # LOC_*
    entries_read: int = 0
    invalid: int = 0
    detail: Optional[str] = None


@dataclass
class InventoryResult:
    provider: str
    status: str                                   # STATUS_*
    host: dict = field(default_factory=dict)      # computer_name, os, scope
    entries: list = field(default_factory=list)   # [InventoryEntry]
    locations: list = field(default_factory=list) # [LocationStatus]
    skipped: dict = field(default_factory=dict)   # counters: updates, nameless, invalid_values, duplicates_merged
    notes: list = field(default_factory=list)     # limitations the user must be told about
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@runtime_checkable
class InventoryProvider(Protocol):
    """Anything that can report the installed software of ONE computer."""
    name: str

    def collect(self) -> InventoryResult:  # pragma: no cover - interface
        ...


def local_host_info(os_description=None):
    """The computer SentriX is running on, as shown in the UI before and after a
    scan. ``supported`` says whether this server can run the local Windows
    software inventory / Defender scan."""
    system = platform.system()
    return {
        "computer_name": platform.node() or "unknown",
        "system": system,
        "os": os_description or platform.platform(),
        "supported": system == "Windows",
        "scope": SCOPE_SERVER_LOCAL,
    }
