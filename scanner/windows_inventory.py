"""Windows installed-software inventory, read from the registry (read-only).

Scope: the computer running the SentriX server process. This module reads the
standard "Uninstall" registry keys:

    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall     (64-bit view)
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall     (32-bit view = WOW6432Node)
    HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall     (64-bit view, SentriX process user)
    HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall     (32-bit view, SentriX process user)

and collects DisplayName, Publisher, DisplayVersion and InstallDate.

What it deliberately does NOT do (requirement of the Software Scan):
  * no ``Win32_Product`` / WMI (querying it can trigger MSI repair/reconfiguration),
  * no registry writes - keys are opened with KEY_READ only,
  * no uninstall command is executed and nothing is installed,
  * no subprocess of any kind.

What it cannot see, and says so in ``InventoryResult.notes``: portable
applications, anything without an Uninstall entry, Microsoft Store (MSIX/AppX)
packages, and software installed per-user for OTHER accounts (HKCU is the hive of
the SentriX process user only).

The registry itself is reached through a small backend interface so the parsing,
de-duplication and error handling are testable on any operating system with a
fake backend; ``WinregBackend`` is the real implementation (Windows only).
"""
from __future__ import annotations

import logging
import platform
import re
from datetime import date

from scanner.inventory import (
    InventoryEntry, InventoryResult, LocationStatus, SCOPE_SERVER_LOCAL, local_host_info,
    STATUS_COMPLETE, STATUS_PARTIAL, STATUS_FAILED, STATUS_UNSUPPORTED,
    LOC_OK, LOC_NOT_FOUND, LOC_ACCESS_DENIED, LOC_ERROR,
)

logger = logging.getLogger(__name__)

UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

# (hive, registry view, label shown to the user)
LOCATIONS = [
    ("HKLM", 64, "HKLM 64-bit"),
    ("HKLM", 32, "HKLM 32-bit (WOW6432Node)"),
    ("HKCU", 64, "HKCU 64-bit (SentriX process user)"),
    ("HKCU", 32, "HKCU 32-bit (SentriX process user)"),
]

# The only values ever read from an Uninstall subkey.
WANTED_VALUES = ("DisplayName", "DisplayVersion", "Publisher", "InstallDate",
                 "SystemComponent", "ParentKeyName", "ReleaseType")

MAX_NAME = 255
MAX_FIELD = 120
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_WS_RE = re.compile(r"\s+")
# Windows/Office patches and updates are not applications; they are counted, not listed.
_UPDATE_RELEASE_TYPES = {"security update", "update rollup", "hotfix", "service pack", "update", "critical update"}
_UPDATE_NAME_RE = re.compile(r"^(?:security update|hotfix|cumulative update|update rollup|update)\b.*\bfor\b|\(KB\d{6,8}\)",
                             re.IGNORECASE)

NOTES = [
    "This inventory comes from the Windows registry 'Uninstall' keys. Portable applications, software without an "
    "uninstall entry, Microsoft Store (MSIX/AppX) packages and components that register nowhere are NOT captured, "
    "so it is not a complete list of everything on the computer.",
    "Per-user installs are read only for the account running the SentriX server process; software installed for "
    "other Windows accounts is not included.",
]


# ---------------------------------------------------------------------------
# Registry access interface
# ---------------------------------------------------------------------------
class RegistryKeyNotFound(Exception):
    """The key does not exist (legitimate: e.g. no per-user 32-bit uninstall key)."""


class RegistryAccessDenied(Exception):
    """The key exists but this process may not read it."""


class RegistryError(Exception):
    """Any other registry failure."""


class WinregBackend:
    """Read-only access to the Windows registry via the standard-library ``winreg``."""

    def __init__(self):
        import winreg                      # ImportError on non-Windows is handled by the caller
        self._w = winreg

    def _open(self, hive, view, subkey=None):
        w = self._w
        flags = w.KEY_READ | (w.KEY_WOW64_64KEY if view == 64 else w.KEY_WOW64_32KEY)   # read-only: never KEY_WRITE
        root = w.HKEY_LOCAL_MACHINE if hive == "HKLM" else w.HKEY_CURRENT_USER
        path = UNINSTALL_PATH + ("\\" + subkey if subkey else "")
        try:
            return w.OpenKey(root, path, 0, flags)
        except FileNotFoundError as e:
            raise RegistryKeyNotFound(str(e)) from e
        except PermissionError as e:
            raise RegistryAccessDenied(str(e)) from e
        except OSError as e:
            if getattr(e, "winerror", None) == 5:
                raise RegistryAccessDenied(str(e)) from e
            raise RegistryError(str(e)) from e

    def subkeys(self, hive, view):
        w = self._w
        names = []
        with self._open(hive, view) as key:
            i = 0
            while True:
                try:
                    names.append(w.EnumKey(key, i))
                except OSError:            # no more items
                    break
                i += 1
        return names

    def values(self, hive, view, subkey):
        w = self._w
        out = {}
        with self._open(hive, view, subkey) as key:
            for name in WANTED_VALUES:
                try:
                    out[name] = w.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    continue               # value simply not present
                except OSError as e:
                    if getattr(e, "winerror", None) == 5:
                        raise RegistryAccessDenied(str(e)) from e
                    raise RegistryError(str(e)) from e
        return out


# ---------------------------------------------------------------------------
# Value parsing
# ---------------------------------------------------------------------------
def _clean_text(value, limit=MAX_FIELD):
    """Printable single-line text, or None. Non-string registry types (DWORD,
    binary, multi-string) are not trusted as text and return None."""
    if not isinstance(value, str):
        return None
    text = _WS_RE.sub(" ", _CONTROL_RE.sub(" ", value)).strip()
    return text[:limit] or None


def parse_install_date(value):
    """ISO date from the registry's usual YYYYMMDD (or YYYY/MM/DD, YYYY-MM-DD); None when absent or invalid."""
    text = _clean_text(value, 20)
    if not text:
        return None
    m = re.fullmatch(r"(\d{4})[-/]?(\d{2})[-/]?(\d{2})", text)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
    except ValueError:
        return None


def _is_update(name, values):
    if _clean_text(values.get("ParentKeyName")):
        return True
    if (_clean_text(values.get("ReleaseType")) or "").lower() in _UPDATE_RELEASE_TYPES:
        return True
    return bool(_UPDATE_NAME_RE.search(name))


def _flag(value):
    return value == 1 or (isinstance(value, str) and value.strip() == "1")


def parse_entry(values):
    """(entry | None, reason). reason is 'nameless' | 'update' | None.
    Counts of unusable field values are returned via the entry's ``missing`` list."""
    raw_name = values.get("DisplayName")
    name = _clean_text(raw_name, MAX_NAME)
    if not name:
        return None, "nameless"
    if _is_update(name, values):
        return None, "update"
    version = _clean_text(values.get("DisplayVersion"))
    publisher = _clean_text(values.get("Publisher"))
    missing = [m for m, v in (("version", version), ("publisher", publisher)) if not v]
    return InventoryEntry(
        name=name, publisher=publisher, version=version,
        install_date=parse_install_date(values.get("InstallDate")),
        missing=missing, system_component=_flag(values.get("SystemComponent")),
    ), None


def _invalid_value_count(values):
    """Values present but of an unusable registry type (e.g. a DWORD DisplayVersion)."""
    bad = 0
    for k in ("DisplayName", "DisplayVersion", "Publisher"):
        if k in values and values[k] is not None and not isinstance(values[k], str):
            bad += 1
    return bad


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------
def collect_windows_inventory(backend=None, platform_system=None):
    """Read, parse and de-duplicate installed applications.

    backend: object with ``subkeys(hive, view)`` and ``values(hive, view, subkey)``;
             None = the real Windows registry. platform_system: override for tests.
    Never raises for registry problems - they become LocationStatus entries and
    an overall 'partial' / 'failed' status.
    """
    system = platform_system or platform.system()
    host = local_host_info(describe_windows_os() if system == "Windows" and backend is None else None)
    host["scope"] = SCOPE_SERVER_LOCAL
    result = InventoryResult(provider="windows-registry", status=STATUS_UNSUPPORTED, host=host,
                             skipped={"updates": 0, "nameless": 0, "invalid_values": 0, "duplicates_merged": 0})

    if backend is None:
        if system != "Windows":
            result.error = (f"The registry software inventory only works on Windows; this SentriX server is running "
                            f"{system or 'an unknown operating system'}.")
            return result
        try:
            backend = WinregBackend()
        except ImportError:
            result.error = "The Windows registry module (winreg) is not available in this Python installation."
            return result

    merged = {}                                    # (name.lower, version.lower) -> InventoryEntry
    for hive, view, label in LOCATIONS:
        loc = LocationStatus(label=label, status=LOC_OK)
        result.locations.append(loc)
        try:
            subkeys = backend.subkeys(hive, view)
        except RegistryKeyNotFound:
            loc.status, loc.detail = LOC_NOT_FOUND, "key not present on this system"
            continue
        except RegistryAccessDenied:
            loc.status = LOC_ACCESS_DENIED
            loc.detail = "access denied - run the SentriX server with rights to read this registry location"
            continue
        except Exception as e:                     # RegistryError or anything unexpected: never abort the inventory
            loc.status, loc.detail = LOC_ERROR, f"could not be read ({e.__class__.__name__})"
            logger.warning("Registry location %s unreadable: %s", label, e)
            continue

        unreadable = 0
        for sub in subkeys:
            try:
                values = backend.values(hive, view, sub)
            except RegistryAccessDenied:
                unreadable += 1
                loc.invalid += 1
                continue
            except Exception:
                unreadable += 1
                loc.invalid += 1
                continue
            bad = _invalid_value_count(values)
            if bad:
                result.skipped["invalid_values"] += bad
            entry, reason = parse_entry(values)
            if entry is None:
                if reason == "update":
                    result.skipped["updates"] += 1
                else:
                    result.skipped["nameless"] += 1
                continue
            loc.entries_read += 1
            entry.sources = [label]
            key = (entry.name.casefold(), (entry.version or "").casefold())
            existing = merged.get(key)
            if existing is None:
                merged[key] = entry
                continue
            result.skipped["duplicates_merged"] += 1
            if label not in existing.sources:
                existing.sources.append(label)
            existing.publisher = existing.publisher or entry.publisher
            existing.install_date = existing.install_date or entry.install_date
            existing.system_component = existing.system_component and entry.system_component
            existing.missing = [m for m in existing.missing
                                if not ((m == "publisher" and existing.publisher) or (m == "version" and existing.version))]
        if unreadable:
            loc.detail = f"{unreadable} entr{'y' if unreadable == 1 else 'ies'} could not be read and were skipped"

    result.entries = sorted(merged.values(), key=lambda e: (e.name.casefold(), e.version or ""))
    # 'not_found' is legitimate (e.g. no per-user 32-bit key); denied/errored locations or unreadable
    # entries mean the list may be incomplete.
    problems = [l for l in result.locations if l.status in (LOC_ACCESS_DENIED, LOC_ERROR) or l.invalid]
    if not any(l.status == LOC_OK for l in result.locations):
        result.status = STATUS_FAILED
        result.error = ("No installed-software registry location could be read: "
                        + "; ".join(f"{l.label}: {l.status.replace('_', ' ')}" for l in result.locations) + ".")
    elif problems:
        result.status = STATUS_PARTIAL
    else:
        result.status = STATUS_COMPLETE
    if result.status == STATUS_PARTIAL:
        result.notes.append("Some registry locations or entries could not be read (see the collection details), so "
                            "this inventory may be missing applications.")
    if result.status in (STATUS_COMPLETE, STATUS_PARTIAL) and not result.entries:
        result.notes.append("The registry was readable but listed no installed applications.")
    result.notes.extend(NOTES)
    return result


class LocalWindowsInventory:
    """InventoryProvider for the computer running the SentriX server process."""
    name = "windows-registry"

    def __init__(self, backend=None, platform_system=None):
        self._backend = backend
        self._platform_system = platform_system

    def collect(self):
        return collect_windows_inventory(self._backend, self._platform_system)


# ---------------------------------------------------------------------------
# OS description (shown so the user sees exactly which computer/OS is inspected)
# ---------------------------------------------------------------------------
def describe_windows_os():
    """e.g. 'Windows 11 Pro 23H2 (build 22631)'. Best effort; falls back to platform.platform().
    Windows 11 still reports ProductName 'Windows 10 ...' in the registry, so the build number decides."""
    fallback = platform.platform()
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            def get(name):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return None
            product = _clean_text(get("ProductName")) or "Windows"
            build = _clean_text(get("CurrentBuildNumber") or get("CurrentBuild"), 12)
            display = _clean_text(get("DisplayVersion") or get("ReleaseId"), 12)
        if build and build.isdigit() and int(build) >= 22000:
            product = product.replace("Windows 10", "Windows 11")
        return " ".join(p for p in (product, display) if p) + (f" (build {build})" if build else "")
    except Exception:
        return fallback
