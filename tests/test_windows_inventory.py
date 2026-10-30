"""Windows registry software inventory: parsing, duplicates, missing metadata, registry access errors and
unsupported operating systems. The registry is faked (and, for WinregBackend, so is the winreg module), so these
run on any OS - they do NOT prove behaviour on a real Windows registry."""
import inspect
import sys
import types

import pytest

import scanner.windows_inventory as wi
from scanner.windows_inventory import (
    collect_windows_inventory, parse_entry, parse_install_date, RegistryAccessDenied, RegistryKeyNotFound, RegistryError,
    LocalWindowsInventory, WinregBackend,
)


class FakeRegistry:
    """locations: {(hive, view): {subkey: values-dict | Exception} | Exception}"""

    def __init__(self, locations):
        self.locations = locations

    def subkeys(self, hive, view):
        loc = self.locations.get((hive, view), RegistryKeyNotFound())
        if isinstance(loc, Exception):
            raise loc
        return list(loc)

    def values(self, hive, view, subkey):
        v = self.locations[(hive, view)][subkey]
        if isinstance(v, Exception):
            raise v
        return v


def app(name, version="1.0", publisher="Acme", date="20240115", **extra):
    d = {"DisplayName": name, "DisplayVersion": version, "Publisher": publisher, "InstallDate": date}
    d.update(extra)
    return {k: v for k, v in d.items() if v is not None}


def collect(locations):
    return collect_windows_inventory(FakeRegistry(locations), platform_system="Windows")


# ---------------------------------------------------------------- collection & fields
def test_collects_name_publisher_version_install_date_and_source():
    r = collect({("HKLM", 64): {"a": app("7-Zip 23.01 (x64)", "23.01", "Igor Pavlov", "20240301")},
                 ("HKLM", 32): RegistryKeyNotFound(), ("HKCU", 64): RegistryKeyNotFound(), ("HKCU", 32): RegistryKeyNotFound()})
    assert r.status == "complete" and len(r.entries) == 1
    e = r.entries[0]
    assert (e.name, e.publisher, e.version, e.install_date) == ("7-Zip 23.01 (x64)", "Igor Pavlov", "23.01", "2024-03-01")
    assert e.sources == ["HKLM 64-bit"] and e.collection_status == "complete"
    assert r.host["scope"] == "server-local" and r.provider == "windows-registry"


def test_all_four_locations_are_read_including_current_user():
    r = collect({("HKLM", 64): {"a": app("A")}, ("HKLM", 32): {"b": app("B")},
                 ("HKCU", 64): {"c": app("C")}, ("HKCU", 32): {"d": app("D")}})
    assert [e.name for e in r.entries] == ["A", "B", "C", "D"]
    assert [l.label for l in r.locations] == [l[2] for l in wi.LOCATIONS]
    assert any("HKCU" in l.label and "SentriX process user" in l.label for l in r.locations)


def test_duplicates_across_32_and_64_bit_views_are_merged_and_counted():
    r = collect({("HKLM", 64): {"a": app("Git", "2.43.0", None, None)},
                 ("HKLM", 32): {"a": app("Git", "2.43.0", "The Git Community", "20240102")}})
    assert len(r.entries) == 1 and r.skipped["duplicates_merged"] == 1
    e = r.entries[0]
    assert e.sources == ["HKLM 64-bit", "HKLM 32-bit (WOW6432Node)"]
    assert e.publisher == "The Git Community" and e.install_date == "2024-01-02"      # filled from the other view
    assert "publisher" not in e.missing


def test_duplicates_are_case_insensitive_but_different_versions_stay_separate():
    r = collect({("HKLM", 64): {"a": app("Python", "3.11.4"), "b": app("PYTHON", "3.11.4"), "c": app("Python", "3.12.0")}})
    assert sorted(e.version for e in r.entries) == ["3.11.4", "3.12.0"] and r.skipped["duplicates_merged"] == 1


def test_missing_version_and_publisher_are_recorded_not_invented():
    r = collect({("HKLM", 64): {"a": app("Mystery App", None, None, None)}})
    e = r.entries[0]
    assert e.version is None and e.publisher is None and e.install_date is None
    assert set(e.missing) == {"version", "publisher"} and e.collection_status == "partial"


def test_entries_without_a_name_and_updates_are_counted_not_listed():
    r = collect({("HKLM", 64): {
        "a": {"DisplayVersion": "1.0"}, "b": {"DisplayName": "   "},
        "c": app("Security Update for Microsoft Office (KB5002345)"), "d": app("Some Hotfix", ParentKeyName="Windows"),
        "e": app("Patch", ReleaseType="Hotfix"), "f": app("Real App")}})
    assert [e.name for e in r.entries] == ["Real App"]
    assert r.skipped["nameless"] == 2 and r.skipped["updates"] == 3


def test_invalid_values_are_handled_without_crashing():
    r = collect({("HKLM", 64): {
        "a": {"DisplayName": "Dword Version", "DisplayVersion": 12345, "Publisher": b"bytes"},
        "b": app("Bad Date", date="not-a-date"), "c": app("Ctrl\x00Chars\nName", "1.0"),
        "d": app("X" * 400, "1.0"), "e": app("Odd Date", date="20241345")}})
    by = {e.name[:12]: e for e in r.entries}
    assert by["Dword Versio"].version is None and "version" in by["Dword Versio"].missing
    assert r.skipped["invalid_values"] == 2                                  # the DWORD version and the bytes publisher
    assert by["Bad Date"].install_date is None and by["Odd Date"].install_date is None
    assert any(e.name == "Ctrl Chars Name" for e in r.entries)               # control characters removed
    assert max(len(e.name) for e in r.entries) <= 255


def test_install_date_parsing():
    assert parse_install_date("20240229") == "2024-02-29"
    assert parse_install_date("2024/03/05") == "2024-03-05" and parse_install_date("2024-03-05") == "2024-03-05"
    for bad in ("20230229", "13/05/2024", "", None, 20240101, "2024"):
        assert parse_install_date(bad) is None


def test_system_component_flag_is_kept():
    e, _ = parse_entry(app("Hidden Runtime", SystemComponent=1))
    assert e.system_component is True


# ---------------------------------------------------------------- registry errors
def test_access_denied_on_one_location_gives_partial_and_a_note():
    r = collect({("HKLM", 64): {"a": app("A")}, ("HKLM", 32): RegistryAccessDenied("denied"),
                 ("HKCU", 64): RegistryKeyNotFound(), ("HKCU", 32): RegistryKeyNotFound()})
    assert r.status == "partial" and [e.name for e in r.entries] == ["A"]
    denied = [l for l in r.locations if l.status == "access_denied"]
    assert len(denied) == 1 and "access denied" in denied[0].detail
    assert any("may be missing applications" in n for n in r.notes)


def test_unexpected_registry_error_is_contained():
    r = collect({("HKLM", 64): {"a": app("A")}, ("HKLM", 32): RegistryError("boom"), ("HKCU", 64): ValueError("weird")})
    assert r.status == "partial" and {l.status for l in r.locations} >= {"ok", "error"}
    assert "boom" not in " ".join(l.detail or "" for l in r.locations)       # internals are not echoed, only the type


def test_unreadable_single_entry_is_skipped_and_flagged_partial():
    r = collect({("HKLM", 64): {"a": app("Good"), "b": RegistryAccessDenied("x"), "c": RegistryError("y")}})
    assert [e.name for e in r.entries] == ["Good"] and r.status == "partial"
    assert "could not be read and were skipped" in r.locations[0].detail


def test_nothing_readable_is_failed_with_a_reason():
    r = collect({("HKLM", 64): RegistryAccessDenied("x"), ("HKLM", 32): RegistryAccessDenied("x"),
                 ("HKCU", 64): RegistryError("x"), ("HKCU", 32): RegistryKeyNotFound()})
    assert r.status == "failed" and r.entries == [] and "No installed-software registry location" in r.error


def test_missing_keys_alone_do_not_make_the_inventory_partial():
    r = collect({("HKLM", 64): {"a": app("A")}})
    assert r.status == "complete"


def test_readable_but_empty_registry_says_so():
    r = collect({("HKLM", 64): {}, ("HKLM", 32): {}})
    assert r.status == "complete" and r.entries == [] and any("listed no installed applications" in n for n in r.notes)


# ---------------------------------------------------------------- unsupported OS / limitations
@pytest.mark.parametrize("system", ["Linux", "Darwin"])
def test_non_windows_is_unsupported_with_a_clear_message(system):
    r = collect_windows_inventory(platform_system=system)
    assert r.status == "unsupported" and r.entries == [] and system in r.error and "only works on Windows" in r.error


def test_provider_object_reports_unsupported_too():
    r = LocalWindowsInventory(platform_system="Linux").collect()
    assert r.status == "unsupported" and LocalWindowsInventory.name == "windows-registry"


def test_limitations_are_always_stated():
    r = collect({("HKLM", 64): {"a": app("A")}})
    text = " ".join(r.notes)
    assert "Portable applications" in text and "Microsoft Store" in text and "other Windows accounts" in text


# ---------------------------------------------------------------- the real backend, against a fake winreg
class FakeWinreg(types.ModuleType):
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 0x20019, 0x100, 0x200
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER = "HKLM", "HKCU"

    def __init__(self):
        super().__init__("winreg")
        self.opened = []
        self.tree = {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall": ["App1"],
                     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\App1":
                         {"DisplayName": "App One", "DisplayVersion": "2.0", "Publisher": "Pub"}}

    class _Key:
        def __init__(self, node):
            self.node = node

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def OpenKey(self, root, path, reserved, flags):
        self.opened.append((root, path, flags))
        if path not in self.tree:
            raise FileNotFoundError(path)
        return self._Key(self.tree[path])

    def EnumKey(self, key, i):
        try:
            return key.node[i]
        except IndexError:
            raise OSError(259, "no more")

    def QueryValueEx(self, key, name):
        if name not in key.node:
            raise FileNotFoundError(name)
        return key.node[name], 1


def test_winreg_backend_opens_keys_read_only_with_the_right_registry_views(monkeypatch):
    fake = FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fake)
    r = collect_windows_inventory(WinregBackend(), platform_system="Windows")
    assert [e.name for e in r.entries] == ["App One"]
    flags = {(root, f) for root, _p, f in fake.opened}
    assert ("HKLM", fake.KEY_READ | fake.KEY_WOW64_64KEY) in flags and ("HKLM", fake.KEY_READ | fake.KEY_WOW64_32KEY) in flags
    assert ("HKCU", fake.KEY_READ | fake.KEY_WOW64_64KEY) in flags
    assert all(f & ~(fake.KEY_READ | fake.KEY_WOW64_64KEY | fake.KEY_WOW64_32KEY) == 0 for _r, _p, f in fake.opened)


def test_winreg_backend_maps_permission_errors(monkeypatch):
    fake = FakeWinreg()
    fake.OpenKey = lambda *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
    monkeypatch.setitem(sys.modules, "winreg", fake)
    r = collect_windows_inventory(WinregBackend(), platform_system="Windows")
    assert r.status == "failed" and all(l.status == "access_denied" for l in r.locations)


def _code_only(module):
    """Module source with docstrings removed (they legitimately say what is NOT done)."""
    import ast
    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body \
                and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant) \
                and isinstance(node.body[0].value.value, str):
            node.body = node.body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def test_inventory_modules_never_write_the_registry_or_run_commands():
    """Static guard for the Software Scan rules: no Win32_Product, no registry writes, no subprocess/uninstall."""
    source = _code_only(wi) + _code_only(sys.modules["scanner.inventory"])
    for forbidden in ("Win32_Product", "KEY_WRITE", "KEY_ALL_ACCESS", "SetValue", "DeleteKey", "CreateKey", "subprocess",
                      "os.system", "msiexec", "UninstallString", "wmic"):
        assert forbidden not in source, forbidden
    assert "KEY_READ" in source
