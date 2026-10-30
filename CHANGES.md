# SentriX - Windows Software Inventory + Defender Threat Scan (change log)

Revises the existing project; nothing was rebuilt. Network Scan, auth, the data model, scan lifecycle,
reports/PDF, CVE/NVD/risk/remediation code and the Linux System Scan (local + SSH) are preserved.

## New files
| File | Why |
|---|---|
| `scanner/inventory.py` | Provider-neutral inventory contract (`InventoryProvider`, `InventoryResult`) so a future agent/remote inventory can plug in; local host description |
| `scanner/windows_inventory.py` | Read-only Windows registry inventory (HKLM 64/32, HKCU 64/32), dedupe, error handling; injectable registry backend |
| `scanner/software_inventory_scan.py` | "Scan this computer": inventory -> existing `assess_item()` engine, bounded NVD work, persistence |
| `scanner/windows_defender.py` | Fixed PowerShell operations, controlled subprocess runner, path validation, protection classification, detection parsing/attribution, completion evidence |
| `scanner/windows_system_scan.py` | Windows System Scan orchestration and honest outcomes |
| `tests/test_windows_inventory.py`, `tests/test_software_inventory_scan.py`, `tests/test_windows_defender.py`, `tests/test_windows_system_scan.py` | 186 new tests |

## Modified files
| File | Change |
|---|---|
| `database/schema.sql` | Additive: 5 nullable columns on `software_inventory`; new `threat_findings` table (idempotent) |
| `database/db.py` | Persist new inventory columns; `save/get/count_threat_findings`; `system-windows` counted as a *system* scan in KPI SQL; `findings_first` ordering; scan progress in status |
| `scanner/jobs.py` | `submit_local_software_scan`, `submit_windows_system_scan`, confirmation/path/admin/OS rules; OS-based backend selection in `submit_system_scan` (Linux path unchanged) |
| `vulnerability/software_catalog.py` | Registry-name normalisation (`normalize_inventory_entry`), Python registry-version decoding, 13 common Windows products added to the catalogue |
| `web/app.py` | Routes `/software-scan/local`, `/system-scan/windows`, `/api/windows-defender/status`; extra data for new scan kinds; progress in `/scan/<id>/status` |
| `web/templates/scan.html`, `_scan_extra.html`, `scan_details.html` | Scan this computer UI (manual lookup kept as secondary), Windows Defender panel, inventory/threat/outcome views, filters, scope notices |
| `app/pdf_report.py` | Inventory and Defender sections, scope text |
| `tests/conftest.py` | Autouse fixture pinning the host OS to Linux for legacy tests (so they pass on any OS) |
| `README.md`, `.env.example` | Windows docs, config, install/migration/verification, limitations |
