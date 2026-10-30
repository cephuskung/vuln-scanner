import logging
import math
import os
import re
import secrets
import shutil
import sys
import networkx as nx
import psycopg2.errors
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, flash, send_file, abort
)
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db
from risk.contextual_risk import calculate_contextual_risk, priority_label
from vulnerability.cwe_reference import cwe_name
from app.pdf_report import build_pdf_report
from app.executive_report import build_executive_report
from assets.asset_intel import get_asset_profile
from attack_path.graph_builder import build_attack_graph
from attack_path.path_finder import find_all_critical_paths
from attack_path.centrality import rank_choke_points
from posture.posture_calc import snapshot_posture
from web.auth import login_manager, User, admin_required
from web.scheduler import start_scheduler
from scanner.jobs import (
    submit_scan, validate_scan_target, submit_software_scan, submit_system_scan, ScanRejected,
    submit_local_software_scan, submit_windows_system_scan, defender_status, local_host_os,
)
from scanner.inventory import local_host_info
from scanner.windows_inventory import describe_windows_os
from scanner.windows_defender import EXPECTED_DURATION
from vulnerability.software_catalog import (
    normalize_software, parse_bulk, catalog_entries, SoftwareInputError, MAX_ITEMS as MAX_SOFTWARE_ITEMS,
)
logger = logging.getLogger(__name__)
app = Flask(__name__)
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    # No hard-coded fallback: a published default would let anyone forge
    # session cookies. A random per-process key is safe but means sessions
    # end on restart - set SECRET_KEY for a stable one.
    _secret_key = secrets.token_hex(32)
    logger.warning("SECRET_KEY is not set; using a random per-process key (sessions will not survive a restart).")
app.secret_key = _secret_key
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
login_manager.init_app(app)
csrf = CSRFProtect(app)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")
EXPOSURE_VALUES = {"INTERNAL", "EXTERNAL"}
LEVEL_VALUES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
MIN_SCHEDULE_MINUTES, MAX_SCHEDULE_MINUTES = 15, 525600


def _is_admin():
    return current_user.is_authenticated and current_user.role == "admin"


def _owner_scope():
    """None = unrestricted (admin); otherwise the user id whose scans may be shown."""
    return None if _is_admin() else int(current_user.id)


def _can_access(created_by):
    return _is_admin() or (created_by is not None and created_by == int(current_user.id))


def _get_scan_or_404(scan_id):
    """Scan row if it exists AND belongs to the current user (admins see
    all). 404 rather than 403 so other users' scan ids aren't confirmable."""
    row = db.get_scan(scan_id)
    if row is None or not _can_access(row.get("created_by")):
        abort(404)
    return row


def _selectable_assets():
    """Assets the current user may attach a Software Scan to: everything for
    admins, otherwise only assets they have scanned themselves (other users'
    asset names and IPs are not disclosed)."""
    return db.get_assets() if _is_admin() else db.get_assets_for_owner(int(current_user.id))


def _scan_extra(scan_row):
    """Scan-type-specific data (software list, system info/checks/inventory,
    Windows inventory / Defender results) for the Software and System scan
    pages and PDF; None for network scans."""
    kind = scan_row["scan_type"]
    if kind not in ("software", "system-local", "system-remote", "system-windows"):
        return None
    sid = scan_row["id"]
    info = scan_row.get("scan_info") or {}
    if kind == "system-windows":
        return {
            "kind": "windows_defender", "info": info, "checks": db.get_system_checks(sid),
            "threats": db.get_threat_findings(sid), "threat_counts": db.count_threat_findings(sid),
            "inventory": [], "inventory_counts": {"total": 0, "assessed": 0},
        }
    if kind == "software" and info.get("mode") == "windows-inventory":
        return {
            "kind": "windows_inventory", "info": info, "checks": [],
            "inventory": db.get_software_inventory(sid, findings_first=True),
            "inventory_counts": db.count_software_inventory(sid),
        }
    system = kind != "software"
    return {
        "kind": "system" if system else "software",
        "info": info,
        "checks": db.get_system_checks(sid) if system else [],
        "inventory": db.get_software_inventory(sid, assessed_only=system, limit=200 if system else None),
        "inventory_counts": db.count_software_inventory(sid),
    }


def _prepare_findings(scan_row):
    """Findings for a scan with live-recomputed contextual priority, used by
    BOTH the scan page and the PDF so the two always agree (weights, KEV and
    EPSS are read live, so the score reflects current settings/intel)."""
    vulns = [dict(v) for v in db.get_vulnerabilities(scan_row["id"])]
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "Unknown": 0}
    weights = db.get_risk_weights()
    kev_ids = db.get_kev_cve_ids()
    epss_map = db.get_epss_scores()
    blast_map = db.get_blast_radius_map()
    max_blast = max(blast_map.values()) if blast_map else 0
    asset_ctx = {
        "exposure": scan_row.get("asset_exposure"),
        "criticality": scan_row.get("asset_criticality"),
        "business_impact": scan_row.get("asset_business_impact"),
    }
    for v in vulns:
        counts[v["severity"] if v["severity"] in counts else "Unknown"] += 1
        blast = blast_map.get(v["cve_id"], 0) if v["cve_id"] else 0
        v["epss_score"] = epss_map.get(v["cve_id"]) if v["cve_id"] else None
        v["cwe_name"] = cwe_name(v.get("cwe_id"))
        v["is_kev"] = bool(v["cve_id"] and v["cve_id"] in kev_ids)
        v["contextual_priority"] = calculate_contextual_risk(
            v, asset_ctx, weights, blast, max_blast, v["is_kev"]
        )
        v["priority_label"] = priority_label(v["contextual_priority"])
        _attach_confidence(v)
    vulns.sort(key=lambda v: v["contextual_priority"], reverse=True)
    return vulns, counts


def confidence_classification(pct):
    """Maps a 0-100 confidence percentage to a display label.

    Display-only helper: does not feed into CVSS, EPSS, contextual risk,
    or any other risk calculation. pct may be None (no confidence score
    persisted for this finding), in which case None is returned.
    """
    if pct is None:
        return None
    if pct >= 90:
        return "Confirmed"
    if pct >= 70:
        return "High Confidence"
    if pct >= 50:
        return "Medium Confidence"
    return "Low Confidence"


def _attach_confidence(v):
    """Mutates a vulnerability dict in-place, adding confidence_pct and
    confidence_label derived from the persisted vulnerability_confidence
    column. Safe to call even if the column is NULL/absent."""
    raw = v.get("vulnerability_confidence")
    v["confidence_pct"] = round(raw * 100) if raw is not None else None
    v["confidence_label"] = confidence_classification(v["confidence_pct"])
    return v


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        row = db.get_user_by_username(username)
        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row))
            return redirect(url_for("dashboard"))
        flash("Invalid username or password", "error")
    return render_template("login.html")
@app.route("/register", methods=["GET", "POST"])
def register():
    if db.any_users_exist():
        flash("Registration is closed. Contact an admin for access.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.match(username):
            flash("Username must be 3-64 characters: letters, digits, and . _ @ -", "error")
            return render_template("register.html")
        if len(password) < 8 or len(password) > 128:
            flash("Password must be between 8 and 128 characters.", "error")
            return render_template("register.html")
        try:
            db.create_user(username, generate_password_hash(password), role="admin")
        except psycopg2.errors.UniqueViolation:
            flash("That username is already taken.", "error")
            return render_template("register.html")
        flash("Account created - please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
@app.route("/")
@login_required
def dashboard():
    search = request.args.get("search", "").strip() or None
    status = request.args.get("status", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    owner = _owner_scope()
    scans = db.get_scans(search=search, status=status, severity=severity, owner_id=owner)
    stats = db.get_severity_stats(owner_id=owner)
    kpis = db.get_kpis(owner_id=owner)
    if owner is None:
        posture = db.get_latest_posture()
        critical_path_count = len(find_all_critical_paths(build_attack_graph()))
    else:
        # Posture and attack paths are organisation-wide views.
        posture, critical_path_count = None, 0
    return render_template(
        "dashboard.html",
        scans=scans,
        stats=stats,
        kpis=kpis,
        filters={"search": search or "", "status": status or "", "severity": severity or ""},
        posture=posture,
        critical_path_count=critical_path_count,
    )
@app.route("/api/chart-data")
@login_required
def api_chart_data():
    owner = _owner_scope()
    stats = db.get_severity_stats(owner_id=owner)
    trend = db.get_risk_trend(owner_id=owner)
    return jsonify({
        "severity": stats,
        "trend": {
            "labels": [str(t["scan_time"]) for t in trend],
            "scores": [float(t["total_risk"] or 0) for t in trend],
        },
    })
@app.route("/api/scans")
@login_required
def api_scans():
    """Used by the dashboard's live search/filter box."""
    search = request.args.get("search", "").strip() or None
    status = request.args.get("status", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    scans = db.get_scans(search=search, status=status, severity=severity, owner_id=_owner_scope())
    return jsonify([dict(s, scan_time=str(s["scan_time"])) for s in scans])
@app.route("/assets")
@login_required
def assets():
    search = request.args.get("search", "").strip() or None
    asset_list = db.get_assets(search=search)
    return render_template("assets.html", assets=asset_list, search=search or "")
@app.route("/assets/<int:asset_id>")
@login_required
def asset_detail(asset_id):
    profile = get_asset_profile(asset_id)
    if profile is None:
        abort(404)
    return render_template("asset_detail.html", **profile)
@app.route("/assets/<int:asset_id>/update", methods=["POST"])
@login_required
def asset_update(asset_id):
    if get_asset_profile(asset_id) is None:
        abort(404)
    def clean(name, allowed=None, max_len=None):
        value = (request.form.get(name) or "").strip()
        if not value:
            return None
        if allowed is not None:
            value = value.upper()
            if value not in allowed:
                raise ValueError(f"Invalid {name.replace('_', ' ')}: {value[:30]}")
        if max_len is not None and len(value) > max_len:
            raise ValueError(f"{name.capitalize()} is too long (max {max_len} characters)")
        return value
    try:
        fields = dict(
            hostname=clean("hostname", max_len=255),
            exposure=clean("exposure", allowed=EXPOSURE_VALUES),
            business_impact=clean("business_impact", allowed=LEVEL_VALUES),
            criticality=clean("criticality", allowed=LEVEL_VALUES),
            owner=clean("owner", max_len=120),
        )
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("asset_detail", asset_id=asset_id))
    db.update_asset_profile(asset_id, **fields)
    flash("Asset profile updated", "success")
    return redirect(url_for("asset_detail", asset_id=asset_id))
@app.route("/api/assets/<int:asset_id>")
@login_required
def api_asset_profile(asset_id):
    profile = get_asset_profile(asset_id)
    if profile is None:
        abort(404)
    def _clean(rows):
        return [dict(r, detected_at=str(r.get("detected_at"))) if "detected_at" in r else
                dict(r, scan_time=str(r.get("scan_time"))) if "scan_time" in r else dict(r)
                for r in rows]
    return jsonify({
        "asset": dict(profile["asset"], first_seen=str(profile["asset"]["first_seen"]),
                       last_scanned=str(profile["asset"]["last_scanned"])),
        "services": _clean(profile["services"]),
        "vulnerabilities": _clean(profile["vulnerabilities"]),
        "risk_score": profile["risk_score"],
        "scan_history": _clean(profile["scan_history"]),
    })
@app.route("/scan-page")
@login_required
def scan_page():
    scheduled = db.get_scheduled_scans(owner_id=_owner_scope())
    tab = request.args.get("tab", "network")
    return render_template(
        "scan.html",
        scheduled=scheduled,
        tab=tab if tab in ("network", "software", "system") else "network",
        catalog=catalog_entries(),
        assets=_selectable_assets(),
        is_admin=_is_admin(),
        ssh_available=bool(shutil.which("ssh") and shutil.which("ssh-keyscan") and shutil.which("ssh-keygen")),
        max_software_items=MAX_SOFTWARE_ITEMS,
        local_host=_local_host(),
        windows_server=local_host_os() == "Windows",
        durations=EXPECTED_DURATION,
    )


def _local_host():
    """The computer SentriX would inspect, shown before any local scan."""
    system = local_host_os()
    info = local_host_info(describe_windows_os() if system == "Windows" else None)
    info["system"] = system
    info["supported"] = system == "Windows"
    return info


@app.route("/software-scan/local", methods=["POST"])
@login_required
def software_scan_local():
    """Software Scan -> 'Scan this computer' (Windows server, administrators only)."""
    try:
        scan_id = submit_local_software_scan(created_by=int(current_user.id), allow_local=_is_admin())
    except ScanRejected as e:
        flash(str(e), "error")
        return redirect(url_for("scan_page", tab="software"))
    flash(f"Software scan #{scan_id} queued - discovering installed applications on this computer", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/system-scan/windows", methods=["POST"])
@login_required
def system_scan_windows():
    """System Scan on a Windows server: Microsoft Defender status / Quick / Full / Custom scan."""
    f = request.form
    try:
        scan_id = submit_windows_system_scan(
            f.get("action", ""), f.get("scan_path"), confirmed=f.get("confirm_scan") == "1",
            created_by=int(current_user.id), allow_local=_is_admin(),
        )
    except ScanRejected as e:
        flash(str(e), "error")
        return redirect(url_for("scan_page", tab="system"))
    flash(f"Windows System Scan #{scan_id} queued", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/api/windows-defender/status")
@login_required
def api_defender_status():
    """Live Microsoft Defender protection status (read-only; administrators only)."""
    if not _is_admin():
        abort(403)
    if local_host_os() != "Windows":
        return jsonify({"state": "unavailable", "summary": f"This SentriX server runs {local_host_os()}; Microsoft "
                        "Defender can only be checked when SentriX runs on Windows."})
    st = defender_status()
    return jsonify({"state": st.state, "summary": st.summary, "registered_av": st.registered_av,
                    "realtime": st.fields.get("RealTimeProtectionEnabled"),
                    "signature_version": st.fields.get("AntivirusSignatureVersion"),
                    "signature_updated": st.fields.get("AntivirusSignatureLastUpdated"),
                    "error_kind": st.error_kind})


@app.route("/software-scan", methods=["POST"])
@login_required
def software_scan():
    """Software Scan: assess entered vendor/product/version (or a list) via the CVE engine."""
    try:
        items = []
        if request.form.get("bulk", "").strip():
            items += parse_bulk(request.form["bulk"])
        if request.form.get("product", "").strip() or request.form.get("cpe", "").strip():
            items.append(normalize_software(request.form.get("vendor"), request.form.get("product"),
                                            request.form.get("version"), request.form.get("cpe")))
        asset_raw = request.form.get("asset_id", "").strip()
        try:
            asset_id = int(asset_raw) if asset_raw else None
        except ValueError:
            raise ScanRejected("Invalid asset selection.")
        if asset_id is not None and asset_id not in {a["id"] for a in _selectable_assets()}:
            raise ScanRejected("The selected asset does not exist.")
        scan_id = submit_software_scan(items, created_by=int(current_user.id), asset_id=asset_id)
    except (SoftwareInputError, ScanRejected) as e:
        flash(str(e), "error")
        return redirect(url_for("scan_page", tab="software"))
    flash(f"Software scan #{scan_id} queued", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/system-scan", methods=["POST"])
@login_required
def system_scan():
    """System Scan: local (admin only) or remote over SSH with key authentication."""
    f = request.form
    try:
        scan_id = submit_system_scan(
            f.get("mode", ""), created_by=int(current_user.id), use_sudo=f.get("use_sudo") == "1",
            allow_local=_is_admin(),
            host=f.get("host"), port=f.get("port"), username=f.get("username"),
            private_key=f.get("private_key"), fingerprint=f.get("fingerprint"),
            accept_unverified=f.get("accept_unverified") == "1",
        )
    except ScanRejected as e:
        flash(str(e), "error")                       # never echoes the submitted key
        return redirect(url_for("scan_page", tab="system"))
    flash(f"System scan #{scan_id} queued", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))
@app.route("/scan", methods=["POST"])
@login_required
def scan():
    target = request.form.get("target", "").strip()
    try:
        scan_id, network = submit_scan(target, created_by=int(current_user.id))
    except ScanRejected as e:
        flash(str(e), "error")
        return redirect(url_for("scan_page"))
    if network:
        flash(f"Network scan #{scan_id} queued for {target}. Live hosts are discovered first, then each "
              "is scanned in turn and gets its own scan record.", "success")
    else:
        flash(f"Scan #{scan_id} queued for {target}", "success")
    return redirect(url_for("dashboard"))
@app.route("/schedule", methods=["POST"])
@login_required
def schedule():
    try:
        target = validate_scan_target(request.form.get("target", ""))
    except ScanRejected as e:
        flash(str(e), "error")
        return redirect(url_for("scan_page"))
    try:
        interval_minutes = int(request.form.get("interval_minutes", 1440))
    except (TypeError, ValueError):
        flash("Interval must be a whole number of minutes.", "error")
        return redirect(url_for("scan_page"))
    if not (MIN_SCHEDULE_MINUTES <= interval_minutes <= MAX_SCHEDULE_MINUTES):
        flash(f"Interval must be between {MIN_SCHEDULE_MINUTES} and {MAX_SCHEDULE_MINUTES} minutes.", "error")
        return redirect(url_for("scan_page"))
    db.create_scheduled_scan(target, interval_minutes, created_by=int(current_user.id))
    flash(f"Recurring scan scheduled for {target} every {interval_minutes} minutes", "success")
    return redirect(url_for("scan_page"))
@app.route("/schedule/<int:scheduled_id>/toggle", methods=["POST"])
@login_required
def toggle_schedule(scheduled_id):
    job = db.get_scheduled_scan(scheduled_id)
    if job is None or not _can_access(job.get("created_by")):
        abort(404)
    active = request.form.get("active") == "1"
    db.set_scheduled_scan_active(scheduled_id, active)
    return redirect(url_for("scan_page"))
@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan_row = _get_scan_or_404(scan_id)
    vulns, counts = _prepare_findings(scan_row)
    extra = _scan_extra(scan_row)
    return render_template("scan_details.html", scan=scan_row, vulns=vulns, counts=counts, extra=extra)
@app.route("/scan/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    """Polled by the dashboard/details page for real-time status updates."""
    row = db.get_scan_status(scan_id)
    if row is None or not _can_access(row.get("created_by")):
        abort(404)
    return jsonify({"status": row["status"], "total_risk": float(row["total_risk"] or 0),
                    "status_detail": row.get("status_detail"), "progress": row.get("progress")})
@app.route("/scan/<int:scan_id>/pdf")
@login_required
def scan_pdf(scan_id):
    scan_row = _get_scan_or_404(scan_id)
    vulns, counts = _prepare_findings(scan_row)
    pdf_buffer = build_pdf_report(scan_row, vulns, counts, _scan_extra(scan_row))
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", str(scan_row["target"]))
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"scan_{scan_id}_{safe_target}.pdf",
    )
@app.route("/vulnerabilities")
@login_required
def vulnerabilities_view():
    search = request.args.get("search", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    kev_only = request.args.get("kev_only") == "1"
    findings = db.get_all_vulnerabilities(search=search, severity=severity, kev_only=kev_only,
                                          owner_id=_owner_scope())
    epss_map = db.get_epss_scores()
    findings = [dict(f) for f in findings]
    for f in findings:
        f["epss_score"] = epss_map.get(f["cve_id"]) if f["cve_id"] else None
        f["cwe_name"] = cwe_name(f.get("cwe_id"))
    return render_template(
        "vulnerabilities.html",
        findings=findings,
        filters={"search": search or "", "severity": severity or "", "kev_only": kev_only},
    )
@app.route("/reports/executive/pdf")
@login_required
def executive_report_pdf():
    kpis = db.get_kpis()
    posture = db.get_latest_posture()
    graph = build_attack_graph()
    critical_paths = find_all_critical_paths(graph)
    pdf_buffer = build_executive_report(kpis, posture, critical_paths)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="executive_security_summary.pdf",
    )
@app.route("/attack-paths")
@login_required
def attack_paths():
    graph = build_attack_graph()
    critical_paths = find_all_critical_paths(graph)
    choke_points = rank_choke_points(graph)
    return render_template(
        "attack_paths.html",
        paths=critical_paths,
        choke_points=choke_points,
        node_count=graph.number_of_nodes(),
        edge_count=graph.number_of_edges(),
    )
@app.route("/api/attack-graph")
@login_required
def api_attack_graph():
    graph = build_attack_graph()
    return jsonify(nx.node_link_data(graph, edges="edges"))
@app.route("/analytics")
@login_required
def analytics():
    latest = db.get_latest_posture()
    history = db.get_posture_history()
    return render_template("analytics.html", latest=latest, history=history)
@app.route("/analytics/recompute", methods=["POST"])
@login_required
def analytics_recompute():
    snapshot_posture()
    flash("Posture snapshot recomputed", "success")
    return redirect(url_for("analytics"))
@app.route("/api/posture-trend")
@login_required
def api_posture_trend():
    history = db.get_posture_history()
    return jsonify({
        "labels": [str(h["snapshot_date"]) for h in history],
        "overall": [float(h["overall_score"] or 0) for h in history],
        "network": [float(h["network_score"] or 0) for h in history],
        "host": [float(h["host_score"] or 0) for h in history],
        "web": [float(h["web_score"] or 0) for h in history],
        "patch": [float(h["patch_score"] or 0) for h in history],
        "config": [float(h["config_score"] or 0) for h in history],
    })
@app.route("/settings")
@login_required
@admin_required
def settings():
    weights = db.get_risk_weights()
    kev_count = len(db.get_kev_cve_ids())
    epss_count = len(db.get_epss_scores())
    return render_template("settings.html", weights=weights, kev_count=kev_count, epss_count=epss_count)
@app.route("/settings/weights", methods=["POST"])
@login_required
@admin_required
def update_weights():
    """Weights must be finite numbers in [0, 1] that total exactly 1.00
    (they are stored with 2 decimals). contextual_risk.py clamps its sum to
    [0, 1] before scaling to 0-100, so a total above 1.00 flattens high
    findings to 100 and one below 1.00 can never reach it."""
    factors = ["cvss", "exploit", "epss", "exposure", "criticality", "business_impact", "complexity", "blast_radius"]
    weights = {}
    for f in factors:
        raw = request.form.get(f)
        try:
            value = float(raw)
        except (TypeError, ValueError):
            flash(f"Weight '{f}' must be a number.", "error")
            return redirect(url_for("settings"))
        if not math.isfinite(value) or not (0.0 <= value <= 1.0):
            flash(f"Weight '{f}' must be between 0 and 1.", "error")
            return redirect(url_for("settings"))
        weights[f] = round(value, 2)
    total = round(sum(weights.values()), 2)
    if total != 1.00:
        flash(f"Weights must total 1.00 (they currently total {total:.2f}). Nothing was changed.", "error")
        return redirect(url_for("settings"))
    db.update_risk_weights(weights)
    flash("Risk weights updated. New scores apply the next time a scan's details are viewed.", "success")
    return redirect(url_for("settings"))
if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Scans run in in-process threads, so anything still queued/running from a
    # previous process can never finish - mark it failed instead of leaving it
    # 'running' forever.
    recovered = db.fail_interrupted_scans()
    if recovered:
        logger.warning("Marked %s interrupted scan(s) from a previous run as failed", recovered)
    start_scheduler()
    # debug is OFF unless explicitly requested: the Werkzeug debugger allows
    # arbitrary code execution and must never be on by default.
    app.run(
        host=os.environ.get("SENTRIX_HOST", "127.0.0.1"),
        debug=os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes"),
    )