"""
setup_ui/app.py
===============
Temporary Flask web UI for server setup.
Runs on port 7070, LAN-accessible only, auto-terminates after setup.
Streams real-time install progress via WebSocket.
"""

import json
import os
import sys
import socket
import threading
import time
import signal
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config_manager import ConfigManager
from core.hardware import HardwareInfo

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["TEMPLATES_AUTO_RELOAD"] = True
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Global state
_suite_dir: Optional[Path] = None
_config_manager: Optional[ConfigManager] = None
_hardware_info: Optional[HardwareInfo] = None
_install_thread: Optional[threading.Thread] = None
_shutdown_event = threading.Event()


# ---------------------------------------------------------------------------
# Role definitions for the UI
# ---------------------------------------------------------------------------

ROLES = {
    "storage": {
        "name": "Storage & Backup",
        "icon": "🗄️",
        "description": "BTRFS RAID, SMART monitoring, automated backups with BorgBackup and rclone.",
        "min_ram_gb": 1,
        "min_cores": 1,
        "docker": False,
        "sub_options": ["btrfs_raid", "smart_monitoring", "borgbackup", "rclone_offsite"],
        "conflicts": [],
        "requires": [],
    },
    "web": {
        "name": "Web Server",
        "icon": "🌐",
        "description": "Nginx Proxy Manager, OpenLiteSpeed, or Apache2 with automatic TLS certificates.",
        "min_ram_gb": 1,
        "min_cores": 1,
        "docker": True,
        "sub_options": ["nginx_proxy_manager", "traefik", "openlitespeed", "apache2"],
        "conflicts": [],
        "requires": [],
    },
    "mail": {
        "name": "Mail Server",
        "icon": "📧",
        "description": "Mailcow: fully-featured mail server with SOGo webmail, spam filtering, DKIM/DMARC.",
        "min_ram_gb": 3,
        "min_cores": 2,
        "docker": True,
        "sub_options": ["mailcow"],
        "conflicts": [],
        "requires": ["web"],
    },
    "identity": {
        "name": "Identity & Directory",
        "icon": "🏛️",
        "description": (
            "FreeIPA: Kerberos KDC, 389 Directory Server, Dogtag PKI CA, "
            "integrated BIND DNS, HBAC, sudo policies, and web UI. "
            "Replaces standalone DNS/DHCP when integrated DNS is enabled."
        ),
        "min_ram_gb": 2,
        "min_cores": 2,
        "docker": False,
        "sub_options": ["freeipa", "samba_ad"],
        "conflicts": [],
        "requires": [],
        "suppresses_if_dns": ["dns_dhcp"],
    },
    "dns_dhcp": {
        "name": "DNS & DHCP",
        "icon": "🔍",
        "description": "Technitium (recommended), BIND9, or FreeIPA-managed DNS with optional DHCP.",
        "min_ram_gb": 0.5,
        "min_cores": 1,
        "docker": True,
        "sub_options": ["technitium", "bind9", "kea_dhcp"],
        "conflicts": [],
        "requires": [],
    },
    "database": {
        "name": "Database Server",
        "icon": "🗃️",
        "description": "MariaDB, PostgreSQL, Redis with Adminer web management interface.",
        "min_ram_gb": 1,
        "min_cores": 1,
        "docker": True,
        "sub_options": ["mariadb", "postgresql", "redis", "adminer"],
        "conflicts": [],
        "requires": [],
    },
    "files": {
        "name": "File Sharing & Collaboration",
        "icon": "📁",
        "description": "Nextcloud with Talk, Calendar, Contacts, and optional Collabora/OnlyOffice.",
        "min_ram_gb": 2,
        "min_cores": 2,
        "docker": True,
        "sub_options": ["nextcloud", "collabora", "onlyoffice", "samba_shares", "nfs", "syncthing"],
        "conflicts": [],
        "requires": ["web", "database"],
    },
    "comms": {
        "name": "Communication Server",
        "icon": "💬",
        "description": "Matrix/Synapse + Element, Jitsi Meet, Mattermost, or Mumble.",
        "min_ram_gb": 2,
        "min_cores": 2,
        "docker": True,
        "sub_options": ["matrix", "jitsi", "mattermost", "mumble"],
        "conflicts": [],
        "requires": ["web", "database"],
    },
    "vpn": {
        "name": "VPN Server",
        "icon": "🔒",
        "description": "WireGuard (recommended) or OpenVPN with web management interface.",
        "min_ram_gb": 0.5,
        "min_cores": 1,
        "docker": True,
        "sub_options": ["wireguard", "openvpn"],
        "conflicts": [],
        "requires": [],
    },
    "security": {
        "name": "Security Monitoring",
        "icon": "🛡️",
        "description": "Wazuh HIDS: threat detection, compliance monitoring, log analysis, security dashboard.",
        "min_ram_gb": 4,
        "min_cores": 4,
        "docker": True,
        "sub_options": ["wazuh_server", "wazuh_agent_only"],
        "conflicts": [],
        "requires": [],
    },
    "logging": {
        "name": "Logging & Metrics",
        "icon": "📊",
        "description": "Graylog, Loki+Grafana, or Prometheus+Grafana for centralized logging and metrics.",
        "min_ram_gb": 2,
        "min_cores": 2,
        "docker": True,
        "sub_options": ["graylog", "loki_grafana", "prometheus_grafana"],
        "conflicts": [],
        "requires": [],
    },
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/hardware")
def api_hardware():
    if _hardware_info is None:
        return jsonify({"error": "Hardware info not available"}), 503
    return jsonify(_hardware_info.to_dict())


@app.route("/api/roles")
def api_roles():
    hw = _hardware_info
    roles_with_status = {}

    for role_id, role in ROLES.items():
        ram_ok = hw.ram.total_gb >= role["min_ram_gb"] if hw else True
        cores_ok = hw.cpu.cores_physical >= role["min_cores"] if hw else True

        roles_with_status[role_id] = {
            **role,
            "feasible": ram_ok and cores_ok,
            "ram_warning": not ram_ok,
            "cpu_warning": not cores_ok,
            "ram_shortfall": max(0, role["min_ram_gb"] - (hw.ram.total_gb if hw else 0)),
            "cpu_shortfall": max(0, role["min_cores"] - (hw.cpu.cores_physical if hw else 0)),
        }

    return jsonify(roles_with_status)


@app.route("/api/resource-check", methods=["POST"])
def api_resource_check():
    """Check if selected roles fit within available resources."""
    data = request.json
    selected_roles = data.get("roles", [])

    total_ram_needed = sum(ROLES[r]["min_ram_gb"] for r in selected_roles if r in ROLES)
    total_cores_needed = max((ROLES[r]["min_cores"] for r in selected_roles if r in ROLES), default=0)

    hw = _hardware_info
    available_ram = hw.ram.available_gb if hw else 0
    available_cores = hw.cpu.cores_physical if hw else 0

    ram_pct = (total_ram_needed / available_ram * 100) if available_ram > 0 else 0
    cores_pct = (total_cores_needed / available_cores * 100) if available_cores > 0 else 0

    warnings = []
    errors = []

    if ram_pct > 95:
        errors.append(f"Selected roles require {total_ram_needed:.1f}GB RAM but only {available_ram:.1f}GB available.")
    elif ram_pct > 80:
        warnings.append(f"Selected roles will use ~{ram_pct:.0f}% of available RAM ({total_ram_needed:.1f}GB / {available_ram:.1f}GB).")

    if total_cores_needed > available_cores:
        errors.append(f"Selected roles recommend {total_cores_needed} CPU cores but only {available_cores} available.")
    elif cores_pct > 80:
        warnings.append(f"Selected roles will use ~{cores_pct:.0f}% of CPU capacity.")

    # Check dependencies
    dep_warnings = []
    for role_id in selected_roles:
        role = ROLES.get(role_id, {})
        for req in role.get("requires", []):
            if req not in selected_roles:
                role_name = ROLES.get(req, {}).get("name", req)
                dep_warnings.append(f"{role['name']} requires {role_name} — add it or it will be auto-included.")

    return jsonify({
        "warnings": warnings,
        "errors": errors,
        "dependency_warnings": dep_warnings,
        "total_ram_needed": total_ram_needed,
        "total_cores_needed": total_cores_needed,
        "ram_percentage": round(ram_pct, 1),
        "cores_percentage": round(cores_pct, 1),
        "can_proceed": len(errors) == 0,
    })


@app.route("/api/save-config", methods=["POST"])
def api_save_config():
    """Save the complete setup configuration."""
    data = request.json
    cm = _config_manager

    if not cm:
        return jsonify({"error": "Config manager not available"}), 503

    try:
        cm.set("setup.roles_selected", data.get("roles", []))
        cm.set("setup.sub_options", data.get("sub_options", {}))
        cm.set("network.domain", data.get("domain", ""))
        cm.set("network.hostname", data.get("hostname", ""))
        cm.set("network.reverse_proxy", data.get("reverse_proxy", "npm"))
        cm.set("notifications.email", data.get("notify_email", ""))
        cm.set("setup.config_saved_at", datetime.utcnow().isoformat())
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/preflight")
def api_preflight():
    """Re-run preflight checks and return results."""
    from core.preflight import PreflightChecker
    checker = PreflightChecker()
    # Run silently (no console output)
    import io
    from contextlib import redirect_stdout
    with redirect_stdout(io.StringIO()):
        passed = checker.run_all()
    return jsonify({
        "passed": passed,
        "summary": checker.get_summary(),
        "port_conflicts": checker.get_port_conflicts(),
    })


@app.route("/api/start-install", methods=["POST"])
def api_start_install():
    """Begin the installation process."""
    global _install_thread

    if _install_thread and _install_thread.is_alive():
        return jsonify({"error": "Installation already in progress"}), 409

    data = request.json
    _install_thread = threading.Thread(
        target=run_installation,
        args=(data,),
        daemon=True
    )
    _install_thread.start()
    return jsonify({"success": True, "message": "Installation started"})


@app.route("/api/credentials")
def api_credentials():
    """Return generated credentials for the summary page."""
    from core.secrets import SecretsManager
    sm = SecretsManager(_suite_dir)
    summary = sm.get_credentials_summary()
    return jsonify(summary)


@app.route("/api/service-urls")
def api_service_urls():
    """Return all registered service URLs."""
    if _config_manager:
        return jsonify(_config_manager.get_service_urls())
    return jsonify({})


@app.route("/api/complete-setup", methods=["POST"])
def api_complete_setup():
    """Mark setup as complete and schedule shutdown."""
    if _config_manager:
        _config_manager.mark_setup_complete()

    # Shutdown the web UI after a short delay
    threading.Thread(target=_deferred_shutdown, daemon=True).start()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# WebSocket events
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    emit("status", {"message": "Connected to Server Suite setup"})


@socketio.on("ping")
def on_ping():
    emit("pong")


# ---------------------------------------------------------------------------
# Installation runner
# ---------------------------------------------------------------------------

def emit_progress(stage: str, message: str, percent: int = 0,
                  level: str = "info", detail: str = ""):
    """Emit a progress update to all connected clients."""
    socketio.emit("progress", {
        "stage":   stage,
        "message": message,
        "percent": percent,
        "level":   level,
        "detail":  detail,
        "time":    datetime.now().strftime("%H:%M:%S"),
    })


def run_installation(config_data: dict):
    """Main installation orchestrator. Runs in a background thread."""
    from core.config_manager import ConfigManager
    from core.docker_engine import DockerEngine
    from core.firewall import FirewallManager
    from core.secrets import SecretsManager
    from base.ssh_hardening import SSHHardener
    from base.fail2ban import Fail2BanManager
    from base.apparmor import AppArmorManager
    from base.chrony import ChronyManager
    from base.unattended_upgrades import UnattendedUpgradesManager
    from base.cockpit import CockpitManager
    from base.auditd import AuditdManager
    from roles.registry import RoleDispatcher

    cm = _config_manager
    sm = SecretsManager(_suite_dir)
    roles = config_data.get("roles", [])
    total_steps = 8 + len(roles)
    current_step = 0

    def step(stage: str, message: str, detail: str = ""):
        nonlocal current_step
        current_step += 1
        pct = int((current_step / total_steps) * 100)
        emit_progress(stage, message, pct, detail=detail)

    try:
        # ---- Base layer ----
        step("base", "Updating system packages...")
        import subprocess
        subprocess.run(["apt-get", "update", "-qq"], capture_output=True)
        subprocess.run(["apt-get", "upgrade", "-y", "-qq"], capture_output=True, timeout=600)

        step("base", "Hardening SSH...")
        ssh_port = config_data.get("ssh_port", 22)
        SSHHardener().harden(custom_port=ssh_port)

        step("base", "Configuring firewall...")
        fw = FirewallManager()
        fw.full_setup(ssh_port=ssh_port)

        step("base", "Installing Fail2Ban...")
        Fail2BanManager().setup_base()

        step("base", "Configuring AppArmor...")
        AppArmorManager().enable()

        step("base", "Setting up NTP (Chrony)...")
        ChronyManager().setup()

        step("base", "Enabling automatic security updates...")
        UnattendedUpgradesManager().setup()

        step("base", "Installing Cockpit management dashboard...")
        CockpitManager().install()
        cm.register_service_url("cockpit", f"https://{config_data.get('hostname', 'localhost')}:9090",
                                 "Server management dashboard")

        step("base", "Configuring auditd (kernel auditing)...")
        AuditdManager().setup()

        # ---- Docker ----
        if any(ROLES.get(r, {}).get("docker") for r in roles):
            step("docker", "Installing and hardening Docker Engine...")
            docker = DockerEngine(_suite_dir)
            if not docker.full_setup():
                emit_progress("docker", "Docker setup failed", level="error")
                return

            step("docker", "Creating Docker networks...")
            subnet_map = docker.resolve_subnet_conflicts()
            docker.create_all_networks(subnet_map)
            cm.set("docker.networks", subnet_map)

        # ---- Roles ----
        for role_id in roles:
            emit_progress("roles", f"Installing: {ROLES.get(role_id, {}).get('name', role_id)}",
                          int((current_step / total_steps) * 100))

            success = _install_role(role_id, config_data, cm, sm)
            if success:
                # Add firewall rules for this role
                fw = FirewallManager()
                fw.add_role_rules(role_id)
                fw.reload()
                emit_progress("roles",
                              f"✓ {ROLES.get(role_id, {}).get('name', role_id)} installed",
                              int((current_step / total_steps) * 100),
                              level="success")
            else:
                emit_progress("roles",
                              f"⚠ {ROLES.get(role_id, {}).get('name', role_id)} failed — check logs",
                              int((current_step / total_steps) * 100),
                              level="warning")
            current_step += 1

        # ---- Post-install ----
        emit_progress("final", "Running security audit (Lynis)...", 95)
        _run_lynis_audit()

        emit_progress("final", "Sending test notification email...", 97)
        _send_test_notification(config_data, cm)

        emit_progress("final", "Setup complete!", 100, level="success")
        socketio.emit("install_complete", {
            "success": True,
            "service_urls": cm.get_service_urls(),
        })

    except Exception as e:
        emit_progress("error", f"Installation failed: {str(e)}", level="error")
        socketio.emit("install_error", {"error": str(e)})


def _install_role(role_id: str, config: dict, cm: ConfigManager, sm) -> bool:
    """Dispatch role installation via the central RoleDispatcher."""
    from roles.registry import RoleDispatcher

    # Determine sub-role from UI selection (e.g. web→npm, web→traefik)
    sub_options = config.get("sub_options", {})
    sub_role = sub_options.get(role_id)

    # DNS/DHCP suppression: if identity (FreeIPA) is selected with integrated
    # DNS and dns_dhcp is also selected, skip dns_dhcp silently.
    if role_id == "dns_dhcp":
        identity_cfg = cm.get("roles.identity") or {}
        if identity_cfg.get("manage_dns"):
            emit_progress("roles",
                          "DNS/DHCP skipped — FreeIPA integrated DNS is active",
                          level="info")
            return True

    dispatcher = RoleDispatcher(
        config_manager=cm,
        secrets_manager=sm,
        suite_dir=_suite_dir,
    )

    try:
        return dispatcher.install_role(role_id, config, sub_role=sub_role)
    except Exception as e:
        emit_progress("roles", f"Role {role_id} error: {e}", level="error")
        return False


def _run_lynis_audit():
    try:
        import subprocess
        subprocess.run(["apt-get", "install", "-y", "-qq", "lynis"], capture_output=True)
        subprocess.run(
            ["lynis", "audit", "system", "--quiet", "--logfile",
             "/var/log/server-suite/lynis.log"],
            capture_output=True, timeout=300
        )
    except Exception:
        pass


def _send_test_notification(config: dict, cm: ConfigManager):
    from core.notifications import NotificationManager
    email = config.get("notify_email") or cm.get("notifications.email")
    if email:
        nm = NotificationManager(_suite_dir)
        nm.send_test_email(email)


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def _deferred_shutdown():
    """Shut down the Flask server after a delay."""
    time.sleep(3)
    _shutdown_event.set()
    socketio.stop()


def get_local_ip() -> str:
    """Get the server's LAN IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "localhost"


class SetupWebUI:
    """Manages the lifecycle of the setup web UI."""

    def __init__(self, config: dict, hardware_info: HardwareInfo, suite_dir: Path):
        global _config_manager, _hardware_info, _suite_dir
        _suite_dir = Path(suite_dir)
        _hardware_info = hardware_info
        _config_manager = ConfigManager(_suite_dir)

        # Update config with hardware info
        _config_manager.update("hardware", hardware_info.to_dict())

    def start(self, port: int = 7070):
        """Start the setup web UI."""
        from rich.console import Console
        from rich.panel import Panel
        local_ip = get_local_ip()

        console = Console()
        console.print(Panel(
            f"[bold green]Setup wizard is running![/bold green]\n\n"
            f"  Open in your browser:\n"
            f"  [bold cyan]http://{local_ip}:{port}[/bold cyan]\n"
            f"  [dim]or  http://localhost:{port}[/dim]\n\n"
            f"  [dim]The setup wizard will guide you through role selection\n"
            f"  and configuration. All progress is saved automatically.[/dim]",
            border_style="green",
            padding=(1, 4),
        ))

        try:
            socketio.run(app, host="0.0.0.0", port=port, debug=False,
                         use_reloader=False, log_output=False)
        except KeyboardInterrupt:
            console.print("\n[yellow]Setup UI stopped.[/yellow]")
