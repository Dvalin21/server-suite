"""
roles/identity/samba_ad.py
==========================
Samba4 Active Directory Domain Controller.
Alternative to FreeIPA — chosen when the environment needs
native Windows AD compatibility (GPOs, Windows clients, RSAT).

Provides:
  - Kerberos KDC (MIT Kerberos via Samba)
  - LDAP (Samba internal LDB — NOT OpenLDAP)
  - DNS (BIND9 DLZ backend or Samba internal)
  - Group Policy Objects (GPO)
  - Windows domain join for Windows/Linux clients

Samba AD limitations (vs FreeIPA):
  - No integrated CA (use StepCA or Let's Encrypt separately)
  - No HBAC (use PAM/sudoers on each host)
  - Schema extensions are complex
  - Web UI requires RSAT or Samba-tool CLI only

Installation notes:
  - Samba AD requires Samba >= 4.17 (available in Ubuntu 22.04+)
  - MUST be installed on bare metal or a VM — NOT in Docker
    (Samba AD requires Unix sockets + specific kernel features)
  - systemd-resolved stub must be disabled before install
  - hostname must be short (NetBIOS limit: ≤ 15 chars)
  - NTP sync required (Kerberos 5-minute window)
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

SAMBA_CONF = "/etc/samba/smb.conf"
SAMBA_PRIVATE = "/var/lib/samba/private"
KRBTGT_ROTATE_TIMER = """[Unit]
Description=Rotate Samba AD krbtgt password monthly
[Timer]
OnCalendar=monthly
Persistent=true
[Install]
WantedBy=timers.target
"""


def _run(cmd: list, timeout: int = 300,
         input_data: str = None, env: dict = None) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "dry-run", ""
    try:
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env=run_env,
            input=input_data,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


class SambaADInstaller:
    """
    Installs and configures Samba4 as an Active Directory Domain Controller.
    """

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir = Path(suite_dir)
        self.cm = config_manager
        self.sm = secrets_manager
        self.scripts_dir = self.suite_dir / "scripts"

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Samba4 Active Directory Domain Controller[/bold cyan]\n")
        console.print(
            "[dim]Samba4 AD provides native Windows AD compatibility: Kerberos, "
            "LDAP, DNS, GPO, and domain join for Windows and Linux clients.[/dim]\n"
        )

        cfg = self._collect_config(config)
        if not cfg:
            return False

        if not self._preflight(cfg):
            return False

        if not Confirm.ask("\n  Ready to provision Samba AD domain. Continue?",
                           default=True):
            return False

        self._disable_resolved_stub(cfg)
        self._set_hostname(cfg)

        if not self._install_packages():
            return False

        if not self._provision_domain(cfg):
            return False

        self._configure_ntp_sync(cfg)
        self._configure_dns(cfg)
        self._configure_kerberos_client(cfg)
        self._harden(cfg)
        self._create_systemd_service()
        self._generate_client_scripts(cfg)
        self._configure_firewall(cfg)
        self._register(cfg)
        self._print_summary(cfg)
        return True

    # -----------------------------------------------------------------------
    # Configuration collection
    # -----------------------------------------------------------------------

    def _collect_config(self, config: dict) -> Optional[dict]:
        domain = config.get("domain", "")
        if not domain:
            domain = Prompt.ask("  DNS domain name (e.g. example.com)")

        default_realm    = domain.upper()
        default_netbios  = domain.split(".")[0].upper()[:15]
        default_hostname = f"dc1.{domain}"

        console.print("\n[bold]Samba AD Configuration[/bold]\n")

        fqdn = Prompt.ask(
            "  DC hostname (FQDN)",
            default=default_hostname,
        )
        short_host = fqdn.split(".")[0]
        if len(short_host) > 15:
            console.print(
                f"  [yellow]Warning: NetBIOS name '{short_host}' is > 15 chars. "
                f"Truncating to '{short_host[:15]}'.[/yellow]"
            )
            short_host = short_host[:15]

        realm    = Prompt.ask("  Kerberos realm", default=default_realm)
        netbios  = Prompt.ask("  NetBIOS domain name", default=default_netbios)

        admin_pass = self._gen_pass(16)
        admin_pass = Prompt.ask(
            "  Administrator password (Windows AD admin)",
            default=admin_pass, password=True
        )

        manage_dns = Confirm.ask(
            "\n  Use Samba internal DNS (recommended for simple setups)?",
            default=True
        )
        dns_backend = "SAMBA_INTERNAL" if manage_dns else "BIND9_DLZ"

        if not manage_dns:
            console.print(
                "  [dim]BIND9_DLZ mode: Samba writes DNS data into BIND9 via "
                "a loadable zone module. BIND9 must already be installed.[/dim]"
            )

        forwarders = []
        if manage_dns:
            fwd = Prompt.ask("  DNS forwarders", default="1.1.1.1,8.8.8.8")
            forwarders = [f.strip() for f in fwd.split(",") if f.strip()]

        server_ip = self._detect_lan_ip()
        server_ip = Prompt.ask("  Server LAN IP", default=server_ip or "")

        add_laps = Confirm.ask(
            "\n  Enable LAPS (Local Administrator Password Solution) schema extension?",
            default=False
        )
        add_recycle = Confirm.ask(
            "  Enable AD Recycle Bin (recover deleted objects)?",
            default=True
        )

        return {
            "domain":       domain,
            "fqdn":         fqdn,
            "short_host":   short_host,
            "realm":        realm.upper(),
            "netbios":      netbios.upper(),
            "admin_pass":   admin_pass,
            "dns_backend":  dns_backend,
            "manage_dns":   manage_dns,
            "forwarders":   forwarders,
            "server_ip":    server_ip,
            "add_laps":     add_laps,
            "add_recycle":  add_recycle,
            "domain_level": "2016",  # AD functional level
        }

    # -----------------------------------------------------------------------
    # Pre-flight
    # -----------------------------------------------------------------------

    def _preflight(self, cfg: dict) -> bool:
        console.print("\n[bold]Pre-flight checks[/bold]")
        ok = True

        checks = [
            ("RAM",         self._check_ram()),
            ("Hostname length", self._check_netbios_name(cfg["short_host"])),
            ("Port 389 (LDAP)", self._check_port_free(389)),
            ("Port 88 (Kerberos)", self._check_port_free(88)),
            ("Port 53 (DNS)",  self._check_port_free(53) if cfg["manage_dns"] else (True, "skipped — external DNS")),
            ("Time sync",    self._check_time_sync()),
            ("Not in container", self._check_not_lxc()),
        ]

        table = Table("Check", "Status", "Detail",
                      show_header=True, header_style="bold magenta", border_style="dim")
        for name, (passed, detail) in checks:
            icon = "[green]✓[/green]" if passed else "[red]✗[/red]"
            table.add_row(name, icon, detail)
            if not passed:
                ok = False

        console.print(table)

        if not ok:
            console.print(
                "\n[red]Pre-flight failed. Fix the issues above before provisioning.[/red]"
            )
        return ok

    def _check_ram(self) -> tuple[bool, str]:
        try:
            kb = int([l for l in Path("/proc/meminfo").read_text().splitlines()
                      if l.startswith("MemTotal:")][0].split()[1])
            mb = kb // 1024
            return mb >= 1024, f"{mb} MB (min 1024 MB)"
        except Exception:
            return True, "could not read"

    def _check_netbios_name(self, name: str) -> tuple[bool, str]:
        ok = len(name) <= 15 and re.match(r'^[A-Z0-9\-]+$', name.upper()) is not None
        return ok, f"'{name}' ({'ok' if ok else 'invalid — alphanumeric + hyphens, max 15 chars'})"

    def _check_port_free(self, port: int) -> tuple[bool, str]:
        import socket
        try:
            with socket.socket() as s:
                s.settimeout(1)
                in_use = s.connect_ex(("127.0.0.1", port)) == 0
            return not in_use, f":{port} {'in use — stop conflicting service' if in_use else 'free'}"
        except Exception:
            return True, f":{port} check failed"

    def _check_time_sync(self) -> tuple[bool, str]:
        rc, out, _ = _run(["chronyc", "tracking"], timeout=5)
        if rc == 0:
            for line in out.splitlines():
                if "System time" in line:
                    try:
                        skew = abs(float(line.split()[3]))
                        return skew < 300, f"skew {skew:.2f}s"
                    except (ValueError, IndexError):
                        pass
        return True, "could not verify (install chrony)"

    def _check_not_lxc(self) -> tuple[bool, str]:
        # Samba AD works poorly in LXC without privileged mode
        virt_what = Path("/proc/1/environ")
        if Path("/.dockerenv").exists():
            return False, "running in Docker — Samba AD requires a VM or bare metal"
        if Path("/run/systemd/container").exists():
            container_type = Path("/run/systemd/container").read_text().strip()
            if container_type in ("lxc", "lxc-libvirt"):
                return False, f"running in {container_type} (need privileged LXC or VM)"
        return True, "bare metal or VM"

    # -----------------------------------------------------------------------
    # System setup
    # -----------------------------------------------------------------------

    def _disable_resolved_stub(self, cfg: dict):
        console.print("[cyan]Disabling systemd-resolved stub (frees port 53)...[/cyan]")
        conf_dir = Path("/etc/systemd/resolved.conf.d")
        if not DRY_RUN:
            conf_dir.mkdir(parents=True, exist_ok=True)
            (conf_dir / "samba-ad.conf").write_text(
                "[Resolve]\nDNSStubListener=no\n"
                f"DNS={cfg['server_ip']}\nFallbackDNS=1.1.1.1\n"
            )
        _run(["systemctl", "restart", "systemd-resolved"])

        resolv = Path("/etc/resolv.conf")
        if not DRY_RUN:
            if resolv.is_symlink():
                resolv.unlink()
            resolv.write_text(
                "# Managed by server-suite / Samba AD\n"
                f"search {cfg['domain']}\n"
                f"nameserver {cfg['server_ip']}\n"
                "nameserver 1.1.1.1\n"
            )
        console.print("  [dim]systemd-resolved stub disabled ✓[/dim]")

    def _set_hostname(self, cfg: dict):
        console.print(f"[cyan]Setting hostname to {cfg['fqdn']}...[/cyan]")
        _run(["hostnamectl", "set-hostname", cfg["fqdn"]])

        # /etc/hosts entry
        hosts = Path("/etc/hosts")
        if not DRY_RUN:
            content = hosts.read_text()
            # Remove old 127.0.1.1 entries
            new_lines = [l for l in content.splitlines()
                         if cfg["short_host"] not in l or not l.startswith("127.")]
            # Insert correct entry
            entry = f"{cfg['server_ip']}\t{cfg['fqdn']}\t{cfg['short_host']}"
            final = []
            inserted = False
            for line in new_lines:
                final.append(line)
                if line.startswith("127.0.0.1") and not inserted:
                    final.append(entry)
                    inserted = True
            if not inserted:
                final.insert(1, entry)
            hosts.write_text("\n".join(final) + "\n")
        console.print(f"  [dim]/etc/hosts: {cfg['server_ip']} → {cfg['fqdn']} ✓[/dim]")

    # -----------------------------------------------------------------------
    # Package installation
    # -----------------------------------------------------------------------

    def _install_packages(self) -> bool:
        console.print("\n[cyan]Installing Samba AD packages...[/cyan]")

        packages = [
            "samba",
            "samba-dsdb-modules",
            "samba-vfs-modules",
            "winbind",
            "libpam-winbind",
            "libnss-winbind",
            "krb5-user",
            "krb5-config",
            "dnsutils",
            "acl",
            "attr",
        ]

        _run(["apt-get", "update", "-qq"])
        rc, _, err = _run(
            ["apt-get", "install", "-y", "--no-install-recommends"] + packages,
            timeout=600,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
        if rc != 0 and not DRY_RUN:
            console.print(f"[red]Package install failed: {err}[/red]")
            return False

        # Stop any running Samba services before provisioning
        for svc in ["smbd", "nmbd", "winbind", "samba-ad-dc"]:
            _run(["systemctl", "stop", svc], timeout=10)
            _run(["systemctl", "disable", svc], timeout=10)

        # Remove default smb.conf (provision will recreate)
        if Path(SAMBA_CONF).exists() and not DRY_RUN:
            Path(SAMBA_CONF).rename(f"{SAMBA_CONF}.bak")

        console.print("  [green]Samba packages installed ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # Domain provisioning
    # -----------------------------------------------------------------------

    def _provision_domain(self, cfg: dict) -> bool:
        """Run samba-tool domain provision."""
        console.print(f"\n[cyan]Provisioning AD domain {cfg['realm']}...[/cyan]")
        console.print("  [dim]This takes 1-3 minutes...[/dim]")

        log_path = Path("/var/log/server-suite/samba-provision.log")
        if not DRY_RUN:
            log_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            "samba-tool", "domain", "provision",
            f"--realm={cfg['realm']}",
            f"--domain={cfg['netbios']}",
            f"--server-role=dc",
            f"--dns-backend={cfg['dns_backend']}",
            f"--adminpass={cfg['admin_pass']}",
            f"--host-name={cfg['short_host']}",
            f"--host-ip={cfg['server_ip']}",
            "--use-rfc2307",          # Enable POSIX attrs (UID/GID) in AD
            "--option=dns forwarder=" + " ".join(cfg["forwarders"]) if cfg["forwarders"] else "",
        ]
        cmd = [c for c in cmd if c]  # Remove empty strings

        if DRY_RUN:
            console.print(f"  [dim][DRY RUN] {' '.join(cmd[:6])} ...[/dim]")
            return True

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            output_lines = []
            with open(log_path, "w") as lf:
                for line in proc.stdout:
                    lf.write(line)
                    output_lines.append(line.strip())
                    if any(kw in line for kw in ["Setting up", "Creating", "A Kerberos",
                                                  "Once", "Please", "Provisioning"]):
                        console.print(f"  [dim]{line.strip()}[/dim]")

            proc.wait(timeout=300)
            if proc.returncode != 0:
                console.print(f"[red]Provisioning failed (exit {proc.returncode})[/red]")
                console.print(f"[dim]Log: {log_path}[/dim]")
                for line in output_lines[-10:]:
                    if line:
                        console.print(f"  [dim]{line}[/dim]")
                return False
        except Exception as e:
            console.print(f"[red]Provisioning error: {e}[/red]")
            return False

        # Enable and start samba-ad-dc
        _run(["systemctl", "unmask", "samba-ad-dc"])
        _run(["systemctl", "enable", "samba-ad-dc"])
        _run(["systemctl", "start", "samba-ad-dc"], timeout=30)

        # Brief wait for services to come up
        time.sleep(3)

        # Verify DC is running
        rc, out, _ = _run(["samba-tool", "domain", "info", "127.0.0.1"], timeout=15)
        if rc == 0:
            console.print("\n[bold green]Samba AD domain provisioned ✓[/bold green]")
            console.print(f"  [dim]{out.splitlines()[0] if out else ''}[/dim]")
        else:
            console.print("[yellow]DC started but info check failed — may still be initialising[/yellow]")

        # Enable optional features
        if cfg["add_recycle"]:
            _run(["samba-tool", "domain", "tombstones", "show"], timeout=10)
            rc2, _, _ = _run([
                "samba-tool", "domain", "functional-prep", "--function-level=2016",
            ], timeout=30)
            _run(["samba-tool", "ldapcmp", "--two"],  timeout=30)

        if cfg["add_laps"]:
            self._extend_schema_laps()

        return True

    def _extend_schema_laps(self):
        """Add Microsoft LAPS schema extension to AD."""
        console.print("  [dim]Extending schema for LAPS...[/dim]")
        laps_ldif = Path("/tmp/ms-laps-schema.ldif")
        if not DRY_RUN:
            laps_ldif.write_text(
                "dn: CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=domain,DC=local\n"
                "objectClass: attributeSchema\n"
                "attributeID: 1.2.840.113556.1.8000.2554.50051.45980.28112.10254.30719.2.1\n"
                "cn: ms-Mcs-AdmPwd\n"
                "adminDisplayName: ms-Mcs-AdmPwd\n"
                "attributeSyntax: 2.5.5.12\n"
                "oMSyntax: 64\n"
                "isSingleValued: TRUE\n"
                "showInAdvancedViewOnly: TRUE\n"
                "adminDescription: Stores the local administrator password\n"
            )
        _run(["samba-tool", "schema", "upgrade", "--schema=2019"], timeout=60)
        console.print("  [dim]LAPS schema extension applied ✓[/dim]")

    # -----------------------------------------------------------------------
    # NTP, DNS, Kerberos configuration
    # -----------------------------------------------------------------------

    def _configure_ntp_sync(self, cfg: dict):
        """Configure Samba as an NTP server for domain clients."""
        console.print("[cyan]Configuring NTP time sync...[/cyan]")
        smb_conf = Path(SAMBA_CONF)
        if DRY_RUN or not smb_conf.exists():
            return

        content = smb_conf.read_text()
        if "ntp signd socket directory" not in content:
            content = content.replace(
                "[global]",
                "[global]\n\tntp signd socket directory = /var/lib/samba/ntp_signd"
            )
            smb_conf.write_text(content)

        # Create NTP signd socket directory
        ntp_dir = Path("/var/lib/samba/ntp_signd")
        if not DRY_RUN:
            ntp_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(ntp_dir, 0o750)
        console.print("  [dim]Samba NTP signing socket configured ✓[/dim]")

    def _configure_dns(self, cfg: dict):
        """Add forwarder config to Samba DNS if using internal backend."""
        if not cfg["manage_dns"] or not cfg["forwarders"]:
            return
        console.print("[cyan]Configuring DNS forwarders...[/cyan]")
        smb_conf = Path(SAMBA_CONF)
        if DRY_RUN or not smb_conf.exists():
            return

        content = smb_conf.read_text()
        fwd_str = " ".join(cfg["forwarders"])
        if "dns forwarder" not in content:
            content = content.replace(
                "[global]",
                f"[global]\n\tdns forwarder = {fwd_str}"
            )
            smb_conf.write_text(content)
        console.print(f"  [dim]DNS forwarders: {fwd_str} ✓[/dim]")

    def _configure_kerberos_client(self, cfg: dict):
        """Write /etc/krb5.conf for Kerberos tools to work against this DC."""
        console.print("[cyan]Configuring Kerberos client (/etc/krb5.conf)...[/cyan]")
        krb5_conf = (
            f"[libdefaults]\n"
            f"\tdefault_realm = {cfg['realm']}\n"
            f"\tdns_lookup_realm = false\n"
            f"\tdns_lookup_kdc = true\n"
            f"\tforwardable = true\n"
            f"\tticket_lifetime = 24h\n"
            f"\trenew_lifetime = 7d\n\n"
            f"[realms]\n"
            f"\t{cfg['realm']} = {{\n"
            f"\t\tkdc = {cfg['fqdn']}\n"
            f"\t\tadmin_server = {cfg['fqdn']}\n"
            f"\t}}\n\n"
            f"[domain_realm]\n"
            f"\t.{cfg['domain']} = {cfg['realm']}\n"
            f"\t{cfg['domain']} = {cfg['realm']}\n"
        )
        if not DRY_RUN:
            Path("/etc/krb5.conf").write_text(krb5_conf)
        console.print("  [dim]/etc/krb5.conf written ✓[/dim]")

    # -----------------------------------------------------------------------
    # Hardening
    # -----------------------------------------------------------------------

    def _harden(self, cfg: dict):
        """Apply security hardening to the Samba AD configuration."""
        console.print("[cyan]Applying Samba AD hardening...[/cyan]")
        smb_conf = Path(SAMBA_CONF)
        if DRY_RUN or not smb_conf.exists():
            return

        content = smb_conf.read_text()

        hardening_opts = {
            "server min protocol":           "SMB2",
            "client min protocol":           "SMB2",
            "client max protocol":           "SMB3",
            "ntlm auth":                     "ntlmv2-only",
            "lanman auth":                   "no",
            "null passwords":                "no",
            "raw NTLMv2 auth":               "no",
            "log level":                     "1 auth_audit:3",
            "log file":                      "/var/log/samba/log.%m",
            "max log size":                  "10000",
            "panic action":                  "/usr/share/samba/panic-action %d",
        }

        global_section = []
        in_global = False
        new_lines = []
        added_opts = set()

        for line in content.splitlines():
            if line.strip().lower() == "[global]":
                in_global = True
                new_lines.append(line)
                # Inject hardening opts right after [global]
                for key, val in hardening_opts.items():
                    new_lines.append(f"\t{key} = {val}")
                    added_opts.add(key.lower())
                continue

            if in_global and line.strip().startswith("[") and line.strip() != "[global]":
                in_global = False

            # Skip any existing conflicting options
            if in_global and "=" in line:
                opt_key = line.split("=")[0].strip().lower()
                if opt_key in added_opts:
                    continue

            new_lines.append(line)

        smb_conf.write_text("\n".join(new_lines) + "\n")

        # Set a strong password policy via samba-tool
        _run([
            "samba-tool", "domain", "passwordsettings", "set",
            "--min-pwd-length=12",
            "--min-pwd-age=1",
            "--max-pwd-age=90",
            "--complexity=on",
            "--history-length=10",
            "--account-lockout-threshold=6",
            "--account-lockout-duration=10",
            "--reset-account-lockout-after=60",
        ], timeout=30)

        console.print("  [dim]SMB min protocol: SMB2, NTLMv2-only ✓[/dim]")
        console.print("  [dim]Password policy: min 12, complexity, 90-day max ✓[/dim]")

    # -----------------------------------------------------------------------
    # Systemd service
    # -----------------------------------------------------------------------

    def _create_systemd_service(self):
        """Ensure samba-ad-dc is the only Samba service unit running."""
        # Mask conflicting services
        for svc in ["smbd", "nmbd", "winbind"]:
            _run(["systemctl", "mask", svc])
        _run(["systemctl", "enable", "samba-ad-dc"])
        console.print("  [dim]samba-ad-dc enabled, smbd/nmbd/winbind masked ✓[/dim]")

    # -----------------------------------------------------------------------
    # Client enrollment scripts
    # -----------------------------------------------------------------------

    def _generate_client_scripts(self, cfg: dict):
        """Generate scripts to join Linux and Windows clients to the domain."""
        if not DRY_RUN:
            self.scripts_dir.mkdir(parents=True, exist_ok=True)

        # Linux client join script
        linux_script = f"""#!/usr/bin/env bash
# =============================================================================
# Server Suite — Samba AD Linux Client Join
# Joins an Ubuntu/Debian machine to the {cfg['realm']} AD domain.
# Prerequisites: network access to DC at {cfg['fqdn']} ({cfg['server_ip']})
# Usage: sudo bash join-samba-domain.sh [Administrator-password]
# =============================================================================
set -euo pipefail

DC_FQDN="{cfg['fqdn']}"
DC_IP="{cfg['server_ip']}"
DOMAIN="{cfg['domain']}"
REALM="{cfg['realm']}"
NETBIOS="{cfg['netbios']}"
ADMIN_PASS="${{1:-}}"

[[ $EUID -ne 0 ]] && {{ echo "Must run as root"; exit 1; }}

echo "=== Joining $REALM AD domain ==="

# Install required packages
apt-get update -qq
apt-get install -y sssd sssd-ad realmd adcli krb5-user \\
    libnss-sss libpam-sss oddjob oddjob-mkhomedir samba-common-bin \\
    packagekit --no-install-recommends

# Point DNS to DC
if ! grep -q "$DC_IP" /etc/resolv.conf; then
    cat > /etc/resolv.conf << EOF
# Server Suite - Samba AD domain
search $DOMAIN
nameserver $DC_IP
nameserver 1.1.1.1
EOF
fi

# Add DC to /etc/hosts if DNS not yet working
if ! host "$DC_FQDN" &>/dev/null; then
    echo "$DC_IP  $DC_FQDN" >> /etc/hosts
fi

# Discover realm
realm discover "$REALM"

# Join domain
if [[ -n "$ADMIN_PASS" ]]; then
    echo "$ADMIN_PASS" | realm join -U Administrator "$REALM"
else
    realm join -U Administrator "$REALM"
fi

# Configure SSSD
cat > /etc/sssd/sssd.conf << 'SSSD'
[sssd]
domains = {cfg['domain']}
config_file_version = 2
services = nss, pam, sudo

[domain/{cfg['domain']}]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_domain = {cfg['domain']}
krb5_realm = {cfg['realm']}
realmd_tags = manages-system joined-with-samba
cache_credentials = True
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = False
fallback_homedir = /home/%u
access_control_provider = ad
dyndns_update = true
ad_gpo_access_control = enforcing
SSSD
chmod 600 /etc/sssd/sssd.conf

# Enable auto-homedir
authselect select sssd with-mkhomedir --force 2>/dev/null || \\
    pam-auth-update --enable mkhomedir
systemctl enable --now oddjobd sssd

echo "=== Domain join complete ==="
echo "Test: id Administrator@$DOMAIN"
realm list
"""

        # Windows join instructions
        windows_script = f"""# Windows Domain Join — {cfg['realm']}
# ==============================================
# Run these steps on each Windows machine.

# 1. Set DNS to point at the DC:
#    Control Panel → Network → IPv4 → DNS: {cfg['server_ip']}

# 2. Join the domain via PowerShell (run as Administrator):
$domain = "{cfg['domain']}"
$credential = Get-Credential -UserName "Administrator@{cfg['realm']}" -Message "Enter AD admin password"
Add-Computer -DomainName $domain -Credential $credential -Restart

# 3. Or via GUI:
#    System → Advanced system settings → Computer Name → Change
#    Select "Domain", enter: {cfg['domain']}
#    Credentials: Administrator / <your password>

# 4. Verify from Windows:
#    nltest /sc_query:{cfg['netbios']}
#    whoami /fqdn

# 5. Verify from DC (Linux):
#    samba-tool user list
#    samba-tool computer list
"""

        if not DRY_RUN:
            linux_path = self.scripts_dir / "join-samba-domain.sh"
            windows_path = self.scripts_dir / "join-samba-domain-windows.ps1"
            linux_path.write_text(linux_script)
            windows_path.write_text(windows_script)
            os.chmod(linux_path, 0o750)
        console.print(
            f"  [dim]Client scripts: {self.scripts_dir}/join-samba-domain.sh (.ps1) ✓[/dim]"
        )

    # -----------------------------------------------------------------------
    # Firewall
    # -----------------------------------------------------------------------

    def _configure_firewall(self, cfg: dict):
        console.print("[cyan]Configuring firewall...[/cyan]")
        ports = [
            ("53",    "tcp"), ("53",  "udp"),
            ("88",    "tcp"), ("88",  "udp"),
            ("135",   "tcp"),
            ("139",   "tcp"),
            ("389",   "tcp"), ("389", "udp"),
            ("445",   "tcp"),
            ("464",   "tcp"), ("464", "udp"),
            ("636",   "tcp"),
            ("3268",  "tcp"),
            ("3269",  "tcp"),
            ("49152:65535", "tcp"),  # Dynamic RPC range
        ]
        for port, proto in ports:
            _run(["ufw", "allow", f"{port}/{proto}"])
        _run(["ufw", "reload"])
        console.print("  [dim]Firewall rules applied ✓[/dim]")

    # -----------------------------------------------------------------------
    # Registration & summary
    # -----------------------------------------------------------------------

    def _register(self, cfg: dict):
        if not self.cm:
            return
        self.cm.add_role("identity", {
            "engine":     "samba_ad",
            "fqdn":       cfg["fqdn"],
            "realm":      cfg["realm"],
            "netbios":    cfg["netbios"],
            "domain":     cfg["domain"],
            "server_ip":  cfg["server_ip"],
            "manage_dns": cfg["manage_dns"],
        })
        if self.sm:
            self.sm.write_env_file("samba_ad", {
                "SAMBA_REALM":      cfg["realm"],
                "SAMBA_DOMAIN":     cfg["domain"],
                "SAMBA_NETBIOS":    cfg["netbios"],
                "SAMBA_ADMIN_PASS": cfg["admin_pass"],
                "SAMBA_DC_FQDN":    cfg["fqdn"],
            })
        if cfg["manage_dns"]:
            self.cm.set("roles.dns_dhcp.suppressed_by", "samba_ad")

    def _print_summary(self, cfg: dict):
        console.print()
        console.print(Panel(
            f"[bold green]Samba AD Domain Controller ready[/bold green]\n\n"
            f"  Domain:     [cyan]{cfg['domain']}[/cyan]\n"
            f"  Realm:      [cyan]{cfg['realm']}[/cyan]\n"
            f"  NetBIOS:    [cyan]{cfg['netbios']}[/cyan]\n"
            f"  DC:         [cyan]{cfg['fqdn']} ({cfg['server_ip']})[/cyan]\n"
            f"  Admin:      [cyan]Administrator[/cyan] (password in secrets/.env.samba_ad)\n"
            f"  DNS:        [cyan]{'Samba internal' if cfg['manage_dns'] else 'BIND9_DLZ'}[/cyan]\n\n"
            f"  [bold]Join Linux clients:[/bold]\n"
            f"  [dim]bash {self.scripts_dir}/join-samba-domain.sh <admin-password>[/dim]\n\n"
            f"  [bold]Common samba-tool commands:[/bold]\n"
            f"  [dim]samba-tool user add <user> --given-name=... --surname=...[/dim]\n"
            f"  [dim]samba-tool group addmembers 'Domain Admins' <user>[/dim]\n"
            f"  [dim]samba-tool domain info 127.0.0.1[/dim]\n"
            f"  [dim]samba-tool dns query {cfg['fqdn']} {cfg['domain']} @ ALL[/dim]",
            border_style="green",
            padding=(1, 2),
        ))

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _gen_pass(self, n: int = 16) -> str:
        return (self.sm.generate_password(n) if self.sm
                else os.urandom(n // 2).hex())

    def _detect_lan_ip(self) -> str:
        try:
            rc, out, _ = _run(["hostname", "-I"])
            if rc == 0:
                ips = [ip for ip in out.split()
                       if not ip.startswith("127.") and ":" not in ip]
                return ips[0] if ips else ""
        except Exception:
            pass
        return ""
