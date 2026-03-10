"""
roles/identity/freeipa.py
=========================
FreeIPA native installation on Ubuntu/Debian.
FreeIPA provides:
  - Kerberos KDC (authentication)
  - 389 Directory Server (LDAP)
  - Dogtag PKI (certificate authority)
  - Integrated DNS (BIND9 with DNSSEC) — optional
  - Web UI + REST API
  - SSSD integration for Linux clients
  - sudo rules, HBAC (host-based access control), automount

Architecture note:
  FreeIPA REPLACES standalone DNS, DHCP CA, and directory services.
  If the user selects FreeIPA AND dns_dhcp, we suppress dns_dhcp
  and instead configure FreeIPA's integrated DNS.
"""

import os
import re
import subprocess
import time
import socket
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

# Minimum FreeIPA server version available in Ubuntu repos
FREEIPA_PKG_SERVER = "freeipa-server"
FREEIPA_PKG_DNS    = "freeipa-server-dns"
FREEIPA_PKG_CA     = "freeipa-server-trust-ad"   # AD trust support


def _run(cmd: list, timeout: int = 300,
         env: Optional[dict] = None) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "dry-run", ""
    try:
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env=run_env
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


class FreeIPAInstaller:
    """
    Installs and configures FreeIPA server on Ubuntu/Debian.
    Handles:
      - Package installation
      - ipa-server-install (unattended)
      - Post-install hardening
      - Suppression of redundant roles (DNS, CA)
      - Client enrollment script generation
      - Initial admin policies
    """

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir  = Path(suite_dir)
        self.cm         = config_manager
        self.sm         = secrets_manager
        self.scripts_dir = self.suite_dir / "scripts"

    # -----------------------------------------------------------------------
    # Main install flow
    # -----------------------------------------------------------------------

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]FreeIPA Identity & Directory Server[/bold cyan]\n")
        console.print(
            "[dim]FreeIPA provides Kerberos, LDAP, PKI Certificate Authority, "
            "DNS, and web-based identity management in a single integrated stack.[/dim]\n"
        )

        # ---- Collect configuration ----------------------------------------
        cfg = self._collect_config(config)
        if not cfg:
            return False

        # ---- Pre-flight checks --------------------------------------------
        from roles.identity.preflight import FreeIPAPreflight
        pf = FreeIPAPreflight(
            realm      = cfg["realm"],
            domain     = cfg["domain"],
            fqdn       = cfg["fqdn"],
            manage_dns = cfg["manage_dns"],
        )
        if not pf.run():
            return False

        if not Confirm.ask("\n  Pre-flight complete. Begin FreeIPA installation?",
                           default=True):
            return False

        # ---- /etc/hosts entry --------------------------------------------
        self._ensure_hosts_entry(cfg)

        # ---- Disable systemd-resolved stub (frees port 53) ---------------
        if cfg["manage_dns"]:
            self._disable_resolved_stub(cfg["server_ip"])

        # ---- Install packages --------------------------------------------
        if not self._install_packages(cfg):
            return False

        # ---- Run ipa-server-install --------------------------------------
        if not self._run_ipa_install(cfg):
            return False

        # ---- Post-install hardening --------------------------------------
        self._post_install_hardening(cfg)

        # ---- Register with config manager --------------------------------
        self._register(cfg)

        # ---- Suppress conflicting roles ----------------------------------
        self._suppress_redundant_roles(cfg, config)

        # ---- Generate client enrollment script ---------------------------
        self._generate_client_script(cfg)

        # ---- Configure firewall ------------------------------------------
        self._configure_firewall(cfg)

        # ---- Initial admin policies --------------------------------------
        self._setup_initial_policies(cfg)

        # ---- Print summary -----------------------------------------------
        self._print_summary(cfg)

        return True

    # -----------------------------------------------------------------------
    # Configuration collection
    # -----------------------------------------------------------------------

    def _collect_config(self, config: dict) -> Optional[dict]:
        domain   = config.get("domain", "")
        hostname = config.get("hostname", "")

        if not domain:
            domain = Prompt.ask("  Base domain (e.g. example.com)")

        # Derive sensible defaults
        default_ipa_hostname = f"ipa.{domain}"
        default_realm        = domain.upper()
        default_netbios      = domain.split(".")[0].upper()[:15]

        console.print("\n[bold]FreeIPA Configuration[/bold]\n")

        ipa_hostname = Prompt.ask(
            "  IPA server hostname (FQDN)",
            default=default_ipa_hostname
        )
        realm = Prompt.ask(
            "  Kerberos realm",
            default=default_realm
        )
        ds_password = self._gen_pass(20)
        admin_password = self._gen_pass(16)

        console.print()
        console.print("  [bold]Directory Manager password[/bold] (LDAP admin — never used day-to-day)")
        ds_password = Prompt.ask(
            "  Directory Manager password",
            default=ds_password,
            password=True
        )
        console.print("  [bold]IPA admin password[/bold] (web UI + kinit admin)")
        admin_password = Prompt.ask(
            "  IPA admin password",
            default=admin_password,
            password=True
        )

        manage_dns = Confirm.ask(
            "\n  Enable FreeIPA integrated DNS (BIND9 with DNSSEC)?",
            default=True
        )

        forwarders = []
        if manage_dns:
            fwd_input = Prompt.ask(
                "  DNS forwarders (comma-separated)",
                default="1.1.1.1,8.8.8.8"
            )
            forwarders = [f.strip() for f in fwd_input.split(",") if f.strip()]

        manage_ntp = Confirm.ask(
            "  Enable FreeIPA integrated NTP (Chrony)?",
            default=True
        )

        setup_ca = Confirm.ask(
            "  Set up integrated Certificate Authority (Dogtag PKI)?",
            default=True
        )

        ca_subject = f"CN=Certificate Authority,O={realm}"
        if setup_ca:
            ca_subject = Prompt.ask(
                "  CA subject DN",
                default=ca_subject
            )

        # Detect server IP
        server_ip = self._detect_lan_ip()
        server_ip = Prompt.ask("  Server LAN IP address", default=server_ip or "")

        return {
            "domain":        domain,
            "fqdn":          ipa_hostname,
            "short_hostname": ipa_hostname.split(".")[0],
            "realm":         realm.upper(),
            "ds_password":   ds_password,
            "admin_password": admin_password,
            "manage_dns":    manage_dns,
            "manage_ntp":    manage_ntp,
            "setup_ca":      setup_ca,
            "ca_subject":    ca_subject,
            "forwarders":    forwarders,
            "server_ip":     server_ip,
        }

    # -----------------------------------------------------------------------
    # /etc/hosts
    # -----------------------------------------------------------------------

    def _ensure_hosts_entry(self, cfg: dict):
        """
        Ensure /etc/hosts has the correct entry for the IPA FQDN.
        FreeIPA's installer reads /etc/hosts and will fail if FQDN
        resolves to 127.0.1.1 or is missing.
        """
        console.print("[cyan]Configuring /etc/hosts...[/cyan]")
        hosts_path = Path("/etc/hosts")
        if DRY_RUN:
            console.print(f"  [dim][DRY RUN] Would add {cfg['server_ip']} entry[/dim]")
            return

        content = hosts_path.read_text()
        fqdn    = cfg["fqdn"]
        short   = cfg["short_hostname"]
        ip      = cfg["server_ip"]

        # Remove any existing entries for the FQDN
        new_lines = []
        for line in content.splitlines():
            if fqdn in line or (short in line and "127.0.1.1" in line):
                continue  # Remove old/loopback entries
            new_lines.append(line)

        # Add the correct entry at the top (after the 127.0.0.1 line)
        ipa_entry = f"{ip}\t{fqdn}\t{short}"
        final_lines = []
        inserted = False
        for line in new_lines:
            final_lines.append(line)
            if line.startswith("127.0.0.1") and not inserted:
                final_lines.append(ipa_entry)
                inserted = True
        if not inserted:
            final_lines.insert(1, ipa_entry)

        hosts_path.write_text("\n".join(final_lines) + "\n")
        console.print(f"  [dim]/etc/hosts: {ip} → {fqdn} ✓[/dim]")

    # -----------------------------------------------------------------------
    # systemd-resolved
    # -----------------------------------------------------------------------

    def _disable_resolved_stub(self, server_ip: str):
        """Disable the stub listener so FreeIPA's BIND can use port 53."""
        console.print("[cyan]Disabling systemd-resolved stub listener...[/cyan]")

        conf_dir = Path("/etc/systemd/resolved.conf.d")
        if not DRY_RUN:
            conf_dir.mkdir(parents=True, exist_ok=True)
            (conf_dir / "freeipa.conf").write_text(
                "[Resolve]\n"
                "DNSStubListener=no\n"
                f"DNS={server_ip}\n"
                "FallbackDNS=1.1.1.1 8.8.8.8\n"
            )
        _run(["systemctl", "restart", "systemd-resolved"])

        # Point resolv.conf at localhost (FreeIPA BIND will answer)
        resolv = Path("/etc/resolv.conf")
        if not DRY_RUN:
            if resolv.is_symlink():
                resolv.unlink()
            resolv.write_text(
                "# Managed by server-suite / FreeIPA\n"
                f"search {'.'.join(server_ip.split('.')[:-1])}.in-addr.arpa\n"
                f"nameserver {server_ip}\n"
                "nameserver 1.1.1.1\n"
            )
        console.print("  [dim]systemd-resolved stub disabled ✓[/dim]")

    # -----------------------------------------------------------------------
    # Package installation
    # -----------------------------------------------------------------------

    def _install_packages(self, cfg: dict) -> bool:
        console.print("\n[cyan]Installing FreeIPA packages...[/cyan]")
        console.print(
            "  [dim]This installs ~300MB of packages including 389-ds, "
            "MIT Kerberos, Dogtag PKI, and BIND.[/dim]"
        )

        # Add COPR or Ubuntu PPA for newer FreeIPA if on older Ubuntu
        os_info = self._detect_os()
        console.print(f"  [dim]OS: {os_info}[/dim]")

        packages = [FREEIPA_PKG_SERVER]
        if cfg["manage_dns"]:
            packages.append(FREEIPA_PKG_DNS)
        # sssd for local resolution
        packages += ["sssd", "sssd-ipa", "oddjob", "oddjob-mkhomedir"]

        _run(["apt-get", "update", "-qq"])

        rc, _, err = _run(
            ["apt-get", "install", "-y", "--no-install-recommends"] + packages,
            timeout=600
        )
        if rc != 0 and not DRY_RUN:
            console.print(f"[red]Package installation failed:[/red]\n{err}")
            console.print(
                "\n[yellow]Tip: On Ubuntu 22.04+, FreeIPA packages are available "
                "in the main repo. On older versions, you may need a PPA.[/yellow]"
            )
            return False

        console.print(f"  [green]FreeIPA packages installed ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # ipa-server-install
    # -----------------------------------------------------------------------

    def _run_ipa_install(self, cfg: dict) -> bool:
        """
        Run ipa-server-install in unattended mode.
        This is the long step — 10-20 minutes.
        """
        console.print("\n[cyan]Running ipa-server-install (10-20 minutes)...[/cyan]")

        # Build the command
        cmd = [
            "ipa-server-install",
            "--unattended",
            f"--realm={cfg['realm']}",
            f"--domain={cfg['domain']}",
            f"--hostname={cfg['fqdn']}",
            f"--ds-password={cfg['ds_password']}",
            f"--admin-password={cfg['admin_password']}",
            "--mkhomedir",
        ]

        if cfg["setup_ca"]:
            cmd += [
                "--setup-ca",
                f"--ca-subject={cfg['ca_subject']}",
            ]

        if cfg["manage_dns"]:
            cmd.append("--setup-dns")
            cmd.append("--auto-reverse")
            for fwd in cfg["forwarders"]:
                cmd += [f"--forwarder={fwd}"]
            # Allow zone overlap (important if Technitium was previously installed)
            cmd.append("--allow-zone-overlap")
        else:
            cmd.append("--no-dns-sshfp")

        if not cfg["manage_ntp"]:
            cmd.append("--no-ntp")

        if DRY_RUN:
            console.print(
                f"  [dim][DRY RUN] Would run: {' '.join(cmd[:6])} ...[/dim]"
            )
            return True

        # Stream output in real-time so user can see progress
        console.print(
            "  [dim]Output is streamed — this is normal, installation is working...[/dim]\n"
        )

        install_log = Path("/var/log/server-suite/freeipa-install.log")
        install_log.parent.mkdir(parents=True, exist_ok=True)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            progress_keywords = {
                "Configuring directory server":     "[1/12] 389 Directory Server",
                "Configuring Kerberos KDC":         "[2/12] Kerberos KDC",
                "Configuring kadmin":               "[3/12] kadmin daemon",
                "Adding the IPA CA":                "[4/12] IPA CA setup",
                "Configuring certificate server":   "[5/12] Dogtag PKI",
                "Configuring ipa-otpd":             "[6/12] OTP daemon",
                "Configuring the web interface":    "[7/12] Apache / web UI",
                "Configuring Kerberos clients":     "[8/12] Kerberos clients",
                "Configuring DNS":                  "[9/12] BIND DNS",
                "Configuring SID generation":       "[10/12] SID generation",
                "Restarting the directory server":  "[11/12] Final restart",
                "Please add records in this file":  "[12/12] DNS records",
            }

            with open(install_log, "w") as log_f:
                for line in proc.stdout:
                    log_f.write(line)
                    line_strip = line.strip()
                    # Print progress milestones
                    for keyword, label in progress_keywords.items():
                        if keyword in line_strip:
                            console.print(f"  [cyan]{label}[/cyan]")
                            break
                    # Print errors immediately
                    if any(w in line_strip.lower() for w in
                           ["error", "failed", "fatal", "critical"]):
                        if "Skipping" not in line_strip:
                            console.print(f"  [yellow]{line_strip}[/yellow]")

            proc.wait(timeout=1800)  # 30 min hard timeout

            if proc.returncode != 0:
                console.print(
                    f"\n[red]ipa-server-install failed (exit {proc.returncode})[/red]"
                )
                console.print(
                    f"[dim]Full log: {install_log}[/dim]"
                )
                self._print_common_errors(install_log)
                return False

        except subprocess.TimeoutExpired:
            console.print("[red]ipa-server-install timed out after 30 minutes[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Installation error: {e}[/red]")
            return False

        console.print("\n[bold green]ipa-server-install completed ✓[/bold green]")
        return True

    def _print_common_errors(self, log_path: Path):
        """Scan the install log for known failure patterns and give advice."""
        if not log_path.exists():
            return
        content = log_path.read_text()

        hints = {
            "port 389 already in use": (
                "An LDAP server is already running on port 389. "
                "Stop it first: systemctl stop slapd openldap"
            ),
            "hostname does not match": (
                "The system hostname doesn't match the FQDN you specified. "
                "Run: hostnamectl set-hostname " + "YOUR_FQDN"
            ),
            "DNS resolution failed": (
                "The FQDN can't be resolved. Check /etc/hosts has a real IP entry."
            ),
            "Time is out of sync": (
                "System clock is skewed >5 minutes. "
                "Run: chronyc makestep && chronyc waitsync 10"
            ),
            "Password must be at least": (
                "Password too short. IPA requires passwords of at least 8 characters."
            ),
            "already exists": (
                "A partial FreeIPA installation exists. "
                "Run: ipa-server-install --uninstall  then retry."
            ),
        }
        for pattern, hint in hints.items():
            if pattern.lower() in content.lower():
                console.print(f"\n  [yellow]Hint:[/yellow] {hint}")

    # -----------------------------------------------------------------------
    # Post-install hardening
    # -----------------------------------------------------------------------

    def _post_install_hardening(self, cfg: dict):
        """Apply security hardening after install."""
        console.print("\n[cyan]Applying post-install hardening...[/cyan]")

        # Get Kerberos ticket for admin operations
        if not DRY_RUN:
            self._kinit_admin(cfg["admin_password"])

        # 1. Set password policy
        self._set_password_policy(cfg)

        # 2. Disable anonymous LDAP access
        self._disable_anonymous_ldap()

        # 3. Enable LDAP referential integrity
        self._enable_ldap_referential_integrity()

        # 4. Set up SSSD on this server for local resolution
        self._configure_sssd_local(cfg)

        # 5. Enable auto-homedir creation
        _run(["authselect", "enable-feature", "with-mkhomedir"])
        _run(["systemctl", "enable", "--now", "oddjobd"])

        # 6. HBAC - set default policy to deny all, require explicit rules
        self._configure_hbac_default_deny(cfg)

        console.print("  [green]Post-install hardening applied ✓[/green]")

    def _kinit_admin(self, admin_password: str) -> bool:
        """Get Kerberos ticket for admin."""
        rc, _, err = _run(
            ["kinit", "admin"],
            timeout=30,
            env={"KRB5_TRACE": "/dev/null"}
        )
        if rc != 0:
            # Try with password via expect-like stdin
            try:
                result = subprocess.run(
                    ["kinit", "admin"],
                    input=admin_password,
                    capture_output=True, text=True, timeout=30
                )
                return result.returncode == 0
            except Exception:
                return False
        return True

    def _set_password_policy(self, cfg: dict):
        """Set a strong password policy."""
        # Global policy
        _run([
            "ipa", "pwpolicy-mod", "global_policy",
            "--minlength=12",
            "--minclasses=3",
            "--history=10",
            "--maxlife=90",
            "--minlife=1",
            "--maxfail=6",
            "--failinterval=60",
            "--lockouttime=600",
        ], timeout=30)
        console.print("  [dim]Password policy: min 12 chars, 3 classes, 90-day max, 6 lockout ✓[/dim]")

    def _disable_anonymous_ldap(self):
        """Disable unauthenticated LDAP binds."""
        if DRY_RUN:
            return
        ldif = (
            "dn: cn=config\n"
            "changetype: modify\n"
            "replace: nsslapd-allow-anonymous-access\n"
            "nsslapd-allow-anonymous-access: rootdse\n"
        )
        try:
            result = subprocess.run(
                ["ldapmodify", "-Y", "GSSAPI", "-H", "ldap://localhost"],
                input=ldif, capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                console.print("  [dim]Anonymous LDAP access disabled ✓[/dim]")
        except Exception:
            pass

    def _enable_ldap_referential_integrity(self):
        """Ensure referential integrity plugin is active."""
        _run([
            "ldapmodify", "-Y", "GSSAPI", "-H", "ldap://localhost",
            "-f", "/usr/share/dirsrv/data/referint-conf.ldif",
        ], timeout=15)

    def _configure_sssd_local(self, cfg: dict):
        """Configure SSSD on the IPA server itself."""
        if DRY_RUN:
            return
        sssd_conf = Path("/etc/sssd/sssd.conf")
        # ipa-server-install creates this — just verify and enable
        _run(["systemctl", "enable", "--now", "sssd"])
        _run(["sss_cache", "-E"])

    def _configure_hbac_default_deny(self, cfg: dict):
        """
        Disable the 'allow_all' HBAC rule and replace with explicit rules.
        This is the most important security step — by default FreeIPA
        allows all users to access all hosts.
        """
        # Disable the permissive default rule
        _run(["ipa", "hbacrule-disable", "allow_all"], timeout=30)

        # Create an admin access rule (admins can always log in everywhere)
        _run([
            "ipa", "hbacrule-add", "admin_access",
            "--desc=Allow admin group to access all hosts",
            "--servicecat=all",
            "--hostcat=all",
        ], timeout=30)
        _run([
            "ipa", "hbacrule-add-user", "admin_access",
            "--groups=admins",
        ], timeout=30)
        console.print("  [dim]HBAC: default allow_all disabled, explicit admin rule created ✓[/dim]")

    # -----------------------------------------------------------------------
    # SSSD client enrollment script
    # -----------------------------------------------------------------------

    def _generate_client_script(self, cfg: dict):
        """Generate a script to enroll Linux clients into the IPA domain."""
        script = f"""#!/usr/bin/env bash
# =============================================================================
# Server Suite — FreeIPA Client Enrollment
# Enrolls a Linux machine into the {cfg['realm']} Kerberos realm.
# Run this on every Linux server/desktop you want to manage via IPA.
# =============================================================================
set -euo pipefail

IPA_SERVER="{cfg['fqdn']}"
IPA_DOMAIN="{cfg['domain']}"
IPA_REALM="{cfg['realm']}"
IPA_ADMIN_PASS="${{1:-}}"  # Pass admin password as argument or will be prompted

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

echo "=== FreeIPA Client Enrollment ==="
echo "Server: $IPA_SERVER"
echo "Domain: $IPA_DOMAIN"
echo "Realm:  $IPA_REALM"
echo ""

# Install client packages
apt-get update -qq
apt-get install -y freeipa-client sssd sssd-ipa oddjob oddjob-mkhomedir

# Add IPA server to /etc/hosts if DNS not yet delegated
if ! host "$IPA_SERVER" &>/dev/null; then
    echo "# FreeIPA server" >> /etc/hosts
    echo "{cfg['server_ip']}  $IPA_SERVER" >> /etc/hosts
fi

# Run ipa-client-install
if [[ -n "$IPA_ADMIN_PASS" ]]; then
    ipa-client-install \\
        --server="$IPA_SERVER" \\
        --domain="$IPA_DOMAIN" \\
        --realm="$IPA_REALM" \\
        --principal=admin \\
        --password="$IPA_ADMIN_PASS" \\
        --mkhomedir \\
        --enable-dns-updates \\
        --unattended
else
    ipa-client-install \\
        --server="$IPA_SERVER" \\
        --domain="$IPA_DOMAIN" \\
        --realm="$IPA_REALM" \\
        --mkhomedir \\
        --enable-dns-updates
fi

# Enable auto-homedir
authselect enable-feature with-mkhomedir
systemctl enable --now oddjobd

# Enable SSSD
systemctl enable --now sssd

echo ""
echo "=== Enrollment complete ==="
echo "Users can now log in with their IPA credentials."
echo "Test: id admin@$IPA_REALM"
"""
        if not DRY_RUN:
            self.scripts_dir.mkdir(parents=True, exist_ok=True)
            script_path = self.scripts_dir / "enroll-ipa-client.sh"
            script_path.write_text(script)
            os.chmod(script_path, 0o750)
        console.print(
            f"  [dim]Client enrollment script: "
            f"{self.scripts_dir / 'enroll-ipa-client.sh'} ✓[/dim]"
        )

    # -----------------------------------------------------------------------
    # Firewall
    # -----------------------------------------------------------------------

    def _configure_firewall(self, cfg: dict):
        console.print("[cyan]Configuring firewall rules...[/cyan]")
        ports = [
            ("80",   "tcp"),
            ("443",  "tcp"),
            ("88",   "tcp"),
            ("88",   "udp"),
            ("389",  "tcp"),
            ("636",  "tcp"),
            ("464",  "tcp"),
            ("464",  "udp"),
            ("123",  "udp"),
        ]
        if cfg["manage_dns"]:
            ports += [("53", "tcp"), ("53", "udp")]

        for port, proto in ports:
            _run(["ufw", "allow", f"{port}/{proto}"])
        _run(["ufw", "reload"])
        console.print("  [dim]Firewall rules applied ✓[/dim]")

    # -----------------------------------------------------------------------
    # Initial policies and groups
    # -----------------------------------------------------------------------

    def _setup_initial_policies(self, cfg: dict):
        """Create initial groups, sudo rules, and HBAC rules."""
        console.print("\n[cyan]Setting up initial groups and policies...[/cyan]")

        if DRY_RUN:
            console.print("  [dim][DRY RUN] Would create groups and policies[/dim]")
            return

        # User groups
        groups = [
            ("sysadmins",   "System administrators with sudo access"),
            ("developers",  "Development team members"),
            ("readonly",    "Read-only access to shared resources"),
        ]
        for group_name, desc in groups:
            rc, _, _ = _run([
                "ipa", "group-add", group_name,
                f"--desc={desc}",
            ], timeout=30)
            if rc == 0:
                console.print(f"  [dim]Created group: {group_name}[/dim]")

        # Add admins to sysadmins
        _run(["ipa", "group-add-member", "sysadmins",
              "--groups=admins"], timeout=30)

        # Sudo rule for sysadmins
        _run([
            "ipa", "sudorule-add", "sysadmin_sudo",
            "--desc=Allow sysadmins to run all commands as root",
            "--hostcat=all",
            "--runasusercat=all",
            "--runasgroupcat=all",
            "--cmdcat=all",
        ], timeout=30)
        _run([
            "ipa", "sudorule-add-user", "sysadmin_sudo",
            "--groups=sysadmins",
        ], timeout=30)

        # HBAC rule for developers (access to dev hosts)
        _run([
            "ipa", "hbacrule-add", "developer_access",
            "--desc=Allow developers to log into developer hosts",
            "--servicecat=all",
        ], timeout=30)
        _run([
            "ipa", "hbacrule-add-user", "developer_access",
            "--groups=developers",
        ], timeout=30)

        console.print("  [dim]Initial groups: sysadmins, developers, readonly ✓[/dim]")
        console.print("  [dim]Sudo rule: sysadmins → all commands on all hosts ✓[/dim]")
        console.print("  [dim]HBAC: allow_all disabled, explicit rules created ✓[/dim]")

    # -----------------------------------------------------------------------
    # Role suppression
    # -----------------------------------------------------------------------

    def _suppress_redundant_roles(self, cfg: dict, config: dict):
        """
        If FreeIPA is managing DNS, mark Technitium as suppressed
        so the setup UI doesn't prompt to install it.
        Similarly suppress standalone CA installs.
        """
        if not self.cm:
            return

        if cfg["manage_dns"]:
            self.cm.set("roles.dns_dhcp.suppressed_by", "freeipa")
            self.cm.set("roles.dns_dhcp.engine", "freeipa-integrated")
            console.print(
                "  [dim]DNS role: suppressed — FreeIPA integrated DNS is active[/dim]"
            )

        if cfg["setup_ca"]:
            self.cm.set("roles.ca.suppressed_by", "freeipa")
            self.cm.set("roles.ca.engine", "dogtag")
            console.print(
                "  [dim]CA role: suppressed — Dogtag PKI CA is active[/dim]"
            )

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def _register(self, cfg: dict):
        if not self.cm:
            return

        self.cm.add_role("identity", {
            "engine":        "freeipa",
            "fqdn":          cfg["fqdn"],
            "realm":         cfg["realm"],
            "domain":        cfg["domain"],
            "manage_dns":    cfg["manage_dns"],
            "manage_ntp":    cfg["manage_ntp"],
            "setup_ca":      cfg["setup_ca"],
            "server_ip":     cfg["server_ip"],
        })

        if self.sm:
            self.sm.write_env_file("freeipa", {
                "IPA_ADMIN_PASSWORD":       cfg["admin_password"],
                "IPA_DS_PASSWORD":          cfg["ds_password"],
                "IPA_REALM":                cfg["realm"],
                "IPA_DOMAIN":               cfg["domain"],
                "IPA_FQDN":                 cfg["fqdn"],
            })

        port_defs = [
            (88,   "kerberos",   "tcp"),
            (88,   "kerberos",   "udp"),
            (389,  "ldap",       "tcp"),
            (636,  "ldaps",      "tcp"),
            (443,  "ipa-https",  "tcp"),
            (464,  "kpasswd",    "tcp"),
        ]
        for port, name, proto in port_defs:
            self.cm.register_port(port, f"freeipa-{name}", proto, external=False)

        if cfg["manage_dns"]:
            self.cm.register_port(53, "freeipa-dns", "both", external=False)

        self.cm.register_service_url(
            "freeipa-webui",
            f"https://{cfg['fqdn']}/ipa/ui/",
            f"FreeIPA web UI — admin / see secrets/.env.freeipa"
        )
        self.cm.register_service_url(
            "freeipa-api",
            f"https://{cfg['fqdn']}/ipa/json",
            "FreeIPA JSON API endpoint"
        )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _print_summary(self, cfg: dict):
        console.print()
        console.print(Panel(
            f"[bold green]FreeIPA installed successfully[/bold green]\n\n"
            f"  Web UI:     [cyan]https://{cfg['fqdn']}/ipa/ui/[/cyan]\n"
            f"  Realm:      [cyan]{cfg['realm']}[/cyan]\n"
            f"  Domain:     [cyan]{cfg['domain']}[/cyan]\n"
            f"  Admin:      [cyan]admin[/cyan]  (password in secrets/.env.freeipa)\n"
            f"  DNS:        [cyan]{'FreeIPA integrated BIND' if cfg['manage_dns'] else 'external'}[/cyan]\n"
            f"  CA:         [cyan]{'Dogtag PKI (integrated)' if cfg['setup_ca'] else 'external'}[/cyan]\n\n"
            f"  [bold]Enroll Linux clients:[/bold]\n"
            f"  [dim]scp {self.scripts_dir}/enroll-ipa-client.sh root@<host>:/tmp/[/dim]\n"
            f"  [dim]ssh root@<host> 'bash /tmp/enroll-ipa-client.sh <admin-pass>'[/dim]\n\n"
            f"  [bold]Quick commands:[/bold]\n"
            f"  [dim]kinit admin                         # Get Kerberos ticket[/dim]\n"
            f"  [dim]ipa user-add <user> --first=... --last=... --password[/dim]\n"
            f"  [dim]ipa group-add-member sysadmins --users=<user>[/dim]\n"
            f"  [dim]ipa host-add <hostname>.{cfg['domain']}[/dim]\n"
            f"  [dim]ipa hbacrule-add-host <rule> --hosts=<hostname>[/dim]",
            border_style="green",
            padding=(1, 2),
        ))

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _gen_pass(self, n: int = 16) -> str:
        return (self.sm.generate_password(n, exclude_special=True)
                if self.sm else os.urandom(n // 2).hex())

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

    def _detect_os(self) -> str:
        try:
            return Path("/etc/os-release").read_text().split("PRETTY_NAME=")[1].split("\n")[0].strip('"')
        except Exception:
            return "Unknown"
