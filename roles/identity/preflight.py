"""
roles/identity/preflight.py
===========================
Pre-installation checks specific to FreeIPA.
FreeIPA has very strict requirements that will cause silent failures
if not met. This module validates all of them before touching anything.

Checks:
  - Minimum RAM (2GB hard minimum, 4GB recommended)
  - FQDN must be resolvable to THIS server's IP
  - Hostname must not be 'localhost' or bare hostname
  - /etc/hosts entry must be correct
  - Port conflicts (88, 389, 636, 443, 80, 53, 123)
  - No existing Kerberos config (/etc/krb5.conf) that would conflict
  - No existing LDAP server on port 389
  - SELinux must not be Enforcing (on Debian/Ubuntu it is off by default)
  - Time sync within 5 minutes (Kerberos requirement)
  - Sufficient disk space (/var needs 5GB+)
  - DNS: reverse lookup of server IP must return the FQDN
"""

import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# FreeIPA well-known ports
FREEIPA_PORTS = {
    80:   "HTTP (ACME / web UI redirect)",
    443:  "HTTPS (web UI)",
    88:   "Kerberos",
    389:  "LDAP",
    636:  "LDAPS",
    464:  "kpasswd",
    53:   "DNS (if managing DNS)",
    123:  "NTP",
    7389: "Dogtag CA (internal)",
    8080: "Dogtag CA HTTP (internal)",
    8443: "Dogtag CA HTTPS (internal)",
}

MIN_RAM_MB      = 2048
REC_RAM_MB      = 4096
MIN_DISK_MB     = 5120   # 5GB for /var
MAX_TIME_SKEW_S = 300    # 5 minutes (Kerberos limit)


def _run(cmd: list, timeout: int = 15) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class FreeIPAPreflight:
    """Validates all FreeIPA prerequisites."""

    def __init__(self, realm: str, domain: str, fqdn: str, manage_dns: bool):
        self.realm      = realm      # e.g. EXAMPLE.COM
        self.domain     = domain     # e.g. example.com
        self.fqdn       = fqdn       # e.g. ipa.example.com
        self.manage_dns = manage_dns
        self.results: list[dict] = []

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    def run(self) -> bool:
        """Run all checks. Returns True only if all critical checks pass."""
        console.print("\n[bold cyan]FreeIPA Pre-flight Checks[/bold cyan]\n")

        self._check_ram()
        self._check_disk()
        self._check_fqdn()
        self._check_hostname_file()
        self._check_time_sync()
        self._check_port_conflicts()
        self._check_existing_kerberos()
        self._check_existing_ldap()
        self._check_selinux()
        if self.manage_dns:
            self._check_dns_conflict()
        self._check_reverse_dns()

        return self._print_results()

    # -----------------------------------------------------------------------
    # Individual checks
    # -----------------------------------------------------------------------

    def _check_ram(self):
        try:
            mem_kb   = int([l for l in Path("/proc/meminfo").read_text().splitlines()
                            if l.startswith("MemTotal:")][0].split()[1])
            mem_mb   = mem_kb // 1024
            ok       = mem_mb >= MIN_RAM_MB
            warning  = mem_mb < REC_RAM_MB and mem_mb >= MIN_RAM_MB
            status   = "pass" if ok else "fail"
            if warning:
                status = "warn"
            self._add(
                check   = "RAM",
                status  = status,
                detail  = f"{mem_mb} MB available (min {MIN_RAM_MB} MB, recommended {REC_RAM_MB} MB)",
                critical= True,
            )
        except Exception as e:
            self._add("RAM", "fail", f"Could not read memory info: {e}", critical=True)

    def _check_disk(self):
        rc, out, _ = _run(["df", "--output=avail", "-BM", "/var"])
        if rc == 0:
            try:
                avail_mb = int(out.splitlines()[-1].strip().rstrip("M"))
                ok = avail_mb >= MIN_DISK_MB
                self._add(
                    check   = "Disk space (/var)",
                    status  = "pass" if ok else "fail",
                    detail  = f"{avail_mb} MB available (need {MIN_DISK_MB} MB)",
                    critical= True,
                )
            except (ValueError, IndexError) as e:
                self._add("Disk space (/var)", "warn", f"Could not parse df output: {e}")
        else:
            self._add("Disk space (/var)", "warn", "Could not check disk space")

    def _check_fqdn(self):
        """FQDN must resolve to this server's IP, not 127.0.0.1."""
        # Get local IPs
        local_ips = self._get_local_ips()

        try:
            resolved_ip = socket.gethostbyname(self.fqdn)
            if resolved_ip in ("127.0.0.1", "127.0.1.1", "::1"):
                self._add(
                    check   = "FQDN resolution",
                    status  = "fail",
                    detail  = (f"{self.fqdn} resolves to {resolved_ip} (loopback). "
                               "Must resolve to a LAN/public IP. Fix /etc/hosts."),
                    critical= True,
                )
            elif resolved_ip in local_ips:
                self._add(
                    check   = "FQDN resolution",
                    status  = "pass",
                    detail  = f"{self.fqdn} → {resolved_ip} ✓",
                )
            else:
                self._add(
                    check   = "FQDN resolution",
                    status  = "warn",
                    detail  = (f"{self.fqdn} resolves to {resolved_ip} but local IPs are "
                               f"{local_ips}. May work if this is a public IP."),
                )
        except socket.gaierror as e:
            self._add(
                check   = "FQDN resolution",
                status  = "fail",
                detail  = f"{self.fqdn} does not resolve: {e}. Add to /etc/hosts or DNS first.",
                critical= True,
            )

    def _check_hostname_file(self):
        """/etc/hosts must have a proper entry — not just 127.0.1.1."""
        try:
            hosts_content = Path("/etc/hosts").read_text()
            local_ips     = self._get_local_ips()

            # Look for FQDN mapped to a real IP
            found_real = False
            found_loopback = False

            for line in hosts_content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and self.fqdn in parts[1:]:
                    ip = parts[0]
                    if ip in ("127.0.0.1", "127.0.1.1"):
                        found_loopback = True
                    elif ip in local_ips or ip not in ("127.0.0.1", "127.0.1.1"):
                        found_real = True

            if found_loopback and not found_real:
                self._add(
                    check   = "/etc/hosts",
                    status  = "fail",
                    detail  = (f"{self.fqdn} is mapped to loopback in /etc/hosts. "
                               "FreeIPA requires it to map to a real LAN IP. "
                               "Add:  <LAN-IP>  {self.fqdn}  {self.fqdn.split('.')[0]}"),
                    critical= True,
                )
            elif found_real:
                self._add("/etc/hosts", "pass",
                          f"{self.fqdn} → real IP in /etc/hosts ✓")
            else:
                self._add(
                    check   = "/etc/hosts",
                    status  = "warn",
                    detail  = (f"{self.fqdn} not found in /etc/hosts. "
                               "FreeIPA works without it if DNS is configured, "
                               "but /etc/hosts entry is strongly recommended."),
                )
        except Exception as e:
            self._add("/etc/hosts", "warn", f"Could not read /etc/hosts: {e}")

    def _check_time_sync(self):
        """System time must be within 5 minutes (Kerberos requirement)."""
        rc, out, _ = _run(["chronyc", "tracking"], timeout=10)
        if rc == 0:
            for line in out.splitlines():
                if "System time" in line:
                    try:
                        skew_s = float(line.split()[3])
                        ok = abs(skew_s) < MAX_TIME_SKEW_S
                        self._add(
                            check   = "Time sync (Kerberos)",
                            status  = "pass" if ok else "fail",
                            detail  = f"Skew: {skew_s:.3f}s (max {MAX_TIME_SKEW_S}s)",
                            critical= True,
                        )
                        return
                    except (ValueError, IndexError):
                        pass

        # Fallback: check against NTP directly
        rc2, out2, _ = _run(["ntpdate", "-q", "pool.ntp.org"], timeout=10)
        if rc2 == 0:
            self._add("Time sync (Kerberos)", "pass", "NTP reachable ✓")
        else:
            self._add(
                check   = "Time sync (Kerberos)",
                status  = "warn",
                detail  = "Could not verify time sync. Ensure chrony/ntpd is running.",
            )

    def _check_port_conflicts(self):
        """Check that FreeIPA ports aren't already in use."""
        in_use = []
        skip_ports = set()
        if not self.manage_dns:
            skip_ports.add(53)

        for port, description in FREEIPA_PORTS.items():
            if port in skip_ports:
                continue
            if self._port_in_use(port):
                in_use.append(f":{port} ({description})")

        if in_use:
            self._add(
                check   = "Port conflicts",
                status  = "fail",
                detail  = "Ports already in use: " + ", ".join(in_use),
                critical= True,
            )
        else:
            self._add("Port conflicts", "pass",
                      "All required ports are available ✓")

    def _check_existing_kerberos(self):
        krb5_conf = Path("/etc/krb5.conf")
        if krb5_conf.exists():
            content = krb5_conf.read_text()
            if "default_realm" in content and self.realm not in content:
                self._add(
                    check   = "Kerberos config",
                    status  = "warn",
                    detail  = ("/etc/krb5.conf exists with a different realm. "
                               "FreeIPA installer will overwrite it."),
                )
                return
        self._add("Kerberos config", "pass", "No conflicting Kerberos config ✓")

    def _check_existing_ldap(self):
        if self._port_in_use(389):
            self._add(
                check   = "Existing LDAP",
                status  = "fail",
                detail  = "Port 389 is in use. Stop/remove any existing LDAP server first.",
                critical= True,
            )
        else:
            self._add("Existing LDAP", "pass", "Port 389 is free ✓")

    def _check_selinux(self):
        rc, out, _ = _run(["getenforce"])
        if rc == 0 and out.strip().lower() == "enforcing":
            self._add(
                check   = "SELinux",
                status  = "fail",
                detail  = "SELinux is Enforcing. FreeIPA on Ubuntu/Debian requires it to be Disabled/Permissive.",
                critical= True,
            )
        else:
            self._add("SELinux", "pass",
                      f"SELinux: {out.strip() or 'not active'} ✓")

    def _check_dns_conflict(self):
        """If managing DNS, port 53 must be free (systemd-resolved stub may hold it)."""
        if self._port_in_use(53):
            # Check if it's systemd-resolved
            rc, out, _ = _run(["ss", "-tlunp", "sport", "53"])
            is_resolved = "systemd-resolved" in out or "stub-resolv" in out
            if is_resolved:
                self._add(
                    check   = "DNS port 53",
                    status  = "warn",
                    detail  = ("systemd-resolved is using port 53. "
                               "FreeIPA installer will disable the stub listener automatically."),
                )
            else:
                self._add(
                    check   = "DNS port 53",
                    status  = "fail",
                    detail  = "Port 53 in use by an unknown process. Stop it before proceeding.",
                    critical= True,
                )
        else:
            self._add("DNS port 53", "pass", "Port 53 is free ✓")

    def _check_reverse_dns(self):
        """Reverse DNS (PTR record) should resolve back to the FQDN."""
        local_ips = self._get_local_ips()
        if not local_ips:
            self._add("Reverse DNS", "warn", "Could not detect local IPs")
            return

        primary_ip = local_ips[0]
        try:
            hostname, _, _ = socket.gethostbyaddr(primary_ip)
            if hostname == self.fqdn or hostname.endswith(f".{self.domain}"):
                self._add("Reverse DNS", "pass",
                          f"{primary_ip} → {hostname} ✓")
            else:
                self._add(
                    check  = "Reverse DNS",
                    status = "warn",
                    detail = (f"{primary_ip} reverse-resolves to '{hostname}', "
                              f"expected '{self.fqdn}'. "
                              "Set PTR record at your router/DNS provider."),
                )
        except socket.herror:
            self._add(
                check  = "Reverse DNS",
                status = "warn",
                detail = (f"No PTR record for {primary_ip}. "
                          "Kerberos will still work but some clients may have issues."),
            )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _port_in_use(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex(("127.0.0.1", port)) == 0
        except Exception:
            return False

    def _get_local_ips(self) -> list:
        ips = []
        rc, out, _ = _run(["hostname", "-I"])
        if rc == 0:
            ips = [ip for ip in out.split()
                   if ip and not ip.startswith("127.") and ":" not in ip]
        return ips

    def _add(self, check: str, status: str, detail: str, critical: bool = False):
        self.results.append({
            "check":    check,
            "status":   status,
            "detail":   detail,
            "critical": critical,
        })

    # -----------------------------------------------------------------------
    # Result display
    # -----------------------------------------------------------------------

    def _print_results(self) -> bool:
        table = Table(
            "Check", "Status", "Detail",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
        )

        all_critical_pass = True
        has_warnings      = False

        for r in self.results:
            if r["status"] == "pass":
                icon = "[green]✓ Pass[/green]"
            elif r["status"] == "warn":
                icon = "[yellow]⚠ Warn[/yellow]"
                has_warnings = True
            else:
                icon = "[red]✗ Fail[/red]"
                if r["critical"]:
                    all_critical_pass = False

            table.add_row(r["check"], icon, r["detail"])

        console.print(table)
        console.print()

        if not all_critical_pass:
            console.print(Panel(
                "[bold red]Pre-flight FAILED[/bold red]\n\n"
                "Fix the issues above before installing FreeIPA.\n"
                "FreeIPA installations that fail mid-way are difficult to clean up.",
                border_style="red",
            ))
            return False

        if has_warnings:
            console.print("[yellow]Pre-flight passed with warnings. "
                          "Review warnings above before proceeding.[/yellow]")
        else:
            console.print("[bold green]All pre-flight checks passed ✓[/bold green]")

        return True
