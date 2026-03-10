"""
base/auditd.py
==============
Linux Audit Daemon (auditd) configuration.
Provides kernel-level syscall auditing, file access logging,
privileged command tracking, and compliance rule sets.

Rule sets included:
  - STIG (DISA Security Technical Implementation Guide) subset
  - CIS (Center for Internet Security) Level 2 subset
  - Custom server-suite rules for critical paths
"""

import os
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


# ---------------------------------------------------------------------------
# Audit rules
# ---------------------------------------------------------------------------

AUDIT_RULES = """\
## ============================================================
## Server Suite — auditd rules
## Based on: STIG RHEL-07-* / CIS Benchmark / server-suite
## ============================================================

## -- Housekeeping ---------------------------------------------------------
# Remove all existing rules before loading
-D

# Set buffer size (increase if getting "audit: backlog limit exceeded")
-b 8192

# Failure mode: 1=log, 2=panic
-f 1

## -- Authentication and authorization ------------------------------------
# Logins and logouts
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# User/group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudoers
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

## -- Privilege escalation ------------------------------------------------
# sudo usage
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fa0=execve -k setuid

# setuid/setgid calls
-a always,exit -F arch=b64 -S setuid -S setgid -F exit=-EPERM -k setuid
-a always,exit -F arch=b32 -S setuid -S setgid -F exit=-EPERM -k setuid

## -- Privileged commands -------------------------------------------------
# Track use of privileged binaries
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged

## -- File system mounts --------------------------------------------------
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

## -- File deletions by non-privileged users ------------------------------
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete

## -- Critical file access ------------------------------------------------
# SSH keys
-w /root/.ssh -p rwxa -k unauthed

# Cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Network configuration changes
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications
-w /etc/sysconfig/network -p wa -k network_modifications
-w /etc/netplan/ -p wa -k network_modifications

# PAM configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam

# SSH daemon
-w /etc/ssh/sshd_config -p wa -k sshd

# System startup files
-w /etc/rc.d/ -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/systemd/ -p wa -k init

## -- Kernel module loading -----------------------------------------------
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

## -- Time changes --------------------------------------------------------
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-a always,exit -F arch=b32 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

## -- Unauthorized access attempts ----------------------------------------
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

## -- Docker socket -------------------------------------------------------
-w /var/run/docker.sock -p rwxa -k docker

## -- Server Suite paths --------------------------------------------------
-w /opt/server-suite/secrets/ -p rwxa -k suite_secrets
-w /opt/server-suite/core/ -p wa -k suite_config
-w /etc/systemd/system/server-suite-*.service -p wa -k suite_units
-w /etc/systemd/system/server-suite-*.timer -p wa -k suite_units

## -- Make rules immutable (requires reboot to change) --------------------
## Uncomment for production hardening — WARNING: cannot be undone until reboot
# -e 2
"""

AUDITD_CONF = """\
# Server Suite — auditd configuration
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 50
num_logs = 10
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 500
space_left_action = SYSLOG
verify_email = no
action_mail_acct = root
admin_space_left = 100
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
distribute_network = no
"""

AUDISP_SYSLOG_CONF = """\
# Forward auditd events to syslog (and therefore journald / Loki)
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_INFO
format = string
"""


class AuditdManager:
    """Installs and configures auditd with production-grade rules."""

    def setup(self) -> bool:
        console.print("\n[cyan]Configuring auditd...[/cyan]")

        # Install
        rc, _, err = _run(["apt-get", "install", "-y", "-qq",
                           "auditd", "audispd-plugins"])
        if rc != 0:
            console.print(f"  [yellow]auditd install warning: {err}[/yellow]")

        # Write configuration files
        self._write_conf()
        self._write_rules()
        self._write_audisp_conf()

        # Enable and start
        _run(["systemctl", "enable", "auditd"])
        _run(["systemctl", "restart", "auditd"])

        # Load rules immediately without reboot
        _run(["augenrules", "--load"])

        # Verify
        rc2, out2, _ = _run(["auditctl", "-s"])
        if "enabled" in (out2 or ""):
            console.print("  [green]auditd active with production rules ✓[/green]")
        else:
            console.print("  [dim]auditd configured (verify with: auditctl -s)[/dim]")

        self._print_usage_hints()
        return True

    def _write_conf(self):
        conf_path = Path("/etc/audit/auditd.conf")
        if not DRY_RUN:
            conf_path.write_text(AUDITD_CONF)
        console.print("  [dim]auditd.conf written ✓[/dim]")

    def _write_rules(self):
        rules_dir = Path("/etc/audit/rules.d")
        if not DRY_RUN:
            rules_dir.mkdir(parents=True, exist_ok=True)
            (rules_dir / "99-server-suite.rules").write_text(AUDIT_RULES)
        console.print("  [dim]Audit rules written (STIG/CIS subset) ✓[/dim]")

    def _write_audisp_conf(self):
        """Forward audit events to syslog for Loki/Graylog ingestion."""
        audisp_conf = Path("/etc/audit/plugins.d/syslog.conf")
        if not DRY_RUN:
            audisp_conf.parent.mkdir(parents=True, exist_ok=True)
            audisp_conf.write_text(AUDISP_SYSLOG_CONF)
        console.print("  [dim]audisp syslog forwarding enabled ✓[/dim]")

    def _print_usage_hints(self):
        console.print()
        console.print("  [bold]Useful auditd commands:[/bold]")
        hints = [
            ("ausearch -k identity",    "Recent user/group changes"),
            ("ausearch -k privileged",  "Recent sudo/privilege use"),
            ("ausearch -k suite_secrets","Access to suite secrets"),
            ("aureport --summary",      "Summary report"),
            ("aureport --auth",         "Authentication report"),
            ("ausearch -ui 1000",       "Events by UID 1000"),
        ]
        for cmd, desc in hints:
            console.print(f"  [dim]{cmd:40} # {desc}[/dim]")
