"""
roles/storage/backup.py
=======================
BorgBackup for encrypted deduplicated local/remote backups.
rclone for offsite cloud sync. Both generate email reports.
"""

import os
import subprocess
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
SUITE_DIR = Path("/opt/server-suite")


def _run(cmd: list, timeout: int = 300) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


BORG_BACKUP_SCRIPT = """#!/usr/bin/env bash
# =============================================================================
# Server Suite — BorgBackup
# Encrypted, deduplicated backup of /mnt/data to local/remote repository.
# =============================================================================
set -euo pipefail

export BORG_PASSPHRASE="{borg_passphrase}"
export BORG_REPO="{borg_repo}"
BACKUP_SOURCE="{backup_source}"
LOG_FILE="/var/log/server-suite/borg-backup.log"
NOTIFY_EMAIL="{notify_email}"
HOSTNAME="$(hostname -f)"
SUITE_DIR="{suite_dir}"

log() {{ echo "[$( date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }}

mkdir -p "$(dirname "$LOG_FILE")"
log "===== BorgBackup Started ====="

# Initialize repo if it doesn't exist
if ! borg info "${{BORG_REPO}}" &>/dev/null; then
    log "Initializing Borg repository at $BORG_REPO"
    borg init --encryption=repokey-blake2 "${{BORG_REPO}}"
fi

# Create archive with timestamp
ARCHIVE_NAME="${{HOSTNAME}}-$(date +%Y-%m-%dT%H:%M:%S)"
log "Creating archive: $ARCHIVE_NAME"

if borg create \\
    --verbose \\
    --filter AME \\
    --list \\
    --stats \\
    --show-rc \\
    --compression lz4 \\
    --exclude-caches \\
    --exclude "${{BACKUP_SOURCE}}/@snapshots" \\
    "${{BORG_REPO}}::${{ARCHIVE_NAME}}" \\
    "${{BACKUP_SOURCE}}" \\
    2>&1 | tee -a "$LOG_FILE"; then
    STATUS="SUCCESS"
    log "Archive created successfully."
else
    STATUS="FAILED"
    log "ERROR: Archive creation failed."
fi

# Prune old archives
log "Pruning old archives..."
borg prune \\
    --list \\
    --glob-archives "${{HOSTNAME}}-*" \\
    --show-rc \\
    --keep-daily 7 \\
    --keep-weekly 4 \\
    --keep-monthly 6 \\
    "${{BORG_REPO}}" 2>&1 | tee -a "$LOG_FILE"

# Compact freed space
borg compact "${{BORG_REPO}}" 2>&1 | tee -a "$LOG_FILE" || true

log "===== BorgBackup Complete: $STATUS ====="

# Send report
python3 -c "
import sys; sys.path.insert(0, '${{SUITE_DIR}}')
from core.notifications import NotificationManager
from pathlib import Path
nm = NotificationManager(Path('${{SUITE_DIR}}'))
results = [{{'path': '${{BACKUP_SOURCE}}', 'label': 'borg-backup',
             'status': '${{STATUS}}'.lower(), 'duration': 'see log', 'files_processed': 'N/A'}}]
html = nm.render_defrag_report(results, '${{HOSTNAME}}')
nm.send_report(f'BorgBackup: ${{STATUS}} — ${{HOSTNAME}}', html, recipient='${{NOTIFY_EMAIL}}')
" 2>/dev/null || true

[[ "$STATUS" == "SUCCESS" ]] && exit 0 || exit 1
"""

RCLONE_SYNC_SCRIPT = """#!/usr/bin/env bash
# =============================================================================
# Server Suite — rclone Offsite Sync
# Syncs /mnt/data to configured cloud storage provider.
# =============================================================================
set -euo pipefail

RCLONE_REMOTE="{rclone_remote}"
BACKUP_SOURCE="{backup_source}"
LOG_FILE="/var/log/server-suite/rclone-sync.log"
NOTIFY_EMAIL="{notify_email}"
HOSTNAME="$(hostname -f)"
SUITE_DIR="{suite_dir}"

log() {{ echo "[$( date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }}

mkdir -p "$(dirname "$LOG_FILE")"
log "===== rclone Sync Started ====="
log "Source: $BACKUP_SOURCE → Remote: $RCLONE_REMOTE"

if rclone sync \\
    "$BACKUP_SOURCE" \\
    "$RCLONE_REMOTE" \\
    --progress \\
    --log-level INFO \\
    --log-file "$LOG_FILE" \\
    --transfers 4 \\
    --checkers 8 \\
    --contimeout 60s \\
    --timeout 300s \\
    --retries 3 \\
    --low-level-retries 10 \\
    --exclude "@snapshots/**" \\
    --exclude "*.tmp" \\
    --stats 30s; then
    STATUS="SUCCESS"
else
    STATUS="FAILED"
fi

log "===== rclone Sync Complete: $STATUS ====="

python3 -c "
import sys; sys.path.insert(0, '${{SUITE_DIR}}')
from core.notifications import NotificationManager
from pathlib import Path
nm = NotificationManager(Path('${{SUITE_DIR}}'))
results = [{{'path': '${{BACKUP_SOURCE}}', 'label': 'rclone-sync',
             'status': '${{STATUS}}'.lower(), 'duration': 'see log', 'files_processed': 'N/A'}}]
html = nm.render_defrag_report(results, '${{HOSTNAME}}')
nm.send_report(f'rclone Sync: ${{STATUS}} — ${{HOSTNAME}}', html, recipient='${{NOTIFY_EMAIL}}')
" 2>/dev/null || true

[[ "$STATUS" == "SUCCESS" ]] && exit 0 || exit 1
"""


class BackupManager:
    """Manages BorgBackup and rclone configuration and scheduling."""

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir  = Path(suite_dir)
        self.cm         = config_manager
        self.sm         = secrets_manager
        self.scripts_dir = self.suite_dir / "scripts"

    def setup_borg(self, backup_source: str = "/mnt/data",
                   borg_repo: str = "/mnt/data/@backups/borg",
                   notify_email: str = "root") -> bool:
        """Set up BorgBackup with local repository."""
        console.print("\n[cyan]Setting up BorgBackup...[/cyan]")

        # Install borg
        _run(["apt-get", "install", "-y", "borgbackup"])

        # Generate passphrase
        passphrase = (self.sm.generate_token(32)
                      if self.sm else os.urandom(32).hex())

        if self.sm:
            self.sm.write_env_file("borgbackup", {
                "BORG_PASSPHRASE": passphrase,
                "BORG_REPO":       borg_repo,
                "BORG_SOURCE":     backup_source,
            })

        # Generate backup script
        script = BORG_BACKUP_SCRIPT.format(
            borg_passphrase=passphrase,
            borg_repo=borg_repo,
            backup_source=backup_source,
            notify_email=notify_email,
            suite_dir=str(self.suite_dir),
        )
        self._write_script("borg-backup.sh", script)

        # Install systemd timer (weekly on Sunday at 02:00)
        self._install_borg_timer()

        console.print("[green]BorgBackup configured ✓[/green]")
        console.print(f"  [dim]Repository: {borg_repo}[/dim]")
        console.print(f"  [yellow]⚠ Save your BorgBackup passphrase: stored in secrets/.env.borgbackup[/yellow]")
        return True

    def setup_rclone(self, backup_source: str = "/mnt/data",
                     notify_email: str = "root") -> bool:
        """Set up rclone for offsite cloud sync."""
        console.print("\n[cyan]Setting up rclone offsite sync...[/cyan]")

        _run(["apt-get", "install", "-y", "rclone"])

        console.print("\n  [bold]rclone Configuration[/bold]")
        console.print("  [dim]rclone supports S3, B2, Wasabi, Dropbox, Google Drive, and more.[/dim]")
        console.print("  [dim]Run 'rclone config' to set up a remote, then enter the name below.[/dim]\n")

        remote_name = Prompt.ask("  rclone remote name (from 'rclone config')",
                                 default="backup-remote")
        remote_path = Prompt.ask("  Remote path (bucket/folder)",
                                 default="server-backup")
        rclone_remote = f"{remote_name}:{remote_path}"

        script = RCLONE_SYNC_SCRIPT.format(
            rclone_remote=rclone_remote,
            backup_source=backup_source,
            notify_email=notify_email,
            suite_dir=str(self.suite_dir),
        )
        self._write_script("rclone-sync.sh", script)
        self._install_rclone_timer()

        console.print("[green]rclone sync configured ✓[/green]")
        return True

    def _write_script(self, name: str, content: str):
        if DRY_RUN:
            console.print(f"  [dim][DRY RUN] Would write: {self.scripts_dir / name}[/dim]")
            return
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
        path = self.scripts_dir / name
        path.write_text(content)
        os.chmod(path, 0o750)
        console.print(f"  [dim]Generated: {name} ✓[/dim]")

    def _install_borg_timer(self):
        systemd_dir = Path("/etc/systemd/system")

        service = """[Unit]
Description=Server Suite — BorgBackup
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/server-suite/scripts/borg-backup.sh
TimeoutStartSec=86400
StandardOutput=journal
StandardError=journal
SyslogIdentifier=server-suite-borg
"""
        timer = """[Unit]
Description=Server Suite — BorgBackup Timer (Weekly, Sunday 02:00)

[Timer]
OnCalendar=Sun *-*-* 02:00:00
Persistent=true
RandomizedDelaySec=600
Unit=server-suite-borg-backup.service

[Install]
WantedBy=timers.target
"""
        if not DRY_RUN:
            (systemd_dir / "server-suite-borg-backup.service").write_text(service)
            (systemd_dir / "server-suite-borg-backup.timer").write_text(timer)
            _run(["systemctl", "daemon-reload"])
            _run(["systemctl", "enable", "--now", "server-suite-borg-backup.timer"])
        console.print("  [dim]BorgBackup timer installed (weekly Sunday @ 02:00) ✓[/dim]")

    def _install_rclone_timer(self):
        systemd_dir = Path("/etc/systemd/system")

        service = """[Unit]
Description=Server Suite — rclone Offsite Sync
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/server-suite/scripts/rclone-sync.sh
TimeoutStartSec=86400
StandardOutput=journal
StandardError=journal
SyslogIdentifier=server-suite-rclone
"""
        timer = """[Unit]
Description=Server Suite — rclone Sync Timer (Daily 03:00)

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true
RandomizedDelaySec=1800
Unit=server-suite-rclone-sync.service

[Install]
WantedBy=timers.target
"""
        if not DRY_RUN:
            (systemd_dir / "server-suite-rclone-sync.service").write_text(service)
            (systemd_dir / "server-suite-rclone-sync.timer").write_text(timer)
            _run(["systemctl", "daemon-reload"])
            _run(["systemctl", "enable", "--now", "server-suite-rclone-sync.timer"])
        console.print("  [dim]rclone sync timer installed (daily @ 03:00) ✓[/dim]")
