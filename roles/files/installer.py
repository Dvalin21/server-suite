"""
roles/files/installer.py
========================
File sharing and collaboration services:
  - Nextcloud (Docker) — cloud storage, Calendar, Contacts, Talk
  - Collabora Online (Docker) — LibreOffice in browser for Nextcloud
  - Samba (native) — Windows file sharing / SMB
  - NFS (native) — Linux/Unix network mounts
  - Syncthing (Docker) — peer-to-peer continuous sync
"""

import os
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


NEXTCLOUD_COMPOSE = """\
services:
  nextcloud:
    image: nextcloud:29.0.7-apache
    container_name: nextcloud
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      MYSQL_HOST:           mariadb
      MYSQL_DATABASE:       nextcloud
      MYSQL_USER:           nextcloud
      MYSQL_PASSWORD_FILE:  /run/secrets/nextcloud_db_pass
      NEXTCLOUD_ADMIN_USER: admin
      NEXTCLOUD_ADMIN_PASSWORD_FILE: /run/secrets/nextcloud_admin_pass
      NEXTCLOUD_TRUSTED_DOMAINS: "{trusted_domains}"
      REDIS_HOST:           redis
      REDIS_HOST_PASSWORD_FILE: /run/secrets/redis_pass
      SMTP_HOST:            "{smtp_host}"
      SMTP_PORT:            "587"
      SMTP_SECURE:          "tls"
      SMTP_NAME:            "{smtp_user}"
      SMTP_PASSWORD_FILE:   /run/secrets/smtp_pass
      MAIL_FROM_ADDRESS:    "nextcloud"
      MAIL_DOMAIN:          "{domain}"
      PHP_MEMORY_LIMIT:     512M
      PHP_UPLOAD_LIMIT:     10G
    volumes:
      - {data_dir}/nextcloud:/var/www/html
      - {storage_mount}/nextcloud-data:/var/www/html/data
    secrets:
      - nextcloud_db_pass
      - nextcloud_admin_pass
      - redis_pass
      - smtp_pass
    networks:
      - proxy_network
      - db_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.nextcloud.rule=Host(`{nc_fqdn}`)"
      - "traefik.http.routers.nextcloud.tls=true"
      - "traefik.http.routers.nextcloud.tls.certresolver=letsencrypt"
      - "traefik.http.middlewares.nextcloud-redirect.redirectregex.regex=/.well-known/(card|cal)dav"
      - "traefik.http.middlewares.nextcloud-redirect.redirectregex.replacement=/remote.php/dav/"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/status.php"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: journald
      options:
        tag: "docker/nextcloud"
    deploy:
      resources:
        limits:
          memory: {nc_mem}M
          cpus: '2.0'

  nextcloud-cron:
    image: nextcloud:29.0.7-apache
    container_name: nextcloud-cron
    restart: unless-stopped
    volumes:
      - {data_dir}/nextcloud:/var/www/html
    entrypoint: /cron.sh
    networks:
      - db_network
    depends_on:
      nextcloud:
        condition: service_healthy

secrets:
  nextcloud_db_pass:
    file: {secrets_dir}/.nextcloud_db_pass
  nextcloud_admin_pass:
    file: {secrets_dir}/.nextcloud_admin_pass
  redis_pass:
    file: {secrets_dir}/.redis_pass
  smtp_pass:
    file: {secrets_dir}/.smtp_pass

networks:
  proxy_network:
    external: true
  db_network:
    external: true
"""

COLLABORA_COMPOSE = """\
services:
  collabora:
    image: collabora/code:24.04.9.4.1
    container_name: collabora
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_add:
      - MKNOD
    environment:
      aliasgroup1: "https://{nc_fqdn}:443"
      DONT_GEN_SSL_CERT: "YES"
      extra_params: "--o:ssl.enable=false --o:ssl.termination=true"
    networks:
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.collabora.rule=Host(`office.{domain}`)"
      - "traefik.http.routers.collabora.tls=true"
      - "traefik.http.routers.collabora.tls.certresolver=letsencrypt"
    logging:
      driver: journald
      options:
        tag: "docker/collabora"
    deploy:
      resources:
        limits:
          memory: 1024M
          cpus: '2.0'

networks:
  proxy_network:
    external: true
"""

SYNCTHING_COMPOSE = """\
services:
  syncthing:
    image: syncthing/syncthing:1.27
    container_name: syncthing
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    hostname: {hostname}
    environment:
      PUID: "1000"
      PGID: "1000"
    ports:
      - "22000:22000/tcp"
      - "22000:22000/udp"
      - "21027:21027/udp"
      - "127.0.0.1:8384:8384"
    volumes:
      - {data_dir}/syncthing:/var/syncthing
      - {storage_mount}:/sync-data
    networks:
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.syncthing.rule=Host(`sync.{domain}`)"
      - "traefik.http.routers.syncthing.tls=true"
      - "traefik.http.routers.syncthing.middlewares=lan-only@file"
    logging:
      driver: journald
      options:
        tag: "docker/syncthing"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'

networks:
  proxy_network:
    external: true
"""

SAMBA_CONF_TEMPLATE = """\
[global]
    workgroup = WORKGROUP
    server string = {hostname} Samba Server
    server role = standalone server
    log file = /var/log/samba/log.%m
    max log size = 50
    dns proxy = no
    security = user
    map to guest = bad user
    passdb backend = tdbsam
    # Security hardening
    ntlm auth = ntlmv2-only
    client min protocol = SMB2
    server min protocol = SMB2
    smb encrypt = desired
    # Performance
    socket options = TCP_NODELAY IPTOS_LOWDELAY SO_RCVBUF=131072 SO_SNDBUF=131072
    read raw = yes
    write raw = yes
    max xmit = 65535
    dead time = 15
    getwd cache = yes

[data]
    comment = Server Data
    path = {share_path}
    browsable = yes
    writable = yes
    valid users = @samba-users
    create mask = 0664
    directory mask = 0775
    force group = samba-users

[homes]
    comment = Home Directories
    browsable = no
    writable = yes
    valid users = %S
"""

NFS_EXPORTS_TEMPLATE = """\
# Server Suite NFS Exports
# Generated by server-suite
{share_path}  {nfs_clients}(rw,sync,no_subtree_check,no_root_squash,anonuid=1000,anongid=1000)
"""


class FilesInstaller:
    """Installs file-sharing and collaboration services."""

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.data_dir    = self.suite_dir / "docker" / "files" / "data"
        self.compose_dir = self.suite_dir / "docker" / "files"
        self.secrets_dir = self.suite_dir / "secrets"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing File & Collaboration Services[/bold cyan]\n")

        domain         = config.get("domain", "local")
        hostname       = config.get("hostname", "server")
        storage_mount  = config.get("storage", {}).get("mount_point", "/mnt/data")

        install_nextcloud  = Confirm.ask("  Install Nextcloud (cloud storage + CalDAV/CardDAV)?", default=True)
        install_collabora  = False
        if install_nextcloud:
            install_collabora = Confirm.ask("    → Include Collabora Online (LibreOffice in browser)?", default=True)
        install_syncthing  = Confirm.ask("  Install Syncthing (peer-to-peer sync)?",  default=False)
        install_samba      = Confirm.ask("  Install Samba (SMB/Windows file shares)?", default=True)
        install_nfs        = Confirm.ask("  Install NFS (Linux network mounts)?",      default=False)

        results = {}

        if not DRY_RUN:
            self.data_dir.mkdir(parents=True, exist_ok=True)

        if install_nextcloud:
            results["nextcloud"] = self._install_nextcloud(
                domain, hostname, storage_mount, install_collabora
            )

        if install_syncthing:
            results["syncthing"] = self._install_syncthing(
                domain, hostname, storage_mount
            )

        if install_samba:
            results["samba"] = self._install_samba(storage_mount, hostname)

        if install_nfs:
            results["nfs"] = self._install_nfs(storage_mount)

        self._print_summary(results, domain)

        if self.cm:
            self.cm.add_role("files", {k: True for k in results if results[k]})

        return any(results.values())

    # -----------------------------------------------------------------------
    # Nextcloud
    # -----------------------------------------------------------------------

    def _install_nextcloud(self, domain: str, hostname: str,
                            storage_mount: str, with_collabora: bool) -> bool:
        console.print("[cyan]Installing Nextcloud...[/cyan]")

        nc_fqdn  = f"cloud.{domain}"
        nc_admin = self.sm.generate_password(16, exclude_special=True) if self.sm else "ChangeMe!"
        nc_db    = self.sm.generate_password(24, exclude_special=True) if self.sm else "ChangeMe!"

        smtp_host = ""
        smtp_user = ""

        if self.cm:
            smtp_host = self.cm.get("notifications.smtp_host", "")
            smtp_user = self.cm.get("notifications.smtp_user", "")

        if self.sm:
            self.sm.write_env_file("nextcloud", {
                "NEXTCLOUD_ADMIN_USER":     "admin",
                "NEXTCLOUD_ADMIN_PASSWORD": nc_admin,
                "NEXTCLOUD_DB_PASSWORD":    nc_db,
                "NEXTCLOUD_URL":            f"https://{nc_fqdn}",
            })

        if not DRY_RUN:
            for secret_file, value in [
                (".nextcloud_admin_pass", nc_admin),
                (".nextcloud_db_pass",    nc_db),
            ]:
                p = self.secrets_dir / secret_file
                p.write_text(value)
                os.chmod(p, 0o600)

            # Ensure SMTP pass secret exists
            smtp_pass_file = self.secrets_dir / ".smtp_pass"
            if not smtp_pass_file.exists():
                smtp_pass_file.write_text("")
                os.chmod(smtp_pass_file, 0o600)

        # Detect total RAM for sizing
        try:
            mem_info = Path("/proc/meminfo").read_text()
            total_mb = int([l for l in mem_info.splitlines()
                           if l.startswith("MemTotal:")][0].split()[1]) // 1024
            nc_mem = max(512, min(2048, int(total_mb * 0.20)))
        except Exception:
            nc_mem = 1024

        compose = NEXTCLOUD_COMPOSE.format(
            nc_fqdn=nc_fqdn,
            domain=domain,
            trusted_domains=f"localhost {nc_fqdn}",
            smtp_host=smtp_host,
            smtp_user=smtp_user,
            data_dir=str(self.data_dir),
            storage_mount=storage_mount,
            secrets_dir=str(self.secrets_dir),
            nc_mem=nc_mem,
        )
        compose_path = self.compose_dir / "nextcloud-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)
            # Create Nextcloud data directory with correct permissions
            nc_data = Path(storage_mount) / "nextcloud-data"
            nc_data.mkdir(parents=True, exist_ok=True)

        # Create the Nextcloud database
        self._create_nextcloud_db(nc_db)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"], timeout=300)
        if rc != 0:
            console.print(f"  [red]Nextcloud failed: {err}[/red]")
            return False

        if with_collabora:
            self._install_collabora(domain, nc_fqdn)

        if self.cm:
            self.cm.register_service_url(
                "nextcloud", f"https://{nc_fqdn}",
                f"Nextcloud — admin user: admin, pass in secrets/.env.nextcloud"
            )
            self.cm.register_service_url(
                "nextcloud-caldav", f"https://{nc_fqdn}/remote.php/dav",
                "CalDAV/CardDAV endpoint"
            )

        console.print(f"  [green]Nextcloud → https://{nc_fqdn} ✓[/green]")
        return True

    def _create_nextcloud_db(self, nc_db_pass: str):
        """Create the Nextcloud database and user in MariaDB."""
        if DRY_RUN:
            return
        # Wait for MariaDB to be ready
        for _ in range(20):
            time.sleep(3)
            rc, _, _ = _run([
                "docker", "exec", "mariadb",
                "healthcheck.sh", "--connect", "--innodb_initialized"
            ], timeout=10)
            if rc == 0:
                break

        # Read root password
        root_pass_file = self.secrets_dir / ".mariadb_root_pass"
        if not root_pass_file.exists():
            console.print("  [yellow]MariaDB not found — Nextcloud will create its own DB on first run[/yellow]")
            return

        root_pass = root_pass_file.read_text().strip()
        sql = (
            f"CREATE DATABASE IF NOT EXISTS nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; "
            f"CREATE USER IF NOT EXISTS 'nextcloud'@'%' IDENTIFIED BY '{nc_db_pass}'; "
            f"GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'%'; "
            f"FLUSH PRIVILEGES;"
        )
        _run([
            "docker", "exec", "mariadb",
            "mysql", f"-uroot", f"-p{root_pass}", "-e", sql
        ], timeout=30)
        console.print("  [dim]Nextcloud database created ✓[/dim]")

    def _install_collabora(self, domain: str, nc_fqdn: str) -> bool:
        console.print("  [cyan]Installing Collabora Online...[/cyan]")
        compose = COLLABORA_COMPOSE.format(nc_fqdn=nc_fqdn, domain=domain)
        compose_path = self.compose_dir / "collabora-compose.yml"
        if not DRY_RUN:
            compose_path.write_text(compose)
        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"], timeout=300)
        if rc == 0:
            console.print(f"  [green]Collabora Online → https://office.{domain} ✓[/green]")
            if self.cm:
                self.cm.register_service_url(
                    "collabora", f"https://office.{domain}",
                    "Collabora Online (connect from Nextcloud admin)"
                )
        return rc == 0

    # -----------------------------------------------------------------------
    # Syncthing
    # -----------------------------------------------------------------------

    def _install_syncthing(self, domain: str, hostname: str, storage_mount: str) -> bool:
        console.print("[cyan]Installing Syncthing...[/cyan]")
        compose = SYNCTHING_COMPOSE.format(
            hostname=hostname,
            domain=domain,
            data_dir=str(self.data_dir),
            storage_mount=storage_mount,
        )
        compose_path = self.compose_dir / "syncthing-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)
        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc == 0:
            if self.cm:
                self.cm.register_service_url(
                    "syncthing", f"https://sync.{domain}  or  http://<server-ip>:8384",
                    "Syncthing UI (LAN only)"
                )
            _run(["ufw", "allow", "22000/tcp"])
            _run(["ufw", "allow", "22000/udp"])
            console.print(f"  [green]Syncthing → https://sync.{domain} ✓[/green]")
        return rc == 0

    # -----------------------------------------------------------------------
    # Samba
    # -----------------------------------------------------------------------

    def _install_samba(self, storage_mount: str, hostname: str) -> bool:
        console.print("[cyan]Installing Samba (SMB)...[/cyan]")
        _run(["apt-get", "install", "-y", "-qq", "samba", "samba-common"])

        share_path = f"{storage_mount}/@data"
        conf_content = SAMBA_CONF_TEMPLATE.format(
            hostname=hostname, share_path=share_path
        )

        if not DRY_RUN:
            Path("/etc/samba/smb.conf").write_text(conf_content)
            # Create samba-users group
            _run(["groupadd", "-f", "samba-users"])

        _run(["systemctl", "enable", "--now", "smbd", "nmbd"])
        _run(["ufw", "allow", "samba"])

        if self.cm:
            self.cm.register_port(445, "samba", "tcp", external=False)
            self.cm.register_service_url(
                "samba", f"\\\\{hostname}\\data",
                "Samba share — add users with: smbpasswd -a <username>"
            )
        console.print(f"  [green]Samba share at \\\\{hostname}\\data ✓[/green]")
        console.print(f"  [dim]Add users: smbpasswd -a <username>[/dim]")
        return True

    # -----------------------------------------------------------------------
    # NFS
    # -----------------------------------------------------------------------

    def _install_nfs(self, storage_mount: str) -> bool:
        console.print("[cyan]Installing NFS...[/cyan]")
        _run(["apt-get", "install", "-y", "-qq", "nfs-kernel-server"])

        nfs_clients = Prompt.ask(
            "  NFS allowed clients (CIDR or host)",
            default="192.168.1.0/24"
        )
        share_path = f"{storage_mount}/@data"

        exports_content = NFS_EXPORTS_TEMPLATE.format(
            share_path=share_path, nfs_clients=nfs_clients
        )
        if not DRY_RUN:
            current = Path("/etc/exports").read_text() if Path("/etc/exports").exists() else ""
            if share_path not in current:
                with open("/etc/exports", "a") as f:
                    f.write(exports_content)
            _run(["exportfs", "-ra"])

        _run(["systemctl", "enable", "--now", "nfs-kernel-server"])
        _run(["ufw", "allow", "2049/tcp"])
        _run(["ufw", "allow", "2049/udp"])

        if self.cm:
            self.cm.register_port(2049, "nfs", "both", external=False)
            self.cm.register_service_url(
                "nfs", f"mount -t nfs <server-ip>:{share_path} /mnt/remote",
                f"NFS share — accessible from {nfs_clients}"
            )
        console.print(f"  [green]NFS export: {share_path} ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _print_summary(self, results: dict, domain: str):
        console.print()
        for svc, ok in results.items():
            icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(f"  {icon} {svc.capitalize()}")


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return FilesInstaller(self.suite_dir, self.cm, self.sm).install(config)
