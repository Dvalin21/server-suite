"""
roles/database/installer.py
============================
Deploys MariaDB, PostgreSQL, Redis, and Adminer as Docker services.
All bound to 127.0.0.1 only. Services on other Docker networks reach
databases via the db_network. Credentials stored in secrets/.env.*.
"""

import os
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

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


MARIADB_COMPOSE = """\
services:
  mariadb:
    image: mariadb:11.4
    container_name: mariadb
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mariadb_root
      MYSQL_DATABASE: default_db
    volumes:
      - {data_dir}/mariadb:/var/lib/mysql
      - {conf_dir}/mariadb/my.cnf:/etc/mysql/conf.d/server-suite.cnf:ro
    secrets:
      - mariadb_root
    networks:
      - db_network
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 10s
      timeout: 5s
      retries: 5
    logging:
      driver: journald
      options:
        tag: "docker/mariadb"
    deploy:
      resources:
        limits:
          memory: {mariadb_mem}M
          cpus: '2.0'

secrets:
  mariadb_root:
    file: {secrets_dir}/.mariadb_root_pass

networks:
  db_network:
    external: true
"""

MARIADB_CONF = """\
# Server Suite — MariaDB Configuration
[mysqld]
# Performance
innodb_buffer_pool_size         = {buffer_pool}M
innodb_buffer_pool_instances    = 2
innodb_log_file_size            = 256M
innodb_flush_log_at_trx_commit  = 2
innodb_flush_method             = O_DIRECT
innodb_file_per_table           = 1
query_cache_type                = 0

# Security
local_infile                    = 0
symbolic_links                  = 0
skip_name_resolve               = 1

# Logging
slow_query_log                  = 1
slow_query_log_file             = /var/log/mysql/slow.log
long_query_time                 = 2

# Connections
max_connections                 = 200
thread_cache_size               = 50
table_open_cache                = 4000
"""

POSTGRESQL_COMPOSE = """\
services:
  postgresql:
    image: postgres:16.4-alpine
    container_name: postgresql
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_pass
      POSTGRES_USER: pgadmin
      POSTGRES_DB: default_db
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - {data_dir}/postgresql:/var/lib/postgresql/data
      - {conf_dir}/postgresql/postgresql.conf:/etc/postgresql/postgresql.conf:ro
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    secrets:
      - postgres_pass
    networks:
      - db_network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U pgadmin"]
      interval: 10s
      timeout: 5s
      retries: 5
    logging:
      driver: journald
      options:
        tag: "docker/postgresql"
    deploy:
      resources:
        limits:
          memory: {pg_mem}M
          cpus: '2.0'

secrets:
  postgres_pass:
    file: {secrets_dir}/.postgres_pass

networks:
  db_network:
    external: true
"""

POSTGRESQL_CONF = """\
# Server Suite — PostgreSQL Configuration
listen_addresses = '*'
max_connections = 200
shared_buffers = {shared_buffers}MB
effective_cache_size = {effective_cache}MB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB
max_worker_processes = {max_workers}
max_parallel_workers_per_gather = {parallel_workers}
max_parallel_workers = {max_workers}
max_parallel_maintenance_workers = 2
log_min_duration_statement = 2000
log_checkpoints = on
log_connections = off
log_disconnections = off
log_lock_waits = on
"""

REDIS_COMPOSE = """\
services:
  redis:
    image: redis:7.4-alpine
    container_name: redis
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    command: >
      redis-server
      --requirepass-file /run/secrets/redis_pass
      --maxmemory {redis_mem}mb
      --maxmemory-policy allkeys-lru
      --save 900 1
      --save 300 10
      --save 60 10000
      --loglevel notice
      --protected-mode yes
    volumes:
      - {data_dir}/redis:/data
    secrets:
      - redis_pass
    networks:
      - db_network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    logging:
      driver: journald
      options:
        tag: "docker/redis"
    deploy:
      resources:
        limits:
          memory: {redis_limit}M
          cpus: '0.5'

secrets:
  redis_pass:
    file: {secrets_dir}/.redis_pass

networks:
  db_network:
    external: true
"""

ADMINER_COMPOSE = """\
services:
  adminer:
    image: adminer:4.8.1
    container_name: adminer
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      ADMINER_DEFAULT_SERVER: mariadb
      ADMINER_DESIGN: pepa-linha-dark
    networks:
      - db_network
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.adminer.rule=Host(`adminer.{domain}`)"
      - "traefik.http.routers.adminer.tls=true"
      - "traefik.http.routers.adminer.middlewares=lan-only@file"
    logging:
      driver: journald
      options:
        tag: "docker/adminer"

networks:
  db_network:
    external: true
  proxy_network:
    external: true
"""


class DatabaseInstaller:
    """Installs MariaDB, PostgreSQL, Redis, and Adminer."""

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.data_dir    = self.suite_dir / "docker" / "database" / "data"
        self.conf_dir    = self.suite_dir / "docker" / "database" / "conf"
        self.compose_dir = self.suite_dir / "docker" / "database"
        self.secrets_dir = self.suite_dir / "secrets"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Database Stack[/bold cyan]\n")

        # Detect available RAM to tune settings
        total_ram_mb = self._detect_ram_mb()
        console.print(f"  [dim]Available RAM: {total_ram_mb} MB — tuning database config[/dim]\n")

        # Ask which databases to install
        install_mariadb  = Confirm.ask("  Install MariaDB (MySQL-compatible)?",  default=True)
        install_postgres = Confirm.ask("  Install PostgreSQL?",                   default=True)
        install_redis    = Confirm.ask("  Install Redis (cache/sessions)?",        default=True)
        install_adminer  = Confirm.ask("  Install Adminer (database web UI)?",     default=True)

        domain = config.get("domain", "local")

        # Create directories
        for subdir in ["mariadb", "postgresql", "redis"]:
            if not DRY_RUN:
                (self.data_dir / subdir).mkdir(parents=True, exist_ok=True)
                (self.conf_dir / subdir).mkdir(parents=True, exist_ok=True)
        if not DRY_RUN:
            self.secrets_dir.mkdir(parents=True, exist_ok=True)

        # Generate credentials
        creds = self._generate_credentials()

        results = {}

        if install_mariadb:
            results["mariadb"] = self._install_mariadb(total_ram_mb, creds)

        if install_postgres:
            results["postgresql"] = self._install_postgresql(total_ram_mb, creds)

        if install_redis:
            results["redis"] = self._install_redis(total_ram_mb, creds)

        if install_adminer:
            results["adminer"] = self._install_adminer(domain)

        self._print_summary(results, creds)

        if self.cm:
            self.cm.add_role("database", {
                "mariadb":    install_mariadb,
                "postgresql": install_postgres,
                "redis":      install_redis,
                "adminer":    install_adminer,
            })

        return all(results.values())

    # -----------------------------------------------------------------------
    # RAM detection and tuning
    # -----------------------------------------------------------------------

    def _detect_ram_mb(self) -> int:
        try:
            mem_info = Path("/proc/meminfo").read_text()
            for line in mem_info.splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
        except Exception:
            pass
        return 4096

    def _calc_mariadb_settings(self, total_ram_mb: int) -> dict:
        # InnoDB buffer pool: 25% of RAM, min 256MB, max 8GB
        buffer_pool = max(256, min(8192, int(total_ram_mb * 0.25)))
        return {
            "buffer_pool": buffer_pool,
            "mem_limit":   buffer_pool + 512,   # Container limit = buffer pool + overhead
        }

    def _calc_postgres_settings(self, total_ram_mb: int) -> dict:
        # shared_buffers: 25% of RAM, effective_cache: 75%
        shared_buffers    = max(128, min(8192, int(total_ram_mb * 0.25)))
        effective_cache   = max(512, int(total_ram_mb * 0.75))
        max_workers       = max(2, min(8, os.cpu_count() or 4))
        parallel_workers  = max(1, max_workers // 2)
        return {
            "shared_buffers":   shared_buffers,
            "effective_cache":  effective_cache,
            "max_workers":      max_workers,
            "parallel_workers": parallel_workers,
            "mem_limit":        shared_buffers * 4,
        }

    def _calc_redis_settings(self, total_ram_mb: int) -> dict:
        # Redis: 10% of RAM, min 128MB, max 2GB
        redis_mem = max(128, min(2048, int(total_ram_mb * 0.10)))
        return {
            "maxmemory": redis_mem,
            "mem_limit": redis_mem + 64,
        }

    # -----------------------------------------------------------------------
    # Credential generation
    # -----------------------------------------------------------------------

    def _generate_credentials(self) -> dict:
        def gen(n=32): return (self.sm.generate_password(n, exclude_special=True)
                               if self.sm else os.urandom(n // 2).hex())
        creds = {
            "mariadb_root": gen(),
            "postgres_pass": gen(),
            "redis_pass":   gen(24),
        }
        if self.sm:
            self.sm.write_env_file("mariadb",    {"MYSQL_ROOT_PASSWORD": creds["mariadb_root"]})
            self.sm.write_env_file("postgresql", {"POSTGRES_PASSWORD":   creds["postgres_pass"]})
            self.sm.write_env_file("redis",      {"REDIS_PASSWORD":      creds["redis_pass"]})

        if not DRY_RUN:
            for name, key in [("mariadb_root", ".mariadb_root_pass"),
                               ("postgres_pass", ".postgres_pass"),
                               ("redis_pass", ".redis_pass")]:
                p = self.secrets_dir / key
                p.write_text(creds[name])
                os.chmod(p, 0o600)
        return creds

    # -----------------------------------------------------------------------
    # Individual installers
    # -----------------------------------------------------------------------

    def _install_mariadb(self, total_ram_mb: int, creds: dict) -> bool:
        console.print("[cyan]Starting MariaDB...[/cyan]")
        settings = self._calc_mariadb_settings(total_ram_mb)

        # Write my.cnf
        conf_path = self.conf_dir / "mariadb" / "my.cnf"
        if not DRY_RUN:
            conf_path.write_text(MARIADB_CONF.format(**settings))

        compose = MARIADB_COMPOSE.format(
            data_dir=str(self.data_dir),
            conf_dir=str(self.conf_dir),
            secrets_dir=str(self.secrets_dir),
            mariadb_mem=settings["mem_limit"],
        )
        compose_path = self.compose_dir / "mariadb-compose.yml"
        if not DRY_RUN:
            compose_path.write_text(compose)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"  [red]MariaDB failed: {err}[/red]")
            return False

        # Wait for healthy
        self._wait_healthy("mariadb", 60)

        if self.cm:
            self.cm.register_port(3306, "mariadb", "tcp", external=False)
            self.cm.register_service_url(
                "mariadb", "mariadb:3306 (db_network)",
                f"MariaDB — root pass in secrets/.env.mariadb"
            )
        console.print("  [green]MariaDB running ✓[/green]")
        return True

    def _install_postgresql(self, total_ram_mb: int, creds: dict) -> bool:
        console.print("[cyan]Starting PostgreSQL...[/cyan]")
        settings = self._calc_postgres_settings(total_ram_mb)

        conf_path = self.conf_dir / "postgresql" / "postgresql.conf"
        if not DRY_RUN:
            conf_path.write_text(POSTGRESQL_CONF.format(**settings))

        compose = POSTGRESQL_COMPOSE.format(
            data_dir=str(self.data_dir),
            conf_dir=str(self.conf_dir),
            secrets_dir=str(self.secrets_dir),
            pg_mem=settings["mem_limit"],
        )
        compose_path = self.compose_dir / "postgresql-compose.yml"
        if not DRY_RUN:
            compose_path.write_text(compose)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"  [red]PostgreSQL failed: {err}[/red]")
            return False

        self._wait_healthy("postgresql", 60)

        if self.cm:
            self.cm.register_port(5432, "postgresql", "tcp", external=False)
            self.cm.register_service_url(
                "postgresql", "postgresql:5432 (db_network)",
                "PostgreSQL — pass in secrets/.env.postgresql"
            )
        console.print("  [green]PostgreSQL running ✓[/green]")
        return True

    def _install_redis(self, total_ram_mb: int, creds: dict) -> bool:
        console.print("[cyan]Starting Redis...[/cyan]")
        settings = self._calc_redis_settings(total_ram_mb)

        compose = REDIS_COMPOSE.format(
            data_dir=str(self.data_dir),
            secrets_dir=str(self.secrets_dir),
            redis_mem=settings["maxmemory"],
            redis_limit=settings["mem_limit"],
        )
        compose_path = self.compose_dir / "redis-compose.yml"
        if not DRY_RUN:
            compose_path.write_text(compose)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"  [red]Redis failed: {err}[/red]")
            return False

        self._wait_healthy("redis", 30)

        if self.cm:
            self.cm.register_port(6379, "redis", "tcp", external=False)
            self.cm.register_service_url(
                "redis", "redis:6379 (db_network)",
                "Redis — pass in secrets/.env.redis"
            )
        console.print("  [green]Redis running ✓[/green]")
        return True

    def _install_adminer(self, domain: str) -> bool:
        console.print("[cyan]Starting Adminer...[/cyan]")

        compose = ADMINER_COMPOSE.format(domain=domain)
        compose_path = self.compose_dir / "adminer-compose.yml"
        if not DRY_RUN:
            compose_path.write_text(compose)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"  [red]Adminer failed: {err}[/red]")
            return False

        if self.cm:
            self.cm.register_port(8080, "adminer", "tcp", external=False)
            self.cm.register_service_url(
                "adminer",
                f"https://adminer.{domain}  or  http://<server-ip>:8080",
                "Adminer — database web UI (LAN only)"
            )
        console.print("  [green]Adminer running ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _wait_healthy(self, container: str, timeout: int = 60):
        if DRY_RUN:
            return
        for _ in range(timeout // 3):
            time.sleep(3)
            rc, out, _ = _run([
                "docker", "inspect", "--format",
                "{{.State.Health.Status}}", container
            ])
            if rc == 0 and out.strip() == "healthy":
                return

    def _print_summary(self, results: dict, creds: dict):
        console.print()
        table = Table("Service", "Status", "Connection", show_header=True,
                      header_style="bold magenta", border_style="dim")
        labels = {
            "mariadb":    ("MariaDB 11.4",    "mariadb:3306   (db_network)"),
            "postgresql": ("PostgreSQL 16.4", "postgresql:5432 (db_network)"),
            "redis":      ("Redis 7.4",       "redis:6379     (db_network)"),
            "adminer":    ("Adminer",          ":8080 / adminer.<domain>"),
        }
        for key, ok in results.items():
            name, conn = labels.get(key, (key, ""))
            status = "[green]✓ Running[/green]" if ok else "[red]✗ Failed[/red]"
            table.add_row(name, status, conn)
        console.print(table)
        console.print()
        console.print("[dim]All credentials stored in /opt/server-suite/secrets/[/dim]")
        console.print("[dim]Databases are only reachable from the db_network — not from outside Docker[/dim]")


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return DatabaseInstaller(self.suite_dir, self.cm, self.sm).install(config)
