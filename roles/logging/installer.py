"""
roles/logging/installer.py
==========================
Observability stack — two options:
  Option A: Grafana + Prometheus + Loki + Promtail (lightweight, recommended)
  Option B: Graylog + MongoDB + Elasticsearch (more powerful, heavier)

Both expose dashboards via the proxy network (LAN only).
"""

import os
import subprocess
import time
from pathlib import Path

from rich.console import Console
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


# ---------------------------------------------------------------------------
# Grafana Stack (Option A)
# ---------------------------------------------------------------------------

GRAFANA_STACK_COMPOSE = """\
services:
  prometheus:
    image: prom/prometheus:v3.0.1
    container_name: prometheus
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=30d"
      - "--storage.tsdb.retention.size=10GB"
      - "--web.console.libraries=/etc/prometheus/console_libraries"
      - "--web.console.templates=/etc/prometheus/consoles"
    volumes:
      - {data_dir}/prometheus:/prometheus
      - {conf_dir}/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - monitor_network
      - logging_network
    logging:
      driver: journald
      options:
        tag: "docker/prometheus"
    deploy:
      resources:
        limits:
          memory: 1024M
          cpus: '1.0'

  grafana:
    image: grafana/grafana:11.3.1
    container_name: grafana
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/grafana_pass
      GF_INSTALL_PLUGINS: "grafana-clock-panel,grafana-simple-json-datasource"
      GF_SERVER_ROOT_URL: "https://grafana.{domain}"
      GF_SMTP_ENABLED: "{smtp_enabled}"
      GF_SMTP_HOST: "{smtp_host}"
      GF_SMTP_USER: "{smtp_user}"
      GF_SMTP_FROM_ADDRESS: "grafana@{domain}"
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_AUTH_ANONYMOUS_ENABLED: "false"
    volumes:
      - {data_dir}/grafana:/var/lib/grafana
      - {conf_dir}/grafana/provisioning:/etc/grafana/provisioning:ro
    secrets:
      - grafana_pass
    networks:
      - monitor_network
      - logging_network
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.grafana.rule=Host(`grafana.{domain}`)"
      - "traefik.http.routers.grafana.tls=true"
      - "traefik.http.routers.grafana.tls.certresolver=letsencrypt"
      - "traefik.http.routers.grafana.middlewares=lan-only@file"
    logging:
      driver: journald
      options:
        tag: "docker/grafana"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  loki:
    image: grafana/loki:3.2.1
    container_name: loki
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    command: -config.file=/etc/loki/loki-config.yml
    volumes:
      - {data_dir}/loki:/loki
      - {conf_dir}/loki-config.yml:/etc/loki/loki-config.yml:ro
    networks:
      - logging_network
    logging:
      driver: journald
      options:
        tag: "docker/loki"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  promtail:
    image: grafana/promtail:3.2.1
    container_name: promtail
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - {conf_dir}/promtail-config.yml:/etc/promtail/promtail-config.yml:ro
    command: -config.file=/etc/promtail/promtail-config.yml
    networks:
      - logging_network
    logging:
      driver: journald
      options:
        tag: "docker/promtail"
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  node-exporter:
    image: prom/node-exporter:v1.8.2
    container_name: node-exporter
    restart: unless-stopped
    pid: host
    volumes:
      - /:/host:ro,rslave
    command:
      - "--path.rootfs=/host"
      - "--collector.filesystem.ignored-mount-points=^/(sys|proc|dev|run)($$|/)"
    networks:
      - monitor_network
    logging:
      driver: journald
      options:
        tag: "docker/node-exporter"
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.25'

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.50.0
    container_name: cadvisor
    restart: unless-stopped
    privileged: true
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker:/var/lib/docker:ro
      - /dev/disk:/dev/disk:ro
    networks:
      - monitor_network
    logging:
      driver: journald
      options:
        tag: "docker/cadvisor"
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

secrets:
  grafana_pass:
    file: {secrets_dir}/.grafana_pass

networks:
  monitor_network:
    external: true
  logging_network:
    external: true
  proxy_network:
    external: true
"""

PROMETHEUS_CONFIG = """\
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'server-suite'

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']

  - job_name: 'traefik'
    static_configs:
      - targets: ['traefik:8082']

  # Add more targets as services are installed
"""

LOKI_CONFIG = """\
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s

schema_config:
  configs:
    - from: 2024-01-01
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /loki/boltdb-shipper-active
    cache_location: /loki/boltdb-shipper-cache
    cache_ttl: 24h
    shared_store: filesystem
  filesystem:
    directory: /loki/chunks

compactor:
  working_directory: /loki/boltdb-shipper-compactor
  shared_store: filesystem

limits_config:
  retention_period: 30d
  enforce_metric_name: false

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: true
  retention_period: 744h
"""

PROMTAIL_CONFIG = """\
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/*.log

  - job_name: docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex: '/(.*)'
        target_label: 'container'
      - source_labels: ['__meta_docker_container_log_stream']
        target_label: 'logstream'
      - source_labels: ['__meta_docker_container_label_com_docker_compose_service']
        target_label: 'service'
"""

# ---------------------------------------------------------------------------
# Graylog Stack (Option B)
# ---------------------------------------------------------------------------

GRAYLOG_COMPOSE = """\
services:
  mongodb:
    image: mongo:6.0
    container_name: graylog-mongodb
    restart: unless-stopped
    volumes:
      - {data_dir}/mongodb:/data/db
    networks:
      - logging_network
    logging:
      driver: journald
      options:
        tag: "docker/graylog-mongodb"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'

  opensearch:
    image: opensearchproject/opensearch:2.12.0
    container_name: graylog-opensearch
    restart: unless-stopped
    environment:
      - OPENSEARCH_JAVA_OPTS=-Xms{os_heap}m -Xmx{os_heap}m
      - bootstrap.memory_lock=true
      - discovery.type=single-node
      - action.auto_create_index=false
      - plugins.security.disabled=true
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - {data_dir}/opensearch:/usr/share/opensearch/data
    networks:
      - logging_network
    logging:
      driver: journald
      options:
        tag: "docker/graylog-opensearch"
    deploy:
      resources:
        limits:
          memory: {os_mem}M
          cpus: '2.0'

  graylog:
    image: graylog/graylog:6.1
    container_name: graylog
    restart: unless-stopped
    depends_on:
      - mongodb
      - opensearch
    entrypoint: /usr/bin/tini -- wait-for-it opensearch:9200 -- /docker-entrypoint.sh
    environment:
      GRAYLOG_PASSWORD_SECRET: "{password_secret}"
      GRAYLOG_ROOT_PASSWORD_SHA2: "{root_password_sha2}"
      GRAYLOG_HTTP_EXTERNAL_URI: "https://logs.{domain}/"
      GRAYLOG_ELASTICSEARCH_HOSTS: "http://opensearch:9200"
      GRAYLOG_MONGODB_URI: "mongodb://mongodb/graylog"
    ports:
      - "514:514/udp"
      - "514:514/tcp"
      - "5044:5044/tcp"
      - "12201:12201/udp"
      - "127.0.0.1:9000:9000/tcp"
    networks:
      - logging_network
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.graylog.rule=Host(`logs.{domain}`)"
      - "traefik.http.routers.graylog.tls=true"
      - "traefik.http.routers.graylog.middlewares=lan-only@file"
      - "traefik.http.services.graylog.loadbalancer.server.port=9000"
    logging:
      driver: journald
      options:
        tag: "docker/graylog"
    deploy:
      resources:
        limits:
          memory: {graylog_mem}M
          cpus: '2.0'

networks:
  logging_network:
    external: true
  proxy_network:
    external: true
"""


class LoggingInstaller:
    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.data_dir    = self.suite_dir / "docker" / "logging" / "data"
        self.conf_dir    = self.suite_dir / "docker" / "logging" / "conf"
        self.compose_dir = self.suite_dir / "docker" / "logging"
        self.secrets_dir = self.suite_dir / "secrets"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Logging & Metrics[/bold cyan]\n")

        console.print("  [bold]Choose your observability stack:[/bold]\n")
        console.print("  1. [cyan]Grafana Stack[/cyan]  — Grafana + Prometheus + Loki + Promtail")
        console.print("     [dim]Lightweight (~1GB RAM), modern UI, recommended for most setups[/dim]\n")
        console.print("  2. [cyan]Graylog[/cyan]        — Graylog + OpenSearch + MongoDB")
        console.print("     [dim]Powerful log management with alerting, needs 4GB+ RAM[/dim]\n")

        choice = Prompt.ask("  Select stack", choices=["1", "2"], default="1")
        domain = config.get("domain", "local")

        if choice == "1":
            return self._install_grafana_stack(domain, config)
        else:
            return self._install_graylog(domain, config)

    # -----------------------------------------------------------------------
    # Grafana Stack
    # -----------------------------------------------------------------------

    def _install_grafana_stack(self, domain: str, config: dict) -> bool:
        console.print("\n[cyan]Installing Grafana + Prometheus + Loki...[/cyan]")

        grafana_pass = self.sm.generate_password(16, exclude_special=True) if self.sm else os.urandom(8).hex()
        if self.sm:
            self.sm.write_env_file("grafana", {
                "GRAFANA_ADMIN_PASSWORD": grafana_pass,
                "GRAFANA_URL": f"https://grafana.{domain}",
            })

        if not DRY_RUN:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.conf_dir.mkdir(parents=True, exist_ok=True)
            (self.conf_dir / "grafana" / "provisioning" / "datasources").mkdir(parents=True, exist_ok=True)
            (self.secrets_dir / ".grafana_pass").write_text(grafana_pass)
            os.chmod(self.secrets_dir / ".grafana_pass", 0o600)

        # Write configs
        if not DRY_RUN:
            (self.conf_dir / "prometheus.yml").write_text(PROMETHEUS_CONFIG)
            (self.conf_dir / "loki-config.yml").write_text(LOKI_CONFIG)
            (self.conf_dir / "promtail-config.yml").write_text(PROMTAIL_CONFIG)
            self._write_grafana_provisioning(domain)

        smtp_enabled = "true" if self.cm and self.cm.get("notifications.smtp_host") else "false"
        smtp_host    = (self.cm.get("notifications.smtp_host") or "") if self.cm else ""
        smtp_user    = (self.cm.get("notifications.smtp_user") or "") if self.cm else ""

        compose = GRAFANA_STACK_COMPOSE.format(
            domain=domain,
            data_dir=str(self.data_dir),
            conf_dir=str(self.conf_dir),
            secrets_dir=str(self.secrets_dir),
            smtp_enabled=smtp_enabled,
            smtp_host=smtp_host,
            smtp_user=smtp_user,
        )
        compose_path = self.compose_dir / "grafana-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)

        console.print("[cyan]Pulling Grafana stack images...[/cyan]")
        _run(["docker", "compose", "-f", str(compose_path), "pull"], timeout=600)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"], timeout=300)
        if rc != 0:
            console.print(f"[red]Grafana stack failed: {err}[/red]")
            return False

        if self.cm:
            self.cm.register_service_url(
                "grafana", f"https://grafana.{domain}",
                f"Grafana — admin / pass in secrets/.env.grafana"
            )
            self.cm.register_service_url(
                "prometheus", "http://prometheus:9090 (monitor_network)",
                "Prometheus metrics"
            )
            self.cm.add_role("logging", {
                "engine": "grafana-stack",
                "grafana_url": f"https://grafana.{domain}",
            })

        console.print(f"\n[bold green]Grafana stack installed ✓[/bold green]")
        console.print(f"  [dim]Grafana: https://grafana.{domain}[/dim]")
        console.print(f"  [dim]Default dashboards: Node Exporter, Docker containers[/dim]")
        console.print(f"  [dim]Loki log aggregation: auto-configured[/dim]")
        return True

    def _write_grafana_provisioning(self, domain: str):
        """Pre-configure Grafana datasources."""
        prov_dir = self.conf_dir / "grafana" / "provisioning" / "datasources"
        prov_dir.mkdir(parents=True, exist_ok=True)

        datasources = """\
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    jsonData:
      timeInterval: '15s'

  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    jsonData:
      maxLines: 1000
"""
        (prov_dir / "datasources.yml").write_text(datasources)

    # -----------------------------------------------------------------------
    # Graylog
    # -----------------------------------------------------------------------

    def _install_graylog(self, domain: str, config: dict) -> bool:
        console.print("\n[cyan]Installing Graylog...[/cyan]")

        # RAM check
        try:
            total_mb = int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1]) // 1024
        except Exception:
            total_mb = 4096

        if total_mb < 4096:
            console.print(f"[yellow]⚠ Graylog recommends 4GB+ RAM. You have ~{total_mb}MB.[/yellow]")
            if not Confirm.ask("  Continue?", default=False):
                return False

        # Generate secrets
        import hashlib
        import secrets
        password_secret  = secrets.token_hex(32)
        root_password    = self.sm.generate_password(16, exclude_special=True) if self.sm else os.urandom(8).hex()
        root_password_sha2 = hashlib.sha256(root_password.encode()).hexdigest()

        if self.sm:
            self.sm.write_env_file("graylog", {
                "GRAYLOG_PASSWORD_SECRET": password_secret,
                "GRAYLOG_ROOT_PASSWORD":   root_password,
                "GRAYLOG_URL":             f"https://logs.{domain}",
            })

        os_heap    = max(512, min(2048, int(total_mb * 0.20)))
        os_mem     = os_heap * 2 + 256
        graylog_mem = max(512, int(total_mb * 0.15))

        # Fix vm.max_map_count
        _run(["sysctl", "-w", "vm.max_map_count=262144"])

        compose = GRAYLOG_COMPOSE.format(
            domain=domain,
            data_dir=str(self.data_dir),
            password_secret=password_secret,
            root_password_sha2=root_password_sha2,
            os_heap=os_heap,
            os_mem=os_mem,
            graylog_mem=graylog_mem,
        )
        compose_path = self.compose_dir / "graylog-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)

        console.print("[cyan]Pulling Graylog images (~2GB)...[/cyan]")
        _run(["docker", "compose", "-f", str(compose_path), "pull"], timeout=900)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"], timeout=300)
        if rc != 0:
            console.print(f"[red]Graylog failed: {err}[/red]")
            return False

        # Open syslog ports
        for port in ["514/udp", "514/tcp", "5044/tcp", "12201/udp"]:
            _run(["ufw", "allow", port])

        if self.cm:
            self.cm.register_service_url(
                "graylog", f"https://logs.{domain}",
                f"Graylog — admin / pass in secrets/.env.graylog"
            )
            self.cm.add_role("logging", {
                "engine":      "graylog",
                "graylog_url": f"https://logs.{domain}",
            })

        console.print(f"\n[bold green]Graylog installed ✓[/bold green]")
        console.print(f"  [dim]Dashboard: https://logs.{domain}[/dim]")
        console.print(f"  [dim]Admin password: stored in secrets/.env.graylog[/dim]")
        return True


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return LoggingInstaller(self.suite_dir, self.cm, self.sm).install(config)
