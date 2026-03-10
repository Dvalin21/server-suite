"""
roles/web/traefik.py
====================
Traefik v3 reverse proxy with auto-discovery, Let's Encrypt,
dashboard, and Docker provider integration.
"""

import os
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    if DRY_RUN:
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


TRAEFIK_COMPOSE = """services:
  traefik:
    image: traefik:v3.2
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - {traefik_dir}/traefik.yml:/traefik.yml:ro
      - {traefik_dir}/acme.json:/acme.json
      - {traefik_dir}/config:/config:ro
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik.rule=Host(`traefik.{domain}`)"
      - "traefik.http.routers.traefik.tls=true"
      - "traefik.http.routers.traefik.tls.certresolver=letsencrypt"
      - "traefik.http.routers.traefik.service=api@internal"
      - "traefik.http.routers.traefik.middlewares=lan-only@file"
    networks:
      - proxy_network
    logging:
      driver: journald
      options:
        tag: "docker/traefik"
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'

networks:
  proxy_network:
    external: true
"""

TRAEFIK_STATIC_CONFIG = """# Traefik Static Configuration
api:
  dashboard: true
  insecure: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt

certificatesResolvers:
  letsencrypt:
    acme:
      email: {acme_email}
      storage: /acme.json
      httpChallenge:
        entryPoint: web

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: proxy_network
  file:
    directory: /config
    watch: true

log:
  level: INFO
  filePath: "/var/log/traefik/traefik.log"

accessLog:
  filePath: "/var/log/traefik/access.log"
  bufferingSize: 100
"""

TRAEFIK_DYNAMIC_CONFIG = """# Traefik Dynamic Configuration
http:
  middlewares:
    # LAN-only access middleware
    lan-only:
      ipWhiteList:
        sourceRange:
          - "127.0.0.1/32"
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"

    # Security headers for all services
    secure-headers:
      headers:
        accessControlAllowMethods:
          - GET
          - OPTIONS
          - PUT
        accessControlMaxAge: 100
        hostsProxyHeaders:
          - "X-Forwarded-Host"
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        forceSTSHeader: true
        customFrameOptionsValue: "SAMEORIGIN"
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "strict-origin-when-cross-origin"
        permissionsPolicy: "camera=(), microphone=(), geolocation=()"

    # Rate limiting
    rate-limit:
      rateLimit:
        average: 100
        burst: 50
"""


class TraefikInstaller:
    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.traefik_dir = self.suite_dir / "docker" / "traefik"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Traefik Reverse Proxy[/bold cyan]\n")

        domain     = config.get("domain", "example.com")
        acme_email = config.get("notify_email", f"admin@{domain}")

        # Create directories
        for subdir in ["config", "logs"]:
            d = self.traefik_dir / subdir
            if not DRY_RUN:
                d.mkdir(parents=True, exist_ok=True)

        # Create empty acme.json with correct permissions
        acme_path = self.traefik_dir / "acme.json"
        if not DRY_RUN:
            acme_path.touch()
            os.chmod(acme_path, 0o600)

        # Write configs
        compose_path  = self.traefik_dir / "docker-compose.yml"
        static_path   = self.traefik_dir / "traefik.yml"
        dynamic_path  = self.traefik_dir / "config" / "dynamic.yml"

        if not DRY_RUN:
            compose_path.write_text(
                TRAEFIK_COMPOSE.format(
                    traefik_dir=str(self.traefik_dir),
                    domain=domain,
                )
            )
            static_path.write_text(
                TRAEFIK_STATIC_CONFIG.format(acme_email=acme_email)
            )
            dynamic_path.write_text(TRAEFIK_DYNAMIC_CONFIG)

        # Start
        console.print("[cyan]Starting Traefik...[/cyan]")
        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"[red]Failed to start Traefik: {err}[/red]")
            return False

        if self.cm:
            self.cm.register_port(80,  "traefik", "tcp", external=True)
            self.cm.register_port(443, "traefik", "tcp", external=True)
            self.cm.register_service_url(
                "traefik-dashboard",
                f"https://traefik.{domain}",
                "Traefik dashboard (LAN only)"
            )
            self.cm.add_role("web", {
                "engine": "traefik",
                "compose_file": str(compose_path),
            })

        console.print("[bold green]Traefik installed ✓[/bold green]")
        console.print(f"  [dim]Dashboard: https://traefik.{domain} (LAN only)[/dim]")
        return True


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm = config_manager
        self.sm = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return TraefikInstaller(self.suite_dir, self.cm, self.sm).install(config)
