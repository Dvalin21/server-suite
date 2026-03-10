"""
roles/web/nginx_npm.py
======================
Nginx Proxy Manager — Docker-based reverse proxy with web GUI.
Handles TLS termination, Let's Encrypt, and proxy routing for all services.
All other web services register themselves here after installation.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

NPM_DIR = Path("/opt/server-suite/docker/nginx-proxy-manager")

COMPOSE_TEMPLATE = """services:
  npm:
    image: jc21/nginx-proxy-manager:2.11.3
    container_name: nginx-proxy-manager
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      # Public ports — these are the ONLY ports exposed to the internet
      - "80:80"
      - "443:443"
      # Admin UI — LAN only (bound to specific IP in production)
      - "127.0.0.1:81:81"
    volumes:
      - {npm_dir}/data:/data
      - {npm_dir}/letsencrypt:/etc/letsencrypt
    environment:
      DB_SQLITE_FILE: "/data/database.sqlite"
      DISABLE_IPV6: "true"
    healthcheck:
      test: ["CMD", "/bin/check-health"]
      interval: 10s
      timeout: 3s
      retries: 3
    networks:
      - proxy_network
    logging:
      driver: journald
      options:
        tag: "docker/nginx-proxy-manager"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'

networks:
  proxy_network:
    external: true
"""

NPM_LAN_ACCESS_CONF = """# Nginx Proxy Manager Admin — LAN access via SSH tunnel or direct LAN
# Access at: http://<server-lan-ip>:81
# Default credentials: admin@example.com / changeme
# CHANGE THESE IMMEDIATELY after first login
"""


def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class NginxProxyManagerInstaller:
    """Installs and configures Nginx Proxy Manager."""

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir = Path(suite_dir)
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.npm_dir   = self.suite_dir / "docker" / "nginx-proxy-manager"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Nginx Proxy Manager[/bold cyan]\n")

        # Create directories
        for subdir in ["data", "letsencrypt"]:
            d = self.npm_dir / subdir
            if not DRY_RUN:
                d.mkdir(parents=True, exist_ok=True)

        # Write compose file
        compose_content = COMPOSE_TEMPLATE.format(npm_dir=str(self.npm_dir))
        compose_path = self.npm_dir / "docker-compose.yml"

        if not DRY_RUN:
            compose_path.write_text(compose_content)

        # Pull and start
        console.print("[cyan]Pulling Nginx Proxy Manager image...[/cyan]")
        _run(["docker", "compose", "-f", str(compose_path), "pull"], timeout=300)

        console.print("[cyan]Starting Nginx Proxy Manager...[/cyan]")
        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"[red]Failed to start NPM: {err}[/red]")
            return False

        # Wait for health
        console.print("[dim]Waiting for NPM to become healthy...[/dim]")
        if not DRY_RUN:
            for i in range(30):
                time.sleep(3)
                rc2, out2, _ = _run([
                    "docker", "inspect", "--format",
                    "{{.State.Health.Status}}", "nginx-proxy-manager"
                ])
                if rc2 == 0 and out2.strip() == "healthy":
                    break
                if i == 29:
                    console.print("[yellow]NPM health check timed out — it may still be starting[/yellow]")

        # Register ports
        if self.cm:
            self.cm.register_port(80,  "nginx-proxy-manager", "tcp", external=True,
                                  description="HTTP (redirects to HTTPS)")
            self.cm.register_port(443, "nginx-proxy-manager", "tcp", external=True,
                                  description="HTTPS reverse proxy")
            self.cm.register_port(81,  "nginx-proxy-manager-admin", "tcp", external=False,
                                  description="NPM admin UI (LAN only)")

            domain   = config.get("domain", "localhost")
            hostname = config.get("hostname", "server")
            self.cm.register_service_url(
                "nginx-proxy-manager",
                f"http://<server-ip>:81",
                "Nginx Proxy Manager admin UI (LAN only, default: admin@example.com / changeme)"
            )
            self.cm.add_role("web", {
                "engine": "nginx-proxy-manager",
                "compose_file": str(compose_path),
                "admin_url": "http://<server-ip>:81",
            })

        console.print("[bold green]Nginx Proxy Manager installed ✓[/bold green]")
        console.print()
        console.print("  [bold]Next steps:[/bold]")
        console.print("  1. Open [cyan]http://<server-ip>:81[/cyan] from your LAN")
        console.print("  2. Log in with [cyan]admin@example.com[/cyan] / [cyan]changeme[/cyan]")
        console.print("  3. [bold red]Change the default password immediately[/bold red]")
        console.print("  4. Add proxy hosts for each service as they are installed")
        console.print()
        return True


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        installer = NginxProxyManagerInstaller(self.suite_dir, self.cm, self.sm)
        return installer.install(config)
