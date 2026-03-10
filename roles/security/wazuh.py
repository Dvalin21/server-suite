"""
roles/security/wazuh.py
=======================
Wazuh SIEM — Docker deployment of Manager + Indexer + Dashboard.
Also supports Agent-only mode (reports to an existing Wazuh manager).

Stack includes:
  - wazuh-manager:  log collection, analysis, active response
  - wazuh-indexer:  OpenSearch-based storage and search
  - wazuh-dashboard: web UI (Kibana fork)
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

WAZUH_VERSION = "4.9.2"


def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


WAZUH_COMPOSE = """\
# Wazuh {version} — Single-node deployment
# See: https://documentation.wazuh.com/current/deployment-options/docker/

services:
  wazuh-manager:
    image: wazuh/wazuh-manager:{version}
    container_name: wazuh-manager
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 655360
        hard: 655360
    ports:
      - "1514:1514/udp"
      - "1514:1514/tcp"
      - "1515:1515/tcp"
      - "514:514/udp"
      - "514:514/tcp"
      - "55000:55000/tcp"
    environment:
      INDEXER_URL: "https://wazuh-indexer:9200"
      INDEXER_USERNAME: "admin"
      INDEXER_PASSWORD_FILE: /run/secrets/wazuh_indexer_pass
      FILEBEAT_SSL_VERIFICATION_MODE: full
      SSL_CERTIFICATE_AUTHORITIES: "/etc/ssl/root-ca.pem"
      SSL_CERTIFICATE: "/etc/ssl/filebeat.pem"
      SSL_KEY: "/etc/ssl/filebeat.key"
    volumes:
      - {data_dir}/wazuh-manager/api_configuration:/var/ossec/api/configuration
      - {data_dir}/wazuh-manager/etc:/var/ossec/etc
      - {data_dir}/wazuh-manager/logs:/var/ossec/logs
      - {data_dir}/wazuh-manager/queue:/var/ossec/queue
      - {data_dir}/wazuh-manager/var_multigroups:/var/ossec/var/multigroups
      - {data_dir}/wazuh-manager/integrations:/var/ossec/integrations
      - {data_dir}/wazuh-manager/active_response:/var/ossec/active-response/bin
      - {data_dir}/wazuh-manager/agentless:/var/ossec/agentless
      - {data_dir}/wazuh-manager/wodles:/var/ossec/wodles
      - {data_dir}/wazuh-manager/etc_filebeat:/etc/filebeat
      - {ssl_dir}:/etc/ssl:ro
    secrets:
      - wazuh_indexer_pass
    networks:
      - monitor_network
    logging:
      driver: journald
      options:
        tag: "docker/wazuh-manager"
    deploy:
      resources:
        limits:
          memory: {manager_mem}M
          cpus: '2.0'

  wazuh-indexer:
    image: wazuh/wazuh-indexer:{version}
    container_name: wazuh-indexer
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    environment:
      OPENSEARCH_JAVA_OPTS: "-Xms{indexer_heap}m -Xmx{indexer_heap}m"
      bootstrap.memory_lock: "true"
    volumes:
      - {data_dir}/wazuh-indexer:/var/lib/wazuh-indexer
      - {ssl_dir}/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem:ro
      - {ssl_dir}/wazuh-indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh-indexer.key:ro
      - {ssl_dir}/wazuh-indexer.pem:/usr/share/wazuh-indexer/certs/wazuh-indexer.pem:ro
      - {conf_dir}/wazuh-indexer/opensearch.yml:/usr/share/wazuh-indexer/opensearch.yml:ro
    networks:
      - monitor_network
    logging:
      driver: journald
      options:
        tag: "docker/wazuh-indexer"
    deploy:
      resources:
        limits:
          memory: {indexer_mem}M
          cpus: '2.0'

  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:{version}
    container_name: wazuh-dashboard
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    depends_on:
      - wazuh-indexer
    environment:
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD_FILE: /run/secrets/wazuh_indexer_pass
      WAZUH_API_URL: "https://wazuh-manager"
      API_USERNAME: "wazuh-wui"
      API_PASSWORD_FILE: /run/secrets/wazuh_api_pass
    volumes:
      - {conf_dir}/wazuh-dashboard/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml:ro
      - {ssl_dir}/wazuh-dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem:ro
      - {ssl_dir}/wazuh-dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.key:ro
      - {ssl_dir}/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem:ro
    ports:
      - "127.0.0.1:443:443"
    secrets:
      - wazuh_indexer_pass
      - wazuh_api_pass
    networks:
      - monitor_network
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.wazuh.rule=Host(`wazuh.{domain}`)"
      - "traefik.http.routers.wazuh.tls=true"
      - "traefik.http.routers.wazuh.middlewares=lan-only@file"
    logging:
      driver: journald
      options:
        tag: "docker/wazuh-dashboard"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'

secrets:
  wazuh_indexer_pass:
    file: {secrets_dir}/.wazuh_indexer_pass
  wazuh_api_pass:
    file: {secrets_dir}/.wazuh_api_pass

networks:
  monitor_network:
    external: true
  proxy_network:
    external: true
"""

WAZUH_AGENT_INSTALL = """\
#!/usr/bin/env bash
# Install Wazuh agent and register with manager
set -euo pipefail
MANAGER_IP="{manager_ip}"
AGENT_NAME="{agent_name}"
WAZUH_VERSION="{version}"

# Install agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update -qq
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install -y wazuh-agent

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
echo "Wazuh agent installed and connected to $MANAGER_IP"
"""


class WazuhInstaller:
    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.data_dir    = self.suite_dir / "docker" / "wazuh" / "data"
        self.conf_dir    = self.suite_dir / "docker" / "wazuh" / "conf"
        self.ssl_dir     = self.suite_dir / "docker" / "wazuh" / "certs"
        self.compose_dir = self.suite_dir / "docker" / "wazuh"
        self.secrets_dir = self.suite_dir / "secrets"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Wazuh Security Monitoring[/bold cyan]\n")

        console.print("  [bold]Deployment Mode[/bold]\n")
        console.print("  1. [cyan]Server[/cyan]   — Deploy full Wazuh stack on this machine")
        console.print("  2. [cyan]Agent[/cyan]    — Install agent only, report to existing manager\n")

        mode = Prompt.ask("  Select mode", choices=["1", "2"], default="1")

        if mode == "2":
            return self._install_agent(config)

        return self._install_server(config)

    # -----------------------------------------------------------------------
    # Server mode
    # -----------------------------------------------------------------------

    def _install_server(self, config: dict) -> bool:
        domain = config.get("domain", "local")

        # RAM check — Wazuh needs at least 4GB
        try:
            total_mb = int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1]) // 1024
        except Exception:
            total_mb = 4096

        if total_mb < 4096:
            console.print(
                f"\n[bold yellow]⚠ Warning:[/bold yellow] Wazuh server recommends 4GB+ RAM. "
                f"You have ~{total_mb}MB. It may run slowly."
            )
            if not Confirm.ask("  Continue anyway?", default=False):
                return False

        # Calculate heap sizes
        indexer_heap = max(512, min(4096, int(total_mb * 0.25)))
        manager_mem  = max(512, int(total_mb * 0.20))
        indexer_mem  = indexer_heap * 2 + 512

        # Generate credentials
        indexer_pass = self.sm.generate_password(24, exclude_special=True) if self.sm else os.urandom(12).hex()
        api_pass     = self.sm.generate_password(24, exclude_special=True) if self.sm else os.urandom(12).hex()

        if self.sm:
            self.sm.write_env_file("wazuh", {
                "WAZUH_INDEXER_PASSWORD": indexer_pass,
                "WAZUH_API_PASSWORD":     api_pass,
                "WAZUH_VERSION":          WAZUH_VERSION,
            })

        if not DRY_RUN:
            for d in [self.data_dir, self.conf_dir, self.ssl_dir]:
                d.mkdir(parents=True, exist_ok=True)
            (self.secrets_dir / ".wazuh_indexer_pass").write_text(indexer_pass)
            (self.secrets_dir / ".wazuh_api_pass").write_text(api_pass)
            for f in [".wazuh_indexer_pass", ".wazuh_api_pass"]:
                os.chmod(self.secrets_dir / f, 0o600)

        # Generate SSL certificates
        self._generate_certs(domain)

        # Write configs
        self._write_configs()

        # Write compose
        compose = WAZUH_COMPOSE.format(
            version=WAZUH_VERSION,
            data_dir=str(self.data_dir),
            conf_dir=str(self.conf_dir),
            ssl_dir=str(self.ssl_dir),
            secrets_dir=str(self.secrets_dir),
            domain=domain,
            manager_mem=manager_mem,
            indexer_heap=indexer_heap,
            indexer_mem=indexer_mem,
        )
        compose_path = self.compose_dir / "wazuh-compose.yml"
        if not DRY_RUN:
            compose_path.write_text(compose)

        # Set vm.max_map_count for OpenSearch
        if not DRY_RUN:
            _run(["sysctl", "-w", "vm.max_map_count=262144"])
            sysctl_d = Path("/etc/sysctl.d/99-wazuh.conf")
            sysctl_d.write_text("vm.max_map_count=262144\n")

        # Pull images
        console.print("[cyan]Pulling Wazuh images (~3-4GB)...[/cyan]")
        _run(["docker", "compose", "-f", str(compose_path), "pull"], timeout=1800)

        # Start
        console.print("[cyan]Starting Wazuh stack...[/cyan]")
        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"], timeout=300)
        if rc != 0:
            console.print(f"[red]Wazuh start failed: {err}[/red]")
            return False

        # Firewall
        for port in ["1514/udp", "1514/tcp", "1515/tcp", "514/udp", "55000/tcp"]:
            _run(["ufw", "allow", port])

        if self.cm:
            self.cm.register_service_url(
                "wazuh-dashboard",
                f"https://wazuh.{domain}  or  https://<server-ip>:443",
                "Wazuh dashboard — admin / changeme (change in indexer settings)"
            )
            self.cm.add_role("security", {
                "engine":  "wazuh",
                "mode":    "server",
                "version": WAZUH_VERSION,
            })

        console.print(f"\n[bold green]Wazuh installed ✓[/bold green]")
        self._print_post_install(domain)
        return True

    # -----------------------------------------------------------------------
    # Agent mode
    # -----------------------------------------------------------------------

    def _install_agent(self, config: dict) -> bool:
        manager_ip  = Prompt.ask("  Wazuh Manager IP/hostname")
        agent_name  = Prompt.ask("  Agent name", default=config.get("hostname", "server"))

        script = WAZUH_AGENT_INSTALL.format(
            manager_ip=manager_ip,
            agent_name=agent_name,
            version=WAZUH_VERSION,
        )
        script_path = self.suite_dir / "scripts" / "install-wazuh-agent.sh"
        if not DRY_RUN:
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(script)
            os.chmod(script_path, 0o750)

        rc, _, err = _run(["bash", str(script_path)], timeout=300)
        if rc != 0:
            console.print(f"[red]Agent installation failed: {err}[/red]")
            return False

        if self.cm:
            self.cm.add_role("security", {
                "engine":     "wazuh",
                "mode":       "agent",
                "manager_ip": manager_ip,
            })
        console.print(f"[bold green]Wazuh agent installed and connected to {manager_ip} ✓[/bold green]")
        return True

    # -----------------------------------------------------------------------
    # Certificate generation
    # -----------------------------------------------------------------------

    def _generate_certs(self, domain: str):
        """Generate self-signed certs for Wazuh internal TLS."""
        console.print("[cyan]Generating Wazuh TLS certificates...[/cyan]")
        if DRY_RUN:
            return

        # Use openssl to generate a simple CA + certs
        ssl_dir = self.ssl_dir
        _run(["apt-get", "install", "-y", "-qq", "openssl"])

        # Root CA
        _run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:4096",
              "-keyout", str(ssl_dir / "root-ca-key.pem"),
              "-out",    str(ssl_dir / "root-ca.pem"),
              "-days",   "3650",
              "-subj",   f"/C=US/O=WazuhCA/CN=Wazuh Root CA"])

        # Generate cert for each component
        for component in ["wazuh-indexer", "wazuh-dashboard", "filebeat"]:
            _run(["openssl", "req", "-nodes", "-newkey", "rsa:4096",
                  "-keyout", str(ssl_dir / f"{component}-key.pem"),
                  "-out",    str(ssl_dir / f"{component}.csr"),
                  "-subj",   f"/C=US/O=Wazuh/CN={component}"])
            _run(["openssl", "x509", "-req", "-days", "3650",
                  "-in",      str(ssl_dir / f"{component}.csr"),
                  "-CA",      str(ssl_dir / "root-ca.pem"),
                  "-CAkey",   str(ssl_dir / "root-ca-key.pem"),
                  "-CAcreateserial",
                  "-out",     str(ssl_dir / f"{component}.pem")])

        # Set correct permissions
        for key_file in ssl_dir.glob("*-key.pem"):
            os.chmod(key_file, 0o600)
        console.print("  [dim]TLS certificates generated ✓[/dim]")

    def _write_configs(self):
        """Write OpenSearch and dashboard config files."""
        if DRY_RUN:
            return

        # OpenSearch config
        opensearch_conf = """\
network.host: 0.0.0.0
node.name: wazuh-indexer
cluster.initial_master_nodes:
  - wazuh-indexer

plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer.key
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer.key
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
"""
        indexer_conf_dir = self.conf_dir / "wazuh-indexer"
        indexer_conf_dir.mkdir(parents=True, exist_ok=True)
        (indexer_conf_dir / "opensearch.yml").write_text(opensearch_conf)

        # Dashboard config
        dashboard_conf = """\
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://wazuh-indexer:9200
opensearch.ssl.verificationMode: certificate
server.ssl.enabled: true
server.ssl.certificate: /usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
server.ssl.key: /usr/share/wazuh-dashboard/certs/wazuh-dashboard.key
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wazuh
"""
        dashboard_conf_dir = self.conf_dir / "wazuh-dashboard"
        dashboard_conf_dir.mkdir(parents=True, exist_ok=True)
        (dashboard_conf_dir / "opensearch_dashboards.yml").write_text(dashboard_conf)

    def _print_post_install(self, domain: str):
        console.print()
        console.print(Panel(
            "[bold]Wazuh is starting up (may take 2-5 minutes)[/bold]\n\n"
            f"  Dashboard: [cyan]https://wazuh.{domain}[/cyan]\n"
            f"  Default login: [cyan]admin[/cyan] / [cyan]changeme[/cyan]\n\n"
            "  [bold]Next steps:[/bold]\n"
            "  1. Log in and change the default password\n"
            "  2. Deploy the Wazuh agent on all servers you want to monitor\n"
            "  3. Configure email alerts in Manager Settings → Alerts\n"
            f"  4. Install agents: run  sudo bash {self.suite_dir}/scripts/install-wazuh-agent.sh\n\n"
            "  [dim]Agent install command for other servers:[/dim]\n"
            f"  [dim]curl -s https://<server-ip>/wazuh-agent-install.sh | bash[/dim]",
            border_style="cyan"
        ))


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return WazuhInstaller(self.suite_dir, self.cm, self.sm).install(config)
