"""
roles/comms/installer.py
========================
Communication services:
  - Matrix Synapse + Element Web (Docker) — federated chat, E2E encrypted
  - Mattermost (Docker) — Slack-alternative team messaging
  - Mumble (Docker) — low-latency voice chat
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


SYNAPSE_COMPOSE = """\
services:
  synapse:
    image: matrixdotorg/synapse:v1.118.0
    container_name: synapse
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      SYNAPSE_SERVER_NAME: "{matrix_domain}"
      SYNAPSE_REPORT_STATS: "no"
    volumes:
      - {data_dir}/synapse:/data
    networks:
      - proxy_network
      - db_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.synapse.rule=Host(`{matrix_fqdn}`)"
      - "traefik.http.routers.synapse.tls=true"
      - "traefik.http.routers.synapse.tls.certresolver=letsencrypt"
      - "traefik.http.services.synapse.loadbalancer.server.port=8008"
    ports:
      # Federation port — needs to be publicly accessible
      - "8448:8448/tcp"
    healthcheck:
      test: ["CMD", "curl", "-fSs", "http://localhost:8008/health"]
      interval: 15s
      timeout: 5s
      retries: 3
    logging:
      driver: journald
      options:
        tag: "docker/synapse"
    deploy:
      resources:
        limits:
          memory: {synapse_mem}M
          cpus: '2.0'

  element-web:
    image: vectorim/element-web:v1.11.85
    container_name: element-web
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    volumes:
      - {conf_dir}/element-config.json:/app/config.json:ro
    networks:
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.element.rule=Host(`{element_fqdn}`)"
      - "traefik.http.routers.element.tls=true"
      - "traefik.http.routers.element.tls.certresolver=letsencrypt"
    logging:
      driver: journald
      options:
        tag: "docker/element"
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.25'

networks:
  proxy_network:
    external: true
  db_network:
    external: true
"""

SYNAPSE_HOMESERVER_YAML = """\
server_name: "{matrix_domain}"
public_baseurl: "https://{matrix_fqdn}/"

listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    resources:
      - names: [client, federation]
        compress: false
  - port: 8448
    tls: false
    type: http
    x_forwarded: true
    resources:
      - names: [federation]
        compress: false

database:
  name: psycopg2
  args:
    user: synapse
    password: "{db_pass}"
    database: synapse
    host: postgresql
    cp_min: 5
    cp_max: 10

media_store_path: /data/media_store
uploads_path: /data/uploads

enable_registration: false
enable_registration_without_verification: false
registration_shared_secret: "{registration_secret}"

macaroon_secret_key: "{macaroon_secret}"
form_secret: "{form_secret}"
signing_key_path: "/data/{matrix_domain}.signing.key"

log_config: "/data/{matrix_domain}.log.config"

federation_domain_whitelist: []

# Rate limiting
rc_message:
  per_second: 0.2
  burst_count: 10
rc_registration:
  per_second: 0.17
  burst_count: 3
rc_login:
  address:
    per_second: 0.17
    burst_count: 3
  account:
    per_second: 0.17
    burst_count: 3

# Turn server (Jitsi/Coturn) — configure if needed
#turn_uris:
#turn_shared_secret:
#turn_user_lifetime: 86400000

report_stats: false
"""

ELEMENT_CONFIG = """\
{{
  "default_server_config": {{
    "m.homeserver": {{
      "base_url": "https://{matrix_fqdn}",
      "server_name": "{matrix_domain}"
    }},
    "m.identity_server": {{
      "base_url": "https://vector.im"
    }}
  }},
  "brand": "Element",
  "integrations_ui_url": "https://scalar.vector.im/",
  "integrations_rest_url": "https://scalar.vector.im/api",
  "integrations_widgets_urls": ["https://scalar.vector.im/_matrix/integrations/v1"],
  "hosting_signup_link": false,
  "bug_report_endpoint_url": null,
  "defaultCountryCode": "US",
  "showLabsSettings": false,
  "features": {{}},
  "default_federate": true,
  "default_theme": "dark",
  "room_directory": {{
    "servers": ["{matrix_domain}"]
  }},
  "enable_presence_by_hs_url": {{
    "https://{matrix_fqdn}": false
  }},
  "setting_defaults": {{
    "breadcrumbs": true
  }},
  "jitsi": {{
    "preferred_domain": "meet.element.io"
  }}
}}
"""

MATTERMOST_COMPOSE = """\
services:
  mattermost:
    image: mattermost/mattermost-team-edition:9.11.3
    container_name: mattermost
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    pids_limit: 200
    read_only: false
    tmpfs:
      - /tmp
    volumes:
      - {data_dir}/mattermost/config:/mattermost/config:rw
      - {data_dir}/mattermost/data:/mattermost/data:rw
      - {data_dir}/mattermost/logs:/mattermost/logs:rw
      - {data_dir}/mattermost/plugins:/mattermost/plugins:rw
      - {data_dir}/mattermost/client-plugins:/mattermost/client/plugins:rw
    environment:
      MM_SQLSETTINGS_DRIVERNAME: postgres
      MM_SQLSETTINGS_DATASOURCE: "postgres://mattermost:{db_pass}@postgresql:5432/mattermost?sslmode=disable&connect_timeout=10"
      MM_SERVICESETTINGS_SITEURL: "https://{mm_fqdn}"
      MM_PLUGINSETTINGS_ENABLEUPLOADS: "true"
      MM_CLUSTERSETTINGS_ENABLE: "false"
      MM_FILESETTINGS_MAXFILESIZE: "104857600"
    networks:
      - proxy_network
      - db_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mattermost.rule=Host(`{mm_fqdn}`)"
      - "traefik.http.routers.mattermost.tls=true"
      - "traefik.http.routers.mattermost.tls.certresolver=letsencrypt"
      - "traefik.http.services.mattermost.loadbalancer.server.port=8065"
    logging:
      driver: journald
      options:
        tag: "docker/mattermost"
    deploy:
      resources:
        limits:
          memory: 1024M
          cpus: '2.0'

networks:
  proxy_network:
    external: true
  db_network:
    external: true
"""

MUMBLE_COMPOSE = """\
services:
  mumble:
    image: mumblevoip/mumble-server:v1.5.735
    container_name: mumble
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    ports:
      - "64738:64738/tcp"
      - "64738:64738/udp"
    environment:
      MUMBLE_CONFIG_welcometext: "Welcome to {hostname} Mumble server"
      MUMBLE_CONFIG_bandwidth: "72000"
      MUMBLE_CONFIG_users: "100"
      MUMBLE_CONFIG_certrequired: "true"
      MUMBLE_SUPERUSER_PASSWORD: "{superuser_pass}"
    volumes:
      - {data_dir}/mumble:/data
    networks:
      - comms_network
    logging:
      driver: journald
      options:
        tag: "docker/mumble"
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.5'

networks:
  comms_network:
    external: true
"""


class CommsInstaller:
    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.data_dir    = self.suite_dir / "docker" / "comms" / "data"
        self.conf_dir    = self.suite_dir / "docker" / "comms" / "conf"
        self.compose_dir = self.suite_dir / "docker" / "comms"
        self.secrets_dir = self.suite_dir / "secrets"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Communication Services[/bold cyan]\n")

        domain   = config.get("domain", "local")
        hostname = config.get("hostname", "server")

        install_matrix      = Confirm.ask("  Install Matrix/Synapse + Element (federated chat)?", default=True)
        install_mattermost  = Confirm.ask("  Install Mattermost (team messaging)?",               default=False)
        install_mumble      = Confirm.ask("  Install Mumble (voice chat)?",                        default=False)

        results = {}

        if not DRY_RUN:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.conf_dir.mkdir(parents=True, exist_ok=True)

        if install_matrix:
            results["matrix"] = self._install_matrix(domain)

        if install_mattermost:
            results["mattermost"] = self._install_mattermost(domain)

        if install_mumble:
            results["mumble"] = self._install_mumble(hostname)

        self._print_summary(results, domain)

        if self.cm:
            self.cm.add_role("comms", {k: True for k in results if results[k]})

        return any(results.values())

    # -----------------------------------------------------------------------
    # Matrix / Synapse
    # -----------------------------------------------------------------------

    def _install_matrix(self, domain: str) -> bool:
        console.print("[cyan]Installing Matrix Synapse + Element...[/cyan]")

        matrix_fqdn  = f"matrix.{domain}"
        element_fqdn = f"element.{domain}"

        db_pass            = self._gen_pass()
        registration_secret = self._gen_pass(32)
        macaroon_secret    = self._gen_pass(32)
        form_secret        = self._gen_pass(32)

        if self.sm:
            self.sm.write_env_file("synapse", {
                "SYNAPSE_DB_PASSWORD":          db_pass,
                "REGISTRATION_SHARED_SECRET":   registration_secret,
                "MATRIX_DOMAIN":                domain,
                "MATRIX_FQDN":                  matrix_fqdn,
            })

        # Create Synapse DB in PostgreSQL
        self._create_synapse_db(db_pass)

        # Write homeserver.yaml
        homeserver_yaml = SYNAPSE_HOMESERVER_YAML.format(
            matrix_domain=domain,
            matrix_fqdn=matrix_fqdn,
            db_pass=db_pass,
            registration_secret=registration_secret,
            macaroon_secret=macaroon_secret,
            form_secret=form_secret,
        )
        if not DRY_RUN:
            synapse_data = self.data_dir / "synapse"
            synapse_data.mkdir(parents=True, exist_ok=True)
            (synapse_data / "homeserver.yaml").write_text(homeserver_yaml)

        # Write Element config
        element_config = ELEMENT_CONFIG.format(
            matrix_domain=domain,
            matrix_fqdn=matrix_fqdn,
        )
        if not DRY_RUN:
            (self.conf_dir / "element-config.json").write_text(element_config)

        # Detect RAM for sizing
        try:
            total_mb = int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1]) // 1024
            synapse_mem = max(512, min(2048, int(total_mb * 0.20)))
        except Exception:
            synapse_mem = 1024

        compose = SYNAPSE_COMPOSE.format(
            matrix_domain=domain,
            matrix_fqdn=matrix_fqdn,
            element_fqdn=element_fqdn,
            data_dir=str(self.data_dir),
            conf_dir=str(self.conf_dir),
            synapse_mem=synapse_mem,
        )
        compose_path = self.compose_dir / "synapse-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"], timeout=300)
        if rc != 0:
            console.print(f"  [red]Synapse failed: {err}[/red]")
            return False

        if self.cm:
            self.cm.register_port(8448, "synapse-federation", "tcp", external=True,
                                  description="Matrix federation")
            self.cm.register_service_url("matrix",  f"https://{matrix_fqdn}",  "Matrix homeserver")
            self.cm.register_service_url("element", f"https://{element_fqdn}", "Element web client")

        _run(["ufw", "allow", "8448/tcp"])
        console.print(f"  [green]Matrix → https://{matrix_fqdn}[/green]")
        console.print(f"  [green]Element → https://{element_fqdn}[/green]")
        console.print(f"  [dim]Create admin user: docker exec -it synapse register_new_matrix_user -c /data/homeserver.yaml http://localhost:8008[/dim]")
        return True

    def _create_synapse_db(self, db_pass: str):
        if DRY_RUN:
            return
        secrets_dir = self.secrets_dir
        pg_pass_file = secrets_dir / ".postgres_pass"
        if not pg_pass_file.exists():
            return
        pg_pass = pg_pass_file.read_text().strip()
        sql = (
            f"CREATE DATABASE synapse ENCODING 'UTF8' LC_COLLATE='C' LC_CTYPE='C' template=template0; "
            f"CREATE USER synapse WITH PASSWORD '{db_pass}'; "
            f"GRANT ALL PRIVILEGES ON DATABASE synapse TO synapse;"
        )
        _run([
            "docker", "exec", "postgresql",
            "psql", f"-U", "pgadmin", "-c", sql
        ], timeout=30)

    # -----------------------------------------------------------------------
    # Mattermost
    # -----------------------------------------------------------------------

    def _install_mattermost(self, domain: str) -> bool:
        console.print("[cyan]Installing Mattermost...[/cyan]")
        mm_fqdn  = f"chat.{domain}"
        db_pass  = self._gen_pass()

        if self.sm:
            self.sm.write_env_file("mattermost", {
                "MATTERMOST_DB_PASSWORD": db_pass,
                "MATTERMOST_URL":         f"https://{mm_fqdn}",
            })

        self._create_mattermost_db(db_pass)

        compose = MATTERMOST_COMPOSE.format(
            mm_fqdn=mm_fqdn,
            db_pass=db_pass,
            data_dir=str(self.data_dir),
        )
        compose_path = self.compose_dir / "mattermost-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)
            for subdir in ["config", "data", "logs", "plugins", "client-plugins"]:
                (self.data_dir / "mattermost" / subdir).mkdir(parents=True, exist_ok=True)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"], timeout=300)
        if rc != 0:
            console.print(f"  [red]Mattermost failed: {err}[/red]")
            return False

        if self.cm:
            self.cm.register_service_url("mattermost", f"https://{mm_fqdn}",
                                         "Mattermost — create admin on first visit")
        console.print(f"  [green]Mattermost → https://{mm_fqdn} ✓[/green]")
        return True

    def _create_mattermost_db(self, db_pass: str):
        if DRY_RUN:
            return
        pg_pass_file = self.secrets_dir / ".postgres_pass"
        if not pg_pass_file.exists():
            return
        sql = (
            f"CREATE DATABASE mattermost; "
            f"CREATE USER mattermost WITH PASSWORD '{db_pass}'; "
            f"GRANT ALL PRIVILEGES ON DATABASE mattermost TO mattermost;"
        )
        _run(["docker", "exec", "postgresql", "psql", "-U", "pgadmin", "-c", sql], timeout=30)

    # -----------------------------------------------------------------------
    # Mumble
    # -----------------------------------------------------------------------

    def _install_mumble(self, hostname: str) -> bool:
        console.print("[cyan]Installing Mumble...[/cyan]")
        superuser_pass = self._gen_pass(16)

        if self.sm:
            self.sm.write_env_file("mumble", {"MUMBLE_SUPERUSER_PASSWORD": superuser_pass})

        compose = MUMBLE_COMPOSE.format(
            hostname=hostname,
            superuser_pass=superuser_pass,
            data_dir=str(self.data_dir),
        )
        compose_path = self.compose_dir / "mumble-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"  [red]Mumble failed: {err}[/red]")
            return False

        _run(["ufw", "allow", "64738/tcp"])
        _run(["ufw", "allow", "64738/udp"])

        if self.cm:
            self.cm.register_port(64738, "mumble", "both", external=True)
            self.cm.register_service_url("mumble", f"<server-ip>:64738",
                                         f"Mumble — superuser pass in secrets/.env.mumble")
        console.print(f"  [green]Mumble server on port 64738 ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _gen_pass(self, n: int = 32) -> str:
        return (self.sm.generate_password(n, exclude_special=True)
                if self.sm else os.urandom(n // 2).hex())

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
        return CommsInstaller(self.suite_dir, self.cm, self.sm).install(config)
