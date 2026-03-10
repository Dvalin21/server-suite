"""
roles/dns_dhcp/technitium.py
============================
Technitium DNS Server — Docker-based, full DNS + DHCP with web UI.
Recommended choice: easier than BIND9, supports DHCP, DNSSEC,
split-horizon, blocklists, and has an excellent REST API.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
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


COMPOSE_TEMPLATE = """\
services:
  technitium-dns:
    image: technitium/dns-server:13.2
    container_name: technitium-dns
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    hostname: {hostname}
    ports:
      # DNS — bind to LAN interface, not 0.0.0.0, in production
      - "53:53/tcp"
      - "53:53/udp"
      # DNS-over-TLS
      - "853:853/tcp"
      # DNS-over-HTTPS (handled via proxy)
      # Web UI — LAN only
      - "127.0.0.1:5380:5380/tcp"
    environment:
      - DNS_SERVER_DOMAIN={fqdn}
      - DNS_SERVER_ADMIN_PASSWORD_FILE=/run/secrets/technitium_admin
      - DNS_SERVER_PREFER_IPV6=false
      - DNS_SERVER_OPTIONAL_PROTOCOL_DNS_OVER_HTTP=true
      - DNS_SERVER_RECURSIVE_RESOLVER_TIMEOUT=5000
      - DNS_SERVER_MAX_STACK_COUNT=10
      - DNS_SERVER_LOG_QUERIES=false
    volumes:
      - {data_dir}:/etc/dns
    secrets:
      - technitium_admin
    networks:
      - proxy_network
    logging:
      driver: journald
      options:
        tag: "docker/technitium-dns"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

secrets:
  technitium_admin:
    file: {secrets_dir}/.technitium_admin_pass

networks:
  proxy_network:
    external: true
"""


class TechnitiumInstaller:
    """Installs and configures Technitium DNS Server."""

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.data_dir    = self.suite_dir / "docker" / "technitium-dns" / "data"
        self.compose_dir = self.suite_dir / "docker" / "technitium-dns"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Technitium DNS Server[/bold cyan]\n")

        domain   = config.get("domain", "local")
        hostname = config.get("hostname", "ns1")
        fqdn     = f"{hostname}.{domain}"

        # Collect network config
        console.print("[bold]DNS/DHCP Network Configuration[/bold]\n")
        lan_subnet    = Prompt.ask("  LAN subnet (CIDR)",              default="192.168.1.0/24")
        lan_gateway   = Prompt.ask("  Gateway/router IP",              default="192.168.1.1")
        server_ip     = Prompt.ask("  This server's LAN IP",           default="192.168.1.10")
        dhcp_start    = Prompt.ask("  DHCP range start",               default="192.168.1.100")
        dhcp_end      = Prompt.ask("  DHCP range end",                 default="192.168.1.200")
        dhcp_lease    = Prompt.ask("  DHCP lease time (hours)",        default="24")
        upstream_dns  = Prompt.ask("  Upstream DNS resolvers",         default="1.1.1.1,8.8.8.8")

        # Disable systemd-resolved stub listener (it occupies port 53)
        self._disable_resolved_stub(server_ip)

        # Generate admin password
        admin_pass = (self.sm.generate_password(20, exclude_special=True)
                      if self.sm else os.urandom(16).hex())

        # Write password secret file
        if not DRY_RUN:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            secrets_dir = self.suite_dir / "secrets"
            secrets_dir.mkdir(parents=True, exist_ok=True)
            secret_file = secrets_dir / ".technitium_admin_pass"
            secret_file.write_text(admin_pass)
            os.chmod(secret_file, 0o600)

        if self.sm:
            self.sm.write_env_file("technitium", {
                "TECHNITIUM_ADMIN_PASSWORD": admin_pass,
                "TECHNITIUM_DOMAIN":         domain,
                "TECHNITIUM_FQDN":           fqdn,
            })

        # Write compose file
        compose_content = COMPOSE_TEMPLATE.format(
            hostname=hostname,
            fqdn=fqdn,
            data_dir=str(self.data_dir),
            secrets_dir=str(self.suite_dir / "secrets"),
        )
        compose_path = self.compose_dir / "docker-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose_content)

        # Start container
        console.print("\n[cyan]Starting Technitium DNS...[/cyan]")
        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"[red]Failed to start Technitium: {err}[/red]")
            return False

        # Wait for API availability
        self._wait_for_api(server_ip)

        # Configure via REST API
        self._configure_via_api(
            server_ip=server_ip,
            domain=domain,
            fqdn=fqdn,
            lan_subnet=lan_subnet,
            lan_gateway=lan_gateway,
            dhcp_start=dhcp_start,
            dhcp_end=dhcp_end,
            dhcp_lease_hours=int(dhcp_lease),
            upstream_dns=upstream_dns.split(","),
            admin_pass=admin_pass,
        )

        # Firewall rules
        self._configure_firewall()

        # Register
        if self.cm:
            self.cm.register_port(53,   "technitium-dns",   "both", external=False)
            self.cm.register_port(853,  "technitium-dot",   "tcp",  external=False)
            self.cm.register_port(5380, "technitium-admin", "tcp",  external=False)
            self.cm.register_service_url(
                "technitium-dns",
                f"http://{server_ip}:5380",
                f"Technitium DNS admin — password in secrets/.env.technitium"
            )
            self.cm.add_role("dns_dhcp", {
                "engine":      "technitium",
                "domain":      domain,
                "server_ip":   server_ip,
                "lan_subnet":  lan_subnet,
                "compose_file": str(compose_path),
            })

        console.print("[bold green]Technitium DNS installed ✓[/bold green]")
        self._print_summary(server_ip, domain, admin_pass)
        return True

    # -----------------------------------------------------------------------
    # systemd-resolved stub listener
    # -----------------------------------------------------------------------

    def _disable_resolved_stub(self, server_ip: str):
        """
        Disable systemd-resolved's stub listener on port 53
        so Technitium can bind to it instead. Keep resolved running
        for DNS resolution on the host itself.
        """
        console.print("[cyan]Configuring systemd-resolved...[/cyan]")

        resolved_conf = Path("/etc/systemd/resolved.conf.d/server-suite.conf")
        if not DRY_RUN:
            resolved_conf.parent.mkdir(parents=True, exist_ok=True)
            resolved_conf.write_text(
                "[Resolve]\n"
                "DNSStubListener=no\n"
                f"DNS={server_ip}\n"
                "FallbackDNS=1.1.1.1 8.8.8.8\n"
            )

        _run(["systemctl", "restart", "systemd-resolved"])

        # Point /etc/resolv.conf at Technitium
        resolv_path = Path("/etc/resolv.conf")
        if not DRY_RUN:
            if resolv_path.is_symlink():
                resolv_path.unlink()
            resolv_path.write_text(
                f"# Managed by server-suite\n"
                f"nameserver {server_ip}\n"
                f"nameserver 1.1.1.1\n"
                f"search local\n"
            )
        console.print("  [dim]systemd-resolved stub disabled ✓[/dim]")

    # -----------------------------------------------------------------------
    # Wait for API
    # -----------------------------------------------------------------------

    def _wait_for_api(self, server_ip: str, timeout: int = 60):
        console.print("[dim]Waiting for Technitium API...[/dim]")
        if DRY_RUN:
            return
        for _ in range(timeout // 3):
            time.sleep(3)
            rc, _, _ = _run(["curl", "-sf", f"http://{server_ip}:5380/api/user/login"], timeout=5)
            if rc == 0:
                console.print("  [dim]API ready ✓[/dim]")
                return
        console.print("  [yellow]API not responding — will need manual configuration[/yellow]")

    # -----------------------------------------------------------------------
    # REST API configuration
    # -----------------------------------------------------------------------

    def _configure_via_api(self, server_ip: str, domain: str, fqdn: str,
                            lan_subnet: str, lan_gateway: str,
                            dhcp_start: str, dhcp_end: str,
                            dhcp_lease_hours: int,
                            upstream_dns: list,
                            admin_pass: str):
        """Configure Technitium via its REST API."""
        import json
        import urllib.request
        import urllib.parse

        base_url = f"http://{server_ip}:5380/api"
        if DRY_RUN:
            console.print("  [dim][DRY RUN] Would configure Technitium via API[/dim]")
            return

        def api_post(endpoint: str, params: dict) -> Optional[dict]:
            url  = f"{base_url}/{endpoint}"
            data = urllib.parse.urlencode(params).encode()
            try:
                req = urllib.request.Request(url, data=data, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return json.loads(resp.read())
            except Exception as e:
                console.print(f"  [yellow]API call failed ({endpoint}): {e}[/yellow]")
                return None

        # Get session token
        resp = api_post("user/login", {
            "user":     "admin",
            "pass":     admin_pass,
            "includeInfo": "false",
        })
        token = resp.get("token") if resp else None
        if not token:
            console.print("  [yellow]Could not authenticate to Technitium API — configure manually[/yellow]")
            return

        # Set upstream resolvers
        api_post("settings/set", {
            "token":            token,
            "dnsServerDomain":  fqdn,
            "dnsServerLocalAddresses": server_ip,
            "defaultRecordTtl": "3600",
        })

        # Add forwarders (upstream DNS)
        for ns in upstream_dns:
            api_post("settings/addForwarder", {
                "token":       token,
                "forwarder":   ns.strip(),
                "proxyType":   "None",
            })

        # Create local zone
        api_post("zones/create", {
            "token":    token,
            "zone":     domain,
            "type":     "Primary",
        })

        # Create reverse zone
        import ipaddress
        try:
            net = ipaddress.IPv4Network(lan_subnet, strict=False)
            octets = str(net.network_address).split(".")
            reverse_zone = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
            api_post("zones/create", {
                "token": token,
                "zone":  reverse_zone,
                "type":  "Primary",
            })
        except ValueError:
            pass

        # Add A record for this server
        api_post("zones/records/add", {
            "token":  token,
            "domain": fqdn,
            "zone":   domain,
            "type":   "A",
            "ttl":    "3600",
            "ipAddress": server_ip,
        })

        # Configure DHCP scope
        api_post("dhcp/scopes/addOrUpdate", {
            "token":          token,
            "name":           "LAN",
            "startingAddress": dhcp_start,
            "endingAddress":   dhcp_end,
            "subnetMask":     str(ipaddress.IPv4Network(lan_subnet, strict=False).netmask),
            "leaseTimeDays":  "0",
            "leaseTimeHours": str(dhcp_lease_hours),
            "leaseTimeMinutes": "0",
            "domainName":     domain,
            "dnsList":        server_ip,
            "routerAddress":  lan_gateway,
        })

        # Enable blocklist (Pi-hole style ad blocking) — optional
        api_post("settings/set", {
            "token":                     token,
            "blockingEnabled":           "true",
            "blockingType":              "NxDomain",
        })

        console.print("  [dim]Technitium configured via API ✓[/dim]")

    # -----------------------------------------------------------------------
    # Firewall
    # -----------------------------------------------------------------------

    def _configure_firewall(self):
        _run(["ufw", "allow", "in", "on", "lo",   "to", "any", "port", "53"])
        _run(["ufw", "allow", "53/udp"])
        _run(["ufw", "allow", "53/tcp"])
        _run(["ufw", "allow", "853/tcp"])
        _run(["ufw", "reload"])

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _print_summary(self, server_ip: str, domain: str, admin_pass: str):
        console.print()
        console.print(Panel(
            f"[bold]Technitium DNS is running[/bold]\n\n"
            f"  Web UI:       [cyan]http://{server_ip}:5380[/cyan]\n"
            f"  DNS Server:   [cyan]{server_ip}:53[/cyan]\n"
            f"  Admin pass:   [cyan]stored in secrets/.env.technitium[/cyan]\n\n"
            f"  [bold]Next steps:[/bold]\n"
            f"  1. Point your router's DHCP to give out [cyan]{server_ip}[/cyan] as DNS\n"
            f"  2. Or set static DNS on each client to [cyan]{server_ip}[/cyan]\n"
            f"  3. Add blocklists in the UI (Blocklist → Add Blocklist)\n"
            f"  4. The local domain [cyan]{domain}[/cyan] is configured for split-horizon DNS",
            border_style="cyan"
        ))


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return TechnitiumInstaller(self.suite_dir, self.cm, self.sm).install(config)
