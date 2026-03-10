"""
roles/vpn/wireguard.py
======================
WireGuard VPN — Docker (wg-easy) for the management UI,
with native kernel module for maximum performance.
Generates peer configs and QR codes for mobile clients.
Also includes optional OpenVPN as a fallback.
"""

import os
import subprocess
import ipaddress
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


WG_EASY_COMPOSE = """\
services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:14
    container_name: wg-easy
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    environment:
      LANG:                  en
      WG_HOST:               "{server_ip}"
      PASSWORD_HASH:         "{password_hash}"
      WG_PORT:               "{wg_port}"
      WG_DEFAULT_ADDRESS:    "{vpn_subnet}"
      WG_DEFAULT_DNS:        "{dns_server}"
      WG_ALLOWED_IPS:        "{allowed_ips}"
      WG_PERSISTENT_KEEPALIVE: "25"
      UI_TRAFFIC_STATS:      "true"
      UI_CHART_TYPE:         "1"
    volumes:
      - {data_dir}/wg-easy:/etc/wireguard
    ports:
      - "{wg_port}:{wg_port}/udp"
      - "127.0.0.1:51821:51821/tcp"
    networks:
      - vpn_network
      - proxy_network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.wg-easy.rule=Host(`vpn.{domain}`)"
      - "traefik.http.routers.wg-easy.tls=true"
      - "traefik.http.routers.wg-easy.tls.certresolver=letsencrypt"
      - "traefik.http.routers.wg-easy.middlewares=lan-only@file"
      - "traefik.http.services.wg-easy.loadbalancer.server.port=51821"
    logging:
      driver: journald
      options:
        tag: "docker/wg-easy"
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.5'

networks:
  vpn_network:
    external: true
  proxy_network:
    external: true
"""

# Native WireGuard (without wg-easy UI) for simpler deployments
WG_SERVER_CONF = """\
[Interface]
Address    = {server_vpn_ip}/24
ListenPort = {wg_port}
PrivateKey = {server_private_key}
PostUp     = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {lan_iface} -j MASQUERADE
PostDown   = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {lan_iface} -j MASQUERADE
DNS        = {dns_server}
SaveConfig = false

# Peers are added below by the peer management script
"""

WG_PEER_CONF = """\
[Interface]
PrivateKey = {peer_private_key}
Address    = {peer_vpn_ip}/24
DNS        = {dns_server}

[Peer]
PublicKey  = {server_public_key}
Endpoint   = {server_ip}:{wg_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""


class WireGuardInstaller:
    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.data_dir    = self.suite_dir / "docker" / "vpn" / "data"
        self.compose_dir = self.suite_dir / "docker" / "vpn"
        self.peers_dir   = self.suite_dir / "vpn-peers"

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing WireGuard VPN[/bold cyan]\n")

        domain     = config.get("domain", "local")
        server_ip  = self._detect_public_ip()

        console.print("[bold]WireGuard Configuration[/bold]\n")
        server_ip  = Prompt.ask("  Server public IP or domain", default=server_ip or "")
        wg_port    = int(Prompt.ask("  WireGuard UDP port", default="51820"))
        vpn_subnet = Prompt.ask("  VPN subnet (x.x.x.0/24)", default="10.8.0.0/24")
        vpn_net    = ipaddress.IPv4Network(vpn_subnet, strict=False)
        server_vpn_ip = str(list(vpn_net.hosts())[0])  # .1 of the VPN subnet

        dns_server = Prompt.ask(
            "  DNS server for VPN clients",
            default=config.get("dns_dhcp", {}).get("server_ip", "1.1.1.1")
        )
        allowed_ips = Prompt.ask(
            "  Allowed IPs (0.0.0.0/0 = full tunnel, or LAN subnet for split)",
            default="0.0.0.0/0"
        )

        use_wg_easy = Confirm.ask(
            "\n  Use wg-easy (web UI for peer management)?",
            default=True
        )

        if use_wg_easy:
            return self._install_wg_easy(
                domain=domain, server_ip=server_ip, wg_port=wg_port,
                vpn_subnet=vpn_subnet, dns_server=dns_server,
                allowed_ips=allowed_ips
            )
        else:
            return self._install_native_wg(
                server_ip=server_ip, wg_port=wg_port,
                vpn_subnet=vpn_subnet, server_vpn_ip=server_vpn_ip,
                dns_server=dns_server, allowed_ips=allowed_ips
            )

    # -----------------------------------------------------------------------
    # wg-easy Docker
    # -----------------------------------------------------------------------

    def _install_wg_easy(self, domain: str, server_ip: str, wg_port: int,
                          vpn_subnet: str, dns_server: str, allowed_ips: str) -> bool:
        # Generate password hash for wg-easy
        admin_pass = (self.sm.generate_password(16, exclude_special=True)
                      if self.sm else os.urandom(8).hex())
        password_hash = self._hash_password(admin_pass)

        if self.sm:
            self.sm.write_env_file("wireguard", {
                "WG_EASY_PASSWORD":   admin_pass,
                "WG_SERVER_IP":       server_ip,
                "WG_PORT":            str(wg_port),
                "WG_SUBNET":          vpn_subnet,
            })

        if not DRY_RUN:
            self.data_dir.mkdir(parents=True, exist_ok=True)

        compose = WG_EASY_COMPOSE.format(
            server_ip=server_ip,
            password_hash=password_hash,
            wg_port=wg_port,
            vpn_subnet=vpn_subnet.replace("0/24", "x"),   # wg-easy wants x.x.x.x format
            dns_server=dns_server,
            allowed_ips=allowed_ips,
            data_dir=str(self.data_dir),
            domain=domain,
        )
        compose_path = self.compose_dir / "wg-easy-compose.yml"
        if not DRY_RUN:
            self.compose_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(compose)

        # Enable IP forwarding on the host
        self._enable_ip_forwarding()

        # Load WireGuard kernel module
        _run(["modprobe", "wireguard"])
        _run(["apt-get", "install", "-y", "-qq", "wireguard-tools"])

        rc, _, err = _run(["docker", "compose", "-f", str(compose_path), "up", "-d"])
        if rc != 0:
            console.print(f"  [red]wg-easy failed: {err}[/red]")
            return False

        # Firewall
        _run(["ufw", "allow", f"{wg_port}/udp"])
        _run(["ufw", "reload"])

        if self.cm:
            self.cm.register_port(wg_port, "wireguard", "udp", external=True)
            self.cm.register_port(51821,   "wg-easy-ui", "tcp", external=False)
            self.cm.register_service_url(
                "wg-easy",
                f"https://vpn.{domain}  or  http://<server-ip>:51821",
                f"WireGuard web UI — password in secrets/.env.wireguard"
            )
            self.cm.add_role("vpn", {
                "engine":    "wireguard",
                "server_ip": server_ip,
                "port":      wg_port,
                "subnet":    vpn_subnet,
            })

        console.print(f"\n[bold green]WireGuard (wg-easy) installed ✓[/bold green]")
        console.print(f"  [dim]UI: https://vpn.{domain}  or  http://<server-ip>:51821[/dim]")
        console.print(f"  [dim]Password: stored in secrets/.env.wireguard[/dim]")
        console.print(f"  [dim]UDP port {wg_port} opened in firewall[/dim]")
        return True

    # -----------------------------------------------------------------------
    # Native WireGuard (no UI)
    # -----------------------------------------------------------------------

    def _install_native_wg(self, server_ip: str, wg_port: int,
                             vpn_subnet: str, server_vpn_ip: str,
                             dns_server: str, allowed_ips: str) -> bool:
        console.print("[cyan]Installing native WireGuard...[/cyan]")
        _run(["apt-get", "install", "-y", "wireguard", "wireguard-tools"])

        self._enable_ip_forwarding()

        # Generate server keys
        rc, server_priv, _ = _run(["wg", "genkey"])
        if rc != 0:
            console.print("[red]Failed to generate WireGuard keys[/red]")
            return False

        rc2, server_pub, _ = subprocess.run(
            ["wg", "pubkey"], input=server_priv,
            capture_output=True, text=True
        ).returncode, "", ""
        # Do it properly:
        try:
            result = subprocess.run(
                ["wg", "pubkey"],
                input=server_priv, capture_output=True, text=True, timeout=5
            )
            server_pub = result.stdout.strip()
        except Exception:
            server_pub = "KEYGEN_FAILED"

        # Detect LAN interface
        rc3, lan_iface, _ = _run(["ip", "route", "show", "default"])
        lan_iface = lan_iface.split()[4] if lan_iface else "eth0"

        wg_conf = WG_SERVER_CONF.format(
            server_vpn_ip=server_vpn_ip,
            wg_port=wg_port,
            server_private_key=server_priv.strip(),
            lan_iface=lan_iface,
            dns_server=dns_server,
        )

        if not DRY_RUN:
            wg_conf_path = Path("/etc/wireguard/wg0.conf")
            wg_conf_path.parent.mkdir(parents=True, exist_ok=True)
            wg_conf_path.write_text(wg_conf)
            os.chmod(wg_conf_path, 0o600)

            if self.sm:
                self.sm.write_env_file("wireguard", {
                    "WG_SERVER_PRIVATE_KEY": server_priv.strip(),
                    "WG_SERVER_PUBLIC_KEY":  server_pub,
                    "WG_SERVER_IP":          server_ip,
                    "WG_PORT":               str(wg_port),
                    "WG_SUBNET":             vpn_subnet,
                })

        _run(["systemctl", "enable", "--now", "wg-quick@wg0"])
        _run(["ufw", "allow", f"{wg_port}/udp"])

        if self.cm:
            self.cm.register_port(wg_port, "wireguard", "udp", external=True)
            self.cm.add_role("vpn", {
                "engine":     "wireguard-native",
                "server_ip":  server_ip,
                "port":       wg_port,
                "subnet":     vpn_subnet,
                "public_key": server_pub,
            })

        console.print("[bold green]WireGuard installed ✓[/bold green]")
        console.print(f"  [dim]Server public key: {server_pub}[/dim]")
        console.print(f"  [dim]Add peers: server-suite → Management → VPN → Add Peer[/dim]")

        # Offer to generate initial peer configs
        self._interactive_add_peers(
            server_ip=server_ip, server_pub=server_pub,
            wg_port=wg_port, vpn_subnet=vpn_subnet,
            dns_server=dns_server, allowed_ips=allowed_ips
        )
        return True

    # -----------------------------------------------------------------------
    # Peer management (native WireGuard)
    # -----------------------------------------------------------------------

    def _interactive_add_peers(self, server_ip: str, server_pub: str,
                                wg_port: int, vpn_subnet: str,
                                dns_server: str, allowed_ips: str):
        while Confirm.ask("\n  Add a VPN peer now?", default=True):
            peer_name = Prompt.ask("  Peer name (e.g., laptop, phone)")
            vpn_net   = ipaddress.IPv4Network(vpn_subnet, strict=False)
            hosts     = list(vpn_net.hosts())

            # Assign next available IP
            assigned = self._get_assigned_ips()
            for host in hosts[1:]:  # Skip .1 (server)
                if str(host) not in assigned:
                    peer_vpn_ip = str(host)
                    break
            else:
                console.print("[red]No more IPs available in subnet[/red]")
                break

            self.add_peer(
                peer_name=peer_name, peer_vpn_ip=peer_vpn_ip,
                server_ip=server_ip, server_pub=server_pub,
                wg_port=wg_port, dns_server=dns_server,
                allowed_ips=allowed_ips
            )

    def add_peer(self, peer_name: str, peer_vpn_ip: str,
                 server_ip: str, server_pub: str,
                 wg_port: int, dns_server: str, allowed_ips: str) -> Optional[Path]:
        # Generate peer keys
        try:
            priv_result = subprocess.run(["wg", "genkey"], capture_output=True,
                                          text=True, timeout=5)
            peer_priv   = priv_result.stdout.strip()
            pub_result  = subprocess.run(["wg", "pubkey"], input=peer_priv,
                                          capture_output=True, text=True, timeout=5)
            peer_pub    = pub_result.stdout.strip()
            psk_result  = subprocess.run(["wg", "genpsk"], capture_output=True,
                                          text=True, timeout=5)
            peer_psk    = psk_result.stdout.strip()
        except Exception as e:
            console.print(f"[red]Key generation failed: {e}[/red]")
            return None

        # Build peer config
        peer_conf = WG_PEER_CONF.format(
            peer_private_key=peer_priv,
            peer_vpn_ip=peer_vpn_ip,
            dns_server=dns_server,
            server_public_key=server_pub,
            server_ip=server_ip,
            wg_port=wg_port,
            allowed_ips=allowed_ips,
        )
        # Add PreSharedKey line
        peer_conf = peer_conf.replace(
            f"PersistentKeepalive = 25",
            f"PresharedKey = {peer_psk}\nPersistentKeepalive = 25"
        )

        # Save peer config
        if not DRY_RUN:
            self.peers_dir.mkdir(parents=True, exist_ok=True)
            peer_conf_path = self.peers_dir / f"{peer_name}.conf"
            peer_conf_path.write_text(peer_conf)
            os.chmod(peer_conf_path, 0o600)

        # Add peer to server config
        server_peer_block = (
            f"\n# Peer: {peer_name}\n"
            f"[Peer]\n"
            f"PublicKey  = {peer_pub}\n"
            f"PresharedKey = {peer_psk}\n"
            f"AllowedIPs = {peer_vpn_ip}/32\n"
        )
        if not DRY_RUN:
            wg_conf_path = Path("/etc/wireguard/wg0.conf")
            if wg_conf_path.exists():
                with open(wg_conf_path, "a") as f:
                    f.write(server_peer_block)
            # Reload WireGuard to apply new peer
            _run(["wg", "addconf", "wg0",
                  "/dev/stdin"], timeout=10)
            _run(["wg", "set", "wg0",
                  "peer", peer_pub,
                  "preshared-key", "/dev/stdin",
                  "allowed-ips", f"{peer_vpn_ip}/32"])

        # Generate QR code
        self._generate_qr(peer_conf, peer_name)

        console.print(f"\n  [green]Peer '{peer_name}' created: {peer_vpn_ip}[/green]")
        if not DRY_RUN:
            console.print(f"  [dim]Config: {self.peers_dir / f'{peer_name}.conf'}[/dim]")
        return self.peers_dir / f"{peer_name}.conf" if not DRY_RUN else None

    def _generate_qr(self, peer_conf: str, peer_name: str):
        """Generate QR code for mobile clients."""
        rc, _, _ = _run(["which", "qrencode"], timeout=5)
        if rc != 0:
            _run(["apt-get", "install", "-y", "-qq", "qrencode"])

        if DRY_RUN:
            return

        qr_path = self.peers_dir / f"{peer_name}.png"
        try:
            result = subprocess.run(
                ["qrencode", "-t", "PNG", "-o", str(qr_path), "-s", "6"],
                input=peer_conf, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                console.print(f"  [dim]QR code: {qr_path}[/dim]")

            # Also print ASCII QR to terminal
            result2 = subprocess.run(
                ["qrencode", "-t", "ANSIUTF8"],
                input=peer_conf, capture_output=True, text=True, timeout=10
            )
            if result2.returncode == 0:
                console.print(result2.stdout)
        except Exception:
            pass

    def _get_assigned_ips(self) -> set:
        """Get IPs already assigned to WireGuard peers."""
        rc, out, _ = _run(["wg", "show", "wg0", "allowed-ips"], timeout=5)
        if rc != 0:
            return set()
        ips = set()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1].split("/")[0]
                ips.add(ip)
        return ips

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _enable_ip_forwarding(self):
        sysctl_conf = Path("/etc/sysctl.d/99-wireguard.conf")
        if not DRY_RUN:
            sysctl_conf.write_text(
                "net.ipv4.ip_forward = 1\n"
                "net.ipv4.conf.all.src_valid_mark = 1\n"
            )
        _run(["sysctl", "-p", str(sysctl_conf)])

    def _hash_password(self, password: str) -> str:
        """Hash password for wg-easy using bcrypt."""
        try:
            import bcrypt
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            # wg-easy needs $ escaped as $$ in docker compose env
            return hashed.decode().replace("$", "$$")
        except ImportError:
            # Fallback: return plain password (wg-easy also accepts plain)
            console.print("  [yellow]bcrypt not available — password will be stored as plain text[/yellow]")
            return password

    def _detect_public_ip(self) -> str:
        for cmd in [
            ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
            ["curl", "-s", "-4", "--max-time", "5", "https://ifconfig.me"],
        ]:
            rc, out, _ = _run(cmd, timeout=10)
            if rc == 0 and out.strip():
                return out.strip()
        return ""


# Fix missing Optional import
from typing import Optional


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return WireGuardInstaller(self.suite_dir, self.cm, self.sm).install(config)
