# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x (latest) | ✅ Yes |
| < 1.0 | ❌ No |

## Reporting a Vulnerability

**Do not open a public GitHub/Forgejo issue for security vulnerabilities.**

If you discover a security issue — whether in Server Suite's own code or in how it configures a third-party service — please report it privately:

1. **GitHub**: Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) (Security → Advisories → Report a vulnerability)
2. **Forgejo / email**: Send details to the maintainer's email listed in the repository profile, with subject line `[SECURITY] server-suite - <brief description>`

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional but appreciated)

You will receive an acknowledgement within **48 hours** and a status update within **7 days**.

## What Qualifies

- Secrets or credentials exposed in logs, config files, or version control
- Privilege escalation via Server Suite's install/management scripts
- Docker escape or container breakout via Server Suite's networking config
- Insecure defaults that meaningfully weaken system security
- Remote code execution in the setup wizard (Flask app on port 7070)

## Out of Scope

- Vulnerabilities in third-party packages (Mailcow, FreeIPA, Samba, etc.) — report those upstream
- Theoretical issues without a practical exploit path
- Issues requiring physical access to the server

## Security Design Principles

Server Suite is designed with these principles that reviewers should be aware of:

- The setup wizard (port 7070) is only opened on LAN-facing interfaces via UFW, and is closed immediately after setup completes
- All Docker containers bind only to `127.0.0.1`; no direct external exposure
- Secrets are Fernet-encrypted at rest; plaintext `.env` files are `chmod 600` and audited by auditd
- SSH hardening, Fail2Ban, AppArmor, and auditd are installed on every server regardless of role selection
- No credentials are ever written to `docker-compose.yml` files
