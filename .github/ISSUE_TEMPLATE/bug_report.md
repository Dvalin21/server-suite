---
name: Bug Report
about: Report a reproducible bug or unexpected behaviour
title: "[BUG] "
labels: bug
assignees: ''
---

## Describe the Bug
A clear and concise description of what the bug is.

## To Reproduce
Steps to reproduce:
1. Run `sudo server-suite`
2. Select role: `...`
3. Enter config: `...`
4. Error occurs at: `...`

## Expected Behaviour
What you expected to happen.

## Actual Behaviour
What actually happened. Paste the error output here:

```
paste error output here
```

## Environment
- **OS**: (e.g. Ubuntu 24.04 LTS)
- **Server Suite version**: (run `server-suite --version`)
- **Role(s) being installed**: (e.g. identity/freeipa, web/npm)
- **RAM**: (e.g. 8 GB)
- **Bare metal / VM / LXC**: 
- **Install method**: `.deb` / `install.sh` / git clone

## Relevant Log Output
```
# Paste from /var/log/server-suite/ or the role-specific log
```

## Additional Context
Any other context — network setup, existing services, previous install attempts.
