#!/usr/bin/env bash
# /usr/bin/server-suite  — installed by postinst as a symlink target
SUITE_DIR="/usr/lib/server-suite"
DEFAULTS="/etc/server-suite/defaults.conf"
[ -f "$DEFAULTS" ] && source "$DEFAULTS" 2>/dev/null || true
if [ "$EUID" -ne 0 ]; then
    echo "server-suite must be run as root.  Try: sudo server-suite"
    exit 1
fi
export PYTHONPATH="$SUITE_DIR:${PYTHONPATH:-}"
export DRY_RUN="${DRY_RUN:-0}"
exec python3 "$SUITE_DIR/server_suite.py" "$@"
