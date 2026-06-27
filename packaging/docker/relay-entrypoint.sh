#!/bin/sh
set -eu

port="${PORT:-8787}"

case "$port" in
  ''|*[!0-9]*)
    echo "CONU_RELAY_STARTUP_ERROR invalid PORT" >&2
    exit 64
    ;;
esac

exec conu-relay --serve "0.0.0.0:${port}"
