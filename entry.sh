#!/bin/sh
set -euo pipefail
mkdir -p /run/nftsetd
NFTSETD_SOCK_PATH=/run/nftsetd/nftsetd.sock /app/nftsetd &
export LUA_PATH="/app/lua/?.lua"
exec dnsdist --disable-syslog --config /data/config.lua "$@"
