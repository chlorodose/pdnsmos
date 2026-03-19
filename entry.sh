#!/bin/sh
NFTSETD_SOCK_PATH=/run/nftsetd.sock /app/nftsetd &
export LUA_PATH="/app/lua/?.lua"
exec dnsdist --disable-syslog --verbose --config /data/config.lua
