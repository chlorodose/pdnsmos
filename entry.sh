#!/bin/sh
export LUA_PATH="/app/lua/?.lua"
exec dnsdist --supervised --disable-syslog --verbose --config /data/config.lua
