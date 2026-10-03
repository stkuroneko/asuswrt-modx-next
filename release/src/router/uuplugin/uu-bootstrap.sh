#!/bin/sh
# Fetch the vendor monitor without blocking the router's service loop.
[ "$(nvram get uu_enable)" = 1 ] || exit 0
[ "$(nvram get sw_mode)" = 1 ] || exit 0
mkdir -p /tmp/uu || exit 1
cd /tmp/uu || exit 1
fail() { logger -t uuplugin "$1"; exit 1; }
curl -fLsS --connect-timeout 15 --max-time 60 'https://router.uu.163.com/api/script/monitor?type=asuswrt-merlin' -o metadata || fail 'Monitor metadata download failed'
url=$(sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p' metadata)
md5=$(sed -n 's/.*"md5"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' metadata)
case "$url" in
    http://uurouter.gdl.netease.com/*) url="https://${url#http://}" ;;
    https://uurouter.gdl.netease.com/*) ;;
    *) fail 'Invalid monitor URL' ;;
esac
[ "${#md5}" = 32 ] || fail 'Invalid monitor checksum'
curl -fLsS --connect-timeout 15 --max-time 60 "$url" -o uuplugin_monitor.sh || fail 'Monitor download failed'
printf '%s  %s\n' "$md5" uuplugin_monitor.sh | md5sum -c - || fail 'Monitor checksum mismatch'
printf 'router=asuswrt-merlin\nmodel=\n' > uuplugin_monitor.config
chmod 755 uuplugin_monitor.sh
[ "$(nvram get uu_enable)" = 1 ] || exit 0
logger -t uuplugin 'Starting UU monitor'
exec ./uuplugin_monitor.sh
