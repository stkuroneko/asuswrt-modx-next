#!/bin/sh

. /sbin/config.sh
. /sbin/global.sh

/bin/netsnmp -c /etc_ro/snmpd.conf
