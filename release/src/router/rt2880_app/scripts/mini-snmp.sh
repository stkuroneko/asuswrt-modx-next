#!/bin/sh

. /sbin/config.sh
. /sbin/global.sh

/bin/snmpd -h localhost -c public &
