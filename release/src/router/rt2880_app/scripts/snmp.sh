#!/bin/sh

ipaddr=`nvram_get 2860 lan_ipaddr`

usage()
{
	echo "Usage:"
	echo "  $0 community_name"
	echo "Example:"
	echo "  $0 public"
	exit 1
}

if [ "$1" = "" ]; then
	echo "$0: insufficient arguments"
	usage $0
fi

snmpd -h $ipaddr -c $1&
