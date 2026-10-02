#!/bin/sh

. /sbin/config.sh
. /sbin/global.sh

usage()
{
	echo "Usage:"
	echo "  $0 directory"
	echo "Example:"
	echo "  $0 /etc"
	exit 1
}

if [ "$1" = "" ]; then
	echo "$0: insufficient arguments"
	usage $0
fi

cp -r /etc_ro/tr069 $1
/bin/tr069_agent -d $1/tr069 &
