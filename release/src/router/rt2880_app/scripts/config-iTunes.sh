#!/bin/sh

. /sbin/config.sh
. /sbin/global.sh

usage()
{
	echo "Usage:"
	echo "  $0 <server_name> <passwd> <mp3_dir>"
	echo "Example:"
	echo "  $0 Ralink ralink /media/sda1/mp3"
	exit 1
}

if [ "$3" = "" ]; then
	echo "$0: insufficient arguments"
	usage $0
fi

lan_ip=`nvram_get 2860 lan_ipaddr`
server_name=$1
passwd=$2
mp3_dir=$3

mt-daapd.sh "$server_name" "$passwd" "$mp3_dir" 
mDNSResponder $lan_ip thehost "$server_name" _daap._tcp. 3689 &
mt-daapd 
