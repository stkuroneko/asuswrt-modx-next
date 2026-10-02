#!/bin/sh

LOCK_FILE=/var/lock/LOCK.3G

if [ -f "$LOCK_FILE" ]; then
	exit 0
else
	if [ ! -f "/var/lock" ]; then
		mkdir -p /var/lock/
	fi
	touch "$LOCK_FILE"
fi

if [ "$1" != "" ]; then
        dev=$1
else
        dev=`nvram_get 2860 wan_3g_dev`
fi

killall -q pppd
hso_connect.sh down
sleep 8
#change 3G dongle state to modem
if [ "$dev" = "MU-Q101" ]; then
        usb_modeswitch -c /etc_ro/usb/usb_modeswitch_MU-Q101.conf
elif [ "$dev" = "HUAWEI-E169" ]; then
        usb_modeswitch -c /etc_ro/usb/usb_modeswitch_HUAWEI-E169.conf
elif [ "$dev" = "BandLuxe-C270" ]; then
	sdparm --command=eject /dev/sr0
	sdparm --command=eject /dev/sg0
elif [ "$dev" = "OPTION-ICON225" ]; then
	usb_modeswitch -c /etc_ro/usb/usb_modeswitch_OPTION-ICON225.conf
elif [ "$dev" = "DATANG-M5731" ]; then
	usb_modeswitch -c /etc_ro/usb/usb_modeswitch_DATANG-M5731.conf
#else
        #other supported devcies
fi

#wait for state change
sleep 5

if [ "$dev" != "OPTION-ICON225" ]; then
	rmmod option
	rmmod hso
	sleep 1
	insmod option
	sleep 1
elif [ "$dev" = "OPTION-ICON225" ]; then
	rmmod option
	rmmod hso
	sleep 1
	insmod hso
	sleep 1
fi

#create ppp call script for 3G connection
if [ "$dev" = "MU-Q101" ]; then
        modem_f=ttyUSB0
elif [ "$dev" = "HUAWEI-E169" ]; then
        modem_f=ttyUSB0
elif [ "$dev" = "BandLuxe-C270" ]; then
        modem_f=ttyUSB0
elif [ "$dev" = "DATANG-M5731" ]; then
        modem_f=ttyUSB0
else
        #other supported devcies
        modem_f=ttyUSB0
fi

user=`nvram_get 2860 wan_3g_user`
pass=`nvram_get 2860 wan_3g_pass`
apn=`nvram_get 2860 wan_3g_apn`
pin=`nvram_get 2860 wan_3g_pin`
if [ "$dev" != "OPTION-ICON225" ]; then
	config-3g-ppp.sh -p $pass -u $user -m $modem_f -c Generic_conn.scr -d Generic_disconn.scr
	pppd call 3g
elif [ "$dev" = "OPTION-ICON225" ]; then
	if [ "$apn" != "" ]; then	
		echo "APN=$apn" > /etc/conninfo.ini
	else	
		echo "APN=internet" > /etc/conninfo.ini
	fi
	if [ "$pin" != "" ]; then	
		echo "PIN=$pin" >> /etc/conninfo.ini
	fi
	echo "USER=$user"  >> /etc/conninfo.ini
	echo "PASS=$pass"  >> /etc/conninfo.ini
	hso_connect.sh up
fi

rm -f $LOCK_FILE
exit 0
