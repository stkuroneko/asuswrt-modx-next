#!/bin/sh

PPP_3G_FILE=/etc_ro/ppp/peers/3g

usage () {
  echo "usage: config-3g-ppp.sh [option]..."
  echo "options:"
  echo "  -h              : print this help"
  echo "  -p password     : set password"
  echo "  -u username     : set username"
  echo "  -b baud         : Set baudrate"
  echo "  -m dev 	  : set modem device"
  echo "  -c conn         : set connect AT script"
  echo "  -d disconn	  : set disconnect AT script"
  exit
}


for arg in $*
  do
    if [ "$1" != "" ] 
    then
      case "$1" in
        "-p")
          PASSWORD="password $2" 
    	  shift ;;
        "-u")
          USERNAME="user $2" 
    	  shift ;;
        "-b")
          BAUD="$2"
	  shift ;;
        "-m")
          MODEM="/dev/$2" 
	  shift ;;
        "-c")
          CONN="$2" 
	  shift ;;
        "-d")
          DISCONN="$2" 
	  shift ;;
        "-h")
	  usage ;;
        *) 
	  echo "illegal option -- $2" 
	  usage ;;
      esac
      shift
  fi
  done



echo $MODEM > $PPP_3G_FILE
echo $BAUD >> $PPP_3G_FILE
echo $USERNAME >> $PPP_3G_FILE
echo $PASSWORD >> $PPP_3G_FILE
echo "modem" >> $PPP_3G_FILE
echo "crtscts" >> $PPP_3G_FILE
echo "noauth" >> $PPP_3G_FILE
echo "defaultroute" >> $PPP_3G_FILE
echo "noipdefault" >> $PPP_3G_FILE
echo "nopcomp" >> $PPP_3G_FILE
echo "noaccomp" >> $PPP_3G_FILE
echo "novj" >> $PPP_3G_FILE
echo "nobsdcomp" >> $PPP_3G_FILE
echo "usepeerdns" >> $PPP_3G_FILE
#if [ $PPPOE_OPMODE == "KeepAlive" ]; then
	echo "persist" >> $PPP_3G_FILE
#	echo "holdoff $PPPOE_OPTIME" >> $PPP_3G_FILE
#elif [ $PPPOE_OPMODE == "OnDemand" ]; then
#	PPPOE_OPTIME=`expr $PPPOE_OPTIME \* 60`
#	echo "demand" >> $PPP_3G_FILE
#	echo "idle $PPPOE_OPTIME" >> $PPP_3G_FILE
#fi
echo "nodeflate" >> $PPP_3G_FILE 
echo "connect \"/bin/comgt -d $MODEM -s /etc_ro/ppp/3g/$CONN\"" >> $PPP_3G_FILE 
echo "disconnect \"/bin/comgt -d $MODEM -s /etc_ro/ppp/3g/$DISCONN\"" >> $PPP_3G_FILE 


