#!/bin/sh

# ====================================================================
#
# --------------------------------------------------------------------

ETH=eth1
DIR=prescaler
PIB=tmp.pib
DEV=local
MODE=${1}

# ====================================================================
#
# --------------------------------------------------------------------

if [ ! -d ${DIR} ]; then
	echo "Folder ${DIR} does not exist."
	exit 1
elif [ "$#" = "0" ]; then
	echo
	echo "Intellon fdm mode utility"
	echo
	echo "usage: fdm mode"
	echo
	echo "mode = \"1\" 2.01MHz to 27.90Mhz w/HAM bands notched"
	echo "mode = \"2\" 2.01Mhz to 7.08MHz w/no notches"
	echo "mode = \"3\" 2.01Mhz to 7.54MHz w/HAM and Aero notches"
	echo "mode = \"4\" 2.01Mhz to 11.91Mhz w/no notches"
	echo "mode = \"5\" 2.01MHz to 11.91MHz w/ HAM and Aero notches"
	echo "mode = \"6a\" 2.0Mhz to 13.0Mhz w/HAM bands notched"
	echo "mode = \"6b\" 17.0Mhz to 28.0Mhz w/HAM bands notched"
	echo "mode = \"7a\" 2.0MHz to 10.1MHz w/HAM bands notched"
	echo "mode = \"7b\" 14.3MHz to 28.0MHz w/HAM bands notched"
	echo "mode = \"8a\" 2.0MHz to 16.0MHz w/HAM bands notched"
	echo "mode = \"8b\" 21.0MHz to 28.0MHz w/HAM bands notched"
	echo "mode = \"9a\" 2.0MHz to 9.0MHz w/HAM bands notched"
	echo "mode = \"9b\" 11.0MHz to 17.0MHz w/HAM bands notched"
	echo "mode = \"9c\" 22.0MHz to 28.0MHz w/HAM bands notched"
	exit 1
elif [ "$MODE" = "1" ]; then 
	echo
	echo "Setting modem to 2.01 to 27.90Mhz w/Ham bands notched..."
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/INT6400-Wall-NA.txt ${PIB}
	setpib ${PIB} a0c byte 0
	int6k -i ${ETH} -P ${PIB} ${DEV}
	echo "programming and resetting ..."
	int6k -i ${ETH} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "2" ]; then 
	echo
	echo "Setting modem to 2.01Mhz to 7.08MHz w/no notches"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To7.txt ${PIB}
	setpib ${PIB} a0c byte 13
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "3" ]; then 
	echo
	echo "Setting modem to 2.01Mhz to 7.54MHz w/HAM and Aero notches"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To75_notched.txt ${PIB}
	setpib ${PIB} a0c byte 14
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "4" ]; then 
	echo
	echo "Setting modem to 2.01Mhz to 11.91Mhz w/no notches"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To12.txt ${PIB}
	setpib ${PIB} a0c byte 15
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "5" ]; then 
	echo
	echo "Setting modem to 2.01MHz to 11.91MHz w/ HAM and Aero notches"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To12_notched.txt ${PIB}
	setpib ${PIB} a0c byte 16
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "6a" ]; then 
	echo
	echo "Setting modem to 2.0Mhz to 13.0Mhz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To13_notched.txt ${PIB}
	setpib ${PIB} a0c byte 5
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "6b" ]; then 
	echo
	echo "Setting modem to 17.0Mhz to 28.0Mhz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/17To28_notched.txt ${PIB}
	setpib ${PIB} a0c byte 6
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "7a" ]; then 
	echo
	echo "Setting modem to 2.0MHz to 10.1MHz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To101_notched.txt ${PIB}
	setpib ${PIB} a0c byte 7
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "7b" ]; then 
	echo
	echo "Setting modem to 14.3MHz to 28.0MHz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/143To28_notched.txt ${PIB}
	setpib ${PIB} a0c byte 8
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "8a" ]; then 
	echo
	echo "Setting modem to 2.0MHz to 16.0MHz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To16_notched.txt ${PIB}
	setpib ${PIB} a0c byte 9
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "8b" ]; then 
	echo
	echo "Setting modem to 21.0MHz to 28.0MHz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/21To28_notched.txt ${PIB}
	setpib ${PIB} a0c byte 10
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "9a" ]; then 
	echo
	echo "Setting modem to 2.0MHz to 9.0MHz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/2To9_notched.txt ${PIB}
	setpib ${PIB} a0c byte 2
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
 	rm ${PIB}
	exit 1
elif [ "$MODE" = "9b" ]; then 
	echo
	echo "Setting modem to 11.0MHz to 17.0MHz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/11To17_notched.txt ${PIB}
	setpib ${PIB} a0c byte 3
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
elif [ "$MODE" = "9c" ]; then 
	echo
	echo "Setting modem to 22.0MHz to 28.0MHz w/HAM bands notched"
	echo
	rm -f ${PIB} 
	int6k -i ${ETH} -p ${PIB} ${DEV} 
	psin < ${DIR}/22To28_notched.txt ${PIB}
	setpib ${PIB} a0c byte 4
	echo "programming and resetting ..."
	int6k -i ${ETH} -P ${PIB} -C2 ${DEV}
	rm ${PIB}
	exit 1
else
	echo "ERROR: not a valid mode number"
	exit 0
fi

