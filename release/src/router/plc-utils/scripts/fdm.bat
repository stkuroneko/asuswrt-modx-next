ECHO off
SET ETH=2
SET DIR=prescaler
SET PIB=temp.pib
SET DEV=local

IF (%1)==() GOTO :NOOPT
IF (%1)==(1) GOTO :ONE
IF (%1)==(2) GOTO :TWO
IF (%1)==(3) GOTO :THREE
IF (%1)==(4) GOTO :FOUR
IF (%1)==(5) GOTO :FIVE
IF (%1)==(6a) GOTO :SIXA
IF (%1)==(6b) GOTO :SIXB
IF (%1)==(7a) GOTO :SEVENA
IF (%1)==(7b) GOTO :SEVENB
IF (%1)==(8a) GOTO :EIGHTA
IF (%1)==(8b) GOTO :EIGHTB
IF (%1)==(9a) GOTO :NINEA
IF (%1)==(9b) GOTO :NINEB
IF (%1)==(9c) GOTO :NINEC

GOTO :INVAL

:NOOPT
	echo Intellon fdm mode utility
	echo usage: fdm mode
	echo mode = "1" 2.01MHz to 27.90Mhz w/HAM bands notched
	echo mode = "2" 2.01Mhz to 7.08MHz w/no notches
	echo mode = "3" 2.01Mhz to 7.54MHz w/HAM and Aero notches
	echo mode = "4" 2.01Mhz to 11.91Mhz w/no notches
	echo mode = "5" 2.01MHz to 11.91MHz w/ HAM and Aero notches
	echo mode = "6a" 2.0Mhz to 13.0Mhz w/HAM bands notched
	echo mode = "6b" 17.0Mhz to 28.0Mhz w/HAM bands notched
	echo mode = "7a" 2.0MHz to 10.1MHz w/HAM bands notched
	echo mode = "7b" 14.3MHz to 28.0MHz w/HAM bands notched
	echo mode = "8a" 2.0MHz to 16.0MHz w/HAM bands notched
	echo mode = "8b" 21.0MHz to 28.0MHz w/HAM bands notched
	echo mode = "9a" 2.0MHz to 9.0MHz w/HAM bands notched
	echo mode = "9b" 11.0MHz to 17.0MHz w/HAM bands notched
	echo mode = "9c" 22.0MHz to 28.0MHz w/HAM bands notched
	GOTO :END

:ONE
	echo Setting modem to 2.01 to 27.90Mhz w/Ham bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/INT6400-Wall-NA.txt
	setpib %PIB% a0c byte 0
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:TWO
	echo Setting modem to 2.01Mhz to 7.08MHz w/no notches
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To7.txt
	setpib %PIB% a0c byte 13
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:THREE
	echo Setting modem to 2.01Mhz to 7.54MHz w/HAM and Aero notches
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To75_notched.txt
	setpib %PIB% a0c byte 14
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:FOUR
	echo Setting modem to 2.01Mhz to 11.91Mhz w/no notches
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To12.txt
	setpib %PIB% a0c byte 15
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:FIVE
	echo Setting modem to 2.01MHz to 11.91MHz w/ HAM and Aero notches
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To12_notched.txt
	setpib %PIB% a0c byte 16
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:SIXA
	echo Setting modem to 2.0Mhz to 13.0Mhz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To13_notched.txt
	setpib %PIB% a0c byte 5
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:SIXB
	echo Setting modem to 17.0Mhz to 28.0Mhz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/17To28_notched.txt
	setpib %PIB% a0c byte 6
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:SEVENA
	echo Setting modem to 2.0MHz to 10.1MHz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To101_notched.txt
	setpib %PIB% a0c byte 7
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:SEVENB
	echo Setting modem to 14.3MHz to 28.0MHz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/143To28_notched.txt
	setpib %PIB% a0c byte 8
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:EIGHTA
	echo Setting modem to 2.0MHz to 16.0MHz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To16_notched.txt
	setpib %PIB% a0c byte 9
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:EIGHTB
	echo Setting modem to 21.0MHz to 28.0MHz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/21To28_notched.txt
	setpib %PIB% a0c byte 10
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:NINEA
	echo Setting modem to 2.0MHz to 9.0MHz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/2To9_notched.txt
	setpib %PIB% a0c byte 2
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END
:NINEB
	echo Setting modem to 11.0MHz to 17.0MHz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/11To17_notched.txt
	setpib %PIB% a0c byte 3
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:NINEC
	echo Setting modem to 22.0MHz to 28.0MHz w/HAM bands notched
	IF EXIST %PIB% del %PIB%
	int6k -i %ETH% -p %PIB% %DEV% 
	psin %PIB% < %DIR%/22To28_notched.txt
	setpib %PIB% a0c byte 4
	int6k -i %ETH% -P %PIB% %DEV%
	int6k -i %ETH% -C2 %DEV%
	del %PIB%
	GOTO :END

:INVAL
echo ERROR: not a valid mode number

:END
