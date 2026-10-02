#!/bin/sh
#
# $Id: storage.sh,v 1.36 2010-07-23 09:12:58 chhung Exp $
#
# usage: storage.sh
#
#
PART1=`mount | grep "/media/" | sed 's/^.*media/\/media/g' | sed 's/ type.*$//g' | sed -n '1p'`
#PART1="/var"
#echo "script fetch the first partition: $PART1"

setUser()
{
	mkdir -p "$PART1/home/"
	for index in 1 2 3 4 5 6 7 8 9 10
	do
		user=`nvram_get 2860 "User"$index""`
		passwd=`nvram_get 2860 "User"$index"Passwd"`
		id=`expr 500 + $index`
		if [ -n "$user" ]; then
			mkdir -p "$PART1/home/$user"
			chmod 777 "$PART1/home/$user"
			echo "$user::$id:$id:$user:$PART1/home/$user:/bin/sh" >> /etc/passwd
			echo "$user:x:$id:$user" >> /etc/group
			chpasswd.sh $user $passwd
		fi
	done
	mkdir -p "$PART1/home/anonymous"
	echo "anonymous::500:500:anonymous:$PART1/home/anonymous:/bin/sh" >> /etc/passwd
	echo "anonymous:x:500:anonymous" >> /etc/group
}

setFtp()
{
	ftpname=`nvram_get 2860 FtpName`
	ftpport=`nvram_get 2860 FtpPort`
	ftpguest=`nvram_get 2860 FtpAnonymous`
	ftpmax=`nvram_get 2860 FtpMaxSessions`
	ftpadddir=`nvram_get 2860 FtpAddDir`
	ftprename=`nvram_get 2860 FtpRename`
	ftpremove=`nvram_get 2860 FtpRemove`
	ftpread=`nvram_get 2860 FtpRead`
	ftpwrite=`nvram_get 2860 FtpWrite`
	ftpdownload=`nvram_get 2860 FtpDownload`
	ftpupload=`nvram_get 2860 FtpUpload`
	admID=`nvram_get 2860 Login`
	admPW=`nvram_get 2860 Password`
	ip=`nvram_get 2860 lan_ipaddr`
	echo "proftpd.sh server "$ftpname" $ip $ftpport $ftpmax"
	proftpd.sh server "$ftpname" $ip $ftpport $ftpmax
	if [ -e "$PART1" ]; then
		echo "proftpd.sh user $ftpadddir $ftprename $ftpremove $ftpread $ftpwrite $ftpdownload $ftpupload"
		proftpd.sh user $ftpadddir $ftprename $ftpremove $ftpread $ftpwrite $ftpdownload $ftpupload
	fi
	if [ "$ftpguest" == "1" ]; then
		echo "proftpd.sh anonymous 10"
		proftpd.sh anonymous 10
	fi
}

setSmb()
{
	smbnetbios=`nvram_get 2860 SmbNetBIOS`
	smbwg=`nvram_get 2860 HostName`
	echo "samba.sh "$smbnetbios" "$smbwg""
	samba.sh "$smbnetbios" "$smbwg" 
	admID=`nvram_get 2860 Login`
	admPW=`nvram_get 2860 Password`
	echo "smbpasswd -a "$admID" "$admPW""
	smbpasswd -a "$admID" "$admPW"
	allusers="$admID"
	if [ -e "$PART1" ]; then
		for index in 1 2 3 4 5 6 7 8 9 10
		do
			user=`nvram_get 2860 "User$index"`
			smbuser=`nvram_get 2860 "SmbUser$index"`
			if [ "$user" -a "$smbuser" == "1" ]; then
				pw=`nvram_get 2860 "User"$index"Passwd"`
				echo "smbpasswd -a "$user" "$pw""
				smbpasswd -a "$user" "$pw"
				allusers="$allusers $user"
			fi
		done
		if [ ! -e "$PART1/public" ]; then
			mkdir -p "$PART1/public"
			chmod 777 "$PART1/public"
		fi
		echo "samba_add_dir.sh Public "$PART1/public" "$allusers""
		samba_add_dir.sh Public "$PART1/public" "$allusers"
	fi
}

case $1 in
	"admin")
		admID=`nvram_get 2860 Login`
		admPW=`nvram_get 2860 Password`
		echo "$admID::0:0:Adminstrator:/:/bin/sh" > /etc/passwd
		echo "$admID:x:0:$admID" > /etc/group
		chpasswd.sh $admID $admPW
		if [ -e "$PART1" ]; then
			setUser
		fi
		;;
	"reparted")
		echo -e "d\n1\nd\n2\nd\n3\nd\nw\n" > /etc/delpart
		sleep 1
		#cat /etc/delpart
		fdisk /dev/sda < /etc/delpart 1>/dev/null 2>&1 
		sleep 10
		reg s 0xb01c0000
		reg w 440 1005
		sleep 10
		echo -e "n\ne\n1\n\n\nt\nf\nw\n" > /etc/extpart
		sleep 1
		#cat /etc/extpart
		fdisk /dev/sda < /etc/extpart 1>/dev/null 2>&1
		sleep 10
		if [ "$2" -gt "0" ]; then
			echo -e "n\nl\n\n+$2M\nt\n5\nb" > /etc/parted
			sleep 1
		fi
		if [ "$3" -gt "0" ]; then
			echo -e "n\nl\n\n+$3M\nt\n6\nb" >> /etc/parted
			sleep 1
		fi
		if [ "$4" -gt "0" ]; then
			echo -e "n\nl\n\n+$4M\nt\n7\nb" >> /etc/parted
			sleep 1
		fi
		if [ "$5" == "4" ]; then
			echo -e "n\nl\n\n\nt\n8\nb" >> /etc/parted
			sleep 1
		fi
		echo -e "w\n" >> /etc/parted
		sleep 1
		#cat /etc/parted
		fdisk /dev/sda < /etc/parted 1>/dev/null 2>&1
		sleep 10
		;;	
	"format")
		#echo "umount -l $2"
		umount -l $2 1>/dev/null 2>&1
		#echo "mkdosfs -F 32 $2 $3"
		mkdosfs -F 32 $2 $3 1>/dev/null 2>&1
		;;
	"restart")
		reg s 0xb01c0000
		reg w 440 5
		reg w 440 1005
		;;
	"ftp")
		killall -q proftpd
		if [ ! -e "$PART1" ]; then
			echo "1st partition does not exist"
			exit 0
		fi
		ftpenabled=`nvram_get 2860 FtpEnabled`
		if [ "$ftpenabled" == "1" ]; then
			setFtp
			echo "proftpd"
			proftpd
		fi
		;;
	"samba")
		killall -q nmbd
		killall -q smbd
		if [ ! -e "$PART1" ]; then
			echo "1st partition does not exist"
			exit 0
		fi
		smbenabled=`nvram_get 2860 SmbEnabled`
		if [ "$smbenabled" == "1" ]; then
			setSmb
		fi
		;;
	"media")
		killall -q ushare
		if [ ! -e "$PART1" ]; then
			echo "1st partition does not exist"
			exit 0
		fi
		media_enabled=`nvram_get 2860 mediaSrvEnabled`
		media_name=`nvram_get 2860 mediaSrvName`
		if [ "$media_enabled" == "1" ]; then
			echo "ushare.sh $media_name "$2" "$3" "$4" "$5""
			ushare.sh $media_name "$2" "$3" "$4" "$5"
			echo "ushare -D"
			ushare -D
		fi
		;;
esac
