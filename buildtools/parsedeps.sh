#!/bin/sh                                                                       

diffs=`echo $1 | sed -e 's/release\///' | sed -e 's/\/.*//'`

if [ "$diffs" != "src" ] && [ "$diffs" != "src-rt" ]; then
        exit
fi

flag="0"

while read line
do
	if [ "$line" = "" ]; then
		continue
	fi

	section=`echo $line | grep '\[' | grep '\]'`

	if [ "$section" != "" ]; then
		s=$section
	else
		ret=`echo $1 | grep "$line"`

		if [ "$ret" != "" ]; then
			if [ "$flag" = "0" ]; then
				echo -n "$1 is modified and may affect:$s"
				flag="1"
			else
				echo -n "$s"
			fi
		fi
	fi
done

if [ "$flag" = "1" ]; then
	echo ""
else
	echo "$1 is modified but no deps so far"
fi
