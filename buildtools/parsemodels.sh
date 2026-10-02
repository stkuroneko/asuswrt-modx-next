#!/bin/sh                                                                       

diffs=`echo $1 | grep 'release\/' | sed -e 's/release\///' | sed -e 's/\/.*//'`

if [ "$diffs" = "" ] || [ "$diffs" = "src" ] || [ "$diffs" = "src-rt" ]; then
	exit
fi

echo -n "$1 modfied and may affect:"
 
while read line
do
	section=`echo $line | grep '\[' | grep '\]' | sed -e 's/\[//' | sed -e 's/\]//'`

	if [ "$section" != "" ]; then
		s=$section
	else
		ret=`echo $s | grep $diffs`
		model=`echo $line | sed -e 's/ .*//'`
		if [ "$ret" != "" ] && [ "$model" != "" ]; then
			echo -n "$model "
		fi
	fi
done

echo ""
