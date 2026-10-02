#!/bin/sh                                                                       

dictflag="0"
targetflag="0"

while read line
do
        diff=`echo $line | grep '\-\-git a' | sed -e 's/.*--git a\///' | sed -e 's/ .*//'`
	
	if [ "$diff" = "" ]; then
		if [ "$targetflag" = "1" ]; then
			export=`echo $line | grep "+export" | sed -e 's/+export //' | sed -e 's/:=.*//'`
		
			if [ "$export" != "" ]; then
				echo -n "$export "
			fi
		
		fi
		continue
	else
		dict=`echo $diff | grep "release/src/router/www" | grep dict`
		target=`echo $diff | grep "buildtools/target.mak"`

		if [ "$target" != "" ]; then
			targetflag="1"
			echo -n "buildtools/earget.mak.* is modified and may affect:"
		else 
			if [ "$targetflag" = "1" ]; then
				echo ""
			fi
			targetflag="0"
		fi

		if [ "$dict" != "" ]; then
			if [ "$dictflag" = "0" ]; then
				echo "release/src/router/www/*.dict is modified and may affect [WWW-DICT]"
				dictflag="1"	
			fi
		elif [ "$target" = "" ]; then
			cat release/deps  | ./buildtools/parsedeps.sh $diff
			cat release/models | ./buildtools/parsemodels.sh $diff
		fi
	fi
done

