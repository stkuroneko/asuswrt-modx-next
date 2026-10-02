#!/bin/sh

# gpl_excludes_router [src dir] [obj-y list]
rm -f $1/.gpl_excludes_router

for dir in `ls -d */ | sed -e 's/\///'` 
do
	if [ "$dir" = "config" ]; then
		continue
	elif [ "$dir" = "compressed" ]; then
		continue
	elif [ "$dir" = "tools" ]; then
		continue
	elif [ "$dir" = "mak" ]; then
		continue
	fi
	for obj in $2
	do
		if [ "$obj" = "$dir" ]; then
			break
		fi
	done
	if [ "$obj" != "$dir" ]; then
		echo "release/src/router/$dir" >> $1/.gpl_excludes_router
	fi
done
