#!/bin/sh

# parse google calendar event every 15 minutes
#  - find first event before current date and not excuted
#    - with "build " 
#    - before current date
#    - no autobuildall tag to go with
# - parse keyword for
#    - fw/gpl, model, branch, commit

check_repo() 
{

	for repo in $REPO
	do
        	TAGFILE="./asuswrt.log/asuswrt-repository-$repo/autobuildalltag"
        	ERRFILE="./asuswrt.log/asuswrt-repository-$repo/autobuild_errlog"
        	if [ -f $TAGFILE ]; then
                	RUNNINGTAG=`cat $TAGFILE`
                	if [ "$RUNNINGTAG" != "STARTING" ]; then
                        	LOG=`cat $ERRFILE`
                        	if [ "$LOG" != "" ]; then
                                	google calendar add "Finish Task with Error" --user asuswrt.global@gmail.com
                        	else
                                	google calendar add "Finish Task" --user asuswrt.global@gmail.com
                        	fi
                        	rm -f $TAGFILE
                	fi
		fi
	done
}

assign_task()
{
	if [ "$MODEL" = "" ]; then
        	MODEL="ALL"
	fi

	if [ "$BRANCH" = "" ]; then
        	BRANCH="asuswrt-router-3004"
	fi

	if [ "$COMMIT" = "" ]; then
        	COMMIT="asuswrt-router-3004"
	fi

	# scan repository
	for repo in $REPO
	do
		#echo gothrough $repo
        	TAGFILE="./asuswrt.log/asuswrt-repository-$repo/autobuildalltag"
        	ERRFILE="./asuswrt.log/asuswrt-repository-$repo/autobuild_errlog"

        	# Assign task to free repository
        	if [ ! -f $TAGFILE ]; then
          		echo assign $repo to $TYPE $MODEL
		      	if [ "$TYPE" != "" ]; then
                        	echo "autobuildall $TYPE $MODEL $BRANCH $COMMIT $repo"
                        	./autobuildall $TYPE $MODEL $BRANCH $COMMIT $repo &
                        	echo "$list" >> ./asuswrt.log/task/${TODAY}-${STARTHOUR}-${STARTMIN}
                	fi
			return
		fi
	done
}


date > ./asuswrt.log/autochecktag

REPO="1 2 3 4 5 6"

check_repo

YESTERDAY=`date --date="1 days ago" "+%Y-%m-%d"`
TODAY=`date "+%Y-%m-%d"`
TODAYDATE=`date "+%d"`

export TZ="GMT"
TASKS1=`google calendar list --user asuswrt.global@gmail.com --date $YESTERDAY | grep "build:"`
TASKS2=`google calendar list --user asuswrt.global@gmail.com --date $TODAY | grep "build:"`
export TZ="Asia/Taipei"

IFS="

"

for list in $TASKS1 $TASKS2
do
	STARTDATE=`echo $list | sed s/.*,// | sed s/\ \-.*// | awk '{print $3}'`
	STARTDAY=`echo $list | sed s/.*,// | sed s/\ \-.*// | awk '{print $2}'`

	#echo $TODAY $STARTDATE
	echo $list

	if [ $STARTDAY != $TODAYDATE ]; then  
		continue;
	fi

	STARTHOUR=`echo $STARTDATE | awk 'BEGIN { FS = ":" }; {print $1}'`
	STARTMIN=`echo $STARTDATE | awk 'BEGIN { FS = ":" }; {print $2}'`

	TASK=`echo $list | sed s/,.*//`

	# check task date 
	CURRENTHOUR=`date "+%H"`
	CURRENTMIN=`date "+%M"`

	BUILDINTERVAL=$STARTINTERVAL
	BUILDDATE=$STARTDATE
	
	#echo "task start date $STARTHOUR, $STARTMIN, $CURRENTHOUR, $CURRENTMIN"
	TYPE=""
	MODEL=""
	COMMIT=""
	BRANCH=""

IFS=" "
	for item in $TASK
	do
		#MODEL="ALL"
		#BRANCH="asuswrt-router-3004"
		#COMMIT=""

		case "$item" in
  		build:fw)
			TYPE="FW"
		;;
		build:gpl)
			TYPE="GPL"
		;;
		model:*)
			MODEL=`echo $item | sed s/model://`
		;;
		branch:*)
			BRANCH=`echo $item | sed s/branch://`
		;;
		commit:*)
			COMMIT=`echo $item | sed s/commit://`
		;;
		esac
	done

	# check if $list is in task file 
        FOUND=`cat ./asuswrt.log/task/${TODAY}-${STARTHOUR}-${STARTMIN} | grep "$list"`

	if [ "$FOUND" != "" ]; then
            	echo "task was assigned"    
	else
		assign_task
        fi

	#echo here is $TYPE $MODEL $BRANCH $COMMIT
IFS="
"

done
	

