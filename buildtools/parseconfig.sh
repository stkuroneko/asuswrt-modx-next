#!/bin/sh

# parseconfig [asuswrt path] [veresion] [logpath] [model] 

asuswrtdir=$1
version=$2
logpath=$3
model=$4


configfile="${asuswrtdir}/release/src/router/.config"
tcodefile="${asuswrtdir}/release/src/router/shared/tcode.prep"
defaultfile="${asuswrtdir}/release/src/router/shared/defaults.prep"
modelcsvdir="/mnt/sharing-new/Projects/ASUSWRT/CI-REPORT/config/model_csv"

#handle config

if [ -f "${configfile}" ]; then
	echo "Date: `date`" > ${logpath}/log/config_${model}_${version}
	cat ${configfile} | grep -v "#"  | grep -v "=n" >> ${logpath}/log/config_${model}_${version}
fi

#handle tcode

if [ -f "${tcodefile}" ]; then

struct_arr="tcode_init_nvram_list tcode_nvram_list tcode_rc_support_list tcode_del_rc_support_list tcode_location_list"

exec < ${tcodefile}

inblock="0"

echo "Date: `date`" > ${logpath}/log/tcode_${model}_${version}

while read line 
do
   #echo "handling $line"
   if [ "$inblock" = "0" ]; then
   	for i in $struct_arr 
   	do
		found=`echo $line | grep "$i" | grep " = {"`
		if [ "$found" != "" ]; then
			inblock="1"
			break;
		fi
   	done
   fi
   if [ "$inblock" = "1" ]; then
	echo $line | grep -v "# " | grep -v "^$" >> ${logpath}/log/tcode_${model}_${version}
	found=`echo $line | grep "};"`
        if [ "$found" != "" ]; then
                inblock="0"
		echo "" >> ${logpath}/log/tcode_${model}_${version}
        fi
   fi
done
fi

if [ -f "${defaultfile}" ]; then

struct_arr="router_defaults"

exec < ${defaultfile}

inblock="0"

echo "Date: `date`" > ${logpath}/log/defaults_${model}_${version}

while read line 
do
   #echo "handling $line"
   if [ "$inblock" = "0" ]; then
        for i in $struct_arr
        do
                found=`echo $line | grep "$i" | grep " = {"`
                if [ "$found" != "" ]; then
                        inblock="1"
                        break;
                fi
        done
   fi
   if [ "$inblock" = "1" ]; then
        echo $line | grep -v "# " | grep -v "^$" >> ${logpath}/log/defaults_${model}_${version}
        found=`echo $line | grep "};"`
        if [ "$found" != "" ]; then
                inblock="0"
                echo "" >> ${logpath}/log/defaults_${model}_${version}
        fi
   fi
done

fi

# record what apps and what version embeded in this firmware
rm -rf ${logpath}/log/speccheck_${model}_${version}.csv
csvfile=`ls -t ${modelcsvdir}/${model}* | head -1`

if [ -f "${logpath}/log/config_${model}_${version}" ] && [ "${csvfile}" != "" ]; then

	exec < ${csvfile}

        while read line
        do
		c123=`echo $line | awk -F "," '{ printf "%s,%s,%s",$1,$2,$3 }'`
                fname=`echo $line | awk -F "," '{ print $4 }'`
                iname=`echo $line | awk -F "," '{ print $5 }'`
                cname=`echo $line | awk -F "," '{ print $6 }'`

                if [ "$cname" = "" ] || [ "$cname" = "Config" ]; then
                	echo "$line"  | sed 's///g' >> ${logpath}/log/speccheck_${model}_${version}.csv
        		continue
                fi

                found=`cat ${logpath}/log/config_${model}_${version} | grep "${cname}"`

                if [ "${found}" != "" ]; then
			flag="1"
		else
			flag="0"
		fi

		if [ "${flag}" = "${iname}" ]; then
                        result="PASS"
		else
			result="FAIL"
		fi

                echo "${c123},${fname},${cname},${iname},,${result}" >> ${logpath}/log/speccheck_${model}_${version}.csv
        done

	cp -rf ${logpath}/log/speccheck_${model}_${version}.csv ${modelcsvdir}/test_result/. 
fi

