#!/bin/bash
cmd=$1"/asuswrt/release/src-ra/router/tools/Lnx_ToolHelp/LnxCodePrep"
output=$1"/err.txt"
dir0=$1"/asuswrt/release/src-ra/router/rc/"
dir1=$1"/asuswrt/release/src-ra/router/shared/"
echo $cmd
$cmd $dir0/sysdeps/init-ralink-dsl.c $output
$cmd $dir0/sysdeps/init-broadcom.c $output
$cmd $dir0/firewall.c $output
$cmd $dir0/wan.c $output
$cmd $dir0/init.c $output
$cmd $dir0/lan.c $output
$cmd $dir0/usb_devices.c $output
$cmd $dir0/dsl.c $output
$cmd $dir0/wanduck.c $output
$cmd $dir1/defaults.c $output
$cmd $dir1/rtstate.c $output
$cmd $dir1/sysdeps/ralink/rtl8367r.c $output
