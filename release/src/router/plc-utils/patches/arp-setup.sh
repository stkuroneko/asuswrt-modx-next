#!/bin/bash
# file: arp-setup.sh

# ====================================================================
# environment;
# --------------------------------------------------------------------

. arp-token.sh

# ====================================================================
# disable loopback/WAN interfaces;
# --------------------------------------------------------------------

ifconfig lo down
ifconfig ${IF0} down

# ====================================================================
# enable send-to-self feature;
# --------------------------------------------------------------------

echo 1 > /proc/sys/net/ipv4/conf/${IF1}/loop
echo 1 > /proc/sys/net/ipv4/conf/${IF2}/loop

# ====================================================================
# disable arp on each device;
# --------------------------------------------------------------------

ip link set dev ${IF1} arp off
ip link set dev ${IF2} arp off

# ====================================================================
# discard routes;
# --------------------------------------------------------------------

route del -net ${NET1} netmask 255.255.255.0 dev ${IF1}  
route del -net ${NET2} netmask 255.255.255.0 dev ${IF2}  

# ====================================================================
# update arp neighbor cache;
# --------------------------------------------------------------------

ip neighbor add dev ${IF1} to ${IP2} lladdr ${NIC2} nud permanent
ip neighbor add dev ${IF2} to ${IP1} lladdr ${NIC1} nud permanent
ip neighbor show

