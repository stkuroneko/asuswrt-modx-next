#!/bin/sh -e

# ====================================================================
#
# --------------------------------------------------------------------

IF1=eth0
IF2=eth1
IF3=eth2
IF4=eth3

# ====================================================================
#
# --------------------------------------------------------------------

IP1=10.0.0.1/24
IP2=10.0.0.2/24
IP3=10.0.0.3/24
IP4=10.0.0.4/24

# ====================================================================
#
# --------------------------------------------------------------------

TBL1=500
TBL2=501
TBL3=502
TBL4=503

# ====================================================================
# move local routing rule to lower priority
# --------------------------------------------------------------------

ip rule add pref 1000 lookup local
#ip rule del pref 0

# ====================================================================
# only reply to ARP requests for addresses configured on the device
# --------------------------------------------------------------------

echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore

# ====================================================================
# configure device and force packets of bound sockets out on eth1
# --------------------------------------------------------------------

ip address add dev ${IF1} ${IP1}
echo 1 > /proc/sys/net/ipv4/conf/${IF1}/accept_local
ip link set ${IF1} up
ip rule add pref ${TBL1} oif ${IF1} lookup ${TBL1}
ip route add default dev ${IF1} table ${TBL1}

# ====================================================================
# configure device and force packets of bound sockets out on eth2
# --------------------------------------------------------------------

ip address add dev ${IF2} ${IP2}
echo 1 > /proc/sys/net/ipv4/conf/${IF2}/accept_local
ip link set ${IF2} up
ip rule add pref ${TBL2} oif ${IF2} lookup ${TBL2}
ip route add default dev ${IF2} table ${TBL2}

# ====================================================================
# configure device and force packets of bound sockets out on ${IF3}
# --------------------------------------------------------------------

ip address add dev ${IF3} ${IP3}
echo 1 > /proc/sys/net/ipv4/conf/${IF3}/accept_local
ip link set ${IF3} up
ip rule add pref ${TBL3} oif ${IF3} lookup ${TBL3}
ip route add default dev ${IF3} table ${TBL3}

# ====================================================================
# configure device and force packets of bound sockets out on ${IF4}
# --------------------------------------------------------------------

ip address add dev ${IF4} ${IP4}
echo 1 > /proc/sys/net/ipv4/conf/${IF4}/accept_local
ip link set ${IF4} up
ip rule add pref ${TBL4} oif ${IF4} lookup ${TBL4}
ip route add default dev ${IF4} table ${TBL4}

