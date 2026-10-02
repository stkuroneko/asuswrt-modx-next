/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   rules.c - Classification Rules Lookup Tables;
 *
 *   rules.h
 *
 *   QoS related symbol tables used by function ParseRule;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef RULES_SOURCE
#define RULES_SOURCE

#include "../plc/rules.h"

struct _code_ const controls [SIZEOF (controls)] =

{
	{
		CONTROL_ADD,
		"Add"
	},
	{
		CONTROL_REM,
		"Rem"
	},
	{
		CONTROL_REMOVE,
		"Remove"
	}
};

struct _code_ const volatilities [SIZEOF (volatilities)] =

{
	{
		VOLATILITY_TEMP,
		"Temp"
	},
	{
		VOLATILITY_PERM,
		"Perm"
	}
};

struct _code_ const actions [SIZEOF (actions)] =

{
	{
		ACTION_CAP0,
		"CAP0"
	},
	{
		ACTION_CAP1,
		"CAP1"
	},
	{
		ACTION_CAP2,
		"CAP2"
	},
	{
		ACTION_CAP3,
		"CAP3"
	},
	{
		ACTION_BOOST,
		"Boost"
	},
	{
		ACTION_DROP,
		"Drop"
	},
	{
		ACTION_DROPTX,
		"DropTX"
	},
	{
		ACTION_DROPRX,
		"DropRX"
	},
	{
		ACTION_AUTOCONNECT,
		"AutoConnect"
	},
	{
		ACTION_STRIPTX,
		"StripTX"
	},
	{
		ACTION_STRIPRX,
		"StripRX"
	},
	{
		ACTION_TAGTX,
		"TagTX"
	},
	{
		ACTION_TAGRX,
		"TagRX"
	}
};

struct _code_ const operands [SIZEOF (operands)] =

{
	{
		OPERAND_ALL,
		"All"
	},
	{
		OPERAND_ANY,
		"Any"
	},
	{
		OPERAND_ALWAYS,
		"Always"
	}
};

struct _code_ const fields [SIZEOF (fields)] =

{
	{
		FIELD_ETH_DA,
		"EthDA"
	},
	{
		FIELD_ETH_SA,
		"EthSA"
	},
	{
		FIELD_VLAN_UP,
		"VLANUP"
	},
	{
		FIELD_VLAN_ID,
		"VLANID"
	},
	{
		FIELD_IPV4_TOS,
		"IPv4TOS"
	},
	{
		FIELD_IPV4_PROT,
		"IPv4PROT"
	},
	{
		FIELD_IPV4_SA,
		"IPv4SA"
	},
	{
		FIELD_IPV4_DA,
		"IPv4DA"
	},
	{
		FIELD_IPV6_TC,
		"IPv6TC"
	},
	{
		FIELD_IPV6_FL,
		"IPv6FL"
	},
	{
		FIELD_IPV6_SA,
		"IPv6SA"
	},
	{
		FIELD_IPV6_DA,
		"IPv6DA"
	},
	{
		FIELD_TCP_SP,
		"TCPSP"
	},
	{
		FIELD_TCP_DP,
		"TCPDP"
	},
	{
		FIELD_UDP_SP,
		"UDPSP"
	},
	{
		FIELD_UDP_DP,
		"UDPDP"
	},
	{
		FIELD_IP_SP,
		"IPSP"
	},
	{
		FIELD_IP_DP,
		"IPDP"
	},
	{
		FIELD_HPAV_MME,
		"MME"
	},
	{
		FIELD_ETH_TYPE,
		"ET"
	},
	{
		FIELD_TCP_ACK,
		"TCPAck"
	},
	{
		FIELD_VLAN_TAG,
		"VLANTag"
	}
};

struct _code_ const operators [SIZEOF (operators)] =

{
	{
		OPERATOR_IS,
		"Is"
	},
	{
		OPERATOR_NOT,
		"Not"
	}
};

struct _code_ const states [SIZEOF (states)] =

{
	{
		OPERATOR_IS,
		"True"
	},
	{
		OPERATOR_NOT,
		"False"
	},
	{
		OPERATOR_IS,
		"On"
	},
	{
		OPERATOR_NOT,
		"Off"
	},
	{
		OPERATOR_IS,
		"Yes"
	},
	{
		OPERATOR_NOT,
		"No"
	},
	{
		OPERATOR_IS,
		"Present"
	},
	{
		OPERATOR_NOT,
		"Missing"
	}
};

#endif



