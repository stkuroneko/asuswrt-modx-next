/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed MulticastInfo1 (struct plc * plc);
 *
 *   plc.h
 *
 *   Request multicast group membership information from the peer device
 *   one VS_MULTICAST_INFO message;
 *
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef MULTICASTINFO1_SOURCE
#define MULTICASTINFO1_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/error.h"

signed MulticastInfo1 (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed source
	{
		uint8_t SOURCEADD [16];
	}
	* source;
	struct __packed member
	{
		uint8_t MEMBERADD [ETHER_ADDR_LEN];
		uint8_t MEMBERTEI;
		uint8_t SOURCEMODE;
		uint8_t NUMSOURCES;
	}
	* member;
	struct __packed group
	{
		uint8_t GROUPADD [16];
		uint8_t NUMMEMBERS;
	}
	* group;
	struct __packed vs_mcast_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t REQTYPE;
		uint8_t GROUP_ADDRESS [16];
	}
	* request = (struct vs_mcast_info_request *) (message);
	struct __packed vs_mcast_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t REQTYPE;
		uint8_t MSTATUS;
		uint8_t NUMGROUP;
		struct group group [1];
	}
	* confirm = (struct vs_mcast_info_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	char string [16 * 3];
	Request (plc, "Fetch Multicast Group Information");
	memset (message, 0, sizeof (struct message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader1 (& confirm->qualcomm, 1, (VS_MULTICAST_INFO | MMTYPE_REQ));
	request->REQTYPE = 0x00;
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 1, (VS_MULTICAST_INFO | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	Confirm (plc, "Found %d Group(s)\n", confirm->NUMGROUP);
	group = (struct group *) (& confirm->group);
	while (confirm->NUMGROUP-- > 0)
	{
		printf ("\tgroup->GROUPADD = %s\n", hexstring (string, sizeof (string), group->GROUPADD, sizeof (group->GROUPADD)));
		printf ("\tgroup->NUMMEMBERS = %d\n", group->NUMMEMBERS);
		printf ("\n");
		member = (struct member *) (& group->NUMMEMBERS +  1);
		while (group->NUMMEMBERS-- > 0)
		{
			printf ("\t\tmember->MEMBERADD = %s\n", hexstring (string, sizeof (string), member->MEMBERADD, sizeof (member->MEMBERADD)));
			printf ("\t\tmember->MEMBERTEI = %d\n", member->MEMBERTEI);
			printf ("\t\tmember->SOURCEMODE = %d\n", member->SOURCEMODE);
			printf ("\t\tmember->NUMSOURCES = %d\n", member->NUMSOURCES);
			source = (struct source *) (& member->NUMSOURCES +  1);
			while (member->NUMSOURCES-- > 0)
			{
				printf ("\t\t\tsource->SOURCEADD = %s\n", hexstring (string, sizeof (string), source->SOURCEADD, sizeof (source->SOURCEADD)));
				printf ("\n");
				source++;
			}
			member = (struct member *) (source);
			printf ("\n");
		}
		group = (struct group *) (member);
	}
	return (0);
}

#endif



