/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed MulticastInfo2 (struct plc * plc);
 *
 *   plc.h
 *
 *   Request multicast group membership information from peer device
 *   one VS_MULTICAST_INFO message;
 *
 *   Contributor(s):
 *      Charles Maier <charles.maier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef MULTICASTINFO2_SOURCE
#define MULTICASTINFO2_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/error.h"
#include "../plc/plc.h"

/*====================================================================*
 *    variables;
 *--------------------------------------------------------------------*/

static char const * addresstypes [] =

{
	"IPv4",
	"IPv6"
};

static char const * sourcemodes [2] [2] =

{
	{
		"Allow",
		"Block"
	},
	{
		"Include",
		"Exclude"
	}
};

/*====================================================================*
 *
 *   static byte * MulticastInfoIPv4 (byte * memory);
 *
 *   treat addresses as IPv4 addresses and display accordingly;
 *
 *   Contributor(s):
 *      Charles Maier <charles.maier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static byte * MulticastInfoIPv4 (byte * memory)

{

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed group
	{
		uint8_t ADDRESS_TYPE;
		uint8_t GROUPADD [4];
		uint16_t MEM_INTERVAL;
		uint8_t NUMMEMBERS;
		struct __packed member
		{
			uint8_t MEMBERADD [ETHER_ADDR_LEN];
			uint8_t MEMBERTEI;
			uint8_t SOURCEMODE;
			uint8_t NUMSOURCES;
			struct __packed source
			{
				uint8_t SOURCEADD [4];
			}
			sources [1];
		}
		members [1];
	}
	* group = (struct group *) (memory);
	struct member * member;
	struct source * source;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	char string [48];
	printf ("group->ADDRESS_TYPE = %s\n", group->ADDRESS_TYPE < SIZEOF (addresstypes)? addresstypes [group->ADDRESS_TYPE]: "Unknown");
	printf ("group->ADDRESS = %s\n", decstring (string, sizeof (string), group->GROUPADD, sizeof (group->GROUPADD)));
	printf ("group->INTERVAL = %d\n", LE16TOH (group->MEM_INTERVAL));
	printf ("group->MEMBERS = %d\n", group->NUMMEMBERS);
	printf ("\n");
	memory += sizeof (group->ADDRESS_TYPE) +  sizeof (group->GROUPADD) +  sizeof (group->MEM_INTERVAL) +  sizeof (group->NUMMEMBERS);
	member = (struct member *) (group->members);
	while (group->NUMMEMBERS-- > 0)
	{
		printf ("\tmember->MAC = %s\n", hexstring (string, sizeof (string), member->MEMBERADD, sizeof (member->MEMBERADD)));
		printf ("\tmember->TEI = %d\n", member->MEMBERTEI);
		printf ("\tmember->SOURCEMODE = %s\n", member->SOURCEMODE < SIZEOF (sourcemodes)? sourcemodes [! member->NUMSOURCES] [member->SOURCEMODE]: "Unknown");
		printf ("\tmember->SOURCES = %d\n", member->NUMSOURCES);
		memory += sizeof (member->MEMBERADD) +  sizeof (member->MEMBERTEI) +  sizeof (member->SOURCEMODE) +  sizeof (member->NUMSOURCES);
		source = (struct source *) (member->sources);
		while (member->NUMSOURCES-- > 0)
		{
			printf ("\t\tsource->ADDRESS = %s\n", decstring (string, sizeof (string), source->SOURCEADD, sizeof (source->SOURCEADD)));
			memory += sizeof (source->SOURCEADD);
			source++;
		}
		member = (struct member *) (source);
		printf ("\n");
	}
	return (memory);
}

/*====================================================================*
 *
 *   static byte * MulticastInfoIPv6 (byte * memory);
 *
 *   treat addresses as IPv6 addresses and display accordingly;
 *
 *   Contributor(s):
 *      Charles Maier <charles.maier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static byte * MulticastInfoIPv6 (byte * memory)

{

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed group
	{
		uint8_t ADDRESS_TYPE;
		uint8_t GROUPADD [16];
		uint16_t MEM_INTERVAL;
		uint8_t NUMMEMBERS;
		struct __packed member
		{
			uint8_t MEMBERADD [ETHER_ADDR_LEN];
			uint8_t MEMBERTEI;
			uint8_t SOURCEMODE;
			uint8_t NUMSOURCES;
			struct __packed source
			{
				uint8_t SOURCEADD [16];
			}
			sources [1];
		}
		members [1];
	}
	* group = (struct group *) (memory);
	struct member * member;
	struct source * source;

#ifndef __GNUC__
#pragma pack (pop)
#endif

	char string [48];
	printf ("group->ADDRESS_TYPE = %s\n", group->ADDRESS_TYPE < SIZEOF (addresstypes)? addresstypes [group->ADDRESS_TYPE]: "Unknown");
	printf ("group->ADDRESS = %s\n", hexstring (string, sizeof (string), group->GROUPADD, sizeof (group->GROUPADD)));
	printf ("group->MEM_INTERVAL = %d\n", LE16TOH (group->MEM_INTERVAL));
	printf ("group->MEMBERS = %d\n", group->NUMMEMBERS);
	printf ("\n");
	memory += sizeof (group->ADDRESS_TYPE) +  sizeof (group->GROUPADD) +  sizeof (group->MEM_INTERVAL) +  sizeof (group->NUMMEMBERS);
	member = (struct member *) (group->members);
	while (group->NUMMEMBERS-- > 0)
	{
		printf ("\tmember->MAC = %s\n", hexstring (string, sizeof (string), member->MEMBERADD, sizeof (member->MEMBERADD)));
		printf ("\tmember->TEI = %d\n", member->MEMBERTEI);
		printf ("\tmember->SOURCEMODE = %s\n", member->SOURCEMODE < SIZEOF (sourcemodes)? sourcemodes [! member->NUMSOURCES] [member->SOURCEMODE]: "Unknown");
		printf ("\tmember->SOURCES = %d\n", member->NUMSOURCES);
		memory += sizeof (member->MEMBERADD) +  sizeof (member->MEMBERTEI) +  sizeof (member->SOURCEMODE) +  sizeof (member->NUMSOURCES);
		source = (struct source *) (member->sources);
		while (member->NUMSOURCES-- > 0)
		{
			printf ("\t\tsource->ADDRESS = %s\n", hexstring (string, sizeof (string), source->SOURCEADD, sizeof (source->SOURCEADD)));
			memory += sizeof (source->SOURCEADD);
			source++;
		}
		member = (struct member *) (source);
		printf ("\n");
	}
	return (memory);
}

/*====================================================================*
 *
 *   signed MulticastInfo2 (struct plc * plc);
 *
 *   plc.h
 *
 *   Contributor(s):
 *      Charles Maier <charles.maier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

signed MulticastInfo2 (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_mcast_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t REQ_TYPE;
		uint32_t REQ_ID;
		uint8_t REQ_ADDRESS_TYPE;
		uint8_t REQ_ADDRESS [16];
		uint32_t RSVD;
		uint8_t NUMGROUP;
	}
	* request = (struct vs_mcast_info_request *) (message);
	struct __packed vs_mcast_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t REQ_TYPE;
		uint32_t REQ_ID;
		uint8_t MSTATUS;
		uint32_t RSVD;
		uint8_t NUMGROUP;
		uint8_t GROUPS [1];
	}
	* confirm = (struct vs_mcast_info_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	byte * group;
	Request (plc, "Fetch Multicast Group Information");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader1 (& request->qualcomm, 1, (VS_MULTICAST_INFO | MMTYPE_REQ));
	request->REQ_TYPE = plc->action;
	request->REQ_ID = HTOLE32 (plc->cookie);
	request->REQ_ADDRESS_TYPE = plc->sector;
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadFMI (plc, 1, (VS_MULTICAST_INFO | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	confirm = (struct vs_mcast_info_confirm *) (plc->content);
	if (confirm->MSTATUS)
	{
		free (plc->content);
		plc->content = NULL;
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	Confirm (plc, "Found %d Group(s)\n", confirm->NUMGROUP);
	group = confirm->GROUPS;
	while (confirm->NUMGROUP-- > 0)
	{
		if (* group == 0x00)
		{
			group = MulticastInfoIPv4 (group);
			continue;
		}
		if (* group == 0x01)
		{
			group = MulticastInfoIPv6 (group);
			continue;
		}
		error (PLC_EXIT (plc), ENOTSUP, "Unknown address type 0x%02x", * (byte *) (group));
		break;
	}
	if (plc->content)
	{
		free (plc->content);
	}
	plc->content = (void *) (0);
	return (0);
}

#endif



