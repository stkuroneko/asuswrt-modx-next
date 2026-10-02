/*====================================================================*
 *	Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   signed RouteInfo (struct plc * plc);
 *
 *
 *   displays the routing table using VS_ROUTE_INFO message;
 *
 *   Contributor(s):
 *      Kalaivani Somasundaram <kalaivan@qti.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ROUTEINFO_SOURCE
#define ROUTEINFO_SOURCE

#include <stdint.h>

#include "../plc/plc.h"
#include "../tools/error.h"	

signed RouteInfo (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed local_routing_entry
	{
		uint8_t mUDTEI;
		uint8_t mNTEI;
		uint8_t mRDR;
		uint8_t mRNH;
		uint8_t mUDTEIMac [ETHER_ADDR_LEN];
		uint8_t mNTEIMAC [ETHER_ADDR_LEN];
	}
	* local_routing_entry;

	struct __packed vs_route_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_route_info_request *) (message);
	
	struct __packed vs_route_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t num_of_entry;
		struct local_routing_entry local_routing_table [1];
	}
	* confirm = (struct vs_route_info_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Route Info");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_ROUTE_INFO | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_ROUTE_INFO | MMTYPE_CNF)) > 0)
	{
		Confirm (plc, "Found %d entry(ies)\n", confirm->num_of_entry);
		local_routing_entry = (struct local_routing_entry *) (confirm->local_routing_table);
		
		if(confirm->num_of_entry > 0)
		{
			printf ("TEI \t");
			printf ("MacAddress \t\t");
			printf ("RoutingMacAddress \t");
			printf ("Number of Hops \t");
			printf ("Routing Data Rate \n");
			while (confirm->num_of_entry-- > 0)
			{
				char string [24];
			
				printf ("%d\t", local_routing_entry->mUDTEI);
				printf ("%s\t", hexstring (string, sizeof (string), local_routing_entry->mUDTEIMac, sizeof (local_routing_entry->mUDTEIMac)));
				printf ("%s\t\t", hexstring (string, sizeof (string), local_routing_entry->mNTEIMAC, sizeof (local_routing_entry->mNTEIMAC)));
				printf ("%d\t\t", local_routing_entry->mRNH);
				printf ("%d\n", local_routing_entry->mRDR);

				local_routing_entry++;
			}
		}
	}
	return (0);
}

signed RouteInfo_7500(struct plc* plc)

{
	struct channel* channel = (struct channel*) (plc->channel);
	struct message* message = (struct message*) (plc->message);

	#ifndef __GNUC__
	#pragma pack (push,1)
	#endif

	struct __packed local_routing_entry
	{
		uint8_t mUDTEI;
		uint8_t mNTEI;
		uint16_t mRDR;
		uint8_t mRNH;
		uint8_t mUDTEIMac[ETHER_ADDR_LEN];
		uint8_t mNTEIMAC[ETHER_ADDR_LEN];
	}
	*local_routing_entry;

	struct __packed vs_route_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	*request = (struct vs_route_info_request*) (message);

	struct __packed vs_route_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t num_of_entry;
		struct local_routing_entry local_routing_table[1];
	}
	*confirm = (struct vs_route_info_confirm*) (message);

	#ifndef __GNUC__
	#pragma pack (pop)
	#endif

	Request(plc, "Route Info");
	memset(message, 0, sizeof(*message));
	EthernetHeader(&request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader(&request->qualcomm, 0, (VS_ROUTE_INFO | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME(plc) <= 0)
	{
		error(PLC_EXIT(plc), ECANCELED, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME(plc, 0, (VS_ROUTE_INFO | MMTYPE_CNF)) > 0)
	{
		Confirm(plc, "Found %d entry(ies)\n", confirm->num_of_entry);
		local_routing_entry = (struct local_routing_entry*) (confirm->local_routing_table);

		if (confirm->num_of_entry > 0)
		{
			printf("TEI \t");
			printf("MacAddress \t\t");
			printf("RoutingMacAddress \t");
			printf("Number of Hops \t");
			printf("Routing Data Rate \n");
			while (confirm->num_of_entry-- > 0)
			{
				char string[24];

				printf("%d\t", local_routing_entry->mUDTEI);
				printf("%s\t", hexstring(string, sizeof(string), local_routing_entry->mUDTEIMac, sizeof(local_routing_entry->mUDTEIMac)));
				printf("%s\t\t", hexstring(string, sizeof(string), local_routing_entry->mNTEIMAC, sizeof(local_routing_entry->mNTEIMAC)));
				printf("%d\t\t", local_routing_entry->mRNH);
				printf("%d\n", local_routing_entry->mRDR);

				local_routing_entry++;
			}
		}
	}
	return (0);
}

#endif