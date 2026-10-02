/*====================================================================*
 *	Copyright (c) 2019 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   signed ProxyNetworkInfo (struct plc * plc);
 *
 *   nda.h
 *
 *   displays the list of PCos and hidden STAs in the network using  
 *   VS_PROXY_NW_INFO message;
 *
 *   Contributor(s):
 *      Kalaivani Somasundaram <kalaivan@qti.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PROXYNETWORKINFO_SOURCE
#define PROXYNETWORKINFO_SOURCE

#include <stdint.h>

#include "../plc/plc.h"
#include "../tools/error.h"

#define MAX_HIDDEN_STA 8

signed GetCCoMacAddress (struct plc * plc, uint8_t * cco_macaddr)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_nw_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
	}
	* request = (struct vs_nw_info_request *) (message);
	struct __packed vs_nw_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t SUB_VERSION;
		uint8_t Reserved;
		uint16_t DATA_LEN;
		uint8_t DATA [1];
	}
	* confirm = (struct vs_nw_info_confirm *) (message);
	struct __packed station
	{
		uint8_t MAC [ETHER_ADDR_LEN];
		uint8_t TEI;
		uint8_t Reserved [3];
		uint8_t BDA [ETHER_ADDR_LEN];
		uint16_t AVGTX;
		uint8_t COUPLING;
		uint8_t Reserved3;
		uint16_t AVGRX;
		uint16_t Reserved4;
	}
	* station;
	struct __packed network
	{
		uint8_t NID [7];
		uint8_t Reserved1 [2];
		uint8_t SNID;
		uint8_t TEI;
		uint8_t Reserved2 [4];
		uint8_t ROLE;
		uint8_t CCO_MAC [ETHER_ADDR_LEN];
		uint8_t CCO_TEI;
		uint8_t Reserved3 [3];
		uint8_t NUMSTAS;
		uint8_t Reserved4 [5];
		struct station stations [1];
	}
	* network;
	struct __packed networks
	{
		uint8_t Reserved;
		uint8_t NUMAVLNS;
		struct network networks [1];
	}
	* networks = (struct networks *) (confirm->DATA);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader1 (& request->qualcomm, 1, (VS_NW_INFO | MMTYPE_REQ));
	if (sendpacket (channel, message, (ETHER_MIN_LEN - ETHER_CRC_LEN)) <= 0)
	{
		error (1, errno, CHANNEL_CANTSEND);
	}
	if (readpacket (channel, message, sizeof (* message)) <= 0)
	{
		error (1, errno, CHANNEL_CANTREAD);
	}
	network = (struct network *) (& networks->networks);
	while (networks->NUMAVLNS--)
	{
		memcpy(cco_macaddr, network->CCO_MAC, sizeof(network->CCO_MAC));
		station = (struct station *) (& network->stations);
		while (network->NUMSTAS--)
		{
			station++;
		}
		network = (struct network *) (station);
	}
	return (0);
}

signed ProxyNetworkInfo (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed hidden_sta_info
	{        
		uint8_t MACAddr [ETHER_ADDR_LEN];
		uint8_t TEI;
	}
	* hidden_sta_info;

	struct __packed proxynetwork
	{
		uint8_t PCoMACAddr [ETHER_ADDR_LEN];
		uint8_t PCoTEI;
		uint8_t NumHSTAs;
		struct hidden_sta_info hidden_sta_info[MAX_HIDDEN_STA];
	}
	* proxynetwork;

	struct __packed vs_proxy_network_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_proxy_network_info_request *) (message);
	
	struct __packed vs_proxy_network_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t NUM_PCOs;
		struct proxynetwork proxynetworks [1];
	}
	* confirm = (struct vs_proxy_network_info_confirm *) (message);

	uint8_t pco_counter;
	uint8_t hsta_counter;
	uint8_t cco_macaddr [ETHER_ADDR_LEN];
	char string [24];

#ifndef __GNUC__
#pragma pack (pop)
#endif

	GetCCoMacAddress(plc, cco_macaddr);
	printf ("CCo MacAddress%20s\n", hexstring (string, sizeof (string), cco_macaddr, sizeof (cco_macaddr)));

	Request (plc, "Proxy Network Info");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, cco_macaddr, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_PROXY_NW_INFO | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_PROXY_NW_INFO | MMTYPE_CNF)) > 0)
	{
		Confirm (plc, "Found %d PCo(s)\n", confirm->NUM_PCOs);
		proxynetwork = (struct proxynetwork *) (confirm->proxynetworks);
		pco_counter = 0; 
		while (confirm->NUM_PCOs-- > 0)
		{
			char string [24];
			pco_counter++;
			printf ("PCo[%d]\n", pco_counter);
			printf ("\t\tPCo MacAddress = %s\n", hexstring (string, sizeof (string), proxynetwork->PCoMACAddr, sizeof (proxynetwork->PCoMACAddr)));
			printf ("\t\tPCo TEI = %d\n", proxynetwork->PCoTEI);
			printf ("\t\tNumber of HSTAs = %d\n", proxynetwork->NumHSTAs);

			hidden_sta_info = (struct hidden_sta_info *) (proxynetwork->hidden_sta_info); 
			hsta_counter = 0; 
			while(proxynetwork->NumHSTAs-- > 0)
			{
				char string [24];
				hsta_counter++;
				printf ("\t\tHSTA[%d]\n", hsta_counter);
				printf ("\t\t\t\tHSTA MacAddress = %s\n", hexstring (string, sizeof (string), hidden_sta_info->MACAddr, sizeof (hidden_sta_info->MACAddr)));
				printf ("\t\t\t\tHSTA TEI = %d\n", hidden_sta_info->TEI);
				hidden_sta_info++;
			}
			printf ("\n");
			proxynetwork++;
		}
	}
	return (0);
}

#endif



