/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed NetworkProbe (struct plc * plc);
 *
 *   nda.h
 *
 *   detect and report neighbor networks using the VS_DIAG_PROBE
 *   message;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NETWORKPROBE_SOURCE
#define NETWORKPROBE_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/error.h"

#define STAMODE_MAX 3
#define NETMODE_MAX 4

static char const * StationMode [STAMODE_MAX] =

{
	"Unassociated Station",
	"Associated not Authenticated",
	"Associated and Authenticated"
};

static char const * NetworkMode [NETMODE_MAX] =

{
	"AVLN Only",
	"Shared CSMA Hybrid",
	"Full Hybrid",
	"Hybrid Delimiters"
};

signed NetworkProbe (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed network
	{
		uint8_t NID [7];
		uint8_t SNID;
		uint8_t HybridMode;
		uint8_t NumSlots;
		uint8_t CoordinatingStatus;
		uint16_t Offset;
		uint8_t CCoMAC [ETHER_ADDR_LEN];
		uint16_t AvgPhyRate;
		uint8_t NumGood_Assoc_Auth;
		uint8_t NumBad_CouldNotAssoc;
		uint8_t NumBad_Assoc_Failure;
		uint8_t NumBad_CouldNotAuth;
		uint8_t NumLeave;
		uint8_t NumLeave_SameMaster;
		uint8_t NumLeave_NextMaster;
		uint8_t NumLeave_NeverReturn;
	}
	* network;
	struct __packed vs_diag_network_probe_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MCONTROL;
	}
	* request = (struct vs_diag_network_probe_request *) (message);
	struct __packed vs_diag_network_probe_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MCONTROL;
		uint8_t ASSOC_STATE;
		uint8_t SNID;
		uint8_t NUM_NETWORKS;
		struct network networks [1];
	}
	* confirm = (struct vs_diag_network_probe_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Network Probe");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_DIAG_NETWORK_PROBE | MMTYPE_REQ));
	request->MCONTROL = plc->action;
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_DIAG_NETWORK_PROBE | MMTYPE_CNF)) > 0)
	{
		Confirm (plc, "Found %d Network(s)\n", confirm->NUM_NETWORKS);
		printf ("\tstation->MODE = %s\n", StationMode [confirm->ASSOC_STATE]);
		printf ("\tstation->SNID = 0x%02X\n", confirm->SNID);
		printf ("\n");
		network = (struct network *) (confirm->networks);
		while (confirm->NUM_NETWORKS-- > 0)
		{
			char string [24];
			printf ("\t\tnetwork->NID = %s\n", hexstring (string, sizeof (string), network->NID, sizeof (network->NID)));
			printf ("\t\tnetwork->SNID = 0x%02X\n", network->SNID);
			printf ("\t\tnetwork->MODE = %s\n", NetworkMode [network->HybridMode]);
			printf ("\t\tnetwork->SLOTS = %d\n", network->NumSlots);
			printf ("\t\tnetwork->CCO = %s\n", hexstring (string, sizeof (string), network->CCoMAC, sizeof (network->CCoMAC)));
			printf ("\t\tnetwork->PHYRate = %d mbps\n", network->AvgPhyRate);
			printf ("\n");
			network++;
		}
	}
	return (0);
}

#endif



