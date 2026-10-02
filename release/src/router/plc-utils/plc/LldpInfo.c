/*====================================================================*
 *	Copyright (c) 2020 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   signed LldpInfo (struct plc * plc);
 *
 *
 *   displays the routing table using VS_LLDP_INFO message;
 *
 *   Contributor(s):
 *      Kalaivani Somasundaram <kalaivan@qti.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef LLDPINFO_SOURCE
#define LLDPINFO_SOURCE

#include <stdint.h>
#include <stdlib.h>

#include "../plc/plc.h"
#include "../tools/error.h"

#define CHASSISIDLENGTH 255
#define PORTIDLENGTH 255
#define PORTDESCLENGTH 256
#define CHASSISID_SUBTYPE_MAC 4
#define CHASSISID_SUBTYPE_NW 5
#define PORTID_SUBTYPE_MAC 3
#define PORTID_SUBTYPE_NW 4
#define ID_NW_ADDR_IPv4 1
#define ID_NW_ADDR_IPv6 2

signed LldpInfo (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed chassis_id_info
	{
		uint16_t 	mChassisIdLength;
		uint8_t		mChassisIdSubtype;
		uint8_t		mChassisId[CHASSISIDLENGTH+1];
	}
	* chassis_id_info;

	struct __packed port_id_info
	{
		uint16_t 	mPortIdLength;
		uint8_t		mPortIdSubtype;
		uint8_t		mPortId[PORTIDLENGTH+1];
	}
	* port_id_info;
		
	struct __packed port_desc_info
	{
		uint16_t 	mPortDescLength;
		uint8_t		mPortDesc[PORTDESCLENGTH+1];
	}
	* port_desc_info;

	struct __packed lldp_info_rx
	{
		uint8_t		mSourceMac [ETHER_ADDR_LEN];
		struct chassis_id_info	mChassisIdInfo;
		struct port_id_info		mPortIdInfo;
		struct port_desc_info	mPortDescInfo;
		uint16_t	mTTL;
		int64_t		mTimeStamp;
	}
	* lldp_info_rx;

	struct __packed vs_lldp_info_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_lldp_info_request *) (message);
	
	struct __packed vs_lldp_info_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t status;
        uint8_t num_of_peers;
		struct lldp_info_rx lldp_info_table [1];
	}
	* confirm = (struct vs_lldp_info_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Lldp Info");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_LLDP_INFO | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), ECANCELED, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadFMI (plc, 1, (VS_LLDP_INFO | MMTYPE_CNF)) <= 0) 
	{ 
		error (1, ECANCELED, CHANNEL_CANTREAD); 
	} 
	confirm = (struct vs_lldp_info_confirm *) (plc->content); 
	if (confirm->status) 
	{ 
		Failure (plc, PLC_WONTDOIT); 
	}

	Confirm (plc, "Found %d entry(ies)\n", confirm->num_of_peers);
	lldp_info_rx = (struct lldp_info_rx *) (confirm->lldp_info_table);
	
	if(confirm->num_of_peers > 0)
	{
		uint8_t count;
		count = 0;
		while (confirm->num_of_peers-- > 0)
		{
			char string [257];

			chassis_id_info = (struct chassis_id_info *) &(lldp_info_rx->mChassisIdInfo);
			port_id_info = (struct port_id_info *) &(lldp_info_rx->mPortIdInfo);
			port_desc_info = (struct port_desc_info *) &(lldp_info_rx->mPortDescInfo);

			printf ("Peer %d\t\n", count);
		
			memset(string, 0, sizeof(string));
			printf ("\t Source Mac: %s\t\n", hexstring (string, sizeof (string), lldp_info_rx->mSourceMac, sizeof(lldp_info_rx->mSourceMac)));
			printf ("\t TTL: %d\t\n", lldp_info_rx->mTTL);

			memset(string, 0, sizeof(string));
			if(chassis_id_info->mChassisIdSubtype == CHASSISID_SUBTYPE_MAC) {
				printf ("\t Chassis Id: %s\t\n", hexstring (string, sizeof (string), chassis_id_info->mChassisId, chassis_id_info->mChassisIdLength));
			} 
			else if(chassis_id_info->mChassisIdSubtype == CHASSISID_SUBTYPE_NW) {
				if(chassis_id_info->mChassisId[0] == ID_NW_ADDR_IPv4) {
					printf ("\t Chassis Id: %s\t\n", hex2IPv4 (string, sizeof (string), &chassis_id_info->mChassisId[1], chassis_id_info->mChassisIdLength-1));
				}
				else {
					printf ("\t Chassis Id: %s\t\n", hexstring (string, sizeof (string), chassis_id_info->mChassisId, chassis_id_info->mChassisIdLength));
				}
			}
			else {
				printf ("\t Chassis Id: %s\t\n", chassis_id_info->mChassisId);
			}
			
			memset(string, 0, sizeof(string));
			if(port_id_info->mPortIdSubtype == PORTID_SUBTYPE_MAC) {
				printf ("\t Port Id: %s\t\n", hexstring (string, sizeof (string), port_id_info->mPortId, port_id_info->mPortIdLength));
			} 
			else if(port_id_info->mPortIdSubtype == PORTID_SUBTYPE_NW) {
				if(port_id_info->mPortId[0] == ID_NW_ADDR_IPv4) {
					printf ("\t port Id: %s\t\n", hex2IPv4 (string, sizeof (string), &port_id_info->mPortId[1], port_id_info->mPortIdLength-1));
				}
				else {
					printf ("\t Port Id: %s\t\n", hexstring (string, sizeof (string), port_id_info->mPortId, port_id_info->mPortIdLength));
				}
			}
			else {
				printf ("\t Port Id: %s\t\n", port_id_info->mPortId);
			}
			
			memset(string, 0, sizeof(string));
			printf ("\t Port Desc: %s\t\n", port_desc_info->mPortDesc);
			
			lldp_info_rx++;
			count++;
		}
	}
	
	free (plc->content); 
	plc->content = NULL; 
	return (0);
}

#endif