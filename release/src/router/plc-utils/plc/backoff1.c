/*====================================================================*
 *	Copyright (c) 2018-2019 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   backoff1.c
 *
 *   Contributor(s):
 *      Nisha K <nishk@qti.qualcomm.com>
 *		Kalaivani Somasundaram <kalaivan@qti.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <sys/time.h>
#include <math.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../tools/number.h"
#include "../tools/timer.h"
#include "../tools/endian.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/tlv.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../plc/Devices.c"
#include "../plc/Failure.c"
#include "../plc/ReadMME.c"
#include "../plc/SendMME.c"
#endif

#ifndef MAKEFILE
#include "../tools/error.c"
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/hexload.c"
#include "../tools/timer.h"
#include "../tools/hexdump.c"
#include "../tools/hexencode.c"
#include "../tools/hexdecode.c"
#include "../tools/hexstring.c"
#include "../tools/todigit.c"
#include "../tools/synonym.c"
#endif

#ifndef MAKEFILE
#include "../ether/openchannel.c"
#include "../ether/closechannel.c"
#include "../ether/readpacket.c"
#include "../ether/sendpacket.c"
#include "../ether/channel.c"
#endif

#ifndef MAKEFILE
#include "../mme/EthernetHeader.c"
#include "../mme/QualcommHeader.c"
#include "../mme/UnwantedMessage.c"
#include "../mme/MMECode.c"
#endif

#define maxnumofbanddescriptor	16
#define minfrequencyindex		0
#define maxfrequencyindex		336

#ifndef __GNUC__
#pragma pack (push,1)
#endif
	struct __packed band {
		uint16_t startidx;
		uint8_t startbackoffdB;
		uint16_t endidx;
		uint8_t endbackoffdB;
	};
	typedef struct band banddesc;

	struct __packed freqband {
		double startfrequency;
		uint8_t startbackoffdB;
		double endfrequency;
		uint8_t endbackoffdB;
	};
	typedef struct freqband freqbanddesc;
#ifndef __GNUC__
#pragma pack (pop)
#endif

uint8_t traffic_peer[ETHER_ADDR_LEN] = {0};
bool unallowed_with_reset_check_flag = false;

double vfrequencyindexmap[] = { 1.8, 2.0, 2.1, 2.3, 2.5, 2.7, 2.9, 3.1, 3.3, 3.5, 3.7, 3.9, 4.1, 4.3, 4.5,
								4.7, 4.9, 5.1, 5.3, 5.5, 5.7, 5.9, 6.1, 6.2, 6.4, 6.6, 6.8, 7.0, 7.2, 7.4,
								7.6, 7.8, 8.0, 8.2, 8.4, 8.6, 8.8, 9.0, 9.2, 9.4, 9.6, 9.8, 10.0, 10.2, 10.4,
								10.5, 10.7, 10.9, 11.1, 11.3, 11.5, 11.7, 11.9, 12.1, 12.3, 12.5, 12.7, 12.9, 13.1, 13.3,
								13.5, 13.7, 13.9, 14.1, 14.3, 14.5, 14.6, 14.8, 15.0, 15.2, 15.4, 15.6, 15.8, 16.0, 16.2,
								16.4, 16.6, 16.8, 17.0, 17.2, 17.4, 17.6, 17.8, 18.0, 18.2, 18.4, 18.6, 18.7, 18.9, 19.1,
								19.3, 19.5, 19.7, 19.9, 20.1, 20.3, 20.5, 20.7, 20.9, 21.1, 21.3, 21.5, 21.7, 21.9, 22.1,
								22.3, 22.5, 22.7, 22.9, 23.0, 23.2, 23.4, 23.6, 23.8, 24.0, 24.2, 24.4, 24.6, 24.8, 25.0,
								25.2, 25.4, 25.6, 25.8, 26.0, 26.2, 26.4, 26.6, 26.8, 27.0, 27.1, 27.3, 27.5, 27.7, 27.9,
								28.1, 28.3, 28.5, 28.7, 28.9, 29.1, 29.3, 29.5, 29.7, 29.9, 30.1, 30.3, 30.5, 30.7, 30.9,
								31.1, 31.2, 31.4, 31.6, 31.8, 32.0, 32.2, 32.4, 32.6, 32.8, 33.0, 33.2, 33.4, 33.6, 33.8,
								34.0, 34.2, 34.4, 34.6, 34.8, 35.0, 35.2, 35.4, 35.5, 35.7, 35.9, 36.1, 36.3, 36.5, 36.7,
								36.9, 37.1, 37.3, 37.5, 37.7, 37.9, 38.1, 38.3, 38.5, 38.7, 38.9, 39.1, 39.3, 39.5, 39.6,
								39.8, 40.0, 40.2, 40.4, 40.6, 40.8, 41.0, 41.2, 41.4, 41.6, 41.8, 42.0, 42.2, 42.4, 42.6,
								42.8, 43.0, 43.2, 43.4, 43.6, 43.7, 43.9, 44.1, 44.3, 44.5, 44.7, 44.9, 45.1, 45.3, 45.5,
								45.7, 45.9, 46.1, 46.3, 46.5, 46.7, 46.9, 47.1, 47.3, 47.5, 47.7, 47.9, 48.0, 48.2, 48.4,
								48.6, 48.8, 49.0, 49.2, 49.4, 49.6, 49.8, 50.0, 50.2, 50.4, 50.6, 50.8, 51.0, 51.2, 51.4,
								51.6, 51.8, 52.0, 52.1, 52.3, 52.5, 52.7, 52.9, 53.1, 53.3, 53.5, 53.7, 53.9, 54.1, 54.3,
								54.5, 54.7, 54.9, 55.1, 55.3, 55.5, 55.7, 55.9, 56.1, 56.2, 56.4, 56.6, 56.8, 57.0, 57.2,
								57.4, 57.6, 57.8, 58.0, 58.2, 58.4, 58.6, 58.8, 59.0, 59.2, 59.4, 59.6, 59.8, 60.0, 60.2,
								60.4, 60.5, 60.7, 60.9, 61.1, 61.3, 61.5, 61.7, 61.9, 62.1, 62.3, 62.5, 62.7, 62.9, 63.1,
								63.3, 63.5, 63.7, 63.9, 64.1, 64.3, 64.5, 64.6, 64.8, 65.0, 65.2, 65.4, 65.6, 65.8, 66.0,
								66.2, 66.4, 66.6, 66.8, 67.0, 67.2, 67.4 };

/*====================================================================*
 *
 *   signed getprescalervalues (struct plc * plc, uint8_t numofbands);
 *
 *===================================================================*/

static signed getprescalervalues (struct plc * plc)
{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
		
#ifndef __GNUC__
#pragma pack (push,1)
#endif
	
	struct __packed vs_get_prescaler_backoff_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t RESERVED[4];
	}
	* request = (struct vs_get_prescaler_backoff_request *) (message);
	
	struct __packed vs_get_prescaler_backoff_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t NUMOFBANDSPRIMARY;
		banddesc BANDDESC_PRI[16];
		uint8_t NUMOFBANDSALTERNATE;
		banddesc BANDDESC_ALT[16];
	}
	* confirm = (struct vs_get_prescaler_backoff_confirm *) (message);
#ifndef __GNUC__
#pragma pack (pop)
#endif

	uint8_t i;
	
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_GET_PRESCALER_BACKOFF | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	
	if (ReadMME (plc, 0, (VS_GET_PRESCALER_BACKOFF | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
		
	if (confirm->NUMOFBANDSPRIMARY) 
	{
		for (i=0; i<confirm->NUMOFBANDSPRIMARY; i++)
		{
			printf("Pri: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
					vfrequencyindexmap[confirm->BANDDESC_PRI[i].startidx], vfrequencyindexmap[confirm->BANDDESC_PRI[i].endidx], 
					confirm->BANDDESC_PRI[i].startbackoffdB, confirm->BANDDESC_PRI[i].endbackoffdB);
		}
	}
	
	if (confirm->NUMOFBANDSALTERNATE) 
	{
		for (i=0; i<confirm->NUMOFBANDSALTERNATE; i++)
		{		
			printf("Alt: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
					vfrequencyindexmap[confirm->BANDDESC_ALT[i].startidx], vfrequencyindexmap[confirm->BANDDESC_ALT[i].endidx], 
					confirm->BANDDESC_ALT[i].startbackoffdB, confirm->BANDDESC_ALT[i].endbackoffdB);
		}
	}

	return 0;
}

/*================================================================================================================================================*
 *
 *   signed setprescalervalues (struct plc * plc, banddesc* aBandDescriptorArray, uint8_t numofbands, uint8_t duration, uint8_t trafficgen_rate);
 *
 *===============================================================================================================================================*/

static signed setprescalervalues (struct plc * plc, banddesc* banddescriptorarray, uint8_t numofbands, uint8_t duration, uint8_t trafficgen_rate)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif
	
	struct __packed vs_set_prescaler_backoff_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t COUPLING;
		uint8_t NUMOFFREQBANDS;
		banddesc BANDDESCRIPTOR[16];
		uint8_t mDuration;
		uint8_t mDestMAC_ForTraffic[ETHER_ADDR_LEN];
		uint8_t TRAFFICGEN_RATE;
	}
	* request = (struct vs_set_prescaler_backoff_request *) (message);

	struct __packed vs_set_prescaler_backoff_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
	}
	* confirm = (struct vs_set_prescaler_backoff_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif
	
	int length = numofbands * sizeof(banddesc);

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SET_PRESCALER_BACKOFF | MMTYPE_REQ));
	plc->packetsize = sizeof (struct vs_set_prescaler_backoff_request);
	request->COUPLING = plc->coupling;
	request->NUMOFFREQBANDS = numofbands;
	memcpy (request->BANDDESCRIPTOR, banddescriptorarray, length);
	request->mDuration = duration;
	memcpy (request->mDestMAC_ForTraffic, traffic_peer, ETHER_ADDR_LEN);
	request->TRAFFICGEN_RATE = trafficgen_rate;
	
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_SET_PRESCALER_BACKOFF | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	
	if (confirm->MSTATUS == 0x01) {
		printf("Invalid Coupling\n");
	} else if (confirm->MSTATUS == 0x02) {
		printf("Invalid Band Descriptor\n");
	} else if (confirm->MSTATUS == 0x03) {
		printf("Operation not permitted\n");
	} else if (confirm->MSTATUS == 0x04) {
		printf("Invalid Number of Bands\n");
	} else if (confirm->MSTATUS == 0x06) {
		printf("Previous Backoff In-progress\n");
	} else if (confirm->MSTATUS == 0x08) {
		printf("Invalid Duration\n");
	} else if (confirm->MSTATUS == 0x0C) {
		printf("Invalid trafficgen rate\n");
	}
	
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}

	return (0);
}

/*====================================================================*
 *
 *   signed getindication1 (struct plc * plc);
 *
 *===================================================================*/

static signed getindication1 (struct plc * plc)

{
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	uint8_t i;
	bool rcvd = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif
	
	struct __packed vs_set_prescaler_backoff_ind
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t NUMOFBANDSPRIMARY;
		banddesc BANDDESC_PRI[16];
		uint8_t NUMOFBANDSALTERNATE;
		banddesc BANDDESC_ALT[16];
	}
	* indicate = (struct vs_set_prescaler_backoff_ind *) (message);
#ifndef __GNUC__
#pragma pack (pop)
#endif
	
	memset (message, 0, sizeof (* message));

	printf("\n");

	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < 90; timer = SECONDS (ts, tc)) //wait 90 secs for indication
	{
		if (ReadMME (plc, 0, (VS_SET_PRESCALER_BACKOFF | MMTYPE_IND)) > 0)
		{	
			rcvd = 1;
			break;
		}
		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
	}

	if(!rcvd)
	{
		error (PLC_EXIT (plc), errno, "IND MME not received");
		return (-1);
	}
	
	if (indicate->MSTATUS == 0x00) {
		printf("New Backoff Applied\n");
	} else if(indicate->MSTATUS == 0x05) {
		printf("New Backoff Caused Link Loss.. Previous Backoff Restored\n");
		return (-1);
	} else if (indicate->MSTATUS == 0x07) {
		error (PLC_EXIT (plc), errno, "Failed to Apply New Backoff");
		return (-1);
	} else if(indicate->MSTATUS == 0x09) {
		error (PLC_EXIT (plc), errno, "Failed to Restore Previous Backoff");
		return (-1);
	} else if (indicate->MSTATUS == 0x0A) {
		printf("New Backoff Applied. But, Traffic Failed\n");
	} else if (indicate->MSTATUS == 0x0B) {
		printf("New Backoff Applied and Traffic Generated\n");
	} else {
		error (PLC_EXIT (plc), errno, "unknown indication1 received");
		return (-1);
	}

	if (indicate->NUMOFBANDSPRIMARY) 
	{
		for (i=0; i<indicate->NUMOFBANDSPRIMARY; i++)
		{
			printf("Pri: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
					vfrequencyindexmap[indicate->BANDDESC_PRI[i].startidx], vfrequencyindexmap[indicate->BANDDESC_PRI[i].endidx], 
					indicate->BANDDESC_PRI[i].startbackoffdB, indicate->BANDDESC_PRI[i].endbackoffdB);
		}
	}
	
	if (indicate->NUMOFBANDSALTERNATE) 
	{
		for (i=0; i<indicate->NUMOFBANDSALTERNATE; i++)
		{		
			printf("Alt: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
					vfrequencyindexmap[indicate->BANDDESC_ALT[i].startidx], vfrequencyindexmap[indicate->BANDDESC_ALT[i].endidx], 
					indicate->BANDDESC_ALT[i].startbackoffdB, indicate->BANDDESC_ALT[i].endbackoffdB);
		}
	}

	return (0);
}

/*====================================================================*
 *
 *   signed getindication2 (struct plc * plc, uint8_t duration);
 *
 *===================================================================*/

static signed getindication2 (struct plc * plc, uint8_t duration)

{
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	bool rcvd = 0;
	uint8_t i;
	unsigned ind_timer = duration + 90;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_set_prescaler_backoff_ind
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t NUMOFBANDSPRIMARY;
		banddesc BANDDESC_PRI[16];
		uint8_t NUMOFBANDSALTERNATE;
		banddesc BANDDESC_ALT[16];
	}
	* indicate = (struct vs_set_prescaler_backoff_ind *) (message);
#ifndef __GNUC__
#pragma pack (pop)
#endif
	
	
	memset (message, 0, sizeof (* message));
		
	printf("\n");
	
	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < ind_timer; timer = SECONDS (ts, tc)) //wait 90 secs for indication
	{
		if (ReadMME (plc, 0, (VS_SET_PRESCALER_BACKOFF | MMTYPE_IND)) > 0)
		{	
			rcvd = 1;
			break;
		}
		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
	}

	if(!rcvd)
	{
		error (PLC_EXIT (plc), errno, "IND MME not received");
		return (-1);
	}
	
	if(indicate->MSTATUS == 0x05) {
		printf("Previous Backoff Restored\n");
	} else if(indicate->MSTATUS == 0x09) {
		error (PLC_EXIT (plc), errno, "Failed to Restore Previous Backoff");
		return (-1);
	} else {
		error (PLC_EXIT (plc), errno, "unknown indication2 received");
		return (-1);
	}

	if (indicate->NUMOFBANDSPRIMARY) 
	{
		for (i=0; i<indicate->NUMOFBANDSPRIMARY; i++)
		{
			printf("Pri: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
					vfrequencyindexmap[indicate->BANDDESC_PRI[i].startidx], vfrequencyindexmap[indicate->BANDDESC_PRI[i].endidx], 
					indicate->BANDDESC_PRI[i].startbackoffdB, indicate->BANDDESC_PRI[i].endbackoffdB);
		}
	}
	
	if (indicate->NUMOFBANDSALTERNATE) 
	{
		for (i=0; i<indicate->NUMOFBANDSALTERNATE; i++)
		{
			printf("Alt: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
					vfrequencyindexmap[indicate->BANDDESC_ALT[i].startidx], vfrequencyindexmap[indicate->BANDDESC_ALT[i].endidx], 
					indicate->BANDDESC_ALT[i].startbackoffdB, indicate->BANDDESC_ALT[i].endbackoffdB);
		}
	}

	return (0);
}

/*====================================================================*
 *
 *   signed getindication3 (struct plc * plc);
 *
 *===================================================================*/

static signed getindication3 (struct plc * plc)

{
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;
	uint8_t i;
	bool rcvd = 0;
	bool reset_done = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif
	
	struct __packed vs_set_prescaler_backoff_ind
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t NUMOFBANDSPRIMARY;
		banddesc BANDDESC_PRI[16];
		uint8_t NUMOFBANDSALTERNATE;
		banddesc BANDDESC_ALT[16];
	}
	* indicate = (struct vs_set_prescaler_backoff_ind *) (message);
#ifndef __GNUC__
#pragma pack (pop)
#endif
	
	memset (message, 0, sizeof (* message));

	printf("\n");

	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < 90; timer = SECONDS (ts, tc)) //wait 90 secs for indication
	{
		if (ReadMME (plc, 0, (VS_SET_PRESCALER_BACKOFF | MMTYPE_IND)) > 0)
		{	
			rcvd = 1;
			break;
		}
		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
	}

	if(!rcvd)
	{
		error (PLC_EXIT (plc), errno, "IND MME not received");
		return (-1);
	}
	
	if (indicate->MSTATUS == 0x00) {
		if(plc->coupling == 0) {
			if(indicate->NUMOFBANDSPRIMARY == 1) {
				if((indicate->BANDDESC_PRI[0].startidx == minfrequencyindex)
					&& (indicate->BANDDESC_PRI[0].endidx ==  maxfrequencyindex)
					&& (indicate->BANDDESC_PRI[0].startbackoffdB == 0)
					&& (indicate->BANDDESC_PRI[0].endbackoffdB == 0) ) 
				{
					printf("Reset Successfull in Primary Coupling\n");
					reset_done = 1;
				}
			}
		} else if(plc->coupling == 1) {
			if(indicate->NUMOFBANDSALTERNATE == 1) {
				if((indicate->BANDDESC_ALT[0].startidx == minfrequencyindex)
					&& (indicate->BANDDESC_ALT[0].endidx ==  maxfrequencyindex)
					&& (indicate->BANDDESC_ALT[0].startbackoffdB == 0)
					&& (indicate->BANDDESC_ALT[0].endbackoffdB == 0)) 
				{
					printf("Reset Successfull in Alternate Coupling\n");
					reset_done = 1;
				}
			}
		} else if(plc->coupling == 2) {
			if(indicate->NUMOFBANDSPRIMARY == 1 && indicate->NUMOFBANDSALTERNATE == 1) {
				if((indicate->BANDDESC_PRI[0].startidx == minfrequencyindex)
					&& (indicate->BANDDESC_PRI[0].endidx ==  maxfrequencyindex)
					&& (indicate->BANDDESC_PRI[0].startbackoffdB == 0)
					&& (indicate->BANDDESC_PRI[0].endbackoffdB == 0) 
					&& (indicate->BANDDESC_ALT[0].startidx == minfrequencyindex)
					&& (indicate->BANDDESC_ALT[0].endidx ==  maxfrequencyindex)
					&& (indicate->BANDDESC_ALT[0].startbackoffdB == 0)
					&& (indicate->BANDDESC_ALT[0].endbackoffdB == 0)) 
				{
					printf("Reset Successfull in Primary and Alternate Coupling\n");
					reset_done = 1;
				}
			}
		}
		
		
		if(reset_done == 0)
		{
			printf("Reset Failed\n");
			if (indicate->NUMOFBANDSPRIMARY) 
			{
				for (i=0; i<indicate->NUMOFBANDSPRIMARY; i++)
				{
					printf("Pri: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
							vfrequencyindexmap[indicate->BANDDESC_PRI[i].startidx], vfrequencyindexmap[indicate->BANDDESC_PRI[i].endidx], 
							indicate->BANDDESC_PRI[i].startbackoffdB, indicate->BANDDESC_PRI[i].endbackoffdB);
				}
			}
			
			if (indicate->NUMOFBANDSALTERNATE) 
			{
				for (i=0; i<indicate->NUMOFBANDSALTERNATE; i++)
				{
					printf("Alt: %4.1f - %4.1f MHz : %2d - %2d dB\n", 
							vfrequencyindexmap[indicate->BANDDESC_ALT[i].startidx], vfrequencyindexmap[indicate->BANDDESC_ALT[i].endidx], 
							indicate->BANDDESC_ALT[i].startbackoffdB, indicate->BANDDESC_ALT[i].endbackoffdB);
				}
			}
		}
	} else if (indicate->MSTATUS == 0x07) {
		error (PLC_EXIT (plc), errno, "Failed to Reset");
		return (-1);	
	} else {
		error (PLC_EXIT (plc), errno, "unknown indication3 received");
		return (-1);
	}

	return (0);
}

double changeprecision(double num, double precision) 
{ 
    return floor(pow(10,precision)*num)/pow(10,precision); 
}

/*====================================================================*
 *
 *   banddesc parsebanddescriptor(char * aOptarg);
 *
 *===================================================================*/

freqbanddesc parsebanddescriptor(char * optarg)
{
	char *tokens, *varoptarg;
	const char *delimiters;
	uint16_t i; uint8_t parsedcount;
	freqbanddesc parsedfreqbanddescriptor;
	double temp;

	i = 0; temp = 0.0;
	varoptarg = optarg;
	// Trim the brackets
	while( varoptarg[i] != '\0' )
	{
		if(varoptarg[i] == '[')
		{ 
			varoptarg += i+1;
			continue;
		}
		if(varoptarg[i] == ']') {
			varoptarg[i] = '\0';
			break;
		}
		i++;
	}

	parsedcount = 0;
	delimiters = ",";
	tokens = strtok(varoptarg, delimiters);
	
	while(tokens != NULL)
	{
		switch(parsedcount)
		{
			case 0:
				temp = atof(tokens);
				temp = changeprecision(temp,1);
				if( temp < vfrequencyindexmap[minfrequencyindex] ) {
					temp = vfrequencyindexmap[minfrequencyindex];
				} else if ( temp > vfrequencyindexmap[maxfrequencyindex] )	{
					temp = vfrequencyindexmap[maxfrequencyindex];
				}
				parsedfreqbanddescriptor.startfrequency = temp;
				break;
			case 1:
				temp = atof(tokens);
				temp = changeprecision(temp,1);
				if( temp < vfrequencyindexmap[minfrequencyindex] ) {
					temp = vfrequencyindexmap[minfrequencyindex];
				} else if ( temp > vfrequencyindexmap[maxfrequencyindex] )	{
					temp = vfrequencyindexmap[maxfrequencyindex];
				}
				parsedfreqbanddescriptor.endfrequency = temp;
				break;
			case 2:
				parsedfreqbanddescriptor.startbackoffdB = atoi(tokens);
				break;
			case 3:
				parsedfreqbanddescriptor.endbackoffdB = atoi(tokens);
				break;
			default:
				//do nothing
				break;
		}
		tokens = strtok(NULL, delimiters);
		parsedcount++;
	}

	if(parsedcount != 4) {
		error (1, errno, "Invalid Band Descriptor");
	}

	return parsedfreqbanddescriptor;
}

void sortdescriptorsandcheckoverlap(freqbanddesc* freqbanddescriptorarray, uint8_t numofbands)
{
	uint8_t i, j;
	freqbanddesc varfreqbanddesc;

	//sort descriptors
	for (i = 1; i < numofbands; i++)
	{
		for(j = 0; j < numofbands-i; j++)
		{
			if(freqbanddescriptorarray[j].startfrequency > freqbanddescriptorarray[j+1].startfrequency)
			{
				varfreqbanddesc = freqbanddescriptorarray[j];
				freqbanddescriptorarray[j] = freqbanddescriptorarray[j+1];
				freqbanddescriptorarray[j+1] = varfreqbanddesc;
			}
		}
	}

	//check for overlap
	for(i = 1; i < numofbands; i++)
	{
		if(freqbanddescriptorarray[i].startfrequency <= freqbanddescriptorarray[i-1].endfrequency)
		{
			error (1, errno, "Invalid band descriptor: overlapping frequencies");
		}
	}
	return;
}

void mapfrequencytoindex(freqbanddesc* freqbanddescriptorarray, banddesc* banddescriptorarray, uint8_t numofbands)
{
	uint8_t i; uint16_t j;
	
	memset(banddescriptorarray, 0x00, sizeof(banddesc)*maxnumofbanddescriptor);
	// Fill start frequency
	for(i = 0; i < numofbands; i++)
	{
		for(j = minfrequencyindex; j <= maxfrequencyindex; j++)
		{
			if(vfrequencyindexmap[j] == freqbanddescriptorarray[i].startfrequency)
			{
				banddescriptorarray[i].startidx = j;
				break;
			}
			else if(vfrequencyindexmap[j] > freqbanddescriptorarray[i].startfrequency)
			{
				banddescriptorarray[i].startidx = j-1;
				break;
			}
		}
	}

	// Fill end frequency
	for(i = 0; i < numofbands; i++)
	{
		for(j = minfrequencyindex; j <= maxfrequencyindex; j++)
		{
			if(vfrequencyindexmap[j] == freqbanddescriptorarray[i].endfrequency)
			{
				banddescriptorarray[i].endidx = j;
				break;
			}
			else if(vfrequencyindexmap[j] > freqbanddescriptorarray[i].endfrequency)
			{
				banddescriptorarray[i].endidx = j;
				break;
			}
		}
	}

	// Fill backoff
	for(i = 0; i < numofbands; i++)
	{
		banddescriptorarray[i].startbackoffdB = freqbanddescriptorarray[i].startbackoffdB;
		banddescriptorarray[i].endbackoffdB = freqbanddescriptorarray[i].endbackoffdB;
	}

	for(i = 1; i < numofbands; i++)
	{
		if(banddescriptorarray[i].startidx <= banddescriptorarray[i-1].endidx )
		{
			banddescriptorarray[i].startidx = banddescriptorarray[i-1].endidx + 1;
		}
	}

	return;
}

/*====================================================================================================================================*
 *
 *   void manager (struct plc * plc, banddesc* aBandDescriptorArray, uint8_t numofbands, uint8_t duration, uint8_t trafficgen_rate) ;
 *
 *====================================================================================================================================*/
 
void manager (struct plc * plc, freqbanddesc* freqbanddescriptorarray, uint8_t numofbands, uint8_t duration, uint8_t trafficgen_rate) 
{ 
	banddesc banddescriptorarray[maxnumofbanddescriptor];

	if (!(_anyset (plc->flags, PLC_SET_PRESCALER)) && !(_anyset (plc->flags, PLC_GET_PRESCALER)) && !(_anyset (plc->flags, PLC_RESET_BACKOFF)))
	{
		error (1, errno, "Missing mandatory argument: get(-g) or set(-b) or reset(-r)");
	} 
	
	if(!(_anyset (plc->flags, PLC_COUPLING)))
	{
		if(!(_anyset (plc->flags, PLC_GET_PRESCALER)))
			error (1, errno, "Missing mandatory argument: coupling");
	}
	
	if ((_anyset (plc->flags, PLC_SET_PRESCALER) && _anyset (plc->flags, PLC_GET_PRESCALER) && _anyset (plc->flags, PLC_RESET_BACKOFF)) ||
		(_anyset (plc->flags, PLC_SET_PRESCALER) && _anyset (plc->flags, PLC_GET_PRESCALER)) ||
		(_anyset (plc->flags, PLC_SET_PRESCALER) && _anyset (plc->flags, PLC_RESET_BACKOFF)) ||
		(_anyset (plc->flags, PLC_RESET_BACKOFF) && _anyset (plc->flags, PLC_GET_PRESCALER))
		)
	{
		error (1, errno, "get(-g), set(-b), reset(-r) are mutually exclusive");
	}
	
	if ((_anyset(plc->flags, PLC_DEV_TRAFFIC_UNIDI)) && (duration == 0))
	{
		error (1, errno, "Missing mandatory argument for traffic generation: timeout");
	}

	if((_anyset (plc->flags, PLC_RESET_BACKOFF)) && ( (unallowed_with_reset_check_flag) || (_anyset(plc->flags, PLC_DEV_TRAFFIC_UNIDI))))
	{
		error (1, errno, "-a, -d, -T options are not allowed along with -r");
	}

	if (_anyset (plc->flags, PLC_SET_PRESCALER))
	{
		sortdescriptorsandcheckoverlap(freqbanddescriptorarray, numofbands);
		mapfrequencytoindex(freqbanddescriptorarray, banddescriptorarray, numofbands);
		if(setprescalervalues(plc, banddescriptorarray, numofbands, duration, trafficgen_rate) == 0)
		{
			if(getindication1(plc) == 0)
			{
				if(duration)
				{
					getindication2(plc, duration);
				}
			}
		}		
	} 
	else if (_anyset (plc->flags, PLC_GET_PRESCALER)) 
	{
		getprescalervalues (plc);
	}
	else if (_anyset (plc->flags, PLC_RESET_BACKOFF))
	{
		memset (banddescriptorarray, 0x00, sizeof(banddesc)*maxnumofbanddescriptor);
		banddescriptorarray[0].startidx = minfrequencyindex;
		banddescriptorarray[0].endidx = maxfrequencyindex;
		banddescriptorarray[0].startbackoffdB = 0;
		banddescriptorarray[0].endbackoffdB = 0;
		numofbands = 1;
		if(setprescalervalues (plc, banddescriptorarray, numofbands, 0, trafficgen_rate) == 0)
		{
			getindication3(plc);
		}
	}
	return;
}

/*====================================================================*
 *
 *   int main (int argc, char const * argv[]);
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv [])

{
	extern struct channel channel;
	static char const * optv [] =
	{
		"a:b:c:d:egi:qrt:Tvx",
		"[device] [device] [...]",
		"Qualcomm QCA75xx Prescaler Control MME utility command line",
		"a\trate(Mbps)[" LITERAL (DEFAULT_TRAFFICGEN_RATE) "] of traffic sent to peer device",
		"b s\tset prescaler backoff values from band descriptor (s) - Example: [1.80,5.90,5,5]",
		"c n\tcoupling is (n) [0|1|2|'pri'|'alt'|'mimo']",
		"d\ttimeout for backoff (and traffic)",
		"e\tredirect stderr to stdout",
		"g\tget prescaler backoff values",
		
#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif
		"q\tquiet mode",
		"r\treset prescaler backoff",
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]",
		"T\tgenerate unidirectional traffic (node to peer)",
		"v\tverbose mode",
		"x\texit on error",
		(char const *) (0)
	};
	static const struct _term_ coupling [] =
	{
		{
			"alt",
			"1"
		},
		{
			"mimo",
			"2"
		},
		{
			"pri",
			"0"
		}
	};

#include "../plc/plc.c"

	freqbanddesc freqbanddescriptorarray[maxnumofbanddescriptor];
	uint8_t numofbands = 0;
	uint8_t duration = 0;
	uint8_t trafficgen_rate = DEFAULT_TRAFFICGEN_RATE;
	signed c;
	if (getenv (PLCDEVICE))
	{

#if defined (WINPCAP) || defined (LIBPCAP)

		channel.ifindex = atoi (getenv (PLCDEVICE));

#else

		channel.ifname = strdup (getenv (PLCDEVICE));

#endif

	}
	optind = 1;
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'a':
			trafficgen_rate = (unsigned) (uintspec (optarg, 0, 50));
			unallowed_with_reset_check_flag = true;
			break;
		case 'b':
			if( numofbands == maxnumofbanddescriptor)
				error (1, errno, "Exceeded maximum number of band desciptor. Maximum is 16");
			freqbanddescriptorarray[numofbands] = parsebanddescriptor(optarg);
			numofbands++;
			_setbits (plc.flags, PLC_SET_PRESCALER);
			break;
		case 'c':
			plc.coupling = (byte) (uintspec (synonym (optarg, coupling, SIZEOF (coupling)), 0, UCHAR_MAX));
			_setbits (plc.flags, PLC_COUPLING);
			break;
		case 'd':
			duration = (unsigned) (uintspec (optarg, 0, 60));
			unallowed_with_reset_check_flag = true;
			break;
		case 'e':
			dup2 (STDOUT_FILENO, STDERR_FILENO);
			break;
		case 'g':
			_setbits (plc.flags, PLC_GET_PRESCALER);
			break;
		case 'i':

#if defined (WINPCAP) || defined (LIBPCAP)

			channel.ifindex = atoi (optarg);

#else

			channel.ifname = optarg;

#endif
			break;
		case 'q':
			_setbits (channel.flags, CHANNEL_SILENCE);
			_setbits (plc.flags, PLC_SILENCE);
			break;
		case 'r':
			_setbits (plc.flags, PLC_RESET_BACKOFF);
			break;
		case 't':
			channel.timeout = (signed) (uintspec (optarg, 0, UINT_MAX));
			break;
		case 'T' :
			_setbits (plc.flags, PLC_DEV_TRAFFIC_UNIDI);
			break; 
		case 'v':
			_setbits (channel.flags, CHANNEL_VERBOSE);
			_setbits (plc.flags, PLC_VERBOSE);
			break;
		case 'x':
			_setbits (plc.flags, PLC_BAILOUT);
			break;
		default: 
			break;
		}
	}

	if (optind == 1)
		exit (0);

	if (_anyset (plc.flags, PLC_SET_PRESCALER))
	{
		if (!numofbands){
			error (1, errno, "Missing mandatory argument: band descriptor");
		}
	}

	argc -= optind;
	argv += optind;
	 
	openchannel (& channel);
	
	if (!(plc.message = malloc (sizeof (* plc.message))))
	{
		error (1, errno, PLC_NOMEMORY);
	}
	
	if (_anyset(plc.flags, PLC_DEV_TRAFFIC_UNIDI))
	{
		if (! argc || ! argv)
		{
			error (1, ECANCELED, "No node address given");
		}

		if (! hexencode (channel.peer, sizeof (channel.peer), synonym (* argv, devices, SIZEOF (devices))))
		{
			error (1, errno, PLC_BAD_MAC, *argv);
		}

		argv++;
		argc--;
		
		if (! argc || ! argv)
		{
			error (1, ECANCELED, "No peer address given");
		}
		
		if (! hexencode (traffic_peer, sizeof (traffic_peer), (char const *) (*argv)))
		{
			error (1, errno, PLC_BAD_MAC, * argv);
		}
		
		argv++;
		argc--;
		
		manager (& plc, freqbanddescriptorarray, numofbands, duration, trafficgen_rate);
	} 
	else if ((argc) && (* argv))
	{
		while ((argc) && (* argv))
		{
			if (! hexencode (channel.peer, sizeof (channel.peer), synonym (* argv, devices, SIZEOF (devices))))
			{
				error (1, errno, PLC_BAD_MAC, * argv);
			}
			manager (& plc, freqbanddescriptorarray, numofbands, duration, trafficgen_rate);
			argc--;
			argv++;
		}
	}
	else if (! argc)
	{
		manager (& plc, freqbanddescriptorarray, numofbands, duration, trafficgen_rate);
	}
	
	free (plc.message);
	closechannel (& channel);
	exit (0);
	
	return (0);
}

