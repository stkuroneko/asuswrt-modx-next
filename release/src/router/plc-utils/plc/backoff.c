/*====================================================================*
 *	Copyright (c) 2018 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   backoff.c
 *
 *   Contributor(s):
 *      Nisha K <nishk@qti.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <sys/time.h>

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
	typedef struct __packed {
		uint16_t startidx;
		uint8_t startbackoffdB;
		uint16_t endidx;
		uint8_t endbackoffdB;
	} banddesc;
	
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
	
	if (confirm->NUMOFBANDSPRIMARY) {
		printf("Frequency bands in Primary chain\n");
		printf("Band | Start index | Start back off(dB) | End index | End back off(dB)\n");
		for (i=0; i<confirm->NUMOFBANDSPRIMARY; i++)
		{
			printf("%d", i);
			printf("%10d", confirm->BANDDESC_PRI[i].startidx);
			printf("%#15x", confirm->BANDDESC_PRI[i].startbackoffdB);
			printf("%20d", confirm->BANDDESC_PRI[i].endidx);
			printf("%#15x\n", confirm->BANDDESC_PRI[i].endbackoffdB);
		}
	} else
		printf("No frequency bands in Primary chain\n");
	
	if (confirm->NUMOFBANDSALTERNATE) {
		printf("Frequency bands in Alternate chain\n");
		printf("Band | Start index | Start back off(dB) | End index | End back off(dB)\n");
		for (i=0; i<confirm->NUMOFBANDSALTERNATE; i++)
		{		
			printf("%d", i);
			printf("%10d", confirm->BANDDESC_ALT[i].startidx);
			printf("%#15x", confirm->BANDDESC_ALT[i].startbackoffdB);
			printf("%20d", confirm->BANDDESC_ALT[i].endidx);
			printf("%#15x\n", confirm->BANDDESC_ALT[i].endbackoffdB);
		}
	} else
		printf("No frequency bands in Alternate chain\n");

	return 0;
}

/*====================================================================*
 *
 *   signed setprescalervalues (struct plc * plc, uint8_t numofbands);
 *
 *===================================================================*/

static signed setprescalervalues (struct plc * plc, void* memory, uint8_t numofbands)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif
	typedef struct {
		uint16_t startidx;
		uint8_t startbackoffdB;
		uint16_t endidx;
		uint8_t endbackoffdB;
	} banddesc;
	
	struct __packed vs_set_prescaler_backoff_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t COUPLING;
		uint8_t NUMOFFREQBANDS;
		banddesc BANDDESCRIPTOR[16];
		uint8_t RESERVED[4];
	}
	* request = (struct vs_set_prescaler_backoff_request *) (message);

	struct __packed vs_set_prescaler_backoff_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
	}
	* confirm = (struct vs_set_prescaler_backoff_confirm *) (message);

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
	
	uint8_t i;
	int length = numofbands * 6;
	bool rcvd = 0;

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SET_PRESCALER_BACKOFF | MMTYPE_REQ));
	plc->packetsize = sizeof (struct vs_set_prescaler_backoff_request);
	request->COUPLING = plc->coupling;
	request->NUMOFFREQBANDS = numofbands;
	memcpy (request->BANDDESCRIPTOR, (byte *)memory, length);	
	
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
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}

	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < 30; timer = SECONDS (ts, tc)) //wait 30 secs for indication
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
	
	if (indicate->MSTATUS == 0x00)
	{
		printf("Back-off Applied Successfully\n");

	} else if(indicate->MSTATUS == 0x05) {
		printf("Previous Backoff Restored\n");

	} else if (indicate->MSTATUS == 0x07) {
		error (PLC_EXIT (plc), errno, "Backoff Request Failed");
		return (-1);
	}

	if (indicate->NUMOFBANDSPRIMARY) {
		printf("Frequency bands in Primary chain\n");
		printf("Band | Start index | Start back off(dB) | End index | End back off(dB)\n");
		for (i=0; i<indicate->NUMOFBANDSPRIMARY; i++)
		{
			printf("%d", i);
			printf("%10d", indicate->BANDDESC_PRI[i].startidx);
			printf("%#15x", indicate->BANDDESC_PRI[i].startbackoffdB);
			printf("%20d", indicate->BANDDESC_PRI[i].endidx);
			printf("%#15x\n", indicate->BANDDESC_PRI[i].endbackoffdB);
		}
	} else
		printf("No frequency bands in Primary chain\n");
	
	if (indicate->NUMOFBANDSALTERNATE) {
		printf("Frequency bands in Alternate chain\n");
		printf("Band | Start index | Start back off(dB) | End index | End back off(dB)\n");
		for (i=0; i<indicate->NUMOFBANDSALTERNATE; i++)
		{		
			printf("%d", i);
			printf("%10d", indicate->BANDDESC_ALT[i].startidx);
			printf("%#15x", indicate->BANDDESC_ALT[i].startbackoffdB);
			printf("%20d", indicate->BANDDESC_ALT[i].endidx);
			printf("%#15x\n", indicate->BANDDESC_ALT[i].endbackoffdB);
		}
	} else
		printf("No frequency bands in Alternate chain\n");

	return (0);
}

/*====================================================================*
 *
 *   void manager (struct plc * plc, uint8_t numofbands);
 *
 *===================================================================*/
 
void manager (struct plc * plc, void* memory, uint8_t numofbands) 
{ 
	if (_anyset (plc->flags, PLC_SET_PRESCALER))
	{
		setprescalervalues (plc, memory, numofbands);
	} else {
		getprescalervalues (plc);
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
		"c:egi:n:qs:t:vx",
		"device [device] [...]",
		"Qualcomm QCA75xx prescaler control MME utility",
		"c n\tcoupling [" LITERAL (PLCOUPLING) "]",
		"e\tredirect stderr to stdout",
		"g\tget prescaler values",

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif
		"n\tnumber of frequency bands",
		"q\tquiet mode",
		"s f\tset prescaler values from input file (f)\n\tinput file should contain only desriptor values",
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]",
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

	FILE * fp;
	byte memory [96];
	uint8_t numofbands = 0;
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
	memset (memory, 0, sizeof (memory));
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'c':
			plc.coupling = (byte) (uintspec (synonym (optarg, coupling, SIZEOF (coupling)), 0, UCHAR_MAX));
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
		case 'n':
			numofbands = (signed) (uintspec (optarg, 0, UINT_MAX));
			break;
		case 'q':
			_setbits (channel.flags, CHANNEL_SILENCE);
			_setbits (plc.flags, PLC_SILENCE);
			break;
		case 's':
			if (! (fp = fopen (optarg, "rb")))
			{
				error (1, errno, "%s", optarg);
			}
			hexload (memory, sizeof (memory), fp);
			fclose (fp);
			_setbits (plc.flags, PLC_SET_PRESCALER);
			break;
		case 't':
			channel.timeout = (signed) (uintspec (optarg, 0, UINT_MAX));
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
		if (!numofbands)
			error (1, errno, "missing mandatory arguments");
	}

	argc -= optind;
	argv += optind;
	 
	openchannel (& channel);
	
	if (!(plc.message = malloc (sizeof (* plc.message))))
	{
		error (1, errno, PLC_NOMEMORY);
	}
	if (! argc)
	{
		manager (& plc, memory, numofbands);
	}
	while ((argc) && (* argv))
	{
		if (! hexencode (channel.peer, sizeof (channel.peer), synonym (* argv, devices, SIZEOF (devices))))
		{
			error (1, errno, PLC_BAD_MAC, * argv);
		}
		manager (& plc, memory, numofbands);
		argc--;
		argv++;
	}
	free (plc.message);
	closechannel (& channel);
	exit (0);
	
	return (0);
}

