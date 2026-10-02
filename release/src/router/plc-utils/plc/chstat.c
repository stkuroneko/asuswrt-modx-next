/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   plcstat.c -
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/symbol.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../plc/chipset.c"
#include "../plc/Confirm.c"
#include "../plc/Display.c"
#include "../plc/Failure.c"
#include "../plc/Request.c"
#include "../plc/ReadMME.c"
#include "../plc/ReadFMI.c"
#include "../plc/SendMME.c"
#include "../plc/Devices.c"
#include "../plc/LocalDevices.c"
#include "../plc/NetworkInformation2.c"
#include "../plc/Topology2.c"
#include "../plc/Platform.c"
#include "../plc/WaitForStart.c"
#endif

#ifndef MAKEFILE
#include "../tools/error.c"
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/hexdump.c"
#include "../tools/hexencode.c"
#include "../tools/hexdecode.c"
#include "../tools/hexstring.c"
#include "../tools/todigit.c"
#include "../tools/synonym.c"
#include "../tools/typename.c"
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
#include "../mme/QualcommHeader1.c"
#include "../mme/UnwantedMessage.c"
#include "../mme/MMECode.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define PLCSTAT_LOOP 1
#define PLCSTAT_WAIT 0

#define PERCENT " %6.2f%%"
#define COUNTER " %20" PRId64

/*====================================================================*
 *   variables;
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push,1)
#endif

typedef struct __packed cheetah_transmit

{
	uint64_t RESERVED;
	uint64_t LAST_TIME_UPDATED;
	uint64_t NUMTXMPDU_ACKD;
	uint64_t NUMTXMPDU_COLL;
	uint64_t NUMTXMPDU_FAIL;
	uint64_t NUMTXPBS_PASSED;
	uint64_t NUMTXPBS_FAILED;
	uint32_t RESERVED1 [24];
}

transmit;
typedef struct __packed cheetah_receive

{
	uint64_t RESERVED;
	uint64_t LAST_TIME_UPDATED;
	uint64_t NUMRXMPDU_ACKD;
	uint64_t NUMRXMPDU_FAIL;
	uint64_t NUMRXPBS_PASSED;
	uint64_t NUMRXPBS_FAILED;
	uint64_t SUMTURBOBER_PASSED;
	uint64_t SUMTURBOBER_FAILED;
	uint64_t RESERVED1 [4];
	uint8_t NUMRXINTERVALS;
	uint8_t RESERVED2 [3];
	struct cheetah_receive_interval
	{
		uint64_t NUMRXPBS_PASSED;
		uint64_t NUMRXPBS_FAILED;
		uint64_t SUMTURBOBER_PASSED;
		uint64_t SUMTURBOBER_FAILED;
		uint8_t RESERVED1 [27];
		uint8_t NUM_PHYRATES;
		uint16_t PHYRATE_MBPS_CHAN0;
		uint16_t PHYRATE_MBPS_CHAN1;
		uint64_t RESERVED2;
	}
	RXINTERVALSTATS [6];
}

receive;

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *
 *   unsigned error_rate (uint64_t passed, uint64_t failed);
 *
 *   compute error rate for a given quantity; the error rate is the
 *   ratio of failures to attempts;
 *
 *--------------------------------------------------------------------*/

static float cheetah_error_rate (uint64_t passed, uint64_t failed)

{
	if ((passed) || (failed))
	{
		return ((float) (failed * 100) / (float) (passed +  failed));
	}
	return (0);
}

/*====================================================================*
 *
 *   float fec_bit_error_rate (struct cheetah_receive * receive);
 *
 *   compute the FEC-BER from the VS_LINK_STATS when DIRECTION=1 and
 *   LID=0xF8;
 *
 *--------------------------------------------------------------------*/

static float cheetah_fec_bit_error_rate (struct cheetah_receive * receive)

{
	float FECBitErrorRate = 0;
	if (receive->SUMTURBOBER_PASSED || receive->SUMTURBOBER_FAILED)
	{
		float TotalSumOfBitError = 100 * (float) (LE64TOH (receive->SUMTURBOBER_PASSED) +  LE64TOH (receive->SUMTURBOBER_FAILED));
		float TotalSumOfBits = 8 * 520 * (float) (LE64TOH (receive->NUMRXPBS_PASSED) +  LE64TOH (receive->NUMRXPBS_FAILED));
		FECBitErrorRate = TotalSumOfBitError / TotalSumOfBits;
	}
	return (FECBitErrorRate);
}

/*====================================================================*
 *
 *   void transmit (struct cheetah_transmit * transmit);
 *
 *   display transmit statistics in fixed field format;
 *
 *--------------------------------------------------------------------*/

static void cheetah_transmit_statistics (struct cheetah_transmit * transmit)

{
	printf ("        TX");
	printf (COUNTER, LE64TOH (transmit->NUMTXPBS_PASSED));
	printf (COUNTER, LE64TOH (transmit->NUMTXPBS_FAILED));
	printf (PERCENT, cheetah_error_rate (LE64TOH (transmit->NUMTXPBS_PASSED), LE64TOH (transmit->NUMTXPBS_FAILED)));
	printf (COUNTER, LE64TOH (transmit->NUMTXMPDU_ACKD));
	printf (COUNTER, LE64TOH (transmit->NUMTXMPDU_FAIL));
	printf (COUNTER, LE64TOH (transmit->NUMTXMPDU_COLL));
	printf (PERCENT, cheetah_error_rate (LE64TOH (transmit->NUMTXMPDU_ACKD), LE64TOH (transmit->NUMTXMPDU_FAIL)));
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   void Receive (struct cheetah_receive * receive);
 *
 *   display receive statistics in fixed field format;
 *
 *--------------------------------------------------------------------*/

static void cheetah_receive_statistics (struct cheetah_receive * receive)

{
	printf ("        RX");
	printf (COUNTER, LE64TOH (receive->NUMRXPBS_PASSED));
	printf (COUNTER, LE64TOH (receive->NUMRXPBS_FAILED));
	printf (PERCENT, cheetah_error_rate (LE64TOH (receive->NUMRXPBS_PASSED), LE64TOH (receive->NUMRXPBS_FAILED)));
	printf (COUNTER, LE64TOH (receive->NUMRXMPDU_ACKD));
	printf (COUNTER, LE64TOH (receive->NUMRXMPDU_FAIL));
	printf (PERCENT, cheetah_error_rate (LE64TOH (receive->NUMRXMPDU_ACKD), LE64TOH (receive->NUMRXMPDU_FAIL)));
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   void Receive (struct receive * receive);
 *
 *   display receive statistics in fixed field format for each slot;
 *   the last line sumarizes results for all slots;
 *
 *--------------------------------------------------------------------*/

static void cheetah_receive_interval (struct cheetah_receive * receive)

{
	struct cheetah_receive_interval * interval = (struct cheetah_receive_interval *) (receive->RXINTERVALSTATS);
	uint8_t slot = 0;
	while (slot < receive->NUMRXINTERVALS)
	{
		printf (" %1d", slot);
		printf (" %3d", interval->PHYRATE_MBPS_CHAN0);
		printf (" %3d", interval->PHYRATE_MBPS_CHAN1);
		printf (COUNTER, LE64TOH (interval->NUMRXPBS_PASSED));
		printf (COUNTER, LE64TOH (interval->NUMRXPBS_FAILED));
		printf (PERCENT, cheetah_error_rate (LE64TOH (interval->NUMRXPBS_PASSED), LE64TOH (interval->NUMRXPBS_FAILED)));
		printf (COUNTER, LE64TOH (interval->SUMTURBOBER_PASSED));
		printf (COUNTER, LE64TOH (interval->SUMTURBOBER_FAILED));
		printf (PERCENT, cheetah_error_rate (LE64TOH (interval->SUMTURBOBER_PASSED), LE64TOH (interval->SUMTURBOBER_FAILED)));
		printf ("\n");
		interval++;
		slot++;
	}
	printf ("       ALL");
	printf (COUNTER, LE64TOH (receive->NUMRXPBS_PASSED));
	printf (COUNTER, LE64TOH (receive->NUMRXPBS_FAILED));
	printf (PERCENT, cheetah_error_rate (LE64TOH (receive->NUMRXPBS_PASSED), LE64TOH (receive->NUMRXPBS_FAILED)));
	printf (COUNTER, LE64TOH (receive->SUMTURBOBER_PASSED));
	printf (COUNTER, LE64TOH (receive->SUMTURBOBER_FAILED));
	printf (PERCENT, cheetah_error_rate (LE64TOH (receive->SUMTURBOBER_PASSED), LE64TOH (receive->SUMTURBOBER_FAILED)));
	printf (PERCENT, cheetah_fec_bit_error_rate (receive));
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   signed CheetahLinkStatistics (struct plc * plc);
 *
 *--------------------------------------------------------------------*/

signed cheetah_link_statistics (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_lnk_stats_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MCONTROL;
		uint8_t DIRECTION;
		uint8_t LID;
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
	}
	* request = (struct vs_lnk_stats_request *) (message);
	struct __packed vs_lnk_stats_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_fmi qualcomm;
		uint8_t MSTATUS;
		uint8_t RESERVED1 [4];
		uint8_t MCONTROL;
		uint8_t DIRECTION;
		uint8_t RESERVED2;
		uint8_t LID;
		uint8_t MACADDR [6];
		uint8_t TEI;
		uint8_t RESERVED3 [4];
		uint8_t LSTATS [708];
	}
	* confirm = (struct vs_lnk_stats_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader1 (& request->qualcomm, 1, (VS_LNK_STATS | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	request->MCONTROL = plc->pushbutton;
	request->DIRECTION = plc->module;
	request->LID = plc->action;
	memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadFMI (plc, 1, (VS_LNK_STATS | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	confirm = (struct vs_lnk_stats_confirm *) (plc->content);
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	if (confirm->DIRECTION == 0)
	{
		printf ("       DIR");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ---------- MPDU ACKD");
		printf (" ---------- MPDU FAIL");
		printf ("\n");
		cheetah_transmit_statistics ((struct cheetah_transmit *) (confirm->LSTATS));
		printf ("\n");
	}
	if (confirm->DIRECTION == 1)
	{
		printf ("       DIR");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ---------- MPDU ACKD");
		printf (" ---------- MPDU FAIL");
		printf ("\n");
		cheetah_receive_statistics ((struct cheetah_receive *) (confirm->LSTATS));
		printf ("\n");
		printf ("   CH0 CH1");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ----------- BER PASS");
		printf (" ----------- BER FAIL");
		printf (" BER ERR");
		printf ("\n");
		cheetah_receive_interval ((struct cheetah_receive *) (confirm->LSTATS));
		printf ("\n");
	}
	if (confirm->DIRECTION == 2)
	{
		printf ("       DIR");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ---------- MPDU ACKD");
		printf (" ---------- MPDU FAIL");
		printf ("\n");
		cheetah_transmit_statistics ((struct cheetah_transmit *) (confirm->LSTATS));
		cheetah_receive_statistics ((struct cheetah_receive *) (confirm->LSTATS +  sizeof (struct cheetah_transmit)));
		printf ("\n");
		printf ("   CH0 CH1");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ----------- BER PASS");
		printf (" ----------- BER FAIL");
		printf (" BER ERR");
		printf ("\n");
		cheetah_receive_interval ((struct cheetah_receive *) (confirm->LSTATS +  sizeof (struct cheetah_transmit)));
		printf ("\n");
	}
	return (0);
}

/*====================================================================*
 *
 *   void manager (struct plc * plc);
 *
 *   perform operations in logical order despite any order specfied
 *   on the command line; for example read PIB before writing PIB;
 *
 *   operation order is controlled by the order of "if" statements
 *   shown here; the entire operation sequence can be repeated with
 *   an optional pause between each iteration;
 *
 *--------------------------------------------------------------------*/

void manager (struct plc * plc, signed count, signed pause)

{
	while (count--)
	{
		if (_anyset (plc->flags, PLC_ANALYSE))
		{
			Topology2 (plc);
		}
		if (_anyset (plc->flags, PLC_NETWORK))
		{
			NetworkInformation2 (plc);
		}
		if (_anyset (plc->flags, PLC_LINK_STATS))
		{
			cheetah_link_statistics (plc);
		}
		sleep (pause);
	}
	return;
}

/*====================================================================*
 *
 *   int main (int argc, char const * argv[]);
 *
 *   parse command line, populate plc structure and perform selected
 *   operations; show help summary if asked; see getoptv and putoptv
 *   to understand command line parsing and help summary display; see
 *   plc.h for the definition of struct plc;
 *
 *   the command line accepts multiple MAC addresses and the program
 *   performs the specified operations on each address, in turn; the
 *   address order is significant but the option order is not; the
 *   default address is a local broadcast that causes all devices on
 *   the local H1 interface to respond but not those at the remote
 *   end of the powerline;
 *
 *   the default address is 00:B0:52:00:00:01; omitting the address
 *   will automatically address the local device; some options will
 *   cancel themselves if this makes no sense;
 *
 *   the default interface is eth1 because most people use eth0 as
 *   their principle network connection; you can specify another
 *   interface with -i or define environment string PLC to make
 *   that the default interface and save typing;
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv [])

{
	extern struct channel channel;
	static char const * optv [] =
	{
		"Cd:ei:l:mp:qs:tvw:",
		"device [device] [...] [> stdout]",
		"Qualcomm Atheros QCA7500 Link Statistics",

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif

		"C\tclear statistics without reading using VS_LNK_STATS",
		"d n\tdirection is (n) (0=tx, 1=rx, 2=both) for VS_LNK_STATS",
		"e\tredirect stderr to stdout",
		"l n\tloop (n) times [" LITERAL (PLCSTAT_LOOP) "]",
		"s n\tLink ID is (n) for VS_LNK_STATS (see Programmer's Guide)",
		"m\tprint network membership information using VS_NW_INFO",
		"p x\tpeer node address is (x) for option -s",
		"q\tquiet mode",
		"t\tprint network topology using VS_NW_INFO with VS_SW_VER",
		"v\tverbose mode",
		"w n\twait (n) seconds [" LITERAL (PLCSTAT_WAIT) "]",
		(char const *) (0)
	};
	static const struct _term_ linkids [] =
	{
		{
			"CSMA-ALL",
			"0xFC"
		},
		{
			"CSMA-CAP0",
			"0x00"
		},
		{
			"CSMA-CAP1",
			"0x01"
		},
		{
			"CSMA-CAP2",
			"0x02"
		},
		{
			"CSMA-CAP3",
			"0x03"
		},
		{
			"CSMA-PEER",
			"0xF8"
		},
	};
	static const struct _term_ directions [] =
	{
		{
			"both",
			"2"
		},
		{
			"rx",
			"1"
		},
		{
			"tx",
			"0"
		}
	};

#include "../plc/plc.c"

	signed loop = PLCSTAT_LOOP;
	signed wait = PLCSTAT_WAIT;
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
	plc.pushbutton = 0;
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'C':
			_setbits (plc.flags, PLC_LINK_STATS);
			plc.pushbutton = 1;
			break;
		case 'd':
			_setbits (plc.flags, PLC_LINK_STATS);
			plc.module = (uint8_t) (uintspec (synonym (optarg, directions, SIZEOF (directions)), 0, UCHAR_MAX));
			break;
		case 'e':
			dup2 (STDOUT_FILENO, STDERR_FILENO);
			break;
		case 'i':

#if defined (WINPCAP) || defined (LIBPCAP)

			channel.ifindex = atoi (optarg);

#else

			channel.ifname = optarg;

#endif

			break;
		case 'm':
			_setbits (plc.flags, PLC_NETWORK);
			break;
		case 'p':
			_setbits (plc.flags, PLC_LINK_STATS);
			if (! hexencode (plc.RDA, sizeof (plc.RDA), (char const *) (optarg)))
			{
				error (1, errno, PLC_BAD_MAC, optarg);
			}
			break;
		case 'l':
			loop = (unsigned) (uintspec (optarg, 0, UINT_MAX));
			break;
		case 'q':
			_setbits (channel.flags, CHANNEL_SILENCE);
			_setbits (plc.flags, PLC_SILENCE);
			break;
		case 's':
			_setbits (plc.flags, PLC_LINK_STATS);
			plc.action = (uint8_t) (uintspec (synonym (optarg, linkids, SIZEOF (linkids)), 0, UCHAR_MAX));
			break;
		case 't':
			_setbits (plc.flags, PLC_ANALYSE);
			break;
		case 'v':
			_setbits (channel.flags, CHANNEL_VERBOSE);
			_setbits (plc.flags, PLC_VERBOSE);
			break;
		case 'w':
			wait = (unsigned) (uintspec (optarg, 0, 3600));
			break;
		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;
	openchannel (& channel);
	if (! (plc.message = malloc (sizeof (* plc.message))))
	{
		error (1, errno, PLC_NOMEMORY);
	}
	if (! argc)
	{
		manager (& plc, loop, wait);
	}
	while ((argc) && (* argv))
	{
		if (! hexencode (channel.peer, sizeof (channel.peer), synonym (* argv, devices, SIZEOF (devices))))
		{
			error (1, errno, PLC_BAD_MAC, * argv);
		}
		manager (& plc, loop, wait);
		argc--;
		argv++;
	}
	free (plc.message);
	closechannel (& channel);
	return (0);
}

