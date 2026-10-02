/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   int6kstat.c - Qualcomm Atheros INT6x00 Link Statistics
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>

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
#include "../plc/Display.c"
#include "../plc/Failure.c"
#include "../plc/Request.c"
#include "../plc/ReadMME.c"
#include "../plc/SendMME.c"
#include "../plc/LocalDevices.c"
#include "../plc/NetworkInformation1.c"
#include "../plc/Topology1.c"
#include "../plc/Devices.c"
#include "../plc/chipset.c"
#include "../plc/Platform.c"
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
#include "../mme/QualcommHeader1.c"
#include "../mme/QualcommHeader.c"
#include "../mme/UnwantedMessage.c"
#include "../mme/MMECode.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define INT6KSTAT_LOOP 1
#define INT6KSTAT_WAIT 0

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

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

/*====================================================================*
 *   programs variables;
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push,1)
#endif

typedef struct __packed thunderbolt_transmit

{
	uint64_t NUMTXMPDU_ACKD;
	uint64_t NUMTXMPDU_COLL;
	uint64_t NUMTXMPDU_FAIL;
	uint64_t NUMTXPBS_PASSED;
	uint64_t NUMTXPBS_FAILED;
}

transmit;
typedef struct __packed thunderbolt_receive

{
	uint64_t NUMRXMPDU_ACKD;
	uint64_t NUMRXMPDU_FAIL;
	uint64_t NUMRXPBS_PASSED;
	uint64_t NUMRXPBS_FAILED;
	uint64_t SUMTURBOBER_PASSED;
	uint64_t SUMTURBOBER_FAILED;
	uint8_t NUMRXINTERVALS;
	uint8_t RXINTERVALSTATS [1];
}

receive;
typedef struct __packed thunderbolt_interval

{
	uint8_t RXPHYRATE_MBPS_0;
	uint64_t NUMRXPBS_PASSED;
	uint64_t NUMRXPBS_FAILED;
	uint64_t SUMTURBOBER_PASSED;
	uint64_t SUMTURBOBER_FAILED;
}

interval;

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *
 *   unsigned thunderbolt_error_rate (uint64_t passed, uint64_t failed);
 *
 *   compute error rate for a given quantity; the error rate is the
 *   ratio of failures to attempts;
 *
 *--------------------------------------------------------------------*/

static float thunderbolt_error_rate (uint64_t passed, uint64_t failed)

{
	if ((passed) || (failed))
	{
		return ((float) (failed * 100) / (float) (passed +  failed));
	}
	return (0);
}

/*====================================================================*
 *
 *   float thunderbolt_fec_bit_error_rate (struct thunderbolt_receive * receive);
 *
 *   compute the FEC-BER from the VS_LINK_STATS when DIRECTION=1 and
 *   LID=0xF8;
 *
 *--------------------------------------------------------------------*/

static float thunderbolt_fec_bit_error_rate (struct thunderbolt_receive * receive)

{
	float FECBitErrorRate = 0;
	if (receive->SUMTURBOBER_PASSED || receive->SUMTURBOBER_FAILED)
	{
		float TotalSumOfBitError = 100 * (float) (receive->SUMTURBOBER_PASSED +  receive->SUMTURBOBER_FAILED);
		float TotalSumOfBits = 8 * 520 * (float) (receive->NUMRXPBS_PASSED +  receive->NUMRXPBS_FAILED);
		FECBitErrorRate = TotalSumOfBitError / TotalSumOfBits;
	}
	return (FECBitErrorRate);
}

/*====================================================================*
 *
 *   void thunderbolt_transmit_statistics (struct thunderbolt_transmit * transmit);
 *
 *   display transmit statistics in fixed field format;
 *
 *--------------------------------------------------------------------*/

static void thunderbolt_transmit_statistics (struct thunderbolt_transmit * transmit)

{
	printf ("    TX");
	printf (" %20" PRId64, transmit->NUMTXPBS_PASSED);
	printf (" %20" PRId64, transmit->NUMTXPBS_FAILED);
	printf (" %6.2f%%", thunderbolt_error_rate (transmit->NUMTXPBS_PASSED, transmit->NUMTXPBS_FAILED));
	printf (" %20" PRId64, transmit->NUMTXMPDU_ACKD);
	printf (" %20" PRId64, transmit->NUMTXMPDU_FAIL);
	printf (" %20" PRId64, transmit->NUMTXMPDU_COLL);
	printf (" %6.2f%%", thunderbolt_error_rate (transmit->NUMTXMPDU_ACKD, transmit->NUMTXMPDU_FAIL));
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   void thunderbolt_receive_statistics (struct thunderbolt_receive * receive);
 *
 *   display receive statistics in fixed field format;
 *
 *--------------------------------------------------------------------*/

static void thunderbolt_receive_statistics (struct thunderbolt_receive * receive)

{
	printf ("    RX");
	printf (" %20" PRId64, receive->NUMRXPBS_PASSED);
	printf (" %20" PRId64, receive->NUMRXPBS_FAILED);
	printf (" %6.2f%%", thunderbolt_error_rate (receive->NUMRXPBS_PASSED, receive->NUMRXPBS_FAILED));
	printf (" %20" PRId64, receive->NUMRXMPDU_ACKD);
	printf (" %20" PRId64, receive->NUMRXMPDU_FAIL);
	printf (" %6.2f%%", thunderbolt_error_rate (receive->NUMRXMPDU_ACKD, receive->NUMRXMPDU_FAIL));
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   void Receive (struct thunderbolt_receive * receive);
 *
 *   display receive statistics in fixed field format for each slot;
 *   the last line sumarizes results for all slots;
 *
 *--------------------------------------------------------------------*/

static void thunderbolt_receive_interval (struct thunderbolt_receive * receive)

{
	struct thunderbolt_interval * interval = (struct thunderbolt_interval *) (receive->RXINTERVALSTATS);
	uint8_t slot = 0;
	while (slot < receive->NUMRXINTERVALS)
	{
		printf (" %1d", slot);
		printf (" %3d", interval->RXPHYRATE_MBPS_0);
		printf (" %20" PRId64, interval->NUMRXPBS_PASSED);
		printf (" %20" PRId64, interval->NUMRXPBS_FAILED);
		printf (" %6.2f%%", thunderbolt_error_rate (interval->NUMRXPBS_PASSED, interval->NUMRXPBS_FAILED));
		printf (" %20" PRId64, interval->SUMTURBOBER_PASSED);
		printf (" %20" PRId64, interval->SUMTURBOBER_FAILED);
		printf (" %6.2f%%", thunderbolt_error_rate (interval->SUMTURBOBER_PASSED, interval->SUMTURBOBER_FAILED));
		printf ("\n");
		interval++;
		slot++;
	}
	printf ("   ALL");
	printf (" %20" PRId64, receive->NUMRXPBS_PASSED);
	printf (" %20" PRId64, receive->NUMRXPBS_FAILED);
	printf (" %6.2f%%", thunderbolt_error_rate (receive->NUMRXPBS_PASSED, receive->NUMRXPBS_FAILED));
	printf (" %20" PRId64, receive->SUMTURBOBER_PASSED);
	printf (" %20" PRId64, receive->SUMTURBOBER_FAILED);
	printf (" %6.2f%%", thunderbolt_error_rate (receive->SUMTURBOBER_PASSED, receive->SUMTURBOBER_FAILED));
	printf (" %6.2f%%", thunderbolt_fec_bit_error_rate (receive));
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *   signed thunderbolt_link_statistics (struct plc * plc);
 *
 *--------------------------------------------------------------------*/

signed thunderbolt_link_statistics (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_lnk_stats_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MCONTROL;
		uint8_t DIRECTION;
		uint8_t LID;
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
	}
	* request = (struct vs_lnk_stats_request *) (message);
	struct __packed vs_lnk_stats_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t DIRECTION;
		uint8_t LID;
		uint8_t TEI;
		uint8_t LSTATS [1];
	}
	* confirm = (struct vs_lnk_stats_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_LNK_STATS | MMTYPE_REQ));
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
	if (ReadMME (plc, 0, (VS_LNK_STATS | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	if (confirm->DIRECTION == 0)
	{
		printf ("   DIR");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ---------- MPDU ACKD");
		printf (" ---------- MPDU FAIL");
		printf ("\n");
		thunderbolt_transmit_statistics ((struct thunderbolt_transmit *) (confirm->LSTATS));
		printf ("\n");
	}
	if (confirm->DIRECTION == 1)
	{
		printf ("   DIR");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ---------- MPDU ACKD");
		printf (" ---------- MPDU FAIL");
		printf ("\n");
		thunderbolt_receive_statistics ((struct thunderbolt_receive *) (confirm->LSTATS));
		printf ("\n");
		printf ("   PHY");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ----------- BER PASS");
		printf (" ----------- BER FAIL");
		printf (" BER ERR");
		printf ("\n");
		thunderbolt_receive_interval ((struct thunderbolt_receive *) (confirm->LSTATS));
		printf ("\n");
	}
	if (confirm->DIRECTION == 2)
	{
		printf ("   DIR");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ---------- MPDU ACKD");
		printf (" ---------- MPDU FAIL");
		printf ("\n");
		thunderbolt_transmit_statistics ((struct thunderbolt_transmit *) (confirm->LSTATS));
		thunderbolt_receive_statistics ((struct thunderbolt_receive *) (confirm->LSTATS +  sizeof (struct thunderbolt_transmit)));
		printf ("\n");
		printf ("   PHY");
		printf (" ----------- PBs PASS");
		printf (" ----------- PBs FAIL");
		printf (" PBs ERR");
		printf (" ----------- BER PASS");
		printf (" ----------- BER FAIL");
		printf (" BER ERR");
		printf ("\n");
		thunderbolt_receive_interval ((struct thunderbolt_receive *) (confirm->LSTATS +  sizeof (struct thunderbolt_transmit)));
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
			Topology1 (plc);
		}
		if (_anyset (plc->flags, PLC_NETWORK))
		{
			NetworkInformation1 (plc);
		}
		if (_anyset (plc->flags, PLC_LINK_STATS))
		{
			thunderbolt_link_statistics (plc);
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
		"Qualcomm Atheros INT6x00 Powerline Link Statistics",

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif

		"C\tclear statistics without reading using VS_LNK_STATS",
		"d n\tdirection (0=tx, 1=rx, 2=both) for VS_LNK_STATS",
		"e\tredirect stderr to stdout",
		"l n\tloop n times [" LITERAL (INT6KSTAT_LOOP) "]",
		"s n\tLink ID for VS_LNK_STATS",
		"m\tprint network membership information using VS_NW_INFO",
		"p x\tpeer node address for options -s",
		"q\tquiet mode",
		"t\tprint network topology using VS_NW_INFO with VS_SW_VER",
		"v\tverbose mode",
		"w n\twait n seconds [" LITERAL (INT6KSTAT_WAIT) "]",
		(char const *) (0)
	};

#include "../plc/plc.c"

	signed loop = INT6KSTAT_LOOP;
	signed wait = INT6KSTAT_WAIT;
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

