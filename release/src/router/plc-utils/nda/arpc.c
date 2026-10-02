/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   arpc.c -
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../ether/channel.h"
#include "../mme/mme.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/hexdump.c"
#include "../tools/uintspec.c"
#include "../tools/todigit.c"
#include "../tools/hexwrite.c"
#include "../tools/error.c"
#endif

#ifndef MAKEFILE
#include "../ether/channel.c"
#include "../ether/openchannel.c"
#include "../ether/closechannel.c"
#include "../ether/sendpacket.c"
#include "../ether/readpacket.c"
#endif

#ifndef MAKEFILE
#include "../mme/ARPCPrint.c"
#include "../mme/ARPCWrite.c"
#include "../mme/ARPCPeek.c"
#endif

/*====================================================================*
 *    program constants;
 *--------------------------------------------------------------------*/

#define PLCDEVICE "PLC"

#if defined (WIN32)
#define TIMEVALUE "%012ld.%06ld"
#elif defined (__APPLE__)
#define TIMEVALUE "%012lu.%06u"
#elif defined (__linux__)
#define TIMEVALUE "%012ld.%06ld"
#elif defined (__OpenBSD__)
#define TIMEVALUE "%012ld.%06ld"
#else
#error "Unknown environment"
#endif

/*====================================================================*
 *
 *   void ARPCDump (struct channel * channel, void const * memory, size_t extent);
 *
 *   print or write ARPC messages based on ARPCID.
 *
 *--------------------------------------------------------------------*/

static void ARPCDump (struct channel * channel, void const * memory, size_t extent)

{

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_arpc_data
	{
		uint32_t BYPASS;
		uint16_t ARPCID;
		uint16_t DATALENGTH;
		uint8_t DATAOFFSET;
		uint8_t RESERVED [3];
		uint16_t ARGOFFSET;
		uint16_t STROFFSET;
		uint16_t ARGLENGTH;
		uint16_t STRLENGTH;
		uint8_t LIST [1];
	}
	* data = (struct vs_arpc_data *) (memory);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	struct timeval tv;
	gettimeofday (& tv, NULL);
	if (LE16TOH (data->ARPCID) == 1)
	{
		if (_anyset (channel->flags, CHANNEL_MONITOR))
		{
			fprintf (stdout, TIMEVALUE " ", tv.tv_sec, tv.tv_usec);
		}
		ARPCPrint (stdout, memory, extent);
		return;
	}
	if (LE16TOH (data->ARPCID) == 2)
	{
		if (_anyset (channel->flags, CHANNEL_MONITOR))
		{
			if (isatty (fileno (stdout)))
			{
				hexwrite (fileno (stdout), & tv, sizeof (tv));
			}
			else 
			{
				fwrite (& tv, sizeof (tv), 1, stdout);
			}
		}
		ARPCWrite (stdout, memory, extent);
		return;
	}
	return;
}

/*====================================================================*
 *
 *   void function (struct channel * channel, signed fd);
 *
 *   capture and record VS_ARPC messages from any Atheros powerline
 *   device; devices must be programmed to send these messages;
 *
 *   this function has no practical use under operation conditions;
 *
 *--------------------------------------------------------------------*/

static void function (struct channel * channel)

{
	struct message message;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_arpc_ind
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint16_t RDATALENGTH;
		uint8_t RDATAOFFSET;
		uint8_t RDATA [1];
	}
	* indicate = (struct vs_arpc_ind *) (& message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	signed length;
	while ((length = readpacket (channel, & message, sizeof (message))) >= 0)
	{
		if (! length)
		{
			continue;
		}
		if (ntohs (indicate->ethernet.MTYPE) != ETH_P_HPAV)
		{
			continue;
		}
		if (indicate->qualcomm.MMV != 0)
		{
			continue;
		}
		if (LE16TOH (indicate->qualcomm.MMTYPE) != (VS_ARPC | MMTYPE_IND))
		{
			continue;
		}
		ARPCDump (channel, & indicate->RDATA [indicate->RDATAOFFSET], LE16TOH (indicate->RDATALENGTH) - indicate->RDATAOFFSET);
	}
	return;
}

/*====================================================================*
 *
 *   void timeout ();
 *
 *   print current time as both hh:mm:ss and seconds.milliseconds;
 *
 *   POSIX says ...
 *
 *      struct { time_t tv_sec; suseconds_t tv_usec; } timeval;
 *
 *   on OSX ...
 *
 *      typedef __darwin_time_t time_t;
 *      typesef __darwin_suseconds_t suseconds_t;
 *
 *      typedef long __darwin_time_t;
 *      typedef __int32_t __darwin_suseconds_t;
 *
 *   on Windows ...
 *
 *   on Linux ...
 *
 *--------------------------------------------------------------------*/

static void timeout ()

{
	char time [9];
	struct timeval tv;
	gettimeofday (& tv, NULL);
	strftime (time, sizeof (time), "%H:%M:%S", localtime ((const time_t *) (& tv.tv_sec)));
	printf ("%s " TIMEVALUE "\n", time, tv.tv_sec, tv.tv_usec);
	printf ("sizeof (tv.tv_sec) is " SIZE_T_SPEC " bytes\n", sizeof (tv.tv_sec));
	printf ("sizeof (tv.tv_usec) is " SIZE_T_SPEC " bytes\n", sizeof (tv.tv_usec));
	return;
}

/*====================================================================*
 *
 *   int main (int argc, char * argv[]);
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv [])

{
	extern struct channel channel;
	static char const * optv [] =
	{
		"i:mqt:vz",
		PUTOPTV_S_DIVINE,
		"Qualcomm Atheros Asynchronous Remote Procedure Call Monitor",

#if defined (WINPCAP) || defined (LIBPCAP)

		"i n\thost interface is (n) [" LITERAL (CHANNEL_ETHNUMBER) "]",

#else

		"i s\thost interface is (s) [" LITERAL (CHANNEL_ETHDEVICE) "]",

#endif

		"m\tprefix messages with system time in seconds.milliseconds",
		"q\tsuppress output on stdout",
		"t n\tread timeout is (n) milliseconds [" LITERAL (CHANNEL_TIMEOUT) "]",
		"v\tverbose messages on stderr",
		"z\tprint sample time as hh:mm:ss and seconds.milliseconds then exit",
		(char const *) (0)
	};
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
		case 'i':

#if defined (WINPCAP) || defined (LIBPCAP)

			channel.ifindex = atoi (optarg);

#else

			channel.ifname = optarg;

#endif

			break;
		case 'm':
			_setbits (channel.flags, CHANNEL_MONITOR);
			break;
		case 'q':
			_setbits (channel.flags, CHANNEL_SILENCE);
			break;
		case 't':
			channel.timeout = (signed) (uintspec (optarg, 0, UINT_MAX));
			break;
		case 'v':
			_setbits (channel.flags, CHANNEL_VERBOSE);
			break;
		case 'z':
			timeout ();
			return (0);
		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc)
	{
		error (1, ENOTSUP, ERROR_TOOMANY);
	}

#ifdef WIN32

	setmode (STDOUT_FILENO, O_BINARY);

#endif

	openchannel (& channel);
	function (& channel);
	closechannel (& channel);
	fflush (stdout);
	return (0);
}

