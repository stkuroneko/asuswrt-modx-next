/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/


/*! \file fapiprocessorstat_.h
    \brief This file contains all the structure definitions, enumerations,
    \structure definitions and macros used in DeviceInfo SL, fapi, kernel module
*/

/** \addtogroup FAPI_SYSTEM System Service
*/
/* @{ */

#ifndef __FAPI_PROCESSORSTAT_H 
#define __FAPI_PROCESSORSTAT_H

/* \brief to collect Processor counter values
	* This structure will collect counter values of Processor

*/
typedef struct
{
    int64_t nIntructions;             /* Total Intructions count for a given Processor*/
    int64_t nICacheMissStallCycles;   /* Total ICacheMissStallCycles count for a given Processor*/
    int64_t nDCacheMissStallCycles;   /* Total uDCacheMissStallCycles count for a given Processor*/
    int64_t nITLBMissCycles;          /* Total uITLBMissCycles count for a given Processor*/
    int64_t nDTLBMissCycles;          /* Total uDTLBMissCycles count for a given Processor*/
    int64_t nCycles;                  /* Total uCycles count for a given Processor*/
    int32_t nProcessorID;	      /* Instance number for the Processor Object*/
    int32_t nFlagID;		      /* list of Parameter values to fetch from system*/
}ProcessorCounter;

#define PROCESSOREVENT_DEVICE     "/dev/pecoevent"
#define PROCESSORSTAT_EVENT_MAJOR 350
#define PROCESSORSTAT_EVENT_MINOR 0
#define PROCESSOR_EVENT _IOR(PROCESSORSTAT_EVENT_MAJOR, 0, char *)

/* \brief to collect Processor counter values from kernel
        * This structure will collect counter values of Processor

*/
typedef struct
{
unsigned flag;		/* list of Parameter values to fetch from system*/
int32_t nPlatform;	/* Platform Name check flag*/
long long uPicEvnt1;	/* Pic event counters*/
long long uPicEvnt2;	/* Pic event counters*/
long long uPicEvnt3;	/* Pic event counters*/
long long uPicEvnt4;	/* Pic event counters*/
long long uPicEvnt5;	/* Pic event counters*/
long long uPicEvnt6;	/* Pic event counters*/
long long uPicEvnt7;	/* Pic event counters*/
long long uPicEvnt8;	/* Pic event counters*/
long long uPicEvnt9;	/* Pic event counters*/
long long uPicEvnt10;	/* Pic event counters*/
long long uPicEvnt11;	/* Pic event counters*/
long long uPicEvnt12;	/* Pic event counters*/
long long uPicEvnt13;	/* Pic event counters*/
long long uPicEvnt14;	/* Pic event counters*/
long long uPicEvnt15;	/* Pic event counters*/	
long long uPicEvnt16;	/* Pic event counters*/
long long uPicEvnt17;	/* Pic event counters*/
long long uPicEvnt18;	/* Pic event counters*/
}ProcessorEvent;

#define INTRUCTIONS     (1 << 0)
#define ICACHEMISSSTALLCYCLES   (1 << 1)
#define DCACHEMISSSTALLCYCLES   (1 << 2)
#define ITLBMISSCYCLES  (1 << 3)
#define DTLBMISSCYCLES  (1 << 4)
#define CPUCYCLES    (1<< 5)

#endif // #ifndef __FAPI_PROCESORSTAT_H
/* @} */

