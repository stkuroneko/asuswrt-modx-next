/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

#ifndef TIME_HEADER
#define TIME_HEADER

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#	define DELTA_EPOCH_IN_MICROSECS 11644473600000000Ui64
#else
#	define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

struct timezone 

{

/* minutes W of Greenwich */

	int tz_minuteswest;

/* type of dst correction */

	int tz_dsttime;
};

int gettimeofday (struct timeval *, struct timezone *);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif

