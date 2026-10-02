/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   in.h - Substitute Linux header for systems without one;
 *
 *   Emulate the POSIX header netinet/in.h; 
 *
 *   specifically, obtain declare endian conversion functions htons(), 
 *   ntohs(), htonl() and ntohl();
 *
 *   Contributor(s):
 *	Charles Maier <charles.maier@atheros.com>
 *
 *--------------------------------------------------------------------*/

#ifndef IN_HEADER
#define IN_HEADER
 
/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#if defined (WIN32)
#include <winsock2.h>
#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif
 

