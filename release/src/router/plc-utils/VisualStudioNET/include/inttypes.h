/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   inttypes.h - substitute inttypes.h file for Windows;
 *
 *   this is an important POSIX header that Microsoft ommits; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Mathieu Olivari <mathieu@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef INTTYPES_HEADER
#define INTTYPES_HEADER

#define PRId64 "I64d"
#define PRIu64 "I64u"
#define PRIX64 "I64X"

#endif

