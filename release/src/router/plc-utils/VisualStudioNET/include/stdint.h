/*====================================================================*
*
*   Copyright (c) 2011 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*

 *
 *   stdint.h - substitute stdint.h file for Windows;
 *
 *   this is an important POSIX header that Microsoft ommits;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier.qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef STDINT_HEADER
#define STDINT_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <limits.h>

/*====================================================================*
 *   variable types;
 *--------------------------------------------------------------------*/

#ifdef _MSC_VER 
typedef __int8 int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef long off_t;
#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#if defined (WIN32)
#define UINT32_MAX (uint32_t)(-1)
#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif

