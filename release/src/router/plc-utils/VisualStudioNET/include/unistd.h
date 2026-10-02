/****************************************************************************
    Copyright (c) 2020 Qualcomm Technologies, Inc.
    All Rights Reserved.
    Confidential and Proprietary - Qualcomm Technologies, Inc.
*****************************************************************************
    2013 Qualcomm Atheros, Inc.  
****************************************************************************/

/*====================================================================*

 *
 *   unistd.h - substitute unistd.h file for Windows;
 *
 *   this is an important POSIX header that Microsoft ommits; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef UNISTD_HEADER
#define UNISTD_HEADER
 
/*====================================================================*
 *   system header files
 *--------------------------------------------------------------------*/

#if defined (WIN32)
#include <io.h>
#endif

 /*====================================================================*
 *
 *--------------------------------------------------------------------*/

#if defined (WIN32)
#define F_OK 0
#define W_OK 2
#define R_OK 4
#define X_OK 8
#endif

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define HOST_NAME_MAX 256

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#if defined (WIN32)
#define sleep(x) Sleep(1000*(x))
#define strcasecmp(a,b) stricmp(a,b)
typedef signed ssize_t;
#endif
 
#if !defined (_MSC_VER) || _MSC_VER < 1500
#define vsnprintf _vsnprintf
#endif

#if _MSC_VER < 1900
#define snprintf _snprintf
#endif

#define access _access

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif
 

