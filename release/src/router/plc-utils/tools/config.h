/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   config.h - configuration file definitions and declarations;
 *
 *--------------------------------------------------------------------*/

#ifndef CONFIG_HEADER
#define CONFIG_HEADER

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

char const * configstring (char const * file, char const * part, char const * item, char const * string); 
unsigned confignumber (char const * file, char const * part, char const * item, unsigned number); 

/*====================================================================*
 *   end definitions;
 *--------------------------------------------------------------------*/

#endif



