/*====================================================================*
 *
 *   oSHA256.hpp - oSHA256 class declaration;
 *
 *   implement 256-bit encryption according to FIPS180-2 sec 5.3.2 by 
 *   encoding variable-length input into fixed-length, 32 byte digest;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oSHA256_HEADER
#define oSHA256_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstring>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define oSHA256_LEFT_SIZE 2
#define oSHA256_HASH_SIZE 256/32
#define oSHA256_BUFFER_LENGTH 256/4
#define oSHA256_DIGEST_LENGTH 256/8

/*====================================================================*
 *   class datatypes;  
 *--------------------------------------------------------------------*/

typedef unsigned char byte;

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) oSHA256 

{
public:
	oSHA256 ();
	~ oSHA256 ();
	static unsigned DigestLength;
	oSHA256 & Reset (void);
	oSHA256 & Write (void const * memory, size_t length);
	oSHA256 & Fetch (byte digest []);
private:
	oSHA256 & Block (const byte buffer []);
	uint32_t * mcount;
	uint32_t * mstate;
	uint8_t * mblock;
	uint8_t * mextra;
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

