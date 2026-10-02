/*====================================================================*
 *
 *   oSHA256.cpp - oSHA256 class definition;
 *
 *   implement 256-bit encryption according to FIPS180-2 sec 5.3.2 by 
 *   encoding variable-length input into fixed-length, 32 byte digest;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oSHA256_SOURCE
#define oSHA256_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h> 
#include <iostream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/oSHA256.hpp"

/*====================================================================*
 *   pseudo functions;
 *--------------------------------------------------------------------*/

#define GET_UINT32(n,b,i) \
    n = ((uint32_t)(b)[(i)+0]<<24) \
      | ((uint32_t)(b)[(i)+1]<<16) \
      | ((uint32_t)(b)[(i)+2]<< 8) \
      | ((uint32_t)(b)[(i)+3]<< 0);

#define PUT_UINT32(n,b,i) \
    (b)[(i)+0]=(uint8_t)((n)>>24); \
    (b)[(i)+1]=(uint8_t)((n)>>16); \
    (b)[(i)+2]=(uint8_t)((n)>> 8); \
    (b)[(i)+3]=(uint8_t)((n)>> 0); 

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

unsigned oSHA256::DigestLength = 32;

/*====================================================================*
 *
 *   oSHA256 & Write (void const * memory, size_t length);
 *
 *   write a variable-length data block to the SHA256 digest; behave
 *   like function write() but return no value and never fail; 
 *
 *   Read standard FIPS180-2 sec 5.3.2 for an explanation;     
 *   
 *--------------------------------------------------------------------*/

oSHA256 & oSHA256::Write (void const * memory, size_t extent) 

{
	if (extent) 
	{
		byte * buffer = (byte *)(memory);
		uint32_t left = this->mcount [0] & 0x3F;
		uint32_t fill = oSHA256_BUFFER_LENGTH - left;
		this->mcount [0] += (uint32_t)(extent);
		this->mcount [0] &= 0xFFFFFFFF;
		if (this->mcount [0] < extent) 
		{
			this->mcount [1]++;
		}
		if ((left) && (extent >= fill)) 
		{
			std::memcpy (this->mblock + left, buffer, (uint16_t) (fill));
			this->Block (this->mblock);
			extent -= fill;
			buffer += fill;
			left = 0;
		}
		while (extent >= oSHA256_BUFFER_LENGTH) 
		{
			oSHA256::Block (buffer);
			extent -= oSHA256_BUFFER_LENGTH;
			buffer += oSHA256_BUFFER_LENGTH;
		}
		if (extent) 
		{
			std::memcpy (this->mblock + left, buffer, (uint16_t) (extent));
		}
	}
	return (*this);
}

/*====================================================================*
 *
 *   oSHA256 & Block (const byte buffer []);
 *
 *   merge a 64 byte data block into an SHA256 digest; 
 *   
 *   Read standard FIPS180-2 sec 5.3.2 for an explanation;     
 *   
 *--------------------------------------------------------------------*/

#define SHR(word,bits) ((word & 0xFFFFFFFF) >> bits)
#define ROTR(word,bits) (SHR(word,bits) | (word << (32 - bits)))

oSHA256 & oSHA256::Block (const byte buffer []) 

{
	static const uint32_t K [oSHA256_BUFFER_LENGTH] = 
	{
		0x428A2F98,
		0x71374491,
		0xB5C0FBCF,
		0xE9B5DBA5,
		0x3956C25B,
		0x59F111F1,
		0x923F82A4,
		0xAB1C5ED5,
		0xD807AA98,
		0x12835B01,
		0x243185BE,
		0x550C7DC3,
		0x72BE5D74,
		0x80DEB1FE,
		0x9BDC06A7,
		0xC19BF174,
		0xE49B69C1,
		0xEFBE4786,
		0x0FC19DC6,
		0x240CA1CC,
		0x2DE92C6F,
		0x4A7484AA,
		0x5CB0A9DC,
		0x76F988DA,
		0x983E5152,
		0xA831C66D,
		0xB00327C8,
		0xBF597FC7,
		0xC6E00BF3,
		0xD5A79147,
		0x06CA6351,
		0x14292967,
		0x27B70A85,
		0x2E1B2138,
		0x4D2C6DFC,
		0x53380D13,
		0x650A7354,
		0x766A0ABB,
		0x81C2C92E,
		0x92722C85,
		0xA2BFE8A1,
		0xA81A664B,
		0xC24B8B70,
		0xC76C51A3,
		0xD192E819,
		0xD6990624,
		0xF40E3585,
		0x106AA070,
		0x19A4C116,
		0x1E376C08,
		0x2748774C,
		0x34B0BCB5,
		0x391C0CB3,
		0x4ED8AA4A,
		0x5B9CCA4F,
		0x682E6FF3,
		0x748F82EE,
		0x78A5636F,
		0x84C87814,
		0x8CC70208,
		0x90BEFFFA,
		0xA4506CEB,
		0xBEF9A3F7,
		0xC67178F2
	};
	signed word;
	signed pass;
	uint32_t H [oSHA256_DIGEST_LENGTH];
	uint32_t W [oSHA256_BUFFER_LENGTH];
	for (word = 0; word < 16; word++) 
	{
		GET_UINT32 (W [word], buffer, word * sizeof (uint32_t));
	}
	while (word < oSHA256_BUFFER_LENGTH) 
	{
		uint32_t s0 = ROTR (W [word-15], 7) ^ ROTR (W [word-15], 18) ^ SHR (W [word-15], 3);
		uint32_t s1 = ROTR (W [word- 2], 17) ^ ROTR (W [word- 2], 19) ^ SHR (W [word- 2], 10);
		W [word] = W [word - 16] + s0 + W [word - 7] + s1;
		word++;
	}
	for (word = 0; word < oSHA256_HASH_SIZE; word++) 
	{
		H [word] = this->mstate [word];
	}
	for (pass = 0; pass < oSHA256_BUFFER_LENGTH; pass++) 
	{
		uint32_t s2 = ROTR (H [0], 2) ^ ROTR (H [0], 13) ^ ROTR (H [0], 22);
		uint32_t maj = (H [0] & H [1]) ^ (H [0] & H [2]) ^ (H [1] & H [2]);
		uint32_t t2 = s2 + maj;
		uint32_t s3 = ROTR (H [4], 6) ^ ROTR (H [4], 11) ^ ROTR (H [4], 25);
		uint32_t ch = (H [4] & H [5]) ^ ((~ H [4]) & H [6]);
		uint32_t t1 = H [7] + s3 + ch + K [pass] + W [pass];
		for (word = oSHA256_DIGEST_LENGTH - 1; word > 0; word--) 
		{
			H [word] = H [word-1];
		}
		H [0] = t1 + t2;
		H [4] += t1;
	}
	for (word = 0; word < oSHA256_DIGEST_LENGTH; word++) 
	{
		this->mstate [word] += H [word];
	}
	return (*this);
}

/*====================================================================*
 *
 *   oSHA256 & Fetch (byte diget []);
 *
 *   read the SHA256 digest; this function works like function read()
 *   but the function returns no value and the digest buffer is fixed
 *   length;
 *
 *   to start a digest, use the Reset method; to write data to
 *   the digest use the Write method;
 *   
 *   Read standard FIPS180-2 sec 5.3.2 for an explanation;     
 *   
 *--------------------------------------------------------------------*/

oSHA256 & oSHA256::Fetch (byte digest []) 

{
	unsigned word;
	unsigned char msglen [8];
	uint32_t upper = (this->mcount [0] >> 29) | (this->mcount [1] << 3);
	uint32_t lower = (this->mcount [0] << 3);
	uint32_t final = (this->mcount [0] & 0x3F);
	uint32_t extra = (final < 56)? (56 - final): (120 - final);
	PUT_UINT32 (upper, msglen, 0);
	PUT_UINT32 (lower, msglen, 4);
	oSHA256::Write (this->mextra, extra);
	oSHA256::Write (msglen, sizeof (msglen));
	for (word = 0; word < oSHA256_DIGEST_LENGTH; word++) 
	{
		PUT_UINT32 (this->mstate [word], digest, word * sizeof (uint32_t));
	}
	oSHA256::Reset ();
	return (*this);
}

/*====================================================================*
 *
 *   oSHA256 & Reset () 
 *
 *--------------------------------------------------------------------*/

oSHA256 & oSHA256::Reset (void) 

{
	this->mstate [0] = 0x6A09E667;
	this->mstate [1] = 0xBB67AE85;
	this->mstate [2] = 0x3C6EF372;
	this->mstate [3] = 0xA54FF53A;
	this->mstate [4] = 0x510E527F;
	this->mstate [5] = 0x9B05688C;
	this->mstate [6] = 0x1F83D9AB;
	this->mstate [7] = 0x5BE0CD19;
	std::memset (this->mcount, 0, oSHA256_LEFT_SIZE * sizeof (uint32_t));
	std::memset (this->mblock, 0, oSHA256_BUFFER_LENGTH);
	std::memset (this->mextra, 0, oSHA256_BUFFER_LENGTH);
	this->mextra [0] = 0x80;
	return (*this);
}

/*====================================================================*
 *
 *   oSHA256 () 
 *
 *--------------------------------------------------------------------*/

oSHA256::oSHA256 () 

{
	this->mcount = new uint32_t [oSHA256_LEFT_SIZE];
	this->mstate = new uint32_t [oSHA256_HASH_SIZE];
	this->mblock = new uint8_t [oSHA256_BUFFER_LENGTH];
	this->mextra = new uint8_t [oSHA256_BUFFER_LENGTH];
	oSHA256::Reset ();
	return;
}

/*====================================================================*
 *
 *   void ~osha256 () 
 *   
 *--------------------------------------------------------------------*/

oSHA256::~oSHA256 () 

{
	delete [] this->mstate;
	delete [] this->mcount;
	delete [] this->mblock;
	delete [] this->mextra;
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

