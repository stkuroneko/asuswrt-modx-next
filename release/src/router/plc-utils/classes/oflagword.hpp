/*====================================================================*
 *
 *   oflagword.hpp - interface for the oflagword class;
 *
 *   bitmapped flagword manager; this class can be inherited by other
 *   classes that need a flagword; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oFLAGWORD_HEADER
#define oFLAGWORD_HEADER

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) oflagword 

{
public:
	oflagword ();
	oflagword (unsigned);
	virtual ~ oflagword ();
	unsigned getword () const;
	unsigned getbits (unsigned bits) const;
	oflagword & setword (unsigned bits);
	oflagword & setbits (unsigned bits);
	oflagword & clearbits (unsigned bits);
	bool anyset (unsigned bits) const;
	bool allset (unsigned bits) const;
	bool anyclear (unsigned bits) const;
	bool allclear (unsigned bits) const;
private:
	unsigned mbits;
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

