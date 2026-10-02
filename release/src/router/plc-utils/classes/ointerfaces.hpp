/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ointerfaces.hpp - interface for the ointerfaces class  
 *
 *   host interface enumerator;
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef oINTERFACES_HEADER
#define oINTERFACES_HEADER

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"
#include "../classes/ointerface.hpp"

/*====================================================================*
 *   class constants;
 *--------------------------------------------------------------------*/

#define oINTERFACES_FILTER  1

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) ointerfaces 

{
public:
	ointerfaces ();
	virtual ~ ointerfaces ();
	bool Empty (void) const;
	bool End (void) const;
	unsigned Count (void) const;
	unsigned Index (void) const;
	ointerfaces & Select (unsigned);
	ointerfaces & SelectPrev ();
	ointerfaces & SelectNext ();
	ointerfaces & SelectFirst ();
	ointerfaces & SelectFinal ();
	ointerfaces & Enumerate (void);
	ointerfaces & operator = (unsigned);
	ointerface & Selected () const;
	ointerface & Interface () const;
	ointerface & operator [] (unsigned);
private:
	ointerface ** mtable;
	unsigned mcount;
	unsigned mindex;
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

