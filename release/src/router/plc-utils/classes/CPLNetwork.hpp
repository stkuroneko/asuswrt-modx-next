/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLNetwork.hpp - interface for the CPLNetwork class  
 *
 *   powerline station enumerator;
 *
 *   the collection of CPLStations on a single powerline network;
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLNETWORK_HEADER
#define CPLNETWORK_HEADER

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"
#include "../classes/CPLChannel.hpp"
#include "../classes/CPLStation.hpp"

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) CPLNetwork 

{
public:
	explicit CPLNetwork (CPLChannel * channel);
	virtual ~ CPLNetwork ();
	bool Empty (void) const;
	bool End (void) const;
	unsigned Count (void) const;
	unsigned Index (void) const;
	CPLNetwork & Select (unsigned);
	CPLNetwork & SelectPrev (void);
	CPLNetwork & SelectNext (void);
	CPLNetwork & SelectFirst (void);
	CPLNetwork & SelectFinal (void);
	CPLNetwork & Enumerate (void);
	CPLNetwork & operator = (unsigned);
	CPLStation & Selected (void) const;
	CPLStation & Station (void) const;
	CPLStation & operator [] (unsigned);
private:
	static void platform (CPLChannel * channel, CPLStation * station);
	CPLStation ** mtable;
	unsigned mcount;
	unsigned mindex;
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

