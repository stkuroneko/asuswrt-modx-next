/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   CPLNetworks.hpp - interface for the CPLNetworks class  
 *
 *   powerline network enumerator;
 *
 *   the collection of CPLNetworks on a single host interface;
 *
 *   Contributor(s): 
 *	    Charles Maier <charles.maier@intellon.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CPLNETWORKS_HEADER
#define CPLNETWORKS_HEADER

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"
#include "../classes/CPLChannel.hpp"
#include "../classes/CPLNetwork.hpp"

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) CPLNetworks 

{
public:
	explicit CPLNetworks (char const * ifname);
	virtual ~ CPLNetworks ();
	bool Empty (void) const;
	bool End (void) const;
	unsigned Count (void) const;
	unsigned Index (void) const;
	CPLNetworks & Select (unsigned);
	CPLNetworks & SelectPrev (void);
	CPLNetworks & SelectNext (void);
	CPLNetworks & SelectFirst (void);
	CPLNetworks & SelectFinal (void);
	CPLNetworks & Enumerate (void);
	CPLNetworks & operator = (unsigned);
	CPLNetwork & Selected (void) const;
	CPLNetwork & Network (void) const;
	CPLNetwork & operator [] (unsigned);
private:
	CPLNetwork ** mtable;
	unsigned mcount;
	unsigned mindex;
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

