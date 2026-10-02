/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   nvm.c - nvm image header constant values;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NVM_SOURCE
#define NVM_SOURCE

#include "../nvm/nvm.h"

char const * nvm_platforms [NVM_PLATFORMS] = 

{ 
	"INT6000", 
	"INT6300", 
	"INT6400", 
	"AR7400", 
	"AR7420"
}; 

char const * nvm_imagetypes [NVM_IMAGETYPES] = 

{ 
	"Generic Image", 
	"Synopsis Configuration", 
	"Denali Configuration", 
	"Denali Applet", 
	"Runtime Firmware", 
	"OAS Client", 
	"Custom Image", 
	"Memory Control Applet", 
	"Power Management Applet", 
	"OAS Client IP Stack", 
	"OAS Client TR069", 
	"SoftLoader", 
	"Flash Layout", 
	"Unknown13", 
	"Chain Manifest", 
	"Runtime Parameters", 
	"Custom Module In Scratch", 
	"Custom Module Update Applet"
}; 

#endif



