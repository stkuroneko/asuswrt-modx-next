/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed evse_cm_atten_char (struct session * session, struct channel * channel, struct message * message);
 *
 *   slac.h
 *
 *   EVSE-HLE sends average msound values to the PEV-HLE for a match
 *   decision;
 *
 *--------------------------------------------------------------------*/

#ifndef EVSE_CM_ATTEN_CHAR_SOURCE
#define EVSE_CM_ATTEN_CHAR_SOURCE

#include <string.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../slac/slac.h"

signed evse_cm_atten_char (struct session * session, struct channel * channel, struct message * message) 

{ 
	struct cm_atten_char_indicate * indicate = (struct cm_atten_char_indicate *) (message); 
	struct cm_atten_char_response * response = (struct cm_atten_char_response *) (message); 
	debug (0, __func__, "--> CM_ATTEN_CHAR.IND"); 
	memset (message, 0, sizeof (* message)); 
	EthernetHeader (& indicate->ethernet, session->PEV_MAC, channel->host, channel->type); 
	HomePlugHeader1 (& indicate->homeplug, HOMEPLUG_MMV, (CM_ATTEN_CHAR | MMTYPE_IND)); 
	indicate->APPLICATION_TYPE = session->APPLICATION_TYPE; 
	indicate->SECURITY_TYPE = session->SECURITY_TYPE; 
	memcpy (indicate->ACVarField.SOURCE_ADDRESS, session->PEV_MAC, sizeof (indicate->ACVarField.SOURCE_ADDRESS)); 
	memcpy (indicate->ACVarField.RunID, session->RunID, sizeof (indicate->ACVarField.RunID)); 
	memset (indicate->ACVarField.SOURCE_ID, 0, sizeof (indicate->ACVarField.SOURCE_ID)); 
	memset (indicate->ACVarField.RESP_ID, 0, sizeof (indicate->ACVarField.RESP_ID)); 
	indicate->ACVarField.NUM_SOUNDS = session->sounds; 
	indicate->ACVarField.ATTEN_PROFILE.NumGroups = session->NumGroups; 
	memcpy (indicate->ACVarField.ATTEN_PROFILE.AAG, session->AAG, session->NumGroups); 
	if (sendmessage (channel, message, sizeof (* indicate)) <= 0) 
	{ 
		return (debug (1, __func__, CHANNEL_CANTSEND)); 
	} 
	if (readmessage (channel, message, HOMEPLUG_MMV, (CM_ATTEN_CHAR | MMTYPE_RSP)) > 0) 
	{ 
		if (! memcmp (session->RunID, response->ACVarField.RunID, sizeof (session->RunID))) 
		{ 
			debug (0, __func__, "<-- CM_ATTEN_CHAR.RSP"); 

#if SLAC_DEBUG

			if (_anyset (session->flags, SLAC_VERBOSE)) 
			{ 
				char string [256]; 
				debug (0, __func__, "CM_ATTEN_CHAR.RSP.APPLICATION_TYPE %d", response->APPLICATION_TYPE); 
				debug (0, __func__, "CM_ATTEN_CHAR.RSP.SECURITY_TYPE %d", response->SECURITY_TYPE); 
				debug (0, __func__, "CM_ATTEN_CHAR.RSP.ACVarfield.SOURCE_ADDRESS %s", HEXSTRING (string, response->ACVarField.SOURCE_ADDRESS)); 
				debug (0, __func__, "CM_ATTEN_CHAR.RSP.ACVarFIeld.RunID %s", HEXSTRING (string, response->ACVarField.RunID)); 
				debug (0, __func__, "CM_ATTEN_CHAR.RSP.ACVarField.SOURCE_ID %s", HEXSTRING (string, response->ACVarField.SOURCE_ID)); 
				debug (0, __func__, "CM_ATTEN_CHAR.RSP.ACVarField.RESP_ID %s", HEXSTRING (string, response->ACVarField.RESP_ID)); 
				debug (0, __func__, "CM_ATTEN_CHAR.RSP.ACVarField.Result %d", response->ACVarField.Result); 
			} 

#endif

			return (0); 
		} 
	} 
	return (debug (session->exit, __func__, "<-- CM_ATTEN_CHAR.RSP ?")); 
} 

#endif



