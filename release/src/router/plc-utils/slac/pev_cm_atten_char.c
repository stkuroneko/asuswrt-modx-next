/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed pev_cm_atten_char (struct session * session, struct channel * channel, struct message * message);
 *
 *   slac.h
 *
 *   PEV-HLE waits for CM_ATTEN_CHAR.IND from EVSE-HLE and responds
 *   to indicate the data was received in good order; this response
 *   does not mean that PEV-HLE will mate with EVSE-HLE;
 *
 *--------------------------------------------------------------------*/

#ifndef PEV_CM_ATTEN_CHAR_SOURCE
#define PEV_CM_ATTEN_CHAR_SOURCE

#include <string.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../slac/slac.h"

signed pev_cm_atten_char (struct session * session, struct channel * channel, struct message * message) 

{ 
	struct cm_atten_char_indicate * indicate = (struct cm_atten_char_indicate *) (message); 
	struct cm_atten_char_response * response = (struct cm_atten_char_response *) (message); 
	while (readmessage (channel, message, HOMEPLUG_MMV, (CM_ATTEN_CHAR | MMTYPE_IND)) > 0) 
	{ 
		if (! memcmp (session->RunID, indicate->ACVarField.RunID, sizeof (session->RunID))) 
		{ 
			debug (0, __func__, "<-- CM_ATTEN_CHAR.IND"); 
			memcpy (session->EVSE_MAC, indicate->ethernet.OSA, sizeof (session->EVSE_MAC)); 
			session->NUM_SOUNDS = indicate->ACVarField.NUM_SOUNDS; 
			session->NumGroups = indicate->ACVarField.ATTEN_PROFILE.NumGroups; 
			memcpy (session->AAG, indicate->ACVarField.ATTEN_PROFILE.AAG, indicate->ACVarField.ATTEN_PROFILE.NumGroups); 

#if SLAC_DEBUG

			if (_anyset (session->flags, SLAC_VERBOSE)) 
			{ 
				char string [256]; 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.APPLICATION_TYPE %d", indicate->APPLICATION_TYPE); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.SECURITY_TYPE %d", indicate->SECURITY_TYPE); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.SOURCE_ADDRESS %s", HEXSTRING (string, indicate->ACVarField.SOURCE_ADDRESS)); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.RunID %s", HEXSTRING (string, indicate->ACVarField.RunID)); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.SOURCE_ID %s", HEXSTRING (string, indicate->ACVarField.SOURCE_ID)); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.RESP_ID %s", HEXSTRING (string, indicate->ACVarField.RESP_ID)); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.NUM_SOUNDS %d", indicate->ACVarField.NUM_SOUNDS); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.ATTEN_PROFILE.NumGroups %d", indicate->ACVarField.ATTEN_PROFILE.NumGroups); 
				debug (0, __func__, "CM_ATTEN_CHAR.IND.ACVarField.ATTEN_PROFILE.AAG %s", hexstring (string, sizeof (string), indicate->ACVarField.ATTEN_PROFILE.AAG, indicate->ACVarField.ATTEN_PROFILE.NumGroups)); 
			} 

#endif

			debug (0, __func__, "--> CM_ATTEN_CHAR.RSP"); 
			memset (message, 0, sizeof (* message)); 
			EthernetHeader (& response->ethernet, session->EVSE_MAC, channel->host, channel->type); 
			HomePlugHeader1 (& response->homeplug, HOMEPLUG_MMV, (CM_ATTEN_CHAR | MMTYPE_RSP)); 
			response->APPLICATION_TYPE = session->APPLICATION_TYPE; 
			response->SECURITY_TYPE = session->SECURITY_TYPE; 
			memcpy (response->ACVarField.SOURCE_ADDRESS, session->PEV_MAC, sizeof (response->ACVarField.SOURCE_ADDRESS)); 
			memcpy (response->ACVarField.RunID, session->RunID, sizeof (response->ACVarField.RunID)); 
			memset (response->ACVarField.SOURCE_ID, 0, sizeof (response->ACVarField.SOURCE_ID)); 
			memset (response->ACVarField.RESP_ID, 0, sizeof (response->ACVarField.RESP_ID)); 
			response->ACVarField.Result = 0; 
			if (sendmessage (channel, message, sizeof (* response)) <= 0) 
			{ 
				return (debug (1, __func__, CHANNEL_CANTSEND)); 
			} 
			return (0); 
		} 
	} 
	return (debug (session->exit, __func__, "<-- CM_ATTEN_CHAR.IND ?")); 
} 

#endif



