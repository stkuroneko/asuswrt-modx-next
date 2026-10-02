/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed evse_cm_start_atten_char (struct session * session, struct channel * channel, struct message * message);
 *
 *   slac.h
 *
 *   EVSE_HLE stores NUM_SOUNDS, TIME_OUT and FORWARDING_STA for use
 *   later in the SLAC session;
 *
 *   accept only CM_ATTEN_CHAR.IND with RunID that match the earlier
 *   CM_SLAC_PARAM.REQ;
 *
 *--------------------------------------------------------------------*/

#ifndef EVSE_CM_START_ATTEN_CHAR_SOURCE
#define EVSE_CM_START_ATTEN_CHAR_SOURCE

#include <string.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../slac/slac.h"

signed evse_cm_start_atten_char (struct session * session, struct channel * channel, struct message * message) 

{ 
	struct cm_start_atten_char_indicate * indicate = (struct cm_start_atten_char_indicate *) (message); 
	if (readmessage (channel, message, HOMEPLUG_MMV, (CM_START_ATTEN_CHAR | MMTYPE_IND)) > 0) 
	{ 
		if (! memcmp (session->RunID, indicate->ACVarField.RunID, sizeof (session->RunID))) 
		{ 
			debug (0, __func__, "<-- CM_START_ATTEN_CHAR.IND"); 

#if SLAC_DEBUG

			if (_anyset (session->flags, SLAC_VERBOSE)) 
			{ 
				char string [256]; 
				debug (0, __func__, "CM_START_ATTEN_CHAR.IND.APPLICATION_TYPE %d", indicate->APPLICATION_TYPE); 
				debug (0, __func__, "CM_START_ATTEN_CHAR.IND.SECURITY_TYPE %d", indicate->SECURITY_TYPE); 
				debug (0, __func__, "CM_START_ATTEN_CHAR.IND.ACVarField.NUM_SOUNDS %d", indicate->ACVarField.NUM_SOUNDS); 
				debug (0, __func__, "CM_START_ATTEN_CHAR.IND.ACVarField.TIME_OUT %d", indicate->ACVarField.TIME_OUT); 
				debug (0, __func__, "CM_START_ATTEN_CHAR.IND.ACVarField.RESP_TYPE %d", indicate->ACVarField.RESP_TYPE); 
				debug (0, __func__, "CM_START_ATTEN_CHAR.IND.ACVarField.FORWARDING_STA %s", HEXSTRING (string, indicate->ACVarField.FORWARDING_STA)); 
				debug (0, __func__, "CM_START_ATTEN_CHAR.IND.ACVarField.RunID %s", HEXSTRING (string, indicate->ACVarField.RunID)); 
			} 

#endif

			if (indicate->APPLICATION_TYPE != session->APPLICATION_TYPE) 
			{ 
				debug (session->exit, __func__, "%s: APPLICATION_TYPE", __func__); 
			} 
			if (indicate->SECURITY_TYPE != session->SECURITY_TYPE) 
			{ 
				debug (session->exit, __func__, "%s: SECURITY_TYPE", __func__); 
			} 
			session->NUM_SOUNDS = indicate->ACVarField.NUM_SOUNDS; 
			session->TIME_OUT = indicate->ACVarField.TIME_OUT; 
			if (indicate->ACVarField.RESP_TYPE != session->RESP_TYPE) 
			{ 
				debug (session->exit, __func__, "%s: RESP_TYPE", __func__); 
			} 
			memcpy (session->FORWARDING_STA, indicate->ACVarField.FORWARDING_STA, sizeof (session->FORWARDING_STA)); 
			return (0); 
		} 
	} 
	return (debug (session->exit, __func__, "CM_START_ATTEN_CHAR.IND ?")); 
} 

#endif



