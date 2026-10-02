/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *  
 *   signed evse_cm_slac_param (struct session * session, struct channel * channel, struct message * message);
 *
 *   slac.h
 *  
 *   EVSE-HLE listens indefinitely for a cm_slac_param request and 
 *   responds with a cm_slac_param confirm; this function should not
 *   exit untile a cm_slac_param request so that SLAC sessions will
 *   properly synchronize;
 *
 *   unlike some other EVSE-HLE functions, this one does not check
 *   the run identifier because this is the first point at which a
 *   new run identifier is received; it should, however, store the
 *   run identifier to verify future messages from the PEV;
 *
 *   EVSE-HLE should copy the message OSA to the session variable PEV
 *   MAC address; the PEV MAC address can then be used to respond in
 *   unicast to the right PEVHLE;
 *
 *   EVSE-HLE should copy the run identifier to the session variable 
 *   for use later in the session; this will be used to distinguish
 *   one PEV-EVSE session from another;   
 *
 *   EVSE-HLE should copy the application type and security type to
 *   the session variable unless it wants to operate in a mode that
 *   is different from the PEV;
 *
 *   at this point, the EVSE-HLE dictates the number of msounds and
 *   the msound timeout;
 *
 *   EVSE-HLE should set the msound target to the broadcast address;
 *
 *   EVSE-HLE should set the number of sounds to 8 and the timeout
 *   to 10 intervals of 100ms.
 *
 *   EVSE-HLE may send zeros for the forwarding station since it is
 *   not used here;
 *  
 *--------------------------------------------------------------------*/

#ifndef EVSE_CM_SLAC_PARAM_SOURCE
#define EVSE_CM_SLAC_PARAM_SOURCE

#include <stdio.h>
#include <string.h>

#include "../ether/channel.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/error.h"
#include "../tools/memory.h"
#include "../slac/slac.h"

signed evse_cm_slac_param (struct session * session, struct channel * channel, struct message * message) 

{ 
	extern byte const broadcast [ETHER_ADDR_LEN]; 
	struct cm_slac_param_request * request = (struct cm_slac_param_request *) (message); 
	struct cm_slac_param_confirm * confirm = (struct cm_slac_param_confirm *) (message); 
	while (readmessage (channel, message, HOMEPLUG_MMV, (CM_SLAC_PARAM | MMTYPE_REQ)) > 0) 
	{ 
		debug (0, __func__, "<-- CM_SLAC_PARAM.REQ"); 
		session->APPLICATION_TYPE = request->APPLICATION_TYPE; 
		session->SECURITY_TYPE = request->SECURITY_TYPE; 
		memcpy (session->PEV_MAC, request->ethernet.OSA, sizeof (session->PEV_MAC)); 
		memcpy (session->RunID, request->RunID, sizeof (session->RunID)); 

#if SLAC_DEBUG

		if (_anyset (session->flags, SLAC_VERBOSE)) 
		{ 
			char string [256]; 
			debug (0, __func__, "CM_SLAC_PARAM.REQ.APPLICATION_TYPE %d", request->APPLICATION_TYPE); 
			debug (0, __func__, "CM_SLAC_PARAM.REQ.SECURITY_TYPE %d", request->SECURITY_TYPE); 
			debug (0, __func__, "CM_SLAC_PARAM.REQ.RunID %s", HEXSTRING (string, request->RunID)); 
			debug (0, __func__, "CM_SLAC_PARAM.REQ.CipherSuiteSetSize %d", request->CipherSuiteSetSize); 
			debug (0, __func__, "CM_SLAC_PARAM.REQ.CipherSuite [0] %d", request->CipherSuite [0]); 
			debug (0, __func__, "CM_SLAC_PARAM.REQ.CipherSuite [1] %d", request->CipherSuite [1]); 
		} 

#endif

		if (_anyset (session->flags, SLAC_COMPARE)) 
		{ 
			if (LE16TOH (request->CipherSuite [0]) != (uint16_t) (session->counter)) 
			{ 
				debug (session->exit, __func__, "session->counter mismatch! PEV=(%d) EVSE=(%d)", LE16TOH (request->CipherSuite [0]), session->counter); 
			} 
		} 
		debug (0, __func__, "--> CM_SLAC_PARAM.CNF"); 
		memset (message, 0, sizeof (* message)); 
		EthernetHeader (& confirm->ethernet, session->PEV_MAC, channel->host, channel->type); 
		HomePlugHeader1 (& confirm->homeplug, HOMEPLUG_MMV, (CM_SLAC_PARAM | MMTYPE_CNF)); 
		memcpy (confirm->MSOUND_TARGET, broadcast, sizeof (confirm->MSOUND_TARGET)); 
		confirm->NUM_SOUNDS = session->NUM_SOUNDS; 
		confirm->TIME_OUT = session->TIME_OUT; 
		confirm->RESP_TYPE = session->RESP_TYPE; 
		memcpy (confirm->FORWARDING_STA, session->FORWARDING_STA, sizeof (confirm->FORWARDING_STA)); 
		confirm->APPLICATION_TYPE = session->APPLICATION_TYPE; 
		confirm->SECURITY_TYPE = session->SECURITY_TYPE; 
		memcpy (confirm->RunID, session->RunID, sizeof (confirm->RunID)); 
		confirm->CipherSuite = HTOLE16 ((uint16_t) (session->counter)); 
		if (sendmessage (channel, message, (ETHER_MIN_LEN - ETHER_CRC_LEN)) <= 0) 
		{ 
			return (debug (1, __func__, CHANNEL_CANTSEND)); 
		} 
		return (0); 
	} 
	return (debug (0, __func__, "<-- CM_SLAC_PARAM.REQ ?")); 
} 

#endif



