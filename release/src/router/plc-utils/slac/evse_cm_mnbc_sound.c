/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed evse_cm_mnbc_sound (struct session * session, struct channel * channel, struct message * message);
 *
 *   slac.h
 *   
 *   the GP specification recommends that the EVSE-HLE set an overall 
 *   timer once the cm_start_atten_char message is received and use it
 *   to terminate the msound loop in case some msounds are lost; 
 *
 *   accept only CM_MNBC_SOUND.IND that match RunID from the earlier
 *   CM_SLAC_PARAM.REQ and CM_START_ATTRN_CHAT.IND;
 *
 *   each CM_MNBC_MSOUND.IND is accompanied by a CM_ATTEN_PROFILE.IND
 *   but sometimes they arrive out of expected order;
 *
 *   store the running total of CM_ATTEN_PROFILE.IND.AAG values in 
 *   the session variable and compute the average based on actual
 *   number of sounds before returning;
 *
 *--------------------------------------------------------------------*/

#ifndef EVSE_CM_MNBC_SOUND_SOURCE
#define EVSE_CM_MNBC_SOUND_SOURCE

#include <stdio.h>
#include <memory.h>
#include <sys/time.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../tools/timer.h"
#include "../slac/slac.h"

signed evse_cm_mnbc_sound (struct session * session, struct channel * channel, struct message * message) 

{ 
	struct timeval ts; 
	struct timeval tc; 
	signed timer = 100 * session->TIME_OUT; 
	unsigned AAG [SLAC_GROUPS]; 
	unsigned sounds = 0; 
	ssize_t length; 
	session->sounds = 0; 
	memset (AAG, 0, sizeof (AAG)); 
	memset (session->AAG, 0, sizeof (session->AAG)); 
	if (gettimeofday (& ts, NULL) == - 1) 
	{ 
		debug (1, __func__, CANT_START_TIMER); 
	} 
	while ((length = readpacket (channel, message, sizeof (* message))) >= 0) 
	{ 
		struct homeplug1 * homeplug = (struct homeplug1 *) (message); 
		if (! length) 
		{ 
		} 
		else if (ntohs (homeplug->ethernet.MTYPE) != ETH_P_HPAV) 
		{ 
			debug (session->exit, __func__, "bad MTYPE"); 
		} 
		else if (homeplug->homeplug.MMV != HOMEPLUG_MMV) 
		{ 
			debug (session->exit, __func__, "bad MMV"); 
		} 
		else if (LE16TOH (homeplug->homeplug.MMTYPE) == (CM_MNBC_SOUND | MMTYPE_IND)) 
		{ 
			struct cm_mnbc_sound_indicate * indicate = (struct cm_mnbc_sound_indicate *) (message); 
			if (! memcmp (session->RunID, indicate->MSVarField.RunID, sizeof (session->RunID))) 
			{ 
				debug (0, __func__, "<-- CM_MNBC_SOUND.IND (%d)", sounds); 

#if SLAC_DEBUG

				if (_anyset (session->flags, SLAC_VERBOSE)) 
				{ 
					char string [256]; 
					debug (0, __func__, "CM_MNBC_SOUND.IND.APPLICATION_TYPE %d", indicate->APPLICATION_TYPE); 
					debug (0, __func__, "CM_MNBC_SOUND.IND.SECURITY_TYPE %d", indicate->SECURITY_TYPE); 
					debug (0, __func__, "CM_MNBC_SOUND.IND.MSVarField.SenderID %s", HEXSTRING (string, indicate->MSVarField.SenderID)); 
					debug (0, __func__, "CM_MNBC_SOUND.IND.MSVarField.Count %d", indicate->MSVarField.CNT); 
					debug (0, __func__, "CM_MNBC_SOUND.IND.MSVarField.RunID %s", HEXSTRING (string, indicate->MSVarField.RunID)); 
					debug (0, __func__, "CM_MNBC_SOUND.IND.MSVarField.RND %s", HEXSTRING (string, indicate->MSVarField.RND)); 
				} 

#endif

				if (memcmp (session->PEV_MAC, indicate->ethernet.OSA, sizeof (session->PEV_MAC))) 
				{ 
					debug (session->exit, __func__, "Unexpected OSA"); 
				} 
				sounds++; 
			} 
		} 
		else if (LE16TOH (homeplug->homeplug.MMTYPE) == (CM_ATTEN_PROFILE | MMTYPE_IND)) 
		{ 
			struct cm_atten_profile_indicate * indicate = (struct cm_atten_profile_indicate *) (message); 
			if (! memcmp (session->PEV_MAC, indicate->PEV_MAC, sizeof (session->PEV_MAC))) 
			{ 
				debug (0, __func__, "<-- CM_ATTEN_PROFILE.IND (%d)", session->sounds); 

#if SLAC_DEBUG

				if (_anyset (session->flags, SLAC_VERBOSE)) 
				{ 
					char string [256]; 
					debug (0, __func__, "CM_ATTEN_PROFILE.PEV_MAC %s", HEXSTRING (string, indicate->PEV_MAC)); 
					debug (0, __func__, "CM_ATTEN_PROFILE.NumGroups %d", indicate->NumGroups); 
					debug (0, __func__, "CM_ATTEN_PROFILE.AAG %s", hexstring (string, sizeof (string), indicate->AAG, indicate->NumGroups)); 
				} 

#endif

				for (session->NumGroups = 0; session->NumGroups < indicate->NumGroups; session->NumGroups++) 
				{ 
					AAG [session->NumGroups] += indicate->AAG [session->NumGroups]; 
				} 
				session->NumGroups = indicate->NumGroups; 
				session->sounds++; 
			} 
		} 
		if (gettimeofday (& tc, NULL) == - 1) 
		{ 
			debug (1, __func__, CANT_RESET_TIMER); 
		} 
		if ((MILLISECONDS (ts, tc) < timer) && (session->sounds < session->NUM_SOUNDS)) 
		{ 
			continue; 
		} 
		if (session->sounds > 0) 
		{ 
			for (session->NumGroups = 0; session->NumGroups < SLAC_GROUPS; ++ session->NumGroups) 
			{ 
				session->AAG [session->NumGroups] = AAG [session->NumGroups] / session->sounds; 
			} 
		} 
		return (0); 
	} 
	return (debug (session->exit, __func__, "Sound timeout")); 
} 

#endif



