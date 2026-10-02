/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed pev_cm_mnbc_sound (struct session * session, struct channel * channel, struct message * message);
 *
 *   slac.h
 *
 *   As HLE-PEV send cm_mnbc_sound indications unicast to the
 *   MSOUND_TARGET address recorded in the session variable;
 *
 *   a brief delay of a few milliseconds is needed between msounds 
 *   so that EVSE-PLC has time to forward CM_MNBC_SOUND.IND and
 *   CM_ATTEN_PROFILE.IND to EVSE-HLE; session.timer controls this
 *   delay;
 *
 *--------------------------------------------------------------------*/

#ifndef PEV_CM_MNBC_SOUND_SOURCE
#define PEV_CM_MNBC_SOUND_SOURCE

#include <string.h>
#include <errno.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/timer.h"
#include "../slac/slac.h"

signed pev_cm_mnbc_sound (struct session * session, struct channel * channel, struct message * message) 

{ 
	struct cm_mnbc_sound_indicate * indicate = (struct cm_mnbc_sound_indicate *) (message); 
	signed sound = session->NUM_SOUNDS; 
	while (sound--) 
	{ 
		debug (0, __func__, "--> CM_MNBC_SOUND.IND"); 
		memset (message, 0, sizeof (* message)); 
		EthernetHeader (& indicate->ethernet, session->MSOUND_TARGET, channel->host, channel->type); 
		HomePlugHeader1 (& indicate->homeplug, HOMEPLUG_MMV, (CM_MNBC_SOUND | MMTYPE_IND)); 
		indicate->APPLICATION_TYPE = session->APPLICATION_TYPE; 
		indicate->SECURITY_TYPE = session->SECURITY_TYPE; 
		memcpy (indicate->MSVarField.SenderID, session->PEV_ID, sizeof (indicate->MSVarField.SenderID)); 
		indicate->MSVarField.CNT = sound; 
		memcpy (indicate->MSVarField.RunID, session->RunID, sizeof (indicate->MSVarField.RunID)); 
		memset (indicate->MSVarField.RND, 0, sizeof (indicate->MSVarField.RND)); 
		if (sendmessage (channel, message, sizeof (* indicate)) <= 0) 
		{ 
			return (debug (1, __func__, CHANNEL_CANTSEND)); 
		} 
		SLEEP (session->pause); 
	} 
	return (0); 
} 

#endif



