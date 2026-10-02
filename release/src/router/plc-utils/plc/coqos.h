/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

#ifndef COQOS_HEADER
#define COQOS_HEADER

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../plc/rules.h"

/*====================================================================*
 *   network classification rule structure;
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push,1)
#endif

struct __packed connection

{
	uint32_t REQ_ID;
	uint32_t RSVD;
	uint8_t APP_DA [6];
	uint8_t RSVD2;
	struct __packed
	{
		uint8_t MOPERAND;
		uint8_t NUM_CLASSIFIERS;
		struct MMEClassifier CLASSIFIERS [RULE_MAX_CLASSIFIERS];
	}
	rule;
	struct __packed
	{
		uint16_t CSPEC_VERSION;
		uint8_t CONN_CAP;
		uint8_t CONN_COQOS_PRIO;
		uint16_t CONN_RATE;
		uint32_t CONN_TTL;
	}
	cspec;
};

struct __packed conn_info

{
	uint8_t SNID;
	uint16_t CID;
	uint8_t STEI;
	uint8_t DTEI;
	uint8_t LLID;
	uint8_t RSVD;
	uint16_t CSPECVERSION;
	uint8_t CONN_CAP;
	uint8_t CONN_COQOS_PRIO;
	uint16_t CONN_RATE;
	uint32_t CONN_TTL;
	uint16_t BW_USED;
};

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



