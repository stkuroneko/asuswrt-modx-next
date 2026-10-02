#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_string.h"
#include "cfg_prelink.h"

/*
========================================================================
Routine Description:
	Add prelink config.

Arguments:
	outRoot             - json object for output

Return Value:
	None

Note:
========================================================================
*/
void cm_addPrelinkConfig(json_object *outRoot)
{
	if (nvram_get("amas_hashbdlkey") && strlen(nvram_safe_get("amas_hashbdlkey"))) {
		/* add hash bundle key */
		json_object_object_add(outRoot, CFG_STR_HASH_BUNDLE_KEY,
			json_object_new_string(nvram_safe_get("amas_hashbdlkey")));
	}
} /* End of cm_addPrelinkConfig */