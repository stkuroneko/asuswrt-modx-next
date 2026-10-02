/*
** 
** cfg_parammgnt.c
**
**
*/
#include <stdio.h>
#include <shared.h>
#include "cfg_parammgnt.h"

int skip_param_mapping(
	char *name, 
	char role)
{
struct skip_param_mapping_s skip_param_mapping_list[] = {
#ifdef RTCONFIG_LANTIQ
	{ "wl0_ampdu_rts", SKIP_SERVER | SKIP_CLIENT },
	{ "wl1_ampdu_rts", SKIP_SERVER | SKIP_CLIENT },
	{ "wl2_ampdu_rts", SKIP_SERVER | SKIP_CLIENT },
#endif	/* RTCONFIG_LANTIQ */	
	/* end */
	{ NULL, 0 }
};

	int ret = 0;
	struct skip_param_mapping_s *p = &skip_param_mapping_list[0];

	for ( ; name != NULL && p->name != NULL && strlen(name) > 0; p++)
	{
		if ((ret = (strncmp(name, p->name, strlen(name)) == 0 && (p->role & role) == role)) == 1)
			break;
	}

	return ret;
}
