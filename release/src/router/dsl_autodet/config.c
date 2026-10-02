/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include <shared.h>
#include <shutils.h>

#include "auto_det.h"

void init_config(autodet_conf_t* config)
{
#if defined(RTCONFIG_DUALWAN)
	config->wans_cap = get_wans_cap();
#elif defined(RTCONFIG_DSL)
	config->wans_cap = WANS_DUALWAN_IF_DSL;
#else
	config->wans_cap = WANS_DUALWAN_IF_WAN;
#endif
}

int is_dsl_plugged()
{
	char status[16] = {0};
	nvram_safe_get_r("dsltmp_adslsyncsts", status, sizeof(status));
	return (!strcmp(status, "up") || !strcmp(status, "init"));
}

int is_dsl_link_up()
{
	return (nvram_match("dsltmp_adslsyncsts","up"));
}

int is_vdsl()
{
	return (nvram_match("dsllog_xdslmode","VDSL"));
}

void set_wan_type(int type)
{
	switch(type)
	{
		case DSL_AUTODET_WAN_TYPE_ATM:
			nvram_set("dsltmp_autodet_wan_type", "ATM");
			break;
		case DSL_AUTODET_WAN_TYPE_PTM:
			nvram_set("dsltmp_autodet_wan_type", "PTM");
			break;
		default:
			cprintf("unknown wan type\n");
			break;
	}
}

void set_autodet_state(int state)
{
	switch(state)
	{
		case DSL_AUTODET_STATE_NONE:
			nvram_set("dsltmp_autodet_state", "");
			break;
		case DSL_AUTODET_STATE_DETECTING:
			nvram_set("dsltmp_autodet_state", "detecting");
			break;
		case DSL_AUTODET_STATE_DHCP:
			nvram_set("dsltmp_autodet_state", "dhcp");
			break;
		case DSL_AUTODET_STATE_PPPOE:
			nvram_set("dsltmp_autodet_state", "pppoe");
			break;
		case DSL_AUTODET_STATE_PPPOA:
			nvram_set("dsltmp_autodet_state", "pppoa");
			break;
		case DSL_AUTODET_STATE_FAIL:
			nvram_set("dsltmp_autodet_state", "Fail");
			break;
		case DSL_AUTODET_STATE_NOLINK:
			nvram_set("dsltmp_autodet_state", "down");
			break;
		default:
			cprintf("unknown state\n");
			break;
	}
}

void set_autodet_state_eth(int state, int auxstate)
{
	nvram_set_int("autodet_state", state);
	nvram_set_int("autodet_auxstate", auxstate);
}

void set_atm_pvc_result(int vpi, int vci, int encap)
{
	nvram_set_int("dsltmp_autodet_vpi", vpi);
	nvram_set_int("dsltmp_autodet_vci", vci);
	nvram_set_int("dsltmp_autodet_encap", encap);
}

void get_eth_wan_interface(char *buf, size_t len)
{
#if defined(RTCONFIG_DUALWAN)
	if (get_dualwan_primary() == WANS_DUALWAN_IF_WAN)
		strlcpy(buf, nvram_safe_get("wan0_ifname"), len);
	else if (get_dualwan_secondary() == WANS_DUALWAN_IF_WAN)
		strlcpy(buf, nvram_safe_get("wan1_ifname"), len);
	else
	{// eth wan not used
		strlcpy(buf, nvram_safe_get("wan_ifname"), len);
	}
#else
	strlcpy(buf, nvram_safe_get("wan0_ifname"), len);
#endif
}
