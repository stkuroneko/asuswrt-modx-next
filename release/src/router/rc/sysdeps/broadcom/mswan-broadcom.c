/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 */

#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <rtstate.h>
#include "rc.h"

#if defined(RTCONFIG_HND_ROUTER)

void config_mswan(int wan_unit)
{
	char wan_prefix[16] = {0};
	MSWAN_PARAM mparam;
	int unit = 0;
	int base_unit = get_ms_base_unit(wan_unit);
	char word[16] = {0};
	char *p = NULL;
	int mr_mswan_idx = nvram_get_int("mr_mswan_idx");
	int real_mr_mswan_idx = 0;
	int wans_dualwan = WANS_DUALWAN_IF_NONE;

#ifdef RTCONFIG_DSL
#ifdef RTCONFIG_DUALWAN
	wans_dualwan = get_dualwan_by_unit(base_unit);
	if (wans_dualwan == WANS_DUALWAN_IF_DSL
	 || wans_dualwan == WANS_DUALWAN_IF_USB
	 || wans_dualwan == WANS_DUALWAN_IF_USB2
	 || wans_dualwan == WANS_DUALWAN_IF_2G
	 || wans_dualwan == WANS_DUALWAN_IF_5G
	 || wans_dualwan == WANS_DUALWAN_IF_SFPP
	)
		return;
#else
	return;
#endif
#endif

	clean_mswan_vitf(wan_unit);

	memset(&mparam, 0, sizeof(mparam));
	mparam.base_wan_unit = base_unit;

	unit = WAN_UNIT_FIRST;
	foreach (word, nvram_safe_get("wan_ifnames"), p)
	{
		if (unit == base_unit)
			snprintf(mparam.base_ifname, sizeof(mparam.base_ifname), "%s", word);
		unit++;
	}

	// calculate how many services are enabled
	// check mr_mswan_idx is enabled.
	// Only WAN_UNIT_FIRST for igmp proxy by definition, not configurable.
	for (unit = 0; unit < WAN_MULTISRV_MAX; unit++)
	{
		snprintf(wan_prefix, sizeof(wan_prefix), "wan%d_", get_ms_wan_unit(base_unit, unit));
		if (nvram_pf_get_int(wan_prefix, "enable"))
		{
			if (unit == mr_mswan_idx)
				real_mr_mswan_idx = mr_mswan_idx;
			mparam.total_config++;
		}
	}

	if (wan_unit < WAN_UNIT_MAX)
	{ // set all virtual interface
		for (unit = 0; unit < WAN_MULTISRV_MAX; unit++)
		{
			snprintf(wan_prefix, sizeof(wan_prefix), "wan%d_", get_ms_wan_unit(base_unit, unit));
			mparam.enable = nvram_pf_get_int(wan_prefix, "enable");
			if (mparam.enable)
			{
				mparam.unit = unit;
				snprintf(mparam.proto, sizeof(mparam.proto), "%s", nvram_pf_safe_get(wan_prefix, "proto"));
				mparam.dot1q = nvram_pf_get_int(wan_prefix, "dot1q");
				mparam.vid = nvram_pf_get_int(wan_prefix, "vid");
				mparam.dot1p = nvram_pf_get_int(wan_prefix, "dot1p");
				mparam.dscp = (p = nvram_pf_get(wan_prefix, "dscp")) ? atoi(p) : -1;
				if (base_unit == WAN_UNIT_FIRST && unit == real_mr_mswan_idx)
					mparam.mcast = 1;
				else
					mparam.mcast = 0;

				// If only one service and not enable 802.1Q, Stopped. (e.g. default case)
				// Don't use virtual interface, otherwise, ETH Onboaring will failed
				// since we set eth_ifnames to real phy interface.
				if (unit == 0
				 && mparam.total_config == 1
				 && mparam.dot1q == 0
				) {
					nvram_pf_set(wan_prefix, "ifname", mparam.base_ifname);
					if (base_unit == WAN_UNIT_FIRST)
						nvram_set("iptv_ifname", mparam.base_ifname);
					return;
				}

				set_mswan_vitf(&mparam);
			}
		}
	}
	else
	{
		snprintf(wan_prefix, sizeof(wan_prefix), "wan%d_", wan_unit);
		mparam.enable = nvram_pf_get_int(wan_prefix, "enable");
		if (mparam.enable)
		{
			mparam.unit = get_ms_idx_by_wan_unit(wan_unit);
			snprintf(mparam.proto, sizeof(mparam.proto), "%s", nvram_pf_safe_get(wan_prefix, "proto"));
			mparam.dot1q = nvram_pf_get_int(wan_prefix, "dot1q");
			mparam.vid = nvram_pf_get_int(wan_prefix, "vid");
			mparam.dot1p = nvram_pf_get_int(wan_prefix, "dot1p");
			mparam.dscp = (p = nvram_pf_get(wan_prefix, "dscp")) ? atoi(p) : -1;
			if (base_unit == WAN_UNIT_FIRST && wan_unit == get_ms_wan_unit(base_unit, real_mr_mswan_idx))
				mparam.mcast = 1;
			else
				mparam.mcast = 0;

			set_mswan_vitf(&mparam);
		}
	}
}

void clean_mswan_vitf(int wan_unit)
{
	char wan_ifname[8] = {0};
	int i = 0;
	int s;
	struct ifreq ifr;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return;

	if (wan_unit < WAN_UNIT_MAX && get_dualwan_by_unit(wan_unit) == WANS_DUALWAN_IF_DSL)
	{ //clean all virtual interface
		for (i = 0; i < WAN_MULTISRV_MAX; i++)
		{
			snprintf(wan_ifname, sizeof(wan_ifname), "wan%d", get_ms_wan_unit(wan_unit, i));
			strlcpy(ifr.ifr_name, wan_ifname, IFNAMSIZ);
			if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
				continue;
			else
			{
				eval("vlanctl", "--rule-remove-all", wan_ifname);
				eval("vlanctl", "--if-delete", wan_ifname);
			}
		}
	}
	else
	{ // clean specific virtual interface
		snprintf(wan_ifname, sizeof(wan_ifname), "wan%d", wan_unit);
		strlcpy(ifr.ifr_name, wan_ifname, IFNAMSIZ);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		{
			close(s);
			return;
		}
		else
		{
			eval("vlanctl", "--rule-remove-all", wan_ifname);
			eval("vlanctl", "--if-delete", wan_ifname);
		}
	}

	close(s);
}

#define VLANCTL_OUTPUT "/tmp/vlanctl.output"
static int is_first_vlanctl_rule(char* ifname, int rx, int tag_nbr)
{
	char tag_str[4] = {0};
	char *argv[] = {"vlanctl", "--if", ifname
			, (rx)?"--rx":"--tx", "--tags", tag_str, "--show-table"
			, NULL};
	char buf[512] = {0};
	int ret = 1;

	snprintf(tag_str, sizeof(tag_str), "%d", tag_nbr);
	if (_eval(argv, ">"VLANCTL_OUTPUT, 0, NULL) == 0)
	{
		f_read_string(VLANCTL_OUTPUT, buf, sizeof(buf));
		if (strstr(buf, "Rule ID :"))
			ret = 0;
		unlink(VLANCTL_OUTPUT);
	}

	return (ret);
}

void set_mswan_vitf(MSWAN_PARAM *p)
{
	char wan_prefix[16] = {0};
	char wan_ifname[16] = {0};
	char vid_str[8] = {0};
	char pbits_str[4] = {0};
	char dscp_str[4] = {0};
	char *rx_argv[] = { "vlanctl", "--if", p->base_ifname
				, "--rx", "--tags", (p->dot1q) ? "1" : "0"
				, "--set-rxif", wan_ifname
				, NULL, NULL, NULL //"--filter-vid", vid_str, "1"
				, NULL //"--pop-tag"
				, NULL, NULL //"--filter-vlan-dev-mac-addr", "1"
				, NULL, NULL //"--rule-insert-before", "0" or "--rule-append"
				, NULL };
	char *tx_argv[] = { "vlanctl", "--if", p->base_ifname
				, "--tx", "--tags", "0"
				, "--filter-txif", wan_ifname
				, NULL //"--push-tag"
				, NULL, NULL, NULL //"--set-vid", vid_str, "0"
				, NULL, NULL, NULL //"--set-pbits", pbits_str, "0"
				, NULL, NULL //"--set-dscp", "0"
				, NULL //"--rule-append"
				, NULL };
	int rx_idx = 8;
	int tx_idx = 8;

	if ( !p || strlen(p->base_ifname) == 0)
		return;
	if (p->base_wan_unit > WAN_UNIT_MAX)
		return;

	//define interface name wanXYZ
	snprintf(wan_ifname, sizeof(wan_ifname), "wan%d", get_ms_wan_unit(p->base_wan_unit, p->unit));
	snprintf(wan_prefix, sizeof(wan_prefix), "%s_", wan_ifname);
	nvram_pf_set(wan_prefix, "ifname", wan_ifname);

	ifconfig(p->base_ifname, IFUP, "0.0.0.0", NULL);

	// config for igmp
	if (p->mcast)
		nvram_set("iptv_ifname", wan_ifname);

	// vlanctl interface
	eval("vlanctl", "--if", p->base_ifname, "--if-create-name", p->base_ifname , wan_ifname
		, "--mcast", "--set-if-mode-rg");

	ifconfig(wan_ifname, IFUP, "0.0.0.0", NULL);

	// vlanctl rule
	snprintf(vid_str, sizeof(vid_str), "%d", p->vid);
	snprintf(pbits_str, sizeof(pbits_str), "%d", p->dot1p);
	snprintf(dscp_str, sizeof(dscp_str), "%d", p->dscp);
	//rx
	if (p->dot1q)
	{
		rx_argv[rx_idx++] = "--filter-vid";
		rx_argv[rx_idx++] = vid_str;
		rx_argv[rx_idx++] = "1";

		if (strcmp(p->proto, "bridge"))
		{
			rx_argv[rx_idx++] = "--filter-vlan-dev-mac-addr";
			rx_argv[rx_idx++] = "1";
		}

		rx_argv[rx_idx++] = "--pop-tag";

		if (is_first_vlanctl_rule(p->base_ifname, 1, 1))
		{
			rx_argv[rx_idx++] = "--rule-append";
		}
		else
		{
			rx_argv[rx_idx++] = "--rule-insert-before";
			rx_argv[rx_idx++] = "0";
		}
	}
	else
	{
		if (strcmp(p->proto, "bridge"))
		{
			rx_argv[rx_idx++] = "--filter-vlan-dev-mac-addr";
			rx_argv[rx_idx++] = "1";
		}

		rx_argv[rx_idx++] = "--rule-append";
	}

	//tx
	if (p->dot1q)
	{
		tx_argv[tx_idx++] = "--push-tag";
		tx_argv[tx_idx++] = "--set-vid";
		tx_argv[tx_idx++] = vid_str;
		tx_argv[tx_idx++] = "0";

		if (p->dot1p)
		{
			tx_argv[tx_idx++] = "--set-pbits";
			tx_argv[tx_idx++] = pbits_str;
			tx_argv[tx_idx++] = "0";
		}
	}

	if (p->dscp >= 0)
	{
		tx_argv[tx_idx++] = "--set-dscp";
		tx_argv[tx_idx++] = dscp_str;
	}

	tx_argv[tx_idx++] = "--rule-append";

	//_dprintf("\n=====\n"); for(rx_idx=0; rx_argv[rx_idx]; rx_idx++) _dprintf("%s ", rx_argv[rx_idx]);
	//_dprintf("\n=====\n"); for(tx_idx=0; tx_argv[tx_idx]; tx_idx++) _dprintf("%s ", tx_argv[tx_idx]);
	//_dprintf("\n=====\n"); usleep(100000);
	_eval(rx_argv, NULL, 0, NULL);
	_eval(tx_argv, NULL, 0, NULL);
}

#else

void config_mswan(int wan_unit)
{
	int unit = 0;
	int base_unit = get_ms_base_unit(wan_unit);
	char wan_prefix[16] = {0};
	int mr_mswan_idx = nvram_get_int("mr_mswan_idx");
	int real_mr_mswan_idx = 0;
	int wans_dualwan = WANS_DUALWAN_IF_NONE;

#ifdef RTCONFIG_DSL
#ifdef RTCONFIG_DUALWAN
	wans_dualwan = get_dualwan_by_unit(base_unit);
	if (wans_dualwan == WANS_DUALWAN_IF_DSL
	 || wans_dualwan == WANS_DUALWAN_IF_USB
	 || wans_dualwan == WANS_DUALWAN_IF_USB2
	 || wans_dualwan == WANS_DUALWAN_IF_2G
	 || wans_dualwan == WANS_DUALWAN_IF_5G
	 || wans_dualwan == WANS_DUALWAN_IF_SFPP
	)
		return;
#else
	return;
#endif
#endif

	//tmp not support, if configured, disable it.
	if (wan_unit > WAN_UNIT_MULTISRV_BASE)
	{
		snprintf(wan_prefix, sizeof(wan_prefix), "wan%d_", wan_unit);
		if (nvram_pf_get_int(wan_prefix, "enable"))
		{
			nvram_pf_set(wan_prefix, "enable", "0");
			nvram_pf_set(wan_prefix, "ifname", "");
		}
	}

	// check mr_mswan_idx is enabled.
	// Only WAN_UNIT_FIRST for igmp proxy by definition, not configurable.
	if (base_unit == WAN_UNIT_FIRST)
	{
		for (unit = 0; unit < WAN_MULTISRV_MAX; unit++)
		{
			snprintf(wan_prefix, sizeof(wan_prefix), "wan%d_", get_ms_wan_unit(base_unit, unit));
			if (nvram_pf_get_int(wan_prefix, "enable"))
			{
				if (unit == mr_mswan_idx)
					real_mr_mswan_idx = mr_mswan_idx;
			}
		}

		snprintf(wan_prefix, sizeof(wan_prefix), "wan%d_", get_ms_wan_unit(base_unit, real_mr_mswan_idx));
		nvram_set("iptv_ifname", nvram_pf_safe_get(wan_prefix, "ifname"));
	}
}

#endif
