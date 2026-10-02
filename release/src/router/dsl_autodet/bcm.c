/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <shared.h>
#include "auto_det.h"

int create_atm_intf(atm_pvc_t* pvc, char *iface, size_t if_len)
{
	char cmd[256] = {0};
	char atm_tuple[32] = {0};
	int port_mask = 1;
	char encap[16] = {0};
	int tdte_idx = 1;
	int mp_prio = 0; // 0 ~ 7
	int mp_wght = 1; // 1 ~ 63
	int q_prio =  0; // 0 ~ 7
	int q_wght = 1; // 1 ~ 63

	if(pvc->encap == ATM_ENCAP_LLC)
	{
		if( pvc->proto == ATM_PROTO_PPPOA )
			strlcpy(encap, "llcencaps_ppp", sizeof(encap));
		else
			strlcpy(encap, "llcsnap_eth", sizeof(encap));
	}
	else
	{
		if( pvc->proto == ATM_PROTO_PPPOA )
			strlcpy(encap, "vcmux_pppoa", sizeof(encap));
		else
			strlcpy(encap, "vcmux_eth", sizeof(encap));
	}

	snprintf(atm_tuple, sizeof(atm_tuple), "%d.%d.%d", port_mask, pvc->vpi, pvc->vci);

	snprintf(iface, if_len, "atm%s", atm_tuple);

	snprintf(cmd, sizeof(cmd), "xtmctl operate conn --delete %s --deletenetdev %s", atm_tuple, atm_tuple);
	_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	system(cmd);

	snprintf(cmd, sizeof(cmd), "xtmctl operate conn"
				" --add %s aal5 %s %d %d %d"
				" --addq %s %d wrr %d dt"
				" --createnetdev %s %s"
		, atm_tuple, encap, mp_prio, mp_wght, tdte_idx
		, atm_tuple, q_prio, q_wght
		, atm_tuple, iface
		);
	_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	return system(cmd);
}

int delete_atm_intf(atm_pvc_t* pvc, const char *iface)
{
	char cmd[256] = {0};
	int port_mask = 1;

	snprintf(cmd, sizeof(cmd), "xtmctl operate conn --delete %d.%d.%d --deletenetdev %d.%d.%d",
		port_mask, pvc->vpi, pvc->vci, port_mask, pvc->vpi, pvc->vci);
	return system(cmd);
}

int is_eth_wan_link_up()
{
	char buf[16] = {0};
	char path[128] = {0};

	get_eth_wan_interface(buf, sizeof(buf));
	snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", buf);

	f_read_string(path, buf, sizeof(buf));
	if(!strncmp(buf, "up", 2))
		return 1;
	else
		return 0;
}
