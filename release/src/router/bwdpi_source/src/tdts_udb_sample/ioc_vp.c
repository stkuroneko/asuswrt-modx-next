/*
 * Copyright 2014 Trend Micro Incorporated
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software without 
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "udb/shell/shell_ioctl.h"

#include "ioc_common.h"
#include "ioc_vp.h"

int get_fw_vp_list(void **output, unsigned int *buf_used_len)
{
	const int buf_len = (sizeof(udb_vp_ioc_entry_t) * UDB_VIRTUAL_PATCH_LOG_SIZE);
	udb_shell_ioctl_t msg;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_VP;
	msg.op = UDB_IOCTL_VP_OP_GET_LOG;

	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_VP, &msg);
}

int set_fw_vp(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_VP;
	msg.op = UDB_IOCTL_VP_OP_SET;
	udb_shell_ioctl_set_in_raw(&msg, input, length);

	if (0 > run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_VP, &msg))
	{
		return -1;
	}

	return 0;
}

int get_fw_vp_log_v2(void **output, unsigned int *buf_used_len)
{
	udb_shell_ioctl_t msg;

	const int buf_len = sizeof(vp_ioc_v2_hdr_t)
		+ (sizeof(vp_ioc_v2_mac_hdr_t) * DEVID_MAX_USER)
		+ (sizeof(vp_ioc_v2_entry_t) * UDB_VIRTUAL_PATCH_LOG_SIZE)
		+ (sizeof(vp_ioc_v2_rt_hdr_t))
		+ (sizeof(vp_ioc_v2_entry_t) * UDB_RT_VIRTUAL_PATCH_LOG_SIZE);

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_VP;
	msg.op = UDB_IOCTL_VP_OP_GET_LOG_V2;
	
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_VP, &msg);
}

static int get_vp(void)
{
	int ret = 0;
	unsigned int ioc_buf;
	char *buf;

	LIST_HEAD(rule_head);
	init_rule_db(&rule_head);

	ret = get_fw_vp_list((void **) &buf, &ioc_buf);

	if (ret)
	{
		DBG("Error: get user!(%d)\n", ret);
	}

	if (buf)
	{
		udb_vp_ioc_entry_t *ioc_ent;

		uint32_t tbl_used_len = 0, i = 0;
		uint32_t entry_cnt = ioc_buf / sizeof(udb_vp_ioc_entry_t);

		//workaround, prevent not memset
		if (entry_cnt > UDB_VIRTUAL_PATCH_LOG_SIZE)
		{
			entry_cnt = 0;
		}

		printf("---entry_cnt = %u ---\n", entry_cnt);
		printf("---------------------------------\n");

		for (i = 0; i < entry_cnt; i++)
		{
			ioc_ent = (udb_vp_ioc_entry_t *) (buf + tbl_used_len);
			printf("---------------------------------\n");
			printf("[%i]mac: "MAC_OCTET_FMT"\n", i, MAC_OCTET_EXPAND(ioc_ent->mac));
			printf("\ttime: %" PRIu64 "\n", ioc_ent->btime);
			printf("\trule_id: %u\n", ioc_ent->rule_id);
			printf("\trule_name: %s\n", search_rule_db(&rule_head, ioc_ent->rule_id));
			printf("\tcat_id: %u\n", ioc_ent->cat_id);
			printf("\thit_cnt: %d\n", ioc_ent->hit_cnt);
			if (ioc_ent->role == IPS_ROLE_ATT)
			{
				printf("\trole: attacker\n");
			}
			else if (ioc_ent->role == IPS_ROLE_VIC)
			{
				printf("\trole: victim\n");
			}
			else
			{
				printf("\trole: unknown\n");
			}
			printf("\tseverity: %u\n", ioc_ent->severity);
			printf("\tip_ver: %d\n", ioc_ent->ip_ver);
			printf("\tproto:  %d\n", ioc_ent->proto);
			printf("\tsport:  %d\n", ioc_ent->sport);
			printf("\tdport:  %d\n", ioc_ent->dport);
			printf("\taction:  %d-%s\n", ioc_ent->action, ioc_ent->action == 1 ? "Block" : (ioc_ent->action == 2) ? "Monitor" : "Accept");

			if (4 == ioc_ent->ip_ver)
			{
				printf("\tsip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ioc_ent->sip));
				printf("\tdip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ioc_ent->dip));
			}
			else if (6 == ioc_ent->ip_ver)
			{
				printf("\tsip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ioc_ent->sip));
				printf("\tdip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ioc_ent->dip));
			}
			printf("---------------------------------\n");

			tbl_used_len += sizeof(udb_vp_ioc_entry_t);
		}

		free(buf);
	}

	free_rule_db(&rule_head);

	return ret;

}

int get_vp_v2(void)
{
	int ret = -1;
	unsigned int buf_pos, buf_len;
	int e, i;
	char *buf;

	ips_event_entry_t *ent = NULL;
	vp_ioc_v2_entry_t *ioc_ent = NULL;
	vp_ioc_v2_hdr_t *tbl = NULL;
	vp_ioc_v2_mac_hdr_t *mac_hdr = NULL;
	vp_ioc_v2_rt_hdr_t *rt_hdr = NULL;

	LIST_HEAD(rule_head);
	init_rule_db(&rule_head);

	if ((ret = get_fw_vp_log_v2((void **) &buf, &buf_len)))
	{
		DBG("Error: get %s(%d)\n", __func__, ret);
		goto __ret;
	}

	if (!buf || !buf_len)
	{
		DBG("Error: no buffer\n");
		goto __ret;
	}

	buf_pos = 0;

	tbl = (vp_ioc_v2_hdr_t *)buf;

	if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(vp_ioc_v2_hdr_t), buf_len))
	{
		goto __ret;
	}

	for (i = 0; i < tbl->mac_cnt; i++)
	{
		mac_hdr = (vp_ioc_v2_mac_hdr_t *)(buf + buf_pos);
		if (!IOC_SHIFT_LEN_SAFE(buf_pos,
			sizeof(vp_ioc_v2_mac_hdr_t), buf_len))
		{
			goto __ret;
		}

		printf("\n\n");
		printf("uid: %u\n", mac_hdr->uid);
		printf("mac: " MAC_OCTET_FMT "\n", MAC_OCTET_EXPAND(mac_hdr->mac));
		printf("ipv4: " IPV4_OCTET_FMT "\n", IPV4_OCTET_EXPAND(mac_hdr->ipv4));
		printf("ipv6: " IPV6_OCTET_FMT "\n", IPV6_OCTET_EXPAND(mac_hdr->ipv6));

		printf("---entry_cnt = %u ---\n", mac_hdr->ent_cnt);
		printf("---------------------------------\n");

		for (e = 0; e < mac_hdr->ent_cnt; e++)
		{
			ioc_ent = (vp_ioc_v2_entry_t *)(buf + buf_pos);
			if (!IOC_SHIFT_LEN_SAFE(buf_pos,
				sizeof(vp_ioc_v2_entry_t), buf_len))
			{
				goto __ret;
			}

			ent = &ioc_ent->event;

			printf("[%d]\n", e);
			printf("\ttime: %" PRIu64 "\n", ent->time);
			printf("\trule_id: %u\n", ent->rule_id);
			printf("\trule_name: %s\n", search_rule_db(&rule_head, (unsigned) ent->rule_id));
			printf("\tcat_id: %u\n", ent->cat_id);
			printf("\thit_cnt: %d\n", ent->hit_cnt);
			printf("\tdir: %u\n", ent->dir);
			printf("\trole: %s\n", ent->role != 0 ? ent->role == 1 ? "attacker" : "victim" : "na");
			printf("\tip_ver: %d\n", ent->ip_ver);
			printf("\tproto: %u\n", ent->proto);

			if (4 == ent->ip_ver)
			{
				printf("\tpeer_ip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ent->peer_ip));
				printf("\tlocal_ip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ent->local_ip));
			}
			else if (6 == ent->ip_ver)
			{
				printf("\tpeer_ip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ent->peer_ip));
				printf("\tlocal_ip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ent->local_ip));
			}
			printf("\tpeer_port:  %d\n", ent->peer_port);
			printf("\tlocal_port:  %d\n", ent->local_port);
			printf("\taction:  %d-%s\n", ent->action, ent->action == 1 ? "Block" : ent->action == 2 ? "Monitor" : "Accept");
			printf("\tseverity: %u\n", ent->severity);
			printf("\thook: %d\n", ent->hook);
			printf("\tin_dev: %s\n", ent->in_dev);
			printf("\tout_dev: %s\n", ent->out_dev);
			printf("---------------------------------\n");
		}
	}

	rt_hdr = (vp_ioc_v2_rt_hdr_t *)(buf + buf_pos);

	if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(vp_ioc_v2_rt_hdr_t), buf_len))
	{
		goto __ret;
	}

	printf("\n\n");
	printf("router's event:\n");
	printf("---entry_cnt = %u ---\n", rt_hdr->ent_cnt);
	printf("---------------------------------\n");
	for (e = 0; e < rt_hdr->ent_cnt; e++)
	{
		ioc_ent = (vp_ioc_v2_entry_t *)(buf + buf_pos);
		if (!IOC_SHIFT_LEN_SAFE(buf_pos,
			sizeof(vp_ioc_v2_entry_t), buf_len))
		{
			goto __ret;
		}

		ent = &ioc_ent->event;

		printf("[%d]\n", e);
		printf("\tsrc_mac: " MAC_OCTET_FMT "\n", MAC_OCTET_EXPAND(ioc_ent->src_mac));
		printf("\ttime: %" PRIu64 "\n", ent->time);
		printf("\trule_id: %u\n", ent->rule_id);
		printf("\trule_name: %s\n", search_rule_db(&rule_head, (unsigned) ent->rule_id));
		printf("\tcat_id: %u\n", ent->cat_id);
		printf("\thit_cnt: %d\n", ent->hit_cnt);
		printf("\trole: %s\n", ent->role != 0 ? ent->role == 1 ? "attacker" : "victim" : "na");
		printf("\tip_ver: %d\n", ent->ip_ver);
		printf("\tproto: %u\n", ent->proto);
		if (4 == ent->ip_ver)
		{
			printf("\tpeer_ip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ent->peer_ip));
			printf("\tlocal_ip: "IPV4_OCTET_FMT"\n", IPV4_OCTET_EXPAND(ent->local_ip));
		}
		else if (6 == ent->ip_ver)
		{
			printf("\tpeer_ip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ent->peer_ip));
			printf("\tlocal_ip: "IPV6_OCTET_FMT"\n", IPV6_OCTET_EXPAND(ent->local_ip));
		}
		printf("\tpeer_port:  %d\n", ent->peer_port);
		printf("\tlocal_port:  %d\n", ent->local_port);
		printf("\taction:  %d-%s\n", ent->action, ent->action == 1 ? "Block" : ent->action == 2 ? "Monitor" : "Accept");
		printf("\tseverity: %u\n", ent->severity);
		printf("\thook: %d\n", ent->hook);
		printf("\tin_dev: %s\n", ent->in_dev);
		printf("\tout_dev: %s\n", ent->out_dev);
		printf("---------------------------------\n");
	}

	ret = 0;

__ret:
	if (buf)
	{
		free(buf);
	}

	free_rule_db(&rule_head);

	return ret;
}


int vp_options_init(struct cmd_option *cmd)
{
#define HELP_LEN_MAX 1024
	int i = 0, j;
	static char help[HELP_LEN_MAX];
	int len = 0;

	cmd->opts[i].action = ACT_VP_GET_LOG;
	cmd->opts[i].name = "get_vp";
	cmd->opts[i].cb = get_vp;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_VP_GET_LOG_V2;
	cmd->opts[i].name = "get_vp_v2";
	cmd->opts[i].cb = get_vp_v2;
	OPTS_IDX_INC(i);

	len += snprintf(help + len, HELP_LEN_MAX - len, "%*s \n",
		HELP_INDENT_L, "");

	for (j = 0; j < i; j++)
	{
		len += snprintf(help + len, HELP_LEN_MAX - len, "%*s %s\n",
			HELP_INDENT_L, (j == 0) ? "vp actions:" : "",
			cmd->opts[j].name);
	}

	cmd->help = help;

	return 0;
}

