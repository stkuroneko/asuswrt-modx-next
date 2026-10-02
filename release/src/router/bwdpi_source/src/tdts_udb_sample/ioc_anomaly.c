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
#include "ioc_anomaly.h"

int get_fw_anomaly_list(void **output, unsigned int *buf_used_len)
{
	udb_shell_ioctl_t msg;

	const int buf_len = sizeof(udb_ano_ioc_entry_list_t)
		+ (sizeof(udb_ano_ioc_entry_t) * UDB_ANOMALY_LOG_SIZE);

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_ANOMALY;
	msg.op = UDB_IOCTL_ANOMALY_OP_GET_LOG;
	
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_ANOMALY, &msg);
}

int get_fw_anomaly_list_v2(void **output, unsigned int *buf_used_len)
{
	udb_shell_ioctl_t msg;

	const int buf_len = sizeof(anomaly_ioc_v2_hdr_t)
		+ (sizeof(anomaly_ioc_v2_mac_hdr_t) * DEVID_MAX_USER)
		+ (sizeof(anomaly_ioc_v2_entry_t) * UDB_ANOMALY_LOG_SIZE)
		+ (sizeof(anomaly_ioc_v2_rt_hdr_t))
		+ (sizeof(anomaly_ioc_v2_entry_t) * UDB_RT_ANOMALY_LOG_SIZE);

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_ANOMALY;
	msg.op = UDB_IOCTL_ANOMALY_OP_GET_LOG_V2;
	
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_ANOMALY, &msg);
}

int get_anomaly(void)
{
	int ret = 0;
	unsigned int e, buf_pos __attribute__((unused)), ioc_buf;
	char *buf;

	udb_ano_ioc_entry_list_t *tbl = NULL;

	LIST_HEAD(rule_head);
	init_rule_db(&rule_head);

	ret = get_fw_anomaly_list((void **) &buf, &ioc_buf);
	if (ret)
	{
		DBG("Error: get %s(%d)\n", __func__, ret);
	}

	if (buf)
	{
		tbl = (udb_ano_ioc_entry_list_t *) buf;
		buf_pos = sizeof(udb_ano_ioc_entry_list_t);

		printf("---entry_cnt = %u ---\n", tbl->cnt);
		printf("%-10s\t%-18s\t%-14s%-11s%-13s%s\n", "time", "mac", "rule_id", "hit_cnt", "action", "rule_name");
		printf("---------------------------------------------------------------------------------------------\n");
		for (e = 0; e < tbl->cnt; e++)
		{
			printf("%-10" PRIu64 "\t", tbl->entry[e].time);
			printf(MAC_OCTET_FMT"\t", MAC_OCTET_EXPAND(tbl->entry[e].mac));
			/* 14 (fixed width) = 10 (max length of rule_id) + 4 (reserved) */
			printf("%-14u", tbl->entry[e].rule_id);
			/* 11 (fixed width) = 7 (strlen("hit_cnt")) + 4 (reserved) */
			printf("%-11u", tbl->entry[e].hit_cnt);
			/* 13 (fixed width) = 9 (strlen("2-Monitor")) + 4 (reserved) */
			printf("%-13s", tbl->entry[e].action == 1 ? "1-Block" : tbl->entry[e].action == 2 ? "2-Monitor" : "0-Accept");

			printf("%s\n", search_rule_db(&rule_head, (unsigned) tbl->entry[e].rule_id));
		}

		free(buf);
	}

	free_rule_db(&rule_head);

	return ret;
}

int get_anomaly_v2(void)
{
	int ret = -1;
	unsigned int buf_pos, buf_len;
	int e, i;
	char *buf;

	ips_event_entry_t *ent = NULL;
	anomaly_ioc_v2_entry_t *ioc_ent = NULL;
	anomaly_ioc_v2_hdr_t *tbl = NULL;
	anomaly_ioc_v2_mac_hdr_t *mac_hdr = NULL;
	anomaly_ioc_v2_rt_hdr_t *rt_hdr = NULL;

	LIST_HEAD(rule_head);
	init_rule_db(&rule_head);

	if ((ret = get_fw_anomaly_list_v2((void **) &buf, &buf_len)))
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

	tbl = (anomaly_ioc_v2_hdr_t *)buf;

	if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(anomaly_ioc_v2_hdr_t), buf_len))
	{
		goto __ret;
	}

	for (i = 0; i < tbl->mac_cnt; i++)
	{
		mac_hdr = (anomaly_ioc_v2_mac_hdr_t *)(buf + buf_pos);
		if (!IOC_SHIFT_LEN_SAFE(buf_pos,
			sizeof(anomaly_ioc_v2_mac_hdr_t), buf_len))
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
			ioc_ent = (anomaly_ioc_v2_entry_t *)(buf + buf_pos);
			if (!IOC_SHIFT_LEN_SAFE(buf_pos,
				sizeof(anomaly_ioc_v2_entry_t), buf_len))
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

	rt_hdr = (anomaly_ioc_v2_rt_hdr_t *)(buf + buf_pos);

	if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(anomaly_ioc_v2_rt_hdr_t), buf_len))
	{
		goto __ret;
	}

	printf("\n\n");
	printf("router's event:\n");
	printf("---entry_cnt = %u ---\n", rt_hdr->ent_cnt);
	printf("---------------------------------\n");
	for (e = 0; e < rt_hdr->ent_cnt; e++)
	{
		ioc_ent = (anomaly_ioc_v2_entry_t *)(buf + buf_pos);
		if (!IOC_SHIFT_LEN_SAFE(buf_pos,
			sizeof(anomaly_ioc_v2_entry_t), buf_len))
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

int anomaly_options_init(struct cmd_option *cmd)
{
#define HELP_LEN_MAX 1024
	int i = 0, j;
	static char help[HELP_LEN_MAX];
	int len = 0;

	cmd->opts[i].action = ACT_ANOMALY_GET_LOG;
	cmd->opts[i].name = "get_anomaly";
	cmd->opts[i].cb = get_anomaly;
	OPTS_IDX_INC(i);
	
	cmd->opts[i].action = ACT_ANOMALY_GET_LOG_V2;
	cmd->opts[i].name = "get_anomaly_v2";
	cmd->opts[i].cb = get_anomaly_v2;
	OPTS_IDX_INC(i);

	len += snprintf(help + len, HELP_LEN_MAX - len, "%*s \n",
		HELP_INDENT_L, "");

	for (j = 0; j < i; j++)
	{
		len += snprintf(help + len, HELP_LEN_MAX - len, "%*s %s\n",
			HELP_INDENT_L, (j == 0) ? "anomaly actions:" : "",
			cmd->opts[j].name);
	}

	cmd->help = help;

	return 0;
}

