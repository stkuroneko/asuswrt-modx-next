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
#include <stdarg.h>
#include <unistd.h>

#include "udb/shell/shell_ioctl.h"

#include "ioc_common.h"
#include "ioc_patrol_tq.h"

static char r_file_path[CONF_PATH_MAX_LEN] = {0};
static char w_file_path[CONF_PATH_MAX_LEN] = {0};
static int write_flag = 0;

int get_fw_patrol_tq(void **output)
{
	const int buf_len = MAX_PATROL_TQ_SIZE;
	uint32_t buf_used_len = 0;
	udb_shell_ioctl_t msg;
	int ret = 0;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_PATROL_TQ;
	msg.op = UDB_IOCTL_PATROL_TQ_OP_GET;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, &buf_used_len);
	ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_PATROL_TQ, &msg);
	//DBG("patrol-TQ Get. Type:%d | Magic:%d NR:%d OP:%d UDB_SHELL_IOCTL_CMD_PATROL_TQ[%d]\n",  msg.in_type, msg.magic, msg.nr, msg.op, UDB_SHELL_IOCTL_CMD_PATROL_TQ);
	return ret;
}

int set_fw_patrol_tq(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_PATROL_TQ;
	msg.op = UDB_IOCTL_PATROL_TQ_OP_SET;
	udb_shell_ioctl_set_in_raw(&msg, input, length);

	if (0 > run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_PATROL_TQ, &msg))
	{
		return -1;
	}
	DBG("patrol at %p %d bytes into kernel. Type:%d | Magic:%d NR:%d OP:%d UDB_SHELL_IOCTL_CMD_PATROL_TQ[%d]\n", input, length, msg.in_type, msg.magic, msg.nr, msg.op, UDB_SHELL_IOCTL_CMD_PATROL_TQ);

	return 0;
}

int conf_fw_patrol_state(unsigned char flag)
{
    udb_shell_ioctl_t msg;
    uint32_t buf_used_len = 0;

    /* prepare and do ioctl */
    udb_shell_init_ioctl_entry(&msg);
    msg.nr = UDB_IOCTL_NR_PATROL_TQ;
    msg.op = (0 == flag ? UDB_IOCTL_PATROL_TQ_OP_DISABLE : UDB_IOCTL_PATROL_TQ_OP_ENABLE);
    (&msg)->out = 0;
    (&msg)->out_len = 0;
    (&msg)->out_used_len = (uintptr_t)&buf_used_len;
    return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_PATROL_TQ, &msg);
}

int reset_fw_patrol_tq()
{
    udb_shell_ioctl_t msg;
    uint32_t buf_used_len = 0;
    /* prepare and do ioctl */
    udb_shell_init_ioctl_entry(&msg);
    msg.nr = UDB_IOCTL_NR_PATROL_TQ;
    msg.op = UDB_IOCTL_PATROL_TQ_OP_RESET;
    (&msg)->out = 0;
    (&msg)->out_len = 0;
    (&msg)->out_used_len = (uintptr_t)&buf_used_len;
    return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_PATROL_TQ, &msg);
}



int get_fw_patrol_tq_log(void **output, unsigned int *buf_used_len) //, int flag)
{
//	patrol_ioc_tq_t *tq_hdr = NULL;
//	patrol_ioc_tq_grp_t *tq_grp = NULL;
//	patrol_ioc_tq_dev_t *tq_dev = NULL;
	udb_shell_ioctl_t msg;

	const int buf_len = 512000;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_PATROL_TQ;
	msg.op = UDB_IOCTL_PATROL_TQ_OP_GET_LOG;

	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_PATROL_TQ, &msg);
}

int get_fw_app_time(app_time_ioctl_entry_t **output, uint32_t *used_len)
{
	const int buf_len =
		DEVID_APP_RATE_TABLE_POOL_SIZE * sizeof(app_time_ioctl_entry_t);

	udb_shell_ioctl_t msg;
	uint32_t buf_used_len = 0;
	int ret = 0;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		DBG("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	if (!used_len)
	{
		used_len = &buf_used_len;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_PATROL_TQ;
	msg.op = UDB_IOCTL_PATROL_TQ_OP_GET_TIME;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, used_len);

	ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_PATROL_TQ, &msg);

	//memset(((char*) *output) + *used_len, 0x00, buf_len - *used_len);

	return ret;
}

////////////////////////////////////////////////////////////////////////////////

static void save_tq_file(const char *fmt, ...)
{
	char buf[10240];	/* FIXME: change to dynamic allocation??? */
	va_list args;
	FILE *fp;
//	char *sample_conf = "patrol_tq.conf";

	if (!write_flag)
	{
		return;
	}

//	if (NULL == file_path)
	if (!*w_file_path)
	{
//		asprintf(&file_path, "%s", sample_conf);
		snprintf(w_file_path, sizeof(w_file_path), "patrol_tq.conf");
	}

//	sample_conf = file_path;

	if ((fp = fopen(w_file_path, "a")) == NULL)
	{
		printf("Can't open %s.\n", w_file_path);
		exit(1);
	}

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	va_start(args, fmt);
	fprintf(fp, "%s", buf);
	va_end(args);

	fclose(fp);
}

static int _backup_patrol_tq_sample(char *pbuf)
{
	int used_len = 0, i = 0, j = 0;

	patrol_ioc_tq_t *patrol_tq = (patrol_ioc_tq_t *) pbuf;
	patrol_ioc_tq_grp_t *tq_grp = NULL;
	patrol_ioc_tq_dev_t *tq_dev = NULL;
	save_tq_file("# Time quota policy_rule\n");
	save_tq_file("# Catgory-Bit: 0/4/24 --> 16810001\n");
	save_tq_file("# Format:\n# \tgrp_cnt=\"GroupCount\",\"UpTime\"\n");
	save_tq_file("# \tgrp_data=\"Group-ID\" , \"Profile-ID\" , \"IS_Update\" , \"Day-ID\" , \"Action\" , \"Device-Count\" , \"Time-Quota(min)\" , \n");
	save_tq_file("# \t\t\"Used-Time(Second)\" , \"Cat-ID by Bit\", \"DL-Quota-pkt\", \"DL-Recv-PKT\" , \"UL-Quota-pkt\" , \"UL-Recv-PKT\" , \n" );
	save_tq_file("# \t\t\"Last_recv_time\" \n");
	save_tq_file("# \t\"dev_mac=\"Group-ID\" , \"mac\"\n\n");
	save_tq_file("grp_cnt=%d,%lu\n", patrol_tq->grp_cnt, patrol_tq->up_time);
	used_len += sizeof(patrol_ioc_tq_t);
	printf("\nGet Group count[%d]uptime[%lu]\n", patrol_tq->grp_cnt, patrol_tq->up_time);
	if (patrol_tq->grp_cnt <= 0)
	{
		return 1;
	}

	for (i = 0; i < patrol_tq->grp_cnt; i++)
	{
		tq_grp = (patrol_ioc_tq_grp_t *) (pbuf + used_len);
		save_tq_file("grp_data= %d,%d,%d,%d,%d,%d,%d,%d,%llu,%lu,%lu,%lu,%lu,%lu\n",
			tq_grp->grp_id, tq_grp->pro_id, tq_grp->is_update, tq_grp->day_id, tq_grp->action,
			tq_grp->dev_cnt, tq_grp->time_quota, tq_grp->used_time, tq_grp->bit_cat_id,
			tq_grp->down_quota_pkt, tq_grp->up_quota_pkt, tq_grp->down_recent_pkt,
			tq_grp->up_recent_pkt,
			tq_grp->last_uptime);
#if 0
		DBG("Get ulen[%d]grp_data=> ID:GID:%d PID:%d IS_UP:%d DayID:%d Act:%d dev_cnt:%d time-q:%d used_time:%d\n"
			"bit-catid:%llu dl_quota_pkt:%lu ul_quota_pkt:%lu dl_recv_pkt:%lu ul_recv_pkt:%lu last_uptime:%lu\n",
			used_len, tq_grp->grp_id, tq_grp->pro_id, tq_grp->is_update, tq_grp->day_id, tq_grp->action,
			tq_grp->dev_cnt, tq_grp->time_quota, tq_grp->used_time, tq_grp->bit_cat_id,
			tq_grp->down_quota_pkt, tq_grp->up_quota_pkt, tq_grp->down_recent_pkt, tq_grp->up_recent_pkt, tq_grp->last_uptime
		);
#endif
		printf(
			"\nResult==>GRP-ID: %d / dev_cnt: %d / Time-Quota-sec: %d / Used-time-sec: %d / Action is \"%s\"\n",
			tq_grp->grp_id, tq_grp->dev_cnt,
			(tq_grp->time_quota * 60), tq_grp->used_time,
			(tq_grp->action == 99) ? "Always accept" : (tq_grp->action == 1) ? "1-Block" : (tq_grp->action == 2) ? "2-Monitor" : "0-Accept");

		used_len += sizeof(patrol_ioc_tq_grp_t);
		for (j = 0; j < tq_grp->dev_cnt; j++)
		{
			tq_dev = (patrol_ioc_tq_dev_t *) (pbuf + used_len);
			save_tq_file("dev_mac=%d," MAC_OCTET_FMT"\n", tq_dev->grp_id,
				MAC_OCTET_EXPAND(tq_dev->mac));
			used_len += sizeof(patrol_ioc_tq_dev_t);
			printf("\t GRP-ID: %d / mac:"MAC_OCTET_FMT "\n", tq_dev->grp_id,
				MAC_OCTET_EXPAND(tq_dev->mac));
		}
	}

	return 1;
}

static int _load_patrol_tq_sample(char *pbuf, unsigned int buf_len)
{
	unsigned int used_len = 0; //, i = 0;
	unsigned int p = 0;
//	char *sample_conf = "patrol_tq.conf";

	static char line_buf[512];
	char tmp_mac[18]; //1E:33:12:56:32:32
	char *tok, *tok_save = NULL;
	FILE *pf;
	int grp_cnt, grp_id, pro_id, is_update, day_id, action, dev_cnt, time_quota;
	uint64_t time_stamp = 0;
	patrol_ioc_tq_t *patrol_tq = (patrol_ioc_tq_t *) pbuf;
	patrol_ioc_tq_grp_t *tq_grp = NULL;
	patrol_ioc_tq_dev_t *tq_dev = NULL;

//	if (NULL == file_path)
	if (!*r_file_path)
	{
//		asprintf(&file_path, "%s", sample_conf);
		snprintf(r_file_path, sizeof(r_file_path), "patrol_tq.conf");
	}

//	sample_conf = file_path;

	if ((pf = fopen(r_file_path, "r")))
	{
		while (fgets(line_buf, sizeof(line_buf), pf))
		{
			//printf("row data line_buf \"%s\" used_len[%d]\n", line_buf, used_len);
			if (used_len > buf_len)
			{
				DBG("Error! policy buf too small.\n");
				fclose(pf);
				return -1;
			}
			if ('#' == line_buf[0] || '\n' == line_buf[0])
			{
				continue;
			}

			if (!strncmp("grp_cnt=", line_buf, 8))
			{
				sscanf(line_buf, "grp_cnt=%d, %llu", &grp_cnt, &time_stamp);
                //sscanf(line_buf, "grp_cnt=%d, %llu", &grp_cnt, &patrol_tq->up_time);
				patrol_tq->grp_cnt = grp_cnt;
				patrol_tq->up_time = 0;
				printf("read group count = %d, time[%llu] sizeof 64[%d]\n",patrol_tq->grp_cnt, patrol_tq->up_time, sizeof(uint64_t));
				//printf("read group count = %d\n",patrol_tq->grp_cnt);
				used_len += sizeof(patrol_ioc_tq_t);
			}
			/*2014/09/18 change parse grp data format
			 * Grp_id,Is_update,day_id,action,dev_cnt,time_quota,used_time,bit_cat_id,down_quota_pkt,up_quota_pkt,down_recent_pkt,ul_recent_pkt,last_uptime
			 * */
			if (!strncmp("grp_data=", line_buf, 9))
			{
				tq_grp = (patrol_ioc_tq_grp_t *) (pbuf + used_len);

				sscanf(line_buf, "grp_data= %d,%d,%d,%d,%d,%d,%d,%d,%llu,%llu,%llu,%llu,%llu,%llu",
					&grp_id, &pro_id, &is_update, &day_id, &action, &dev_cnt, &time_quota, 
					&tq_grp->used_time, &tq_grp->bit_cat_id,
					&tq_grp->down_quota_pkt, &tq_grp->up_quota_pkt, &tq_grp->down_recent_pkt,
					&tq_grp->up_recent_pkt, &tq_grp->last_uptime
					);
				
				tq_grp->grp_id = grp_id;
				tq_grp->pro_id = pro_id;
				tq_grp->is_update = is_update;
				tq_grp->day_id = day_id;
				tq_grp->action = action;
				tq_grp->dev_cnt = dev_cnt;
				tq_grp->time_quota = time_quota;

				used_len += sizeof(patrol_ioc_tq_grp_t);
#if 1
				printf(
					"Setup Patrol-TQ policy: grp_data=> ID:GID:%d PID:%d IS_UP:%d DayID:%d Act:%d dev_cnt:%d time-q:%d used_time:%d\n"
						"\t bit-catid:%llu dl_quota_pkt:%llu ul_quota_pkt:%llu dl_recv_pkt:%llu ul_recv_pkt:%llu last_uptime:%llu\n",
					tq_grp->grp_id, tq_grp->pro_id, tq_grp->is_update, tq_grp->day_id,
					tq_grp->action,
					tq_grp->dev_cnt, tq_grp->time_quota, tq_grp->used_time, tq_grp->bit_cat_id,
					tq_grp->down_quota_pkt, tq_grp->up_quota_pkt, tq_grp->down_recent_pkt,
					tq_grp->up_recent_pkt, tq_grp->last_uptime
					);
#endif
			}

			if (!strncmp("dev_mac=", line_buf, 8))
			{
				tq_dev = (patrol_ioc_tq_dev_t *) (pbuf + used_len);

				if (0 < sscanf(line_buf, "dev_mac= %d, %s", &grp_id, tmp_mac))
				{
					tq_dev->grp_id = grp_id;
					if ((tok = strtok_r(tmp_mac, ":", &tok_save)))
					{
						p = 0;
						do
						{
							tq_dev->mac[p++] = (char) strtol(tok, NULL, 16);
						}
						while ((tok = strtok_r(NULL, ":", &tok_save)));
					}
				}
				else
				{
					DBG("Process Mac Error: %s\n", line_buf);
					tmp_mac[0] = 0x0;
				}
				printf("Setup patrol-tq policy: grp_id[%d]mac: "MAC_OCTET_FMT"\n", tq_dev->grp_id,
					MAC_OCTET_EXPAND(tq_dev->mac));
				used_len += sizeof(patrol_ioc_tq_dev_t);
			}
		}
		fclose(pf);
	}
	else
	{
		DBG("File not found ! %s\n", r_file_path);
	}
	return used_len;
}

int get_patrol_tq(void)
{
	int ret = 0;
//	uint32_t buf_len = 0;
	char *pbuf = NULL;

	ret = get_fw_patrol_tq((void **) &pbuf);
	if (ret)
	{
		DBG("Error: get patrol time quota !(%d)\n", ret);
		return ret;
	}

	_backup_patrol_tq_sample(pbuf);
	/*Need write conf to file~*/

	if (pbuf)
	{
		printf("free time-quota memory~\n");
		free(pbuf);
	}
	else
	{
		printf("Error!Get-PTQ, Maybe it's OOM issue.\n");
	}
	return ret;
}

int set_patrol_tq(void)
{
	int ret = 0;
	unsigned int used_len = 0;
	unsigned int buf_len = MAX_PATROL_TQ_SIZE;
	char *pbuf = calloc(buf_len, sizeof(char));
	printf("calloc buf address:%p len:%d\n", pbuf, buf_len);
	if (!pbuf)
	{
		return -1;
	}
	used_len = _load_patrol_tq_sample(pbuf, buf_len);
	//printHEX(pbuf,buf_len);
	if (used_len)
	{
		//DBG("load patrol time-quota len[%d] memory\n", used_len);
		ret = set_fw_patrol_tq(pbuf, buf_len);
	}

	if (pbuf)
	{
		DBG(" Free memory [%d].\n", buf_len);
		free(pbuf);
	}
	else
	{
		printf("Error!..Set-PTQ, Maybe it's OOM issue.\n");
	}

	printf("Push time-quota policy size[%d] result: %s\n", used_len, ret ? "NG" : "OK");
	return ret;
}

int get_patrol_tq_log(void)
{
	int ret = 0;
	char *pbuf = NULL;
	uint32_t buf_used_len = 0;
	
//	FILE *pf;
	
	ret = get_fw_patrol_tq_log((void **) &pbuf, &buf_used_len);
	if (ret)
	{
		DBG("Error: get patrol time quota !(%d)\n", ret);
	}
	/*Need write conf to file~*/

	if (pbuf)
	{
		free(pbuf);
	}
	return ret;
}

int get_app_time(void)
{
	int ret = 0;
	unsigned long uptime;
	udb_ioctl_entry_t *usr_lst = NULL;
	uint32_t usr_buf_len = 0;
	uint32_t usr_cnt = 0;
	int r;

	app_time_ioctl_entry_t *app_lst = NULL;
	uint32_t app_buf_len = 0;
	uint32_t app_cnt = 0;
	int r2;

	LIST_HEAD(app_inf_head);
	LIST_HEAD(app_cat_head);

	if ((ret = get_fw_user_list(&usr_lst, &usr_buf_len)))
	{
		DBG("Error: get user!(%d)\n", ret);
	}

	if ((ret = get_fw_app_time(&app_lst, &app_buf_len)))
	{
		DBG("Error: get app!(%d)\n", ret);
	}

	init_app_inf(&app_inf_head);
	init_app_cat(&app_cat_head);

	if (usr_lst)
	{
		usr_cnt = usr_buf_len / sizeof(*usr_lst);

		if (app_lst)
		{
			app_cnt = app_buf_len / sizeof(*app_lst);
		}

		for (r = 0; r < usr_cnt; r++)
		{
			if (usr_lst[r].available <= 0)
			{
				break;
			}

			printf("---------------------------------\n");
			printf("uid  : %u\n", usr_lst[r].uid);
			printf("mac  : " MAC_OCTET_FMT "\n", MAC_OCTET_EXPAND(usr_lst[r].mac));
			printf("ipv4 : " IPV4_OCTET_FMT "\n", IPV4_OCTET_EXPAND(usr_lst[r].ipv4));
			printf("ipv6 : " IPV6_OCTET_FMT "\n", IPV6_OCTET_EXPAND(usr_lst[r].ipv6));
			printf("host : %s\n", usr_lst[r].host_name);

			uptime = usr_lst[r].ts - usr_lst[r].ts_create;
			printf("%-*s : %luh %lum %lus\n", 15, "uptime",
				uptime / 3600,
				(uptime % 3600) / 60,
				(uptime % 3600) % 60);
#if TMCFG_E_UDB_CORE_RULE_FORMAT_V2
			printf("%-*s : %uh %um %us\n", 15, "used_time",
				usr_lst[r].used_time_sec / 3600,
				(usr_lst[r].used_time_sec % 3600) / 60,
				(usr_lst[r].used_time_sec % 3600) % 60);
#endif

			for (r2 = 0; r2 < app_cnt; r2++)
			{
				if (app_lst[r2].available <= 0)
				{
					break;
				}
				if (usr_lst[r].uid == app_lst[r2].uid)
				{
					printf("\t---------------------------------\n");
					printf("\tcat_id   : %u\n", app_lst[r2].cat_id);
					printf("\tapp_id   : %u\n", app_lst[r2].app_id);

					if (0 == app_lst[r2].cat_id && 0 == app_lst[r2].app_id)
					{
						printf("\tcat_name : Others\n");
						printf("\tapp_name : Others\n");
					}
					else
					{
						printf("\tcat_name : %s\n",
							search_app_cat(&app_cat_head, app_lst[r2].cat_id));
						printf("\tapp_name : %s\n",
							search_app_inf(&app_inf_head, app_lst[r2].cat_id, app_lst[r2].app_id));
					}

					printf("\tused_time : %uh %um %us\n",
						app_lst[r2].used_time_sec / 3600,
						(app_lst[r2].used_time_sec % 3600) / 60,
						(app_lst[r2].used_time_sec % 3600) % 60);
				}
			}
		}
	}

	free_app_inf(&app_inf_head);
	free_app_cat(&app_cat_head);

	if (app_lst) free(app_lst);
	if (usr_lst) free(usr_lst);

	return ret;
}

int parse_w_path_arg(int argc, char **argv)
{
	return parse_single_str_arg(argc, argv, 'W', w_file_path, sizeof(w_file_path));
}

int parse_r_path_arg(int argc, char **argv)
{
	return parse_single_str_arg(argc, argv, 'R', r_file_path, sizeof(r_file_path));
}

int patrol_tq_options_init(struct cmd_option *cmd)
{
#define HELP_LEN_MAX 1024
	int i = 0, j;
	static char help[HELP_LEN_MAX];
	int len = 0;

	cmd->opts[i].action = ACT_TQ_GET_APP_TIME;
	cmd->opts[i].name = "get_app_time";
	cmd->opts[i].cb = get_app_time;
	OPTS_IDX_INC(i);
	
	cmd->opts[i].action = ACT_TQ_SET_PATROL_TQ;
	cmd->opts[i].name = "set_patrol_tq";
	cmd->opts[i].cb = set_patrol_tq;
	cmd->opts[i].parse_arg = parse_r_path_arg;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_TQ_GET_PATROL_TQ;
	cmd->opts[i].name = "get_patrol_tq";
	cmd->opts[i].cb = get_patrol_tq;
	cmd->opts[i].parse_arg = parse_w_path_arg;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_TQ_GET_PATROL_TQ_LOG;
	cmd->opts[i].name = "get_patrol_tq_log";
	cmd->opts[i].cb = get_patrol_tq_log;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_TQ_RESET_PATROL_TQ;
	cmd->opts[i].name = "reset_patrol_tq";
	cmd->opts[i].cb = reset_fw_patrol_tq;
	OPTS_IDX_INC(i);

	len += snprintf(help + len, HELP_LEN_MAX - len, "%*s \n",
		HELP_INDENT_L, "");

	for (j = 0; j < i; j++)
	{
		len += snprintf(help + len, HELP_LEN_MAX - len, "%*s %s\n",
			HELP_INDENT_L, (j == 0) ? "patrol_tq actions:" : "",
			cmd->opts[j].name);
	}

	cmd->help = help;

	return 0;
}

