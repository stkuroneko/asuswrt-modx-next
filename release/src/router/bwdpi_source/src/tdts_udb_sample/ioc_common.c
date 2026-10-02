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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>

#include "udb/shell/shell_ioctl.h"

#include "conf_app.h"

#include "ioc_common.h"

#ifdef __INTERNAL__
#include "ioc_internal.h"
#endif

static char file_path[CONF_PATH_MAX_LEN] = {0};
static char url_path[MAX_REDIRECT_URL_LEN] = {0};

int run_ioctl(const char *path, int req, void *arg)
{
	int fd;

	if ((fd = open(path, O_RDWR)) < 0)
	{
		ERR("Cannot open file '%s' %s\n", path, strerror(errno));
		return -1;
	}

	if (ioctl(fd, req, arg) < 0)
	{
		ERR("Cannot run ioctl w/ req 0x%X with arg %p %s\n"
			, (unsigned) req, arg, strerror(errno));
		close(fd);
		return -2;
	}

	DBG("...Run ioctl on %s w/ req 0x%X -> %s\n"
		, path, (unsigned) req, strerror(errno));
	close(fd);

	return 0;
}

int get_fw_user_list(udb_ioctl_entry_t **output, uint32_t *used_len)
{
	uint32_t buf_len = DEVID_MAX_USER * sizeof(udb_ioctl_entry_t);

	udb_shell_ioctl_t msg;
	uint32_t buf_used_len;
	int ret = 0;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		ERR("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	if (!used_len)
	{
		used_len = &buf_used_len;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = UDB_IOCTL_COMMON_OP_GET_USER;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, used_len);

	ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg);

//	memset((*output) + *used_len, 0x00, buf_len - *used_len);

	return ret;
}

int get_fw_user_app_rate(app_ioctl_entry_t **output, uint32_t *used_len)
{
	uint32_t buf_len =
		DEVID_APP_RATE_TABLE_POOL_SIZE * sizeof(app_ioctl_entry_t);

	udb_shell_ioctl_t msg;
	uint32_t buf_used_len = 0;
	int ret = 0;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		ERR("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	if (!used_len)
	{
		used_len = &buf_used_len;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = UDB_IOCTL_COMMON_OP_GET_APP;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, used_len);

	ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg);

	//memset((*output) + *used_len, 0x00, buf_len - *used_len);

	return ret;
}

int get_fw_app_patrol(app_patrol_list_ioc_entry_t **output, uint32_t *used_len)
{
	uint32_t buf_len =
		DEVID_APP_RATE_TABLE_POOL_SIZE * sizeof(app_patrol_list_ioc_entry_t);

	udb_shell_ioctl_t msg;
	uint32_t buf_used_len = 0;
	int ret = 0;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		ERR("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	if (!used_len)
	{
		used_len = &buf_used_len;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = UDB_IOCTL_COMMON_OP_GET_APP_PATROL;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, used_len);

	ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg);

	//memset((*output) + *used_len, 0x00, buf_len - *used_len);

	return ret;
}

int get_fw_app_bw_clear(app_bw_ioctl_entry_t **output, uint32_t *used_len)
{
	uint32_t buf_len =
		DEVID_APP_RATE_TABLE_POOL_SIZE * sizeof(app_bw_ioctl_entry_t);

	udb_shell_ioctl_t msg;
	uint32_t buf_used_len = 0;
	int ret = 0;

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		ERR("Cannot allocate buffer space %u bytes", buf_len);
		return -1;
	}

	if (!used_len)
	{
		used_len = &buf_used_len;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = UDB_IOCTL_COMMON_OP_GET_APP_BW_RESET;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, used_len);

	ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg);

	//memset((*output) + *used_len, 0x00, buf_len - *used_len);

	return ret;
}

int set_fw_app_patrol(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;
//	uint32_t buf_used_len = 0;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = UDB_IOCTL_COMMON_OP_SET_APP_PATROL;
	udb_shell_ioctl_set_in_raw(&msg, input, length);

	if (0 > run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg))
	{
		return -1;
	}
	//DBG("Copy app patrol at %p %d bytes into kernel", input, length);

	return 0;
}

int set_fw_wpr_conf(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = UDB_IOCTL_COMMON_OP_SET_WPR_CONF;
	udb_shell_ioctl_set_in_raw(&msg, input, length);
	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg);
}

int set_wpr_state(unsigned char flag)
{
	udb_shell_ioctl_t msg;
	uint32_t buf_used_len = 0;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = (0 == flag ? UDB_IOCTL_COMMON_OP_SET_WPR_DISABLE : UDB_IOCTL_COMMON_OP_SET_WPR_ENABLE);
	(&msg)->out = 0;
	(&msg)->out_len = 0;
	(&msg)->out_used_len = (uintptr_t)&buf_used_len;
	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg);
}

int set_fw_redirect_url(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_COMMON;
	msg.op = UDB_IOCTL_COMMON_OP_SET_REDIRECT_URL;
	udb_shell_ioctl_set_in_raw(&msg, input, length);
	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_COMMON, &msg);
}

////////////////////////////////////////////////////////////////////////////////

int get_user_lst(void)
{
	int ret = 0;
	int r;
	udb_ioctl_entry_t *usr_lst = NULL;
	uint32_t buf_len = 0;
	uint32_t usr_cnt = 0;
	
	if ((ret = get_fw_user_list(&usr_lst, &buf_len)))
	{
		DBG("Error: get user!(%d)\n", ret);
	}

	if (usr_lst)
	{
		usr_cnt = buf_len / sizeof(*usr_lst);

		for (r = 0; r < usr_cnt; r++)
		{
			if (!usr_lst[r].available)
			{
				break;
			}

			printf("--------------\n");
			printf("uid  : %u\n", usr_lst[r].uid);
			printf("mac  : " MAC_OCTET_FMT "\n", MAC_OCTET_EXPAND(usr_lst[r].mac));
			printf("ipv4 : " IPV4_OCTET_FMT "\n", IPV4_OCTET_EXPAND(usr_lst[r].ipv4));
			printf("ipv6 : " IPV6_OCTET_FMT "\n", IPV6_OCTET_EXPAND(usr_lst[r].ipv6));
			printf("host : %s\n", usr_lst[r].host_name);

			PRT_DEVID("dev_name_id", usr_lst[r].os.de.dev_id);
			PRT_DEVID("dev_type_id", usr_lst[r].os.de.cat_id);
			PRT_DEVID("dev_family_id", usr_lst[r].os.de.family_id);
			PRT_DEVID("os_name_id", usr_lst[r].os.de.name_id);
			PRT_DEVID("os_class_id", usr_lst[r].os.de.class_id);
			PRT_DEVID("os_vendor_id", usr_lst[r].os.de.vendor_id);
			PRT_DEVID("devid_priority", usr_lst[r].os.de_prio);

			printf("%-*s : %" PRIu64 "\n", 15, "last_used_ts", usr_lst[r].ts);
			printf("%-*s : %" PRIu64 "\n", 15, "created_ts", usr_lst[r].ts_create);
		}

		free(usr_lst);
	}

	return ret;
}

int get_user_app_lst(void)
{
	int ret = 0;
	int r;
	app_ioctl_entry_t *app_lst = NULL;
	uint32_t app_cnt = 0;
	uint32_t buf_len = 0;

	if ((ret = get_fw_user_app_rate(&app_lst, &buf_len)))
	{
		DBG("Error: get app!(%d)\n", ret);
	}

	if (app_lst)
	{
		app_cnt = buf_len / sizeof(*app_lst);

		for (r = 0; r < app_cnt; r++)
		{
			if (!app_lst[r].available)
			{
				break;
			}

			printf("--------------\n");
			printf("uid    : %u\n", app_lst[r].uid);
			printf("cat_id : %u\n", app_lst[r].cat_id);
			printf("app_id : %u\n", app_lst[r].app_id);
			printf("down_accl_byte : %" PRIu64 "\n", app_lst[r].down_recent_accl);
			printf("down_accl_pkt  : %u\n", app_lst[r].down_recent_accl_pkt);
			printf("up_accl_byte   : %" PRIu64 "\n", app_lst[r].up_recent_accl);
			printf("up_accl_pkt    : %u\n", app_lst[r].up_recent_accl_pkt);
			printf("last_used_ts   : %" PRIu64 "\n", app_lst[r].last_elapsed_ts);
		}

		free(app_lst);
	}

	return ret;
}

int get_user_detail(void)
{
	int ret = 0;
	uint32_t usr_cnt = 0, app_cnt = 0;
	int r = 0, r2 = 0;
	unsigned long app_couont = 0;
	uint64_t total_down_byte = 0, total_up_byte = 0;
	udb_ioctl_entry_t *usr_lst = NULL;
	app_ioctl_entry_t *app_lst = NULL;
	uint32_t usr_buf_len = 0, app_buf_len = 0;

	LIST_HEAD(app_inf_head);
	LIST_HEAD(app_cat_head);
	LIST_HEAD(dev_os_head);

	dev_os_t *dev_os;

	if ((ret = get_fw_user_list(&usr_lst, &usr_buf_len)))
	{
		ERR("Error: get user!(%d)\n", ret);
	}

	if ((ret = get_fw_user_app_rate(&app_lst, &app_buf_len)))
	{
		ERR("Error: get app!(%d)\n", ret);
	}

	init_app_inf(&app_inf_head);
	init_app_cat(&app_cat_head);
	init_dev_os(&dev_os_head);

	if (usr_lst)
	{
		usr_cnt = usr_buf_len / sizeof(*usr_lst);

		if (app_lst)
		{
			app_cnt = app_buf_len / sizeof(*app_lst);
		}

		for (r = 0; r < usr_cnt; r++)
		{
			if (!usr_lst[r].available)
			{
				break;
			}

			printf("---------------------------------\n");
			printf("uid  : %u\n", usr_lst[r].uid);
			printf("mac  : " MAC_OCTET_FMT "\n", MAC_OCTET_EXPAND(usr_lst[r].mac));
			printf("ipv4 : " IPV4_OCTET_FMT "\n", IPV4_OCTET_EXPAND(usr_lst[r].ipv4));
			printf("ipv6 : " IPV6_OCTET_FMT "\n", IPV6_OCTET_EXPAND(usr_lst[r].ipv6));
			printf("host : %s\n", usr_lst[r].host_name);

			dev_os = search_dev_os(&dev_os_head,
				usr_lst[r].os.de.vendor_id,
				usr_lst[r].os.de.name_id,
				usr_lst[r].os.de.class_id,
				usr_lst[r].os.de.cat_id,
				usr_lst[r].os.de.dev_id,
				usr_lst[r].os.de.family_id);

			PRT_DEVID_STR("dev_name_id", usr_lst[r].os.de.dev_id,
				(dev_os) ? dev_os->dev_name : "");
			PRT_DEVID_STR("dev_type_id", usr_lst[r].os.de.cat_id,
				(dev_os) ? dev_os->type_name : "");
			PRT_DEVID_STR("dev_family_id", usr_lst[r].os.de.family_id,
				(dev_os) ? dev_os->family_name : "");
			PRT_DEVID_STR("os_name_id", usr_lst[r].os.de.name_id,
				(dev_os) ? dev_os->os_name : "");
			PRT_DEVID_STR("os_class_id", usr_lst[r].os.de.class_id,
				(dev_os) ? dev_os->class_name : "");
			PRT_DEVID_STR("os_vendor_id", usr_lst[r].os.de.vendor_id,
				(dev_os) ? dev_os->vendor_name : "");

			printf("%-*s : %" PRIu64 "\n", 15, "last_used_ts", usr_lst[r].ts);
			printf("%-*s : %" PRIu64 "\n", 15, "created_ts", usr_lst[r].ts_create);
			printf("%-*s : %" PRIu64 "\n", 15, "uptime", usr_lst[r].ts - usr_lst[r].ts_create);

			total_down_byte = total_up_byte = app_couont = 0;
			for (r2 = 0; r2 < app_cnt; r2++)
			{
				if (app_lst[r2].available <= 0)
				{
					break;
				}
				if (usr_lst[r].uid == app_lst[r2].uid)
				{
					printf("\t---------------------------------\n");
					printf("\tcat_id         : %u\n", app_lst[r2].cat_id);
					printf("\tapp_id         : %u\n", app_lst[r2].app_id);

					if (0 == app_lst[r2].cat_id && 0 == app_lst[r2].app_id)
					{
						printf("\tcat_name       : Others\n");
						printf("\tapp_name       : Others\n");
					}
					else
					{
						printf("\tcat_name       : %s\n",
							search_app_cat(&app_cat_head, app_lst[r2].cat_id));
						printf("\tapp_name       : %s\n",
							search_app_inf(&app_inf_head, app_lst[r2].cat_id, app_lst[r2].app_id));
					}
					printf("\tdown_accl_byte : %" PRIu64 "\n", app_lst[r2].down_recent_accl);
					printf("\tdown_accl_pkt  : %u\n", app_lst[r2].down_recent_accl_pkt);
					printf("\tup_accl_byte   : %" PRIu64 "\n", app_lst[r2].up_recent_accl);
					printf("\tup_accl_pkt    : %u\n", app_lst[r2].up_recent_accl_pkt);
					printf("\tlast_used_ts   : %" PRIu64 "\n", app_lst[r2].last_elapsed_ts);

					total_down_byte += app_lst[r2].down_recent_accl;
					total_up_byte += app_lst[r2].up_recent_accl;
					app_couont++;
				}
			}
#if TMCFG_E_UDB_CORE_URL_QUERY
			int r3 = 0;
			for (r2 = 0; r2 < MAX_WRS_CAT_NUM; r2++)
			{
				if (usr_lst[r].wrs_stat[r2])
				{
					if (!r3)
					{
						printf("WRS Stats:\n");
					}
					printf("%s[%.3d] : %-5" PRIu32, "WRS_CAT", r2, usr_lst[r].wrs_stat[r2]);
					r3++;
					if (!(r3 % 4))
					{
						printf("\n");
					}
				}
			}
			printf("\n");
#endif
			printf("%-*s : %lu\n", 15, "app_count", app_couont);
			printf("%-*s : %" PRIu64 "\n", 15, "total_down_byte", total_down_byte);
			printf("%-*s : %" PRIu64 "\n", 15, "total_up_byte", total_up_byte);
			printf("%-*s : %" PRIu64 "\n", 15, "total_traffic", total_down_byte + total_up_byte);
			printf("---------------------------------\n");

		}
	}

	free_app_inf(&app_inf_head);
	free_app_cat(&app_cat_head);
	free_dev_os(&dev_os_head);

	if (app_lst) free(app_lst);
	if (usr_lst) free(usr_lst);

	return ret;
}

int get_app_patrol(void)
{
	int ret = 0;
	int r;
	app_patrol_list_ioc_entry_t *app_lst = NULL;
	uint32_t app_cnt = 0;
	uint32_t buf_len = 0;

	if ((ret = get_fw_app_patrol(&app_lst, &buf_len)))
	{
		DBG("Error: get app!(%d)\n", ret);
	}

	if (app_lst)
	{
		app_cnt = buf_len / sizeof(*app_lst);

		for (r = 0; r < app_cnt; r++)
		{
			if (app_lst[r].available <= 0)
			{
				break;
			}
			printf("--------------\n");
			printf("uid    : %u\n", app_lst[r].uid);
			printf("mac    : "MAC_OCTET_FMT "\n", MAC_OCTET_EXPAND(app_lst[r].mac));
			printf("cat_id : %u\n", app_lst[r].cat_id);
			printf("app_id : %u\n", app_lst[r].app_id);
			printf("time   : %" PRIu64 "\n", app_lst[r].time);
			printf("flag   : %s\n", app_lst[r].flag == 1 ? "1-Block" : (app_lst[r].flag == 2) ? "2-Monitor" : "0-Accept");
		}

		free(app_lst);
	}

	return ret;
}

static int load_app_patrol_conf(FILE *pf, char *pfile_e,
	uint32_t all_len, uint32_t *used_len)
{
	int ret = 0;

	uint32_t pfile_len = 0;
	uint32_t mac_len = 0;

	uint32_t mac_buflen = 0;
	char *mac_e = NULL;

	patrol_ioc_app_t *ioc_app = NULL;
	patrol_ioc_pfile_t *ioc_pfile_id = NULL;
	patrol_ioc_pfile_ptr_t *ioc_pfile_ptr = NULL;

	patrol_ioc_mac_t *ioc_mac = NULL;
	patrol_ioc_mac_ptr_t *ioc_mac_ptr = NULL;

	static char line_buf[512];
	int line_no = 1;

	char tmp_buf[32];
	int tok_no = 0;
	char *tok;
	char delim[] = ",.-:[] \t\r\n";
	uint32_t cnt = 0;
	int pfile_id, cat_id, app_id;

	mac_buflen = sizeof(patrol_ioc_mac_ptr_t)
		+ sizeof(patrol_ioc_mac_t) * DEVID_MAX_USER;

	mac_e = calloc(mac_buflen, sizeof(char));
	if (!mac_e)
	{
		printf("Malloc failed\n");
		return -1;
	}

	if (pf)
	{
		ioc_pfile_ptr = (patrol_ioc_pfile_ptr_t *) pfile_e;
		pfile_len += sizeof(patrol_ioc_pfile_ptr_t);

		ioc_mac_ptr = (patrol_ioc_mac_ptr_t *) mac_e;
		mac_len += sizeof(patrol_ioc_mac_ptr_t);

		while (fgets(line_buf, sizeof(line_buf), pf))
		{
			if ('#' == line_buf[0] || '\r' == line_buf[0]
				|| '\n' == line_buf[0])
			{
				line_no++;
				continue;
			}

			if (line_buf[0] == '[')
			{
				ioc_pfile_ptr->pfile_cnt++;
				ioc_pfile_id = (patrol_ioc_pfile_t *) (pfile_e + pfile_len);
				pfile_len += sizeof(patrol_ioc_pfile_t);

				if (pfile_len > all_len)
				{
					printf("Buf(%u) is not enough\n", all_len);
					ret = -1;
					goto __error;
				}

				tok_no = 0;
				tok = strtok(line_buf, delim);
				while (tok != NULL)
				{
					sscanf(tok, "%u", &pfile_id);
					ioc_pfile_id->pfile_id = pfile_id;

					tok = strtok(NULL, delim);
					tok_no++;
				}

				if (tok_no != 1)
				{
					printf("pfile tok_num = %u, it should be 1\n", tok_no);
					ret = -1;
					goto __error;
				}

				DBG("pid = %u\n", ioc_pfile_id->pfile_id);
			}
			else if (!strncmp("app=", line_buf, 4) && ioc_pfile_id)
			{
				if (0 < sscanf(line_buf, "app=%s", tmp_buf))
				{
					ioc_pfile_id->app_cnt++;
					ioc_app = (patrol_ioc_app_t *) (pfile_e + pfile_len);
					pfile_len += sizeof(patrol_ioc_app_t);

					if (pfile_len > all_len)
					{
						printf("Buf(%u) is not enough\n", all_len);
						ret = -1;
						goto __error;
					}

					tok_no = 0;
					tok = strtok(tmp_buf, delim);
					while (tok != NULL)
					{
						if (tok_no == 0)
						{
							sscanf(tok, "%u", &cat_id);
							ioc_app->cat_id = cat_id;
						}
						else if (tok_no == 1)
						{
							sscanf(tok, "%u", &app_id);
							ioc_app->app_id = app_id;
						}

						tok = strtok(NULL, delim);
						tok_no++;
					}

					if (tok_no != 2)
					{
						printf("app tok_num = %u, it should be 2\n", tok_no);
						ret = -1;
						goto __error;
					}

					DBG("cat = %u, app = %u\n", ioc_app->cat_id, ioc_app->app_id);
				}
				else
				{
					printf("Parse error(line %u)\n", line_no);
					ret = -1;
					goto __error;
				}
			}
			else if (!strncmp("mac=", line_buf, 4))
			{
				if (0 < sscanf(line_buf, "mac=%s", tmp_buf))
				{
					ioc_mac_ptr->mac_cnt++;
					ioc_mac = (patrol_ioc_mac_t *) (mac_e + mac_len);
					mac_len += sizeof(patrol_ioc_mac_t);

					if (mac_len > mac_buflen)
					{
						printf("Buf(%u) is not enough\n", mac_buflen);
						ret = -1;
						goto __error;
					}

					tok_no = 0;
					tok = strtok(tmp_buf, delim);
					while (tok != NULL)
					{
						if (tok_no < 6)
						{
							ioc_mac->mac[tok_no] = (char) strtol(tok, NULL, 16);
						}
						else if (tok_no == 6)
						{
							sscanf(tok, "%u", &pfile_id);
							ioc_mac->pfile_id = pfile_id;
						}

						tok = strtok(NULL, delim);
						tok_no++;
					}

					if (tok_no != 7)
					{
						printf("mac tok_num = %u, it should be 7\n", tok_no);
						ret = -1;
						goto __error;
					}

					DBG("mac = "MAC_OCTET_FMT ", pid = %u\n",
						MAC_OCTET_EXPAND(ioc_mac->mac), ioc_mac->pfile_id);
				}
				else
				{
					printf("Parse error(line %u)\n", line_no);
					ret = -1;
					goto __error;
				}
			}
			else
			{
				printf("Parse error(line %u)\n", line_no);
				ret = -1;
				goto __error;
			}

			line_no++;
		}
	}

	/* put mac conf on end of pfile conf */
	if ((pfile_len + mac_len) < all_len)
	{
		*used_len = pfile_len + mac_len;

		for (cnt = 0; cnt < mac_len; cnt++)
		{
			pfile_e[pfile_len++] = mac_e[cnt];
		}
	}
	else
	{
		printf("Buf(%u) is not enough\n", all_len);
		ret = -1;
		goto __error;
	}

	__error:

	if (mac_e)
	{
		free(mac_e);
	}

	return ret;
}

int set_app_patrol(void)
{
	int ret = 0;
	FILE *pf;

	uint32_t used_len;
	uint32_t all_len;
	char *pfile_e = NULL;

	if (!*file_path)
	{
		snprintf(file_path, sizeof(file_path), "app_patrol.conf");
	}

	if (NULL != (pf = fopen(file_path, "r")))
	{
		fseek(pf, 0, SEEK_END);
		all_len = ftell(pf) + 10;
		fseek(pf, 0, SEEK_SET);

		pfile_e = calloc(all_len, sizeof(char));
		if (!pfile_e)
		{
			printf("Malloc failed\n");
			fclose(pf);
			return -1;
		}

		ret = load_app_patrol_conf(pf, pfile_e, all_len, &used_len);
		fclose(pf);
	}
	else
	{
		printf("File not found ! %s\n", file_path);
		return -1;
	}

	if (!ret)
	{
		ret = set_fw_app_patrol(pfile_e, used_len);
	}

	if (pfile_e)
	{
		free(pfile_e);
	}

	printf("Result: %s\n", ret ? "Fail" : "Pass");
	return ret;
}


int get_app_bw_clear(void)
{
	int ret = 0;
	int r;
	app_bw_ioctl_entry_t *app_lst = NULL;
	uint32_t app_cnt = 0;
	uint32_t buf_len = 0;
	
	if ((ret = get_fw_app_bw_clear(&app_lst, &buf_len)))
	{
		DBG("Error: get app!(%d)\n", ret);
	}

	if (app_lst)
	{
		app_cnt = buf_len / sizeof(*app_lst);

		for (r = 0; r < app_cnt; r++)
		{
			if (app_lst[r].available <= 0)
			{
				break;
			}

			printf("--------------\n");
			printf("uid    : %u\n", app_lst[r].uid);
			printf("cat_id : %u\n", app_lst[r].cat_id);
			printf("app_id : %u\n", app_lst[r].app_id);
			printf("down_recent : %" PRIu64 "\n", app_lst[r].down_recent);
			printf("up_recent  : %" PRIu64 "\n", app_lst[r].up_recent);
		}

		free(app_lst);
	}

	return ret;
}

int set_wpr_conf(void)
{
	int ret = 0;
	FILE *pf = NULL;

	uint32_t used_len = 0;
	wpr_config_t *wpr_conf = NULL;
	static char line_buf[1024];

	uint32_t period_min = 0;
	uint32_t max_num = 0;
	char *url = calloc(MAX_REDIRECT_URL_LEN, sizeof(char));

	if (!*file_path)
	{
		snprintf(file_path, sizeof(file_path), "wpr.conf");
	}

	if (NULL != (pf = fopen(file_path, "r")))
	{
		while (fgets(line_buf, sizeof(line_buf), pf))
		{
			if ('#' == line_buf[0])
			{
				continue;
			}

			sscanf(line_buf, "%u,%u,%[^\n]", &period_min, &max_num, url);
			wpr_conf = (wpr_config_t *) calloc(sizeof(wpr_config_t), sizeof(char));
			if (wpr_conf)
			{
				wpr_conf->period_min = period_min;
				wpr_conf->max_num = max_num;
				memcpy(wpr_conf->url, url, MAX_REDIRECT_URL_LEN - 1);
				used_len += sizeof(wpr_config_t);
				DBG("%u,%u,%s\n", wpr_conf->period_min, wpr_conf->max_num, wpr_conf->url);
				break;
			}
		}
		fclose(pf);
	}
	else
	{
		printf("File not found ! %s\n", file_path);
		return -1;
	}

	if (!ret)
	{
		ret = set_fw_wpr_conf(wpr_conf, used_len);
	}

	if (url)
	{
		free(url);
	}
	if (wpr_conf)
	{
		free(wpr_conf);
	}

	printf("Result: %s\n", ret ? "Fail" : "Pass");
	return ret;
}

int set_wpr_on(void)
{
	int ret = 0;
	
	ret = set_wpr_state(1);
	if (ret)
	{
		DBG("Error: set wpr state is (%d).\\n", ret);
	}
	printf("result: %s\n", ret ? "NG" : "OK");

	return ret;
}

int set_wpr_off(void)
{
	int ret = 0;

	ret = set_wpr_state(0);
	if (ret)
	{
		DBG("Error: set wpr state is (%d).\\n", ret);
	}
	printf("result: %s\n", ret ? "NG" : "OK");

	return ret;
}

int set_redirect_url(void)
{
	int ret = 0;
	char *url = NULL;
	int url_len = 0;

	url_len = strlen(url_path);

	if (!url_len)
	{
		printf("Please Set URL Path !\n");
		return -1;
	}

	url = calloc(url_len, sizeof(char));
	if (NULL == url)
	{
		printf("Malloc URL Path Fail !\n");
		return -1;
	}
	
	memcpy(url, url_path, url_len);

	if (!ret)
	{
		ret = set_fw_redirect_url(url, url_len);
	}

	if (url)
	{
		free(url);
	}

	printf("Result: %s\n", ret ? "Fail" : "Pass");
	return ret;
}

int parse_single_str_arg(int argc, char **argv, char opt, char *buf, int buf_len)
{
	int optret;
	char optstr[3];

	if (!buf)
	{
		return -1;
	}

	snprintf(optstr, 3, "%c:", opt);

	while (-1 != (optret = getopt(argc, argv, optstr)))
	{
		if (optret == (int)opt)
		{
			if (optarg != NULL)
			{
				snprintf(buf, buf_len, "%s", optarg);
			}
			else
			{
				ERR("Option -%c has no argument!\n", opt);
				return -2;
			}
			break;
		}
		else
		{
			//ERR("Unknown option -%c", optret);
			return -1;
		}
	}

	return 0;
}

int parse_app_patrol_args(int argc, char **argv)
{
	return parse_single_str_arg(argc, argv, 'R', file_path, sizeof(file_path));
}

int parse_wpr_conf_args(int argc, char **argv)
{
	return parse_single_str_arg(argc, argv, 'R', file_path, sizeof(file_path));
}

int parse_redir_url_args(int argc, char **argv)
{
	parse_single_str_arg(argc, argv, 'u', url_path, sizeof(url_path));
}

int common_options_init(struct cmd_option *cmd)
{
#define HELP_LEN_MAX 1024
	int i = 0, j;
	static char help[HELP_LEN_MAX];
	int len = 0;

	cmd->opts[i].action = ACT_COMMON_GET_ALL_USR; 
	cmd->opts[i].name = "get_all_user";
	cmd->opts[i].cb = get_user_lst;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_GET_USR_DETAIL;
	cmd->opts[i].name = "get_user_detail";
	cmd->opts[i].cb = get_user_detail;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_GET_ALL_APP;
	cmd->opts[i].name = "get_all_app";
	cmd->opts[i].cb = get_user_app_lst;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_GET_ALL_APP_CLEAR;
	cmd->opts[i].name = "get_all_app_clear";
	cmd->opts[i].cb = get_app_bw_clear;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_SET_APP_PATROL;
	cmd->opts[i].name = "set_app_patrol";
	cmd->opts[i].cb = set_app_patrol;
	cmd->opts[i].parse_arg = parse_app_patrol_args;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_GET_APP_PATROL;
	cmd->opts[i].name = "get_app_patrol";
	cmd->opts[i].cb = get_app_patrol;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_SET_WPR_CONF;
	cmd->opts[i].name = "set_wpr_conf";
	cmd->opts[i].cb = set_wpr_conf;
	cmd->opts[i].parse_arg = parse_wpr_conf_args;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_SET_WPR_ON;
	cmd->opts[i].name = "set_wpr_on";
	cmd->opts[i].cb = set_wpr_on;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_SET_WPR_OFF;
	cmd->opts[i].name = "set_wpr_off";
	cmd->opts[i].cb = set_wpr_off;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_COMMON_SET_REDIRECT_URL;
	cmd->opts[i].name = "set_redirect_url";
	cmd->opts[i].cb = set_redirect_url;
	cmd->opts[i].parse_arg = parse_redir_url_args;
	OPTS_IDX_INC(i);

#ifdef __INTERNAL__
	if (0 > (i = common_internal_opts_init(cmd, i)))
	{
		return -1;
	}
#endif

	len += snprintf(help + len, HELP_LEN_MAX - len, "%*s \n",
		HELP_INDENT_L, "");

	for (j = 0; j < i; j++)
	{
		len += snprintf(help + len, HELP_LEN_MAX - len, "%*s %s\n",
			HELP_INDENT_L, (j == 0) ? "common actions:" : "",
			cmd->opts[j].name);
	}

	cmd->help = help;

	return 0;
}

