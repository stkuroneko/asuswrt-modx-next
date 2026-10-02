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
#include <unistd.h>
#define _GNU_SOURCE	//strcasestr()
#include <string.h>	//strcasestr()
#include <inttypes.h>

#include "udb/shell/shell_ioctl.h"

#include "ioc_common.h" // for get_fw_user_list()
#include "ioc_qos.h"

#define NO_RSV_UPLOAD_BW 1

#define APP_QOS_FLAG_RSV_MASK		(0x1 << 31)
#define APP_QOS_FLAG_P_CLSID_MASK	(0x3fff << 16)
#define APP_QOS_FLAG_CLSID_MASK		(0xffff)
#define is_app_qos_flag_rsv(__f) 	(__f & APP_QOS_FLAG_RSV_MASK)

#define IS_INTERESTED_IN_APP (qos_args.catid >= 0 && qos_args.appid >= 0)
#define IS_INTERESTED_IN_CAT (qos_args.catid >= 0 && qos_args.appid < 0)

typedef struct
{
	int intvl;
	uint8_t uid;
	int catid;
	int appid;
} qos_args_t;

typedef struct
{
	char *cmd;
	int nr_lin;
	int nr_kwd;
	char *kwd[4];
} read_cmd_t;

static char file_path[CONF_PATH_MAX_LEN] = {0};

static qos_app_stat_t *qos_app_stat_tbl = NULL;
static uint32_t qos_app_stat_cnt = 0;
static qos_tc_cls_t *qos_tc_dl_cls_tbl = NULL;
static uint32_t qos_tc_dl_cls_cnt = 0;
static qos_tc_cls_t *qos_tc_ul_cls_tbl = NULL;
static uint32_t qos_tc_ul_cls_cnt = 0;

static qos_args_t qos_args = {
	.intvl = 3,
	.uid = 0,
	.catid = -1,
	.appid = -1
};

int set_fw_iqos_state(unsigned char flag)
{
	udb_shell_ioctl_t msg;
	uint32_t buf_used_len = 0;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_IQOS;
	msg.op = (0 == flag ? UDB_IOCTL_IQOS_OP_DISABLE : UDB_IOCTL_IQOS_OP_ENABLE);
	(&msg)->out = 0;
	(&msg)->out_len = 0;
	(&msg)->out_used_len = (uintptr_t)&buf_used_len;
	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_IQOS, &msg);
}

int set_fw_iqos(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_IQOS;
	msg.op = UDB_IOCTL_IQOS_OP_SET_CONFIG;
	udb_shell_ioctl_set_in_raw(&msg, input, length);

	if (0 > run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_IQOS, &msg))
	{
		return -1;
	}

	DBG("Forward iqos at %p %d bytes into kernel. Type:%d | Magic:%d NR:%d OP:%d UDB_SHELL_IOCTL_CMD_IQOS[%d]\n", input, length, msg.in_type, msg.magic, msg.nr, msg.op, UDB_SHELL_IOCTL_CMD_IQOS);
	return 0;
}

int get_fw_iqos_conf(qos_conf_ioctl_t *conf)
{
	udb_shell_ioctl_t msg;
	uint32_t buf_len = sizeof(qos_conf_ioctl_t);
	uint32_t buf_used_len = 0;
	int ret = 0;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_IQOS;
	msg.op = UDB_IOCTL_IQOS_OP_GET_CONFIG;
	udb_shell_ioctl_set_out_buf(&msg, conf, buf_len, &buf_used_len);

	if (0 != (ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_IQOS, &msg)))
	{
		DBG("Error: run_ioctl failed (%d)\n", ret);
		return -1;
	}

	if (buf_used_len != sizeof(qos_conf_ioctl_t))
	{
		DBG("Error: wrong ioctl data size!\n");
		return -1;
	}

	return 0;
}

int get_fw_iqos_app_info(app_qos_ioctl_t **output, uint32_t *used_len)
{
	uint32_t buf_len =
		DEVID_APP_RATE_TABLE_POOL_SIZE * sizeof(app_qos_ioctl_t);

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
	msg.nr = UDB_IOCTL_NR_IQOS;
	msg.op = UDB_IOCTL_IQOS_OP_GET_APP_INFO;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, used_len);

	ret = run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_IQOS, &msg);

	//memset(((char*) *output) + *used_len, 0x00, buf_len - *used_len);

	return ret;
}

////////////////////////////////////////////////////////////////////////////////

static inline int numlen(double val, int pre)
{
	char str[16 + 1];
	return snprintf(str, sizeof(str), "%.*f", pre, val);
}

static int read_cmd(read_cmd_t *rc, char *spad)
{
	int use_fopen;

	FILE *fp;
	char *p = spad;

	use_fopen = !memcmp(rc->cmd, "r* ", 3);

	if (use_fopen)
	{
		fp = fopen(rc->cmd + 3/* "r* " */, "r");
	}
	else
	{
		fp = popen(rc->cmd, "r");
	}

	if (fp)
	{
		char *lin = NULL;
		size_t lin_siz = 0;

		int nr_read, tot_lin = 0, nr_lin = 0;

		while (-1 != (nr_read = getline(&lin, &lin_siz, fp)))
		{
			if (++tot_lin <= rc->nr_lin)
			{
				if (rc->nr_kwd)
				{
					/* do keyword filtering */
					int i;

					for (i = 0; i < rc->nr_kwd; i++)
					{
						if (strcasestr(lin, rc->kwd[i]))
						{
							break;
						}
					}

					if (i == rc->nr_kwd)
					{ /* no keyword found; continue to the next line */
						continue;
					}
				}
				nr_lin++;
				//DBG("lin#%d: siz=%d, nr_read=%d\n", nr_lin, lin_siz, nr_read);
				memcpy(p, lin, nr_read);
				p += nr_read;
			}
		}

		if (p != spad)
		{ /* trim the last newline */
			*--p = 0;
		}

		if (lin)
		{
			free(lin);
		}

		if (use_fopen)
		{
			fclose(fp);
		}
		else
		{
			pclose(fp);
		}

		return nr_lin;
	}

	return 0;
}

int set_qos_on(void)
{
	int ret = 0;

	ret = set_fw_iqos_state(1);
	if (ret)
	{
		DBG("Error: set qos state is (%d).\\n", ret);
	}
	printf("result: %s\n", ret ? "NG" : "OK");

	return ret;
}

int set_qos_off(void)
{
	int ret = 0;

	ret = set_fw_iqos_state(0);
	if (ret)
	{
		DBG("Error: set qos state is (%d).\\n", ret);
	}
	printf("result: %s\n", ret ? "NG" : "OK");

	return ret;
}

int set_qos_conf(void)
{
	int ret = 0;
	FILE *fp;
	unsigned int buf_len = 0;
	char *buf = NULL;

	if (!*file_path)
	{
		snprintf(file_path, sizeof(file_path), "qos.conf");
	}

	fp = fopen(file_path, "r");
	if (fp == NULL)
	{
		DBG("Open %s file failure.\n", file_path);
		return 1;

	}

	/* Go to the end of the file. */
	if (fseek(fp, 0L, SEEK_END) == 0)
	{
		/* Get the size of the file. */
		buf_len = ftell(fp);
		if (buf_len <= 0)
		{
			DBG("Error! Read file length is %d.\n",buf_len);
			ret = 1;
			goto iqos_error;
		}
	}
	DBG("File %s size is %d.\n", file_path, buf_len);

	/* Allocate our buffer to that size. */
	buf = calloc(sizeof(char) * (buf_len + 1), sizeof(char));
	if (!buf)
	{
		ret = 1;
		goto iqos_error;
	}
	fseek(fp, SEEK_SET, 0);

	/* Read the entire file into memory. */
	size_t read_len = fread(buf, sizeof(char), buf_len, fp);
	if (read_len == 0)
	{
		fputs("Error reading file", stderr);
		ret = 1;
		goto iqos_error;
	}
	else
	{
		buf[read_len] = '\0'; /* Just to be safe. */
	}

	if (buf)
	{
		DBG("load qos.conf len[%d] memory\n", buf_len);
		ret = set_fw_iqos(buf, buf_len);
		DBG(" Free memory [%d].\n", buf_len);
		free(buf);
	}
	else
	{
		printf("Error! Set Forward IQOS conf, Maybe it's OOM issue.\n");
		ret = 1;
	}
	iqos_error:
	fclose(fp);
	printf("Push forward IQoS policy size[%d] result: %s\n", buf_len, ret ? "NG" : "OK");
	return ret;
}

static qos_app_stat_t *find_qos_app_stat(
	uint8_t uid, uint8_t catid, uint16_t appid)
{
	int i;
	qos_app_stat_t *ent;

	for (i = 0; i < qos_app_stat_cnt; i++)
	{
		ent = &qos_app_stat_tbl[i];

		if (ent->uid == uid 
			&& ent->catid == catid 
			&& ent->appid == appid)
		{
			return ent;
		}
	}

	return NULL;
}

static qos_app_stat_t *new_qos_app_stat(
	uint8_t uid, uint8_t catid, uint16_t appid)
{
	qos_app_stat_t *ent = NULL;

	if (!(qos_app_stat_tbl = realloc(
		qos_app_stat_tbl,
		(qos_app_stat_cnt + 1) * sizeof(qos_app_stat_t))))
	{
		ERR("Error: malloc %lu bytes failed!\n", sizeof(qos_app_stat_t));
		return NULL;
	}

	ent = &qos_app_stat_tbl[qos_app_stat_cnt];

	memset(ent, 0, sizeof(qos_app_stat_t));
	ent->uid = uid;
	ent->catid = catid;
	ent->appid = appid;
	ent->tc_dl_cls = NULL;
	ent->tc_ul_cls = NULL;

	qos_app_stat_cnt++;

	return ent;
}

static int free_qos_app_stat_list(void)
{
	if (qos_app_stat_tbl && qos_app_stat_cnt)
	{
		free(qos_app_stat_tbl);
		qos_app_stat_tbl = NULL;
		qos_app_stat_cnt = 0;
	}

	return 0;
}

static int update_qos_app_stats(void)
{
	int ret = 0;
	int i;
	app_qos_ioctl_t *app_lst = NULL;
	qos_app_stat_t *app_stat = NULL;
	uint32_t app_cnt;
	uint32_t buf_len;

	ret = get_fw_iqos_app_info(&app_lst, &buf_len);
	if (ret || !app_lst)
	{
		DBG("Error: get app!(%d)\n", ret);
		ret = -1;
		goto __exit;
	}

	app_cnt = buf_len / sizeof(*app_lst);

	for (i = 0; i < app_cnt; i++)
	{
		if (!app_lst[i].available)
		{
			continue;
		}

		//DBG("update app %d-%d-%d\n", app_lst[i].uid, app_lst[i].cat_id, app_lst[i].app_id);

		if (!(app_stat = find_qos_app_stat(
			app_lst[i].uid, app_lst[i].cat_id, app_lst[i].app_id)))
		{
			if (!(app_stat = new_qos_app_stat(
				app_lst[i].uid, app_lst[i].cat_id, app_lst[i].app_id)))
			{
				DBG("Error: create app stat failed!\n");
				ret = -1;
				goto __exit;
			}
		}

		app_stat->inc_dl_bytes = app_lst[i].down_recent_accl - app_stat->acc_dl_bytes;
		app_stat->inc_ul_bytes = app_lst[i].up_recent_accl - app_stat->acc_ul_bytes;
		app_stat->acc_dl_bytes = app_lst[i].down_recent_accl;
		app_stat->acc_ul_bytes = app_lst[i].up_recent_accl;
		app_stat->qos_flag = app_lst[i].qos_flag;
		app_stat->paid = app_lst[i].paid;
		app_stat->bndwidth = app_lst[i].bndwidth;
	}

__exit:
	if (app_lst)
	{
		free(app_lst);
	}

	return ret;
}

static qos_tc_cls_t *find_qos_tc_cls(uint16_t id, uint16_t p_id, uint8_t dir)
{
	qos_tc_cls_t *ent = NULL;
	int i = 0;

	if (dir)
	{
		for (i = 0; i < qos_tc_dl_cls_cnt; i++)
		{
			if (qos_tc_dl_cls_tbl[i].p_id == p_id &&
				qos_tc_dl_cls_tbl[i].id == id)
			{
				ent = &qos_tc_dl_cls_tbl[i];
				break;
			}
		}
	}
	else
	{
		for (i = 0; i < qos_tc_ul_cls_cnt; i++)
		{
			if (qos_tc_ul_cls_tbl[i].p_id == p_id &&
				qos_tc_ul_cls_tbl[i].id == id)
			{
				ent = &qos_tc_ul_cls_tbl[i];
				break;
			}
		}
	}

	return ent;
}

static qos_tc_cls_t *new_qos_tc_cls(uint16_t id, uint16_t p_id, uint8_t dir)
{
	qos_tc_cls_t *ent = NULL;
	qos_app_stat_t *app_stat = NULL;
	int i = 0;

	if (dir)
	{
		if (!(qos_tc_dl_cls_tbl = realloc(
			qos_tc_dl_cls_tbl, 
			(qos_tc_dl_cls_cnt + 1) * sizeof(qos_tc_cls_t))))
		{
			ERR("Error: malloc %lu bytes failed!\n", sizeof(qos_tc_cls_t));
			return NULL;
		}

		ent = &qos_tc_dl_cls_tbl[qos_tc_dl_cls_cnt];
		qos_tc_dl_cls_cnt++;
	}
	else
	{
		if (!(qos_tc_ul_cls_tbl = realloc(
			qos_tc_ul_cls_tbl, 
			(qos_tc_ul_cls_cnt + 1) * sizeof(qos_tc_cls_t))))
		{
			ERR("Error: malloc %lu bytes failed!\n", sizeof(qos_tc_cls_t));
			return NULL;
		}

		ent = &qos_tc_ul_cls_tbl[qos_tc_ul_cls_cnt];
		qos_tc_ul_cls_cnt++;
	}

	memset(ent, 0, sizeof(qos_tc_cls_t));
	ent->id = id;
	ent->p_id = p_id;
	ent->rate = 0;
	ent->sent_bytes = 0;

	for (i = 0; i < qos_app_stat_cnt; i++)
	{
		uint16_t app_p_cls_id, app_cls_id;
		app_stat = &qos_app_stat_tbl[i];
		
		app_p_cls_id = (app_stat->qos_flag & APP_QOS_FLAG_P_CLSID_MASK) >> 16;
		app_cls_id = (app_stat->qos_flag & APP_QOS_FLAG_CLSID_MASK);

		if (dir)
		{
			if (app_p_cls_id == p_id && app_cls_id == id)
			{
				if (!app_stat->tc_dl_cls)
				{
					app_stat->tc_dl_cls = ent;
					DBG("%u-%u-%u has tc dl class %u:%u\n", 
						app_stat->uid,
						app_stat->catid,
						app_stat->appid,
						p_id,
						id);
				}
				else
				{
					DBG("%u-%u-%u already has tc dl class!\n",
						app_stat->uid,
						app_stat->catid,
						app_stat->appid);
				}
			}
		}
		else
		{
			if (app_p_cls_id == p_id &&
				((app_cls_id == 0 && (app_stat->uid + 1) == id) 
				|| (app_cls_id > 0 && app_cls_id == id)))
			{
				if (!app_stat->tc_ul_cls)
				{
					app_stat->tc_ul_cls = ent;
					DBG("%u-%u-%u has tc ul class %u:%u\n", 
						app_stat->uid,
						app_stat->catid,
						app_stat->appid,
						p_id,
						id);
				}
				else
				{
					DBG("%u-%u-%u already has tc ul class!\n",
						app_stat->uid,
						app_stat->catid,
						app_stat->appid);
				}
			}
		}
	}

	return ent;
}

static int free_qos_tc_cls_list(void)
{
	if (qos_tc_dl_cls_tbl && qos_tc_dl_cls_cnt)
	{
		free(qos_tc_dl_cls_tbl);
		qos_tc_dl_cls_tbl = NULL;
		qos_tc_dl_cls_cnt = 0;
	}

	if (qos_tc_ul_cls_tbl && qos_tc_ul_cls_cnt)
	{
		free(qos_tc_ul_cls_tbl);
		qos_tc_ul_cls_tbl = NULL;
		qos_tc_ul_cls_cnt = 0;
	}

	return 0;
}

static int update_qos_app_tc_rates(qos_conf_ioctl_t *qos_conf)
{
	int dir;
	char tc_cmd[256];
	FILE *fp;

	for (dir = 1; dir >= 0; dir--)
	{
		memset(tc_cmd, 0, sizeof(tc_cmd));
		snprintf(tc_cmd, sizeof(tc_cmd), "tc -s class show dev %s"
			, (dir) ? qos_conf->lan : qos_conf->wan);
	
		//DBG("tc_cmd = %s\n", tc_cmd);
		fp = popen(tc_cmd, "r");

		if (fp)
		{
			char *lin = NULL;
			size_t lin_siz = 0;
			int nr_read;

			char *anc;
			char *e_anc;
			uint16_t p_cls_id;
			uint16_t cls_id;
			qos_tc_cls_t *tc_cls = NULL;
			uint8_t is_new = 0;

			while (-1 != (nr_read = getline(&lin, &lin_siz, fp)))
			{
				if (tc_cls)
				{
					if ((anc = strcasestr(lin, "sent ")))
					{
						uint32_t sent_bytes = (uint32_t)strtoul((anc + 5), &e_anc, 10);
						if (!is_new)
						{
							tc_cls->rate = (sent_bytes - tc_cls->sent_bytes) / qos_args.intvl;
						}
						tc_cls->sent_bytes = sent_bytes;
					}

					tc_cls = NULL;
					continue;
				}

				if ((anc = strcasestr(lin, "htb ")))
				{
					p_cls_id = (uint16_t)strtoul((anc + 4), &e_anc, 10);
					if (*e_anc == ':')
					{
						cls_id = (uint16_t)strtoul((e_anc + 1), NULL, 10);
						is_new = 0;
						if (!(tc_cls = find_qos_tc_cls(cls_id, p_cls_id, dir)))
						{
							tc_cls = new_qos_tc_cls(cls_id, p_cls_id, dir);
							is_new = 1;
						}
					}
					continue;
				}
			}

			if (lin)
			{
				free(lin);
			}

			pclose(fp);
		}
	}
}

#define RSV_LOCAL_CLS_ID 2
#define RSV_DEF_CLS_ID 3

static int print_qos_root_info(qos_conf_ioctl_t *qos_conf)
{
	qos_tc_cls_t *root_dl_cls = NULL;
	qos_tc_cls_t *root_ul_cls = NULL;
	qos_tc_cls_t *local_dl_cls = NULL;
	qos_tc_cls_t *local_ul_cls = NULL;
	qos_tc_cls_t *def_dl_cls = NULL;
	qos_tc_cls_t *def_ul_cls = NULL;
	int root_dl_rate = -1;
	int root_ul_rate = -1;
	int local_dl_rate = -1;
	int local_ul_rate = -1;
	int def_dl_rate = -1;
	int def_ul_rate = -1;

	qos_tc_cls_t *tc_cls_e;
	int i;

	int pad_len = 0;

	for (i = 0; i < qos_tc_dl_cls_cnt; i++)
	{
		tc_cls_e = &qos_tc_dl_cls_tbl[i];

		if (root_dl_cls != NULL && def_dl_cls != NULL)
		{
			break;
		}

		if (tc_cls_e->p_id == 1 && tc_cls_e->id == 1)
		{
			root_dl_cls = tc_cls_e;
			DBG("got root dl class!\n");
			continue;
		}

		if (tc_cls_e->p_id == 1 && tc_cls_e->id == RSV_LOCAL_CLS_ID)
		{
			local_dl_cls = tc_cls_e;
			DBG("got local dl class!\n");
			continue;
		}

		if (tc_cls_e->p_id == 1 && tc_cls_e->id == RSV_DEF_CLS_ID)
		{
			def_dl_cls = tc_cls_e;
			DBG("got default dl class!\n");
			continue;
		}
	}

	for (i = 0; i < qos_tc_ul_cls_cnt; i++)
	{
		tc_cls_e = &qos_tc_ul_cls_tbl[i];

		if (root_ul_cls != NULL && def_ul_cls != NULL)
		{
			break;
		}

		if (tc_cls_e->p_id == 1 && tc_cls_e->id == 1)
		{
			root_ul_cls = tc_cls_e;
			DBG("got root ul class!\n");
			continue;
		}

		if (tc_cls_e->p_id == 1 && tc_cls_e->id == RSV_LOCAL_CLS_ID)
		{
			local_ul_cls = tc_cls_e;
			DBG("got local ul class!\n");
			continue;
		}

		if (tc_cls_e->p_id == 1 && tc_cls_e->id == RSV_DEF_CLS_ID)
		{
			def_ul_cls = tc_cls_e;
			DBG("got default ul class!\n");
			continue;
		}
	}

	root_dl_rate = root_dl_cls ? (int)root_dl_cls->rate : -1;
	root_ul_rate = root_ul_cls ? (int)root_ul_cls->rate : -1;
	local_dl_rate = local_dl_cls ? (int)local_dl_cls->rate : -1;
	local_ul_rate = local_ul_cls ? (int)local_ul_cls->rate : -1;
	def_dl_rate = def_dl_cls ? (int)def_dl_cls->rate : -1;
	def_ul_rate = def_ul_cls ? (int)def_ul_cls->rate : -1;
	
	printf("----------------------------------------------------  ");
	printf("----------------------------------------------------\n");
	pad_len = 53 - 32 - numlen(root_dl_rate, 0)
		- numlen(local_dl_rate, 0)
		- numlen(def_dl_rate, 0);
	printf("root: dl = %d Bps (local %d / def %d) %*.s ",
		root_dl_rate,
		local_dl_rate,
		def_dl_rate,
		(pad_len >= 0) ? pad_len : 1, "");
	printf("ul = %d Bps (local %d / def %d)\n",
		root_ul_rate,
		local_ul_rate,
		def_ul_rate);

	return 0;
}

int get_qos_user_info(void)
{
	int ret = 0;
	int intvl = qos_args.intvl;
	uint8_t uid = qos_args.uid;
	int i, j;
	uint16_t p_id, c_id;
	uint32_t tot_inc_dl_bytes, tot_inc_ul_bytes;
	udb_ioctl_entry_t *usr_lst = NULL;
	uint32_t usr_buf_len = 0;
	uint32_t usr_cnt = 0;
	qos_app_stat_t *app_stat = NULL;

	qos_conf_ioctl_t *qos_conf;

	dev_os_t *dev_os = NULL;

	LIST_HEAD(app_inf_head);
	LIST_HEAD(dev_os_head);

	init_app_inf(&app_inf_head);
	init_dev_os(&dev_os_head);

	if (!(qos_conf = malloc(sizeof(qos_conf_ioctl_t))))
	{
		DBG("Error: malloc %d bytes failed!\n", sizeof(qos_conf_ioctl_t));
		ret = -1;
		goto __ret;
	}

	if (get_fw_iqos_conf(qos_conf))
	{
		DBG("Error: get qos conf failed!\n");
		ret = -1;
		goto __ret;
	}

	update_qos_app_stats();
	update_qos_app_tc_rates(qos_conf);
	sleep(intvl);
	update_qos_app_stats();
	update_qos_app_tc_rates(qos_conf);

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst)
	{
		DBG("Error: get user!(%d)\n", ret);
		goto __ret;
	}

	usr_cnt = usr_buf_len / sizeof(*usr_lst);

	print_qos_root_info(qos_conf);

	//DBG("usr_cnt = %u\n", usr_cnt);

	for (i = 0; i < usr_cnt; i++)
	{
		if (!usr_lst[i].available)
		{
			break;
		}

		if (uid > 0 && usr_lst[i].uid != uid)
		{
			continue;
		}

		printf("------------------------------------------------------");
		printf("----------------------------------------------------\n");
		printf("%-*s : %u\n", 4, "uid", usr_lst[i].uid);
		printf("%-*s : " MAC_OCTET_FMT "\n", 4, "mac", MAC_OCTET_EXPAND(usr_lst[i].mac));
		printf("%-*s : " IPV4_OCTET_FMT "\n", 4, "ipv4", IPV4_OCTET_EXPAND(usr_lst[i].ipv4));
		printf("%-*s : " IPV6_OCTET_FMT "\n", 4, "ipv6", IPV6_OCTET_EXPAND(usr_lst[i].ipv6));
		printf("%-*s : %s\n", 4, "host", usr_lst[i].host_name);

		dev_os = search_dev_os(
			&dev_os_head,
			usr_lst[i].os.de.vendor_id,
			usr_lst[i].os.de.name_id,
			usr_lst[i].os.de.class_id,
			usr_lst[i].os.de.cat_id,
			usr_lst[i].os.de.dev_id,
			usr_lst[i].os.de.family_id);

		printf("type_id     : %u (%s)\n", usr_lst[i].os.de.cat_id,
			(dev_os) ? dev_os->type_name : "Unknown");
		printf("class_id    : %u (%s)\n", usr_lst[i].os.de.class_id,
			(dev_os) ? dev_os->class_name : "Unknown");
		printf("os_id       : %u (%s)\n", usr_lst[i].os.de.name_id,
			(dev_os) ? dev_os->os_name : "Unknown");
		printf("vendor_id   : %u (%s)\n", usr_lst[i].os.de.vendor_id,
			(dev_os) ? dev_os->vendor_name : "Unknown");
		printf("dev_id      : %u (%s)\n", usr_lst[i].os.de.dev_id,
			(dev_os) ? dev_os->dev_name : "Unknown");
		printf("family_id   : %u (%s)\n", usr_lst[i].os.de.family_id,
			(dev_os) ? dev_os->family_name : "Unknown");

		printf("%-*s : %" PRIu64 "\n", 15, "last_used_ts", usr_lst[i].ts);
		printf("%-*s : %" PRIu64 "\n", 15, "created_ts", usr_lst[i].ts_create);
		printf("%-*s : %" PRIu64 "\n", 15, "uptime", usr_lst[i].ts - usr_lst[i].ts_create);

		printf("\n");
		printf("app id     ");
		printf("download info                                         ");
		printf("upload info\n");
		printf("---------  ");
		printf("---------------------------------------------------   ");
		printf("-----------------------------------------\n");
		printf("cat,app    ");
		printf("cumu(B),   rate(Bps)(%%),  rsv(kb),   tc_rate, tc_id   ");
#if NO_RSV_UPLOAD_BW
		printf("cumu(B),   rate(Bps)(%%),   tc_rate, tc_id\n");
#else
		printf("cumu(B),   rate(Bps)(%%),  rsv(kb),   tc_rate, tc_id\n");
#endif

		tot_inc_dl_bytes = 0;
		tot_inc_ul_bytes = 0;

		//DBG("qos_app_stat_cnt = %u\n", qos_app_stat_cnt);

		for (j = 0; j < qos_app_stat_cnt; j++)
		{
			app_stat = &qos_app_stat_tbl[j];

			if (app_stat->uid == usr_lst[i].uid)
			{
				tot_inc_dl_bytes += app_stat->inc_dl_bytes;
				tot_inc_ul_bytes += app_stat->inc_ul_bytes;
			}
		}

		//DBG("tot_inc_dl_bytes = %u, tot_inc_ul_bytes = %u\n", tot_inc_dl_bytes, tot_inc_ul_bytes);

		for (j = 0; j < qos_app_stat_cnt; j++)
		{
			app_stat = &qos_app_stat_tbl[j];

			if (app_stat->uid == usr_lst[i].uid) // && app_stat->qos_flag
			{
				char *app_name = search_app_inf(
					&app_inf_head, app_stat->catid, app_stat->appid);
				double rate_dl_perc = 0;
				double rate_ul_perc = 0;

				if (tot_inc_dl_bytes > 0)
				{
					rate_dl_perc = ((double) app_stat->inc_dl_bytes / tot_inc_dl_bytes) * 100;
				}

				if (tot_inc_ul_bytes > 0)
				{
					rate_ul_perc = ((double) app_stat->inc_ul_bytes / tot_inc_ul_bytes) * 100;
				}

				//DBG("rate_dl_perc = %.2f, rate_ul_perc = %.2f\n", rate_dl_perc, rate_ul_perc);
				//DBG("app = %d-%d %s\n", app_stat->catid, app_stat->appid, app_name);

				p_id = (app_stat->qos_flag & APP_QOS_FLAG_P_CLSID_MASK) >> 16;
				c_id = (app_stat->qos_flag & APP_QOS_FLAG_CLSID_MASK);

				//DBG("p_id = %d, c_id = %d\n", p_id, c_id);
				printf(
					"%*u,%-*u%*u,%*u(%.2f%%),%*s(%u),%*u,%*u:%-*u%*u,%*u(%.2f%%),%*u,%*u:%-*u %s\n",
					3, app_stat->catid,
					3, app_stat->appid,
					11, app_stat->acc_dl_bytes,
					12 - numlen(rate_dl_perc, 2), (app_stat->inc_dl_bytes / intvl),
					rate_dl_perc,
					7 - numlen(app_stat->bndwidth * 8, 0), is_app_qos_flag_rsv(app_stat->qos_flag) ? "yes" : "no",
					app_stat->bndwidth * 8,
					10, (app_stat->tc_dl_cls) ? app_stat->tc_dl_cls->rate : 0,
					3, p_id,
					3, c_id,
					9, app_stat->acc_ul_bytes,
					12 - numlen(rate_ul_perc, 2), (app_stat->inc_ul_bytes / intvl),
					rate_ul_perc,
					10, (app_stat->tc_ul_cls) ? app_stat->tc_ul_cls->rate : 0,
					3, p_id,
					3, (c_id == 0) ? c_id : usr_lst[i].uid + 1,
					(app_name) ? app_name : "Unknow");
			}
		}
		printf("\n");

		if (uid > 0)
		{
			break;
		}
	}

__ret:
	if (qos_conf)
	{
		free(qos_conf);
	}

	free_app_inf(&app_inf_head);
	free_dev_os(&dev_os_head);

	free_qos_app_stat_list();
	free_qos_tc_cls_list();

	if (usr_lst)
	{
		free(usr_lst);
	}

	return ret;
}

int get_qos_app_info(void)
{
	int ret = 0;
	int intvl = qos_args.intvl;
	int arg_catid = qos_args.catid;
	int arg_appid = qos_args.appid;
	int i, j, k;
	uint16_t p_id, c_id;
	uint32_t tot_inc_dl_bytes, tot_inc_ul_bytes;
	udb_ioctl_entry_t *usr_lst = NULL;
	uint32_t usr_buf_len = 0;
	uint32_t usr_cnt = 0;
	qos_app_stat_t *app_stat = NULL;
	qos_app_stat_t *app_stat2 = NULL;

	qos_conf_ioctl_t *qos_conf;

	LIST_HEAD(app_inf_head);
	LIST_HEAD(app_cat_head);

	init_app_inf(&app_inf_head);
	init_app_cat(&app_cat_head);

	if (arg_appid >= 0 && arg_catid < 0)
	{
		DBG("Error: wrong argument!\n");
		return -1;
	}

	if (!(qos_conf = malloc(sizeof(qos_conf_ioctl_t))))
	{
		DBG("Error: malloc %d bytes failed!\n", sizeof(qos_conf_ioctl_t));
		ret = -1;
		goto __ret;
	}

	if (get_fw_iqos_conf(qos_conf))
	{
		DBG("Error: get qos conf failed!\n");
		ret = -1;
		goto __ret;
	}

	update_qos_app_stats();
	update_qos_app_tc_rates(qos_conf);
	sleep(intvl);
	update_qos_app_stats();
	update_qos_app_tc_rates(qos_conf);

	ret = get_fw_user_list(&usr_lst, &usr_buf_len);
	if (ret || !usr_lst)
	{
		DBG("Error: get user!(%d)\n", ret);
		goto __ret;
	}

	usr_cnt = usr_buf_len / sizeof(*usr_lst);

	DBG("usr_cnt = %u\n", usr_cnt);

	print_qos_root_info(qos_conf);

	for (i = 0; i < qos_app_stat_cnt; i++)
	{
		uint8_t catid = 0;
		uint16_t appid = 0;
		char *app_name = NULL;
		char *app_cat = NULL;

		app_stat = &qos_app_stat_tbl[i];
		catid = app_stat->catid;
		appid = app_stat->appid;

		DBG("Check1 app %d-%d-%d\n", app_stat->uid, catid, appid);

		if (app_stat->checked)
		{
			continue;
		}

		if (IS_INTERESTED_IN_APP
			&& (catid != qos_args.catid || appid != qos_args.appid))
		{
			continue;
		}

		if (IS_INTERESTED_IN_CAT
			&& (catid != qos_args.catid || appid == 0))
		{
			continue;
		}

		if (!IS_INTERESTED_IN_CAT)
		{
			app_name = search_app_inf(
				&app_inf_head, app_stat->catid, app_stat->appid);
		}

		app_cat = search_app_cat(
			&app_cat_head, app_stat->catid);

		printf("------------------------------------------------------");
		printf("----------------------------------------------------\n");
		printf("cat_id = %u (%s)\n", catid, (app_stat->appid > 0) ? app_cat : "Unknown");
		if (!IS_INTERESTED_IN_CAT)
		{
			printf("app_id = %u (%s)\n", appid, (app_stat->appid > 0) ? app_name : "Unknown");
		}
		printf("\n");

		printf("user%s", (IS_INTERESTED_IN_CAT) ? ",app   " : "       ");
		printf("download info                                         ");
		printf("upload info\n");
		printf("---------  ");
		printf("---------------------------------------------------   ");
		printf("-----------------------------------------\n");
		printf("uid%s", (IS_INTERESTED_IN_CAT) ? ",appid  " : "        ");
		printf("cumu(B),   rate(Bps)(%%),  rsv(kb),   tc_rate, tc_id   ");
#if NO_RSV_UPLOAD_BW
		printf("cumu(B),   rate(Bps)(%%),   tc_rate, tc_id\n");
#else
		printf("cumu(B),   rate(Bps)(%%),  rsv(kb),   tc_rate, tc_id\n");
#endif

		tot_inc_dl_bytes = 0;
		tot_inc_ul_bytes = 0;

		for (j = 0; j < qos_app_stat_cnt; j++)
		{
			app_stat2 = &qos_app_stat_tbl[j];

			if (catid != app_stat2->catid
				|| (!IS_INTERESTED_IN_CAT && appid != app_stat2->appid))
			{
				continue;
			}

			tot_inc_dl_bytes += app_stat2->inc_dl_bytes;
			tot_inc_ul_bytes += app_stat2->inc_ul_bytes;
		}

		for (j = 0; j < qos_app_stat_cnt; j++)
		{
			app_stat2 = &qos_app_stat_tbl[j];

			DBG("Check2 app %d-%d-%d\n", app_stat2->uid, app_stat2->catid, app_stat2->appid);

			if (catid != app_stat2->catid
				|| (!IS_INTERESTED_IN_CAT && appid != app_stat2->appid))
			{
				continue;
			}

			if (1) //(app_stat2->qos_flag)
			{
				double rate_dl_perc = 0;
				double rate_ul_perc = 0;
				uint8_t *dev_mac = NULL;
				char *host_name = NULL;

				for (k = 0; k < usr_cnt; k++)
				{
					if (!usr_lst[k].available)
					{
						break;
					}

					if (usr_lst[k].uid == app_stat2->uid)
					{
						dev_mac = usr_lst[k].mac;
						host_name = usr_lst[k].host_name;
						break;
					}
				}

				if (tot_inc_dl_bytes > 0)
				{
					rate_dl_perc = ((double) app_stat2->inc_dl_bytes / tot_inc_dl_bytes) * 100;
				}

				if (tot_inc_ul_bytes > 0)
				{
					rate_ul_perc = ((double) app_stat2->inc_ul_bytes / tot_inc_ul_bytes) * 100;
				}

				p_id = (app_stat2->qos_flag & APP_QOS_FLAG_P_CLSID_MASK) >> 16;
				c_id = (app_stat2->qos_flag & APP_QOS_FLAG_CLSID_MASK);

				if (IS_INTERESTED_IN_CAT)
				{
					printf("%*u,%-*u%*u,",
						3, app_stat2->uid,
						3, app_stat2->appid,
						11, app_stat2->acc_dl_bytes);
				}
				else
				{
					printf("%*u%*u,",
						3, app_stat2->uid,
						15, app_stat2->acc_dl_bytes);
				}

				printf("%*u(%.2f%%),%*s(%u),%*u,%*u:%-*u%*u,%*u(%.2f%%),%*u,%*u:%-*u",
					12 - numlen(rate_dl_perc, 2), (app_stat2->inc_dl_bytes / intvl),
					rate_dl_perc,
					7 - numlen(app_stat->bndwidth * 8, 0), is_app_qos_flag_rsv(app_stat2->qos_flag) ? "yes" : "no",
					app_stat2->bndwidth * 8,
					10, (app_stat2->tc_dl_cls) ? app_stat2->tc_dl_cls->rate : 0,
					3, p_id,
					3, c_id,
					9, app_stat2->acc_ul_bytes,
					12 - numlen(rate_ul_perc, 2), (app_stat2->inc_ul_bytes / intvl),
					rate_ul_perc,
					10, (app_stat2->tc_ul_cls) ? app_stat2->tc_ul_cls->rate : 0,
					3, p_id,
					3, (c_id == 0) ? c_id : usr_lst[k].uid + 1);

				if (IS_INTERESTED_IN_CAT)
				{
					app_name = search_app_inf(
						&app_inf_head, app_stat2->catid, app_stat2->appid);

					printf(" %s @ %s " MAC_OCTET_FMT "\n",
						(app_name) ? app_name : "Unknown",
						host_name,
						MAC_OCTET_EXPAND(dev_mac));
				}
				else
				{
					printf(" %s " MAC_OCTET_FMT "\n",
						host_name,
						MAC_OCTET_EXPAND(dev_mac));
				}

				app_stat2->checked = 1;
			}
		}
		printf("\n");

		if (IS_INTERESTED_IN_CAT || IS_INTERESTED_IN_APP)
		{
			break;
		}
	}

__ret:
	if (qos_conf)
	{
		free(qos_conf);
	}

	free_app_inf(&app_inf_head);
	free_app_cat(&app_cat_head);

	free_qos_app_stat_list();
	free_qos_tc_cls_list();

	if (usr_lst)
	{
		free(usr_lst);
	}

	return ret;
}

int parse_qos_conf_arg(int argc, char **argv)
{
	return parse_single_str_arg(argc, argv, 'R', file_path, sizeof(file_path));
}

int parse_user_info_arg(int argc, char **argv)
{
	int optret;

	while (-1 != (optret = getopt(argc, argv, "u:i:")))
	{
		switch (optret)
		{
		case 'u':
			if (optarg != NULL)
			{
				qos_args.uid = strtoul(optarg, NULL, 10);
			}
			break;

		case 'i':
			if (optarg != NULL)
			{
				qos_args.intvl = atoi(optarg);
			}
			break;

		default:
			return -1;
		}
	}

	return 0;
}

int parse_app_info_arg(int argc, char **argv)
{
	int optret;

	while (-1 != (optret = getopt(argc, argv, "c:p:i:")))
	{
		switch (optret)
		{
		case 'i':
			if (optarg != NULL)
			{
				qos_args.intvl = atoi(optarg);
			}
			break;
	
		case 'c':
			if (optarg != NULL)
			{
				qos_args.catid = atoi(optarg);
			}
			break;
	
		case 'p':
			if (optarg != NULL)
			{
				qos_args.appid = atoi(optarg);
			}
			break;
	
		default:
			return -1;
		}
	}
	
	return 0;
}

int iqos_options_init(struct cmd_option *cmd)
{
#define HELP_LEN_MAX 1024
	int i = 0, j;
	static char help[HELP_LEN_MAX];
	int len = 0;

	cmd->opts[i].action = ACT_QOS_SET_CONF; 
	cmd->opts[i].name = "set_qos_conf";
	cmd->opts[i].cb = set_qos_conf;
	cmd->opts[i].parse_arg = parse_qos_conf_arg;
	OPTS_IDX_INC(i);
	
	cmd->opts[i].action = ACT_QOS_SET_ON;
	cmd->opts[i].name = "set_qos_on";
	cmd->opts[i].cb = set_qos_on;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_QOS_SET_OFF;
	cmd->opts[i].name = "set_qos_off";
	cmd->opts[i].cb = set_qos_off;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_QOS_GET_USER_INFO;
	cmd->opts[i].name = "get_qos_user_info";
	cmd->opts[i].cb = get_qos_user_info;
	cmd->opts[i].parse_arg = parse_user_info_arg;
	OPTS_IDX_INC(i);

	cmd->opts[i].action = ACT_QOS_GET_APP_INFO;
	cmd->opts[i].name = "get_qos_app_info";
	cmd->opts[i].cb = get_qos_app_info;
	cmd->opts[i].parse_arg = parse_app_info_arg;
	OPTS_IDX_INC(i);

	len += snprintf(help + len, HELP_LEN_MAX - len, "%*s \n",
		HELP_INDENT_L, "");

	for (j = 0; j < i; j++)
	{
		len += snprintf(help + len, HELP_LEN_MAX - len, "%*s %s\n",
			HELP_INDENT_L, (j == 0) ? "iqos actions:" : "",
			cmd->opts[j].name);
	}

	cmd->help = help;

	return 0;
}

