/*
	wrs_app.c for apps filter (app patrol)
*/

#include "bwdpi.h"
#include <bcmnvram.h>

char *file_path = NULL;

static void output_app_block(FILE *fp, char *mac, cid_s *ids, int count){
	cid_s *follow_id;

	fprintf(fp, "[%d]\n", count);

	for (follow_id = ids; follow_id != NULL; follow_id = follow_id->next)
		fprintf(fp, "app=%d,0\n", follow_id->id);

	fprintf(fp, "mac=%s,%d\n", mac, count);
}

static void setup_wrs_app_conf(char *path, char *cmd){
	int enabled;
	FILE *fp;
	wrs_s *wrs_list = NULL, *enabled_list = NULL, *follow_wrs;
	mac_g *mac_group;
	mac_s *follow_mac;
	int count = 0; // for profile

	enabled = nvram_get_int("wrs_app_enable");

	// check APP_SET_CONF
	if ((fp = fopen(path, "w")) == NULL) {
		printf("fail to open %s.\n", APP_SET_CONF);
		return;
	}

	if (!enabled)
	{
		// function disabled
		BWDPI_DBG("app patrol disabled.\n");
		fprintf(fp, "\n");
		fclose(fp);
		return;
	}
	else if (!strcmp(cmd, "0"))
	{
		// use command to disable
		BWDPI_DBG("force to disable app patrol.\n");
		fprintf(fp, "\n");
		fclose(fp);
		return;
	}

	get_all_wrs_list(&wrs_list, nvram_safe_get("wrs_app_rulelist"));
	match_enabled_wrs_list(wrs_list, &enabled_list, 1);
	free_wrs_list(&wrs_list);

	for (follow_wrs = enabled_list; follow_wrs != NULL; follow_wrs = follow_wrs->next) {
		if (follow_wrs->enabled == 0)
			continue;
		count++;

		if (follow_wrs->mac[0] == '@') {
			get_group_mac(&mac_group, follow_wrs->mac+1);
			for (follow_mac = mac_group->macs; follow_mac != NULL; follow_mac = follow_mac->next) {
				output_app_block(fp, follow_mac->mac, follow_wrs->ids, count);
			}
		}
		else {
			output_app_block(fp, follow_wrs->mac, follow_wrs->ids, count);
		}

		if (follow_wrs->next != NULL)
			fprintf(fp, "\n");
	}
	free_wrs_list(&enabled_list);

	fclose(fp);
}

static int load_app_patrol_conf(FILE *pf, char *pfile_e, uint32_t all_len, uint32_t *used_len)
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
	int cnt = 0;
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

				printf("pid = %u\n", ioc_pfile_id->pfile_id);
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

					printf("cat = %u, app = %u\n", ioc_app->cat_id, ioc_app->app_id);
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

					printf("mac = "MAC_OCTET_FMT ", pid = %u\n",
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

int wrs_app_main(char *cmd)
{
	FILE *pf;
	uint32_t used_len = 0;
	uint32_t all_len;
	char *pfile_e = NULL;
	int ret = 0;

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return 0;
	}

	if (!is_router_mode())
		return 0;

	file_path = APP_SET_CONF;

	// step1. create app patrol config
	setup_wrs_app_conf(file_path, cmd);

	// setp2. set_app_partol via ioctl
	if ((pf = fopen(file_path, "r")) != NULL)
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

	BWDPI_DBG("app patrol result: %s\n", ret ? "Fail" : "Pass");

	return ret;
}

int wrs_app_service(int cmd){
	char *flag;

	if (cmd == 0)
		flag = "0";
	else
		flag = "1";

	return wrs_app_main(flag);
}
