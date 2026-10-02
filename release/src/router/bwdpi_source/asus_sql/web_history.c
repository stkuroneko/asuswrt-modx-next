/*
	web_history.c
*/

#include "bwdpi.h"
#include "bwdpi_sqlite.h"

static int do_web_history(char *action, char *option, char *_mac, char *_url)
{
	int lock;
	int ret;
	long int size;
	char *zErr;
	char *path = BWDPI_HIS_DB;
	sqlite3 *db = NULL;

	if (action == NULL) {
		printf("%s: action = do nothing\n", __FUNCTION__);
		return 0;
	}

	// create path first and chmod 666
	if (!f_exists(BWDPI_DB_DIR))
		mkdir(BWDPI_DB_DIR, 0666);

	if (!f_exists(BWDPI_HIS_DIR))
		mkdir(BWDPI_HIS_DIR, 0666);

	if (!f_exists(path)) {
		eval("touch", path);
		chmod(path, 0666);
	}

	if (IS_IDPFW() == 0 || check_tdts_module_exist() == 0) {
		BWDPI_DBG(" fail to get /dev/idpfw\n");
		return 0;
	}

	/* write process PID and revert */
	ProcessCheckPid("BWHIS");

	lock = file_lock("web_history");
	ret = sqlite3_open(path, &db);
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		goto error;
	}

	if (!strcmp(action, "exe")) {
		/* if *-journal exists, remove it !! */
		sql_remove_journal(BWDPI_MON_DB);

		/* integrity check */
		if (sql_integrity_check(db, BWDPI_HIS_DB) == 0) goto error;

		ret = sqlite3_exec(db,
			"CREATE TABLE history("
			"mac TEXT,"
			"timestamp UNSIGNED BIG INT,"
			"url TEXT)",
			NULL, NULL, &zErr);

		if (ret != SQLITE_OK) {
			if(zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX mac ON history(mac ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX timestamp ON history(timestamp ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX url ON history(url ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		char sql[QUERY_LEN];
		char mac_addr[18];
		char domain[64];
		unsigned int m, d, buf_pos, ioc_buf;
		char *buf;
		int rows;
		int cols;
		char **result;
		int update_flag = 0;
		long long unsigned int curr_time = 0;
		long long unsigned int start_time = 0;

		ret = 0;
		udb_dn_ioctl_list_t *dmn = NULL;
		udb_dn_ioctl_mac_t *mac = NULL;
		udb_dn_ioctl_entry_t *ent = NULL;

		ret = get_fw_user_domain_list((void **) &buf, &ioc_buf, 1);
		if (ret)
			printf("Error: get user!(%d)\n", ret);
		
		if (buf)
		{
			dmn = (udb_dn_ioctl_list_t *) buf;
			buf_pos = sizeof(udb_dn_ioctl_list_t);
			for (m = 0; m < dmn->mac_cnt; m++)
			{
				mac = (udb_dn_ioctl_mac_t *) (buf + buf_pos);
				memset(mac_addr, 0 , sizeof(mac_addr));
                                snprintf(mac_addr, sizeof(mac_addr), MAC_OCTET_FMT, MAC_OCTET_EXPAND(mac->mac));

				buf_pos += sizeof(udb_dn_ioctl_mac_t);
				for (d = 0; d < mac->domain_cnt; d++)
				{
					ent = &mac->entry[d];
					memset(domain, 0, sizeof(domain));
					snprintf(domain, sizeof(domain)-1, "%s", ent->domain);

					curr_time = ent->time;
					start_time = (long long unsigned int)nvram_get_int("bwdpi_wh_stamp");
					BWSQL_DBG("curr = %llu, start = %llu\n", curr_time, start_time);
					if (curr_time < start_time) continue;

					// step1. query timestamp from mac and url, and set update_flag
					memset(sql, 0, sizeof(sql));
					snprintf(sql, sizeof(sql)-1, "SELECT timestamp FROM history WHERE mac='%s' AND url='%s'", mac_addr, domain);
					if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
					{
						if (rows != 0)
							update_flag = 1;
						else
							update_flag = 0;
						sqlite3_free_table(result);
					}

					// step2. write new data or update old data
					memset(sql, 0, sizeof(sql));
					if (update_flag == 1) {
						snprintf(sql, sizeof(sql)-1,
							"UPDATE history SET timestamp='%" PRIu64 "' WHERE mac='%s' AND url='%s'",
							ent->time, mac_addr, domain
						);
						BWSQL_DBG("old data: %s\n", sql);
					}
					else {
						snprintf(sql, sizeof(sql)-1,
							"INSERT INTO history VALUES ('%s', '%" PRIu64 "', '%s')",
							mac_addr, ent->time, domain
						);
						BWSQL_DBG("new data: %s\n", sql);
					}
					ret = sqlite3_exec(db, sql, NULL, NULL, &zErr);
				}
				buf_pos += (sizeof(udb_dn_ioctl_entry_t) * mac->domain_cnt);
			}
			free(buf);
		}
	}
	else if (!strcmp(action, "get")) {
		int rows;
		int cols;
		char **result;
		char sql[QUERY_LEN];

		memset(sql, 0, sizeof(sql));
		if (_mac == NULL)
			snprintf(sql, sizeof(sql), "SELECT * FROM history ORDER BY timestamp DESC");
		else
			snprintf(sql, sizeof(sql), "SELECT * FROM history WHERE mac='%s' ORDER BY timestamp DESC", _mac);

		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK) {
			int i = 0, j = 0;
			int index = cols;

			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					BWSQL_DBG("[%s : %5d/%5d] %s\n", __FUNCTION__, i, j, result[index]);
					++index;
				}
			}
			sqlite3_free_table(result);
		}
	}
	else if (!strcmp(action, "del")) {
		BWSQL_DBG("  delete history : WebHistory -d -m [mac] -u [url]\n");

		if (_url == NULL) printf("%s : del history need option url\n", __FUNCTION__);

		char sql[QUERY_LEN];
		memset(sql, 0, sizeof(sql));
		if (_mac == NULL)
			snprintf(sql, sizeof(sql), "DELETE from history WHERE url='%s'",  _url);
		else 
			snprintf(sql, sizeof(sql), "DELETE from history WHERE mac='%s' AND url='%s'", _mac, _url);

		if (sqlite3_exec(db, sql,  NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}
	}
	else if (!strcmp(action, "clean")) {
		BWSQL_DBG("  clean  history : WebHistory -z\n");
		if (db != NULL) sqlite3_close(db);
		unlink(BWDPI_HIS_DB);
		file_unlock(lock);
		return 1;
	}
	else if (!strcmp(action, "size")) {
		BWSQL_DBG("%s: check size %s\n", __FUNCTION__, option);

		/* if *-journal exists, remove it !! */
		sql_remove_journal(BWDPI_MON_DB);

		/* integrity check */
		if (sql_integrity_check(db, BWDPI_HIS_DB) == 0) goto error;

		if (option == NULL)
			size = 0;
		else
			size = atol(option);

		if (size == 0) goto error;
		if (size < 8) size = 8; // the smallest size : 8KB

		int count = 0;
		time_t timestamp = get_last_month_timestamp();
		int checked = check_filesize_over(BWDPI_HIS_DB, size);

		while (checked) {
			count++;
			// step1. get timestamp
			if (count > 1) timestamp = timestamp + (DAY_SEC * 5);
			BWSQL_DBG("[%3d] over size %ld, timestamp=%ld\n", count, size, timestamp);

			char sql[QUERY_LEN];
			memset(sql, 0, sizeof(sql));
			snprintf(sql, sizeof(sql), "DELETE from history WHERE timestamp < %ld", timestamp);
			BWSQL_DBG("start to delete some rules from %s because of over size\n", BWDPI_HIS_DB);

			// step2. execute to delete
			if (sqlite3_exec(db, sql,  NULL, NULL, &zErr) != SQLITE_OK) {
				if (zErr != NULL) {
					printf("SQL error: %s\n", zErr);
					sqlite3_free(zErr);
					goto error;
				}
			}

			// step3. compact file
			if (sqlite3_exec(db, "VACUUM;",  NULL, NULL, &zErr) != SQLITE_OK) {
				if (zErr != NULL) {
					printf("SQL error: %s\n", zErr);
					sqlite3_free(zErr);
					goto error;
				}
			}

			// step4. check again
			checked = check_filesize_over(BWDPI_HIS_DB, size);
		}
	}

	unlink(BWHIS_PID);
	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
	return 1;

error:
	unlink(BWHIS_PID);
	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
	return 0;
}

static void show_help()
{
	printf("Usage :\n");
	printf("  write  history : WebHistory -e\n");
	printf("  query  history : WebHistory -g -m [mac]\n");
	printf("  delete history : WebHistory -d -m [mac] -u [url]\n");
	printf("  clean  history : WebHistory -z\n");
	printf("  check  size    : WebHistory -s [size], unit: KB\n");
}

int web_history_main(int argc, char **argv)
{
	int c;
	char *action = NULL, *option = NULL;
	char *mac = NULL, *url = NULL;

	if (dump_dpi_support(INDEX_WEB_HISTORY) == 0) {
		printf("%s: AiProtection is disabled in software spec.\n", __FUNCTION__);
		return 0;
	}

	if (argc == 1) {
		show_help();
		return 0;
	}
	
	while ((c = getopt(argc, argv, "egdzs:m:u:")) != -1)
	{
		switch(c)
		{
			case 'e':
				action = "exe";
				break;
			case 'g':
				action = "get";
				break;
			case 'd':
				action = "del";
				break;
			case 'z':
				action = "clean";
				break;
			case 's':
				action = "size";
				option = optarg;
				break;
			case 'm':
				mac = optarg;
				break;
			case 'u':
				url = optarg;
				break;
			case '?':
				printf("%s: option %c has wrong command\n", __FUNCTION__, optopt);
				return -1;
			default:
				show_help();
				break;
		}
	}

	return do_web_history(action, option, mac, url);
}
