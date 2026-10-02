/*
	traffic_analyzer.c
	for command : bwdpi_sqlite in traffic analyzer
*/
#include <inttypes.h>

#include "bwdpi.h"
#include "bwdpi_sqlite.h"

/*
	integrity check
	Check database integrity : if it's broken, delete this database
*/
int sql_integrity_check(sqlite3 *db, char *db_path)
{
	int ret = 1;
	sqlite3_stmt *integrity;
	int verify = 0;

	int test = sqlite3_prepare_v2(db, "PRAGMA integrity_check;", -1, &integrity, NULL);
	if (test == SQLITE_OK) {
		while (sqlite3_step(integrity) == SQLITE_ROW) {
			const unsigned char *result = sqlite3_column_text(integrity, 0);
			if (result && strcmp((const char *)result, (const char *)"ok") == 0) {
				verify = 1;
				ret = 1;
				break;
			}
		}
		sqlite3_finalize(integrity);

		/* if the result isn't "ok", database is broken, remove this db */
		if (verify == 0) {
			eval("rm", "-f", db_path);
			BWSQL_DBG(" remove broken database : %s\n", db_path);
			ret = 0;
		}

	}
	BWSQL_DBG(" test=%d, ret=%d\n", test, ret);

	return ret;
}

/*
	remove *-journal file
*/
void sql_remove_journal(char *db_file)
{
	char buf[160] = {0};

	snprintf(buf, sizeof(buf), "%s-journal", db_file);
	if (f_exists(buf)) {
		eval("rm", "-f", buf);
		BWSQL_DBG(" remove %s\n", buf);
	}
}

static void get_timestamp(char *timestamp, int len)
{
	time_t now;
	time(&now);
	snprintf(timestamp, len, "%lu", now);
}

static int table_main(char *select, char *action, char *path, char *group, char *having, char *full)
{
	int lock; // file lock
	int ret;
	unsigned int i, j, rec_max, rec_max2;
	unsigned long app_count = 0;
	udb_ioctl_entry_t *usr_lst = NULL;
	app_bw_ioctl_entry_t *app_lst = NULL;
	uint32_t usr_buf_len = 0, buf_len = 0;
	char cat_name[64];
	char app_name[64];
	char mac[18];
	char *zErr;
	char *db_path = BWDPI_ANA_DB;
	sqlite3 *db = NULL;

	if (action == NULL) {
		printf("%s: action = do nothing\n", __FUNCTION__);
		return 0;
	}

	memset(cat_name, 0 , sizeof(cat_name));
	memset(app_name, 0 , sizeof(app_name));

	// create path first and chmod 666
	if (!f_exists(BWDPI_DB_DIR))
		mkdir(BWDPI_DB_DIR, 0666);

	if (!f_exists(BWDPI_ANA_DIR))
		mkdir(BWDPI_ANA_DIR, 0666);

	if (!f_exists(BWDPI_ANA_DB)) {
		eval("touch", BWDPI_ANA_DB);
		chmod(db_path, 0666);
	}

	if (IS_IDPFW() == 0 || check_tdts_module_exist() == 0) {
		BWDPI_DBG(" fail to get /dev/idpfw\n");
		return 0;
	}

	lock = file_lock("TrafficAnalyzer");
	ret = sqlite3_open(db_path, &db);
	
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		goto error;
	}

	if (!strcmp(action, "exe"))
	{// ACTION = sqlite3_exec

		/* if *-journal exists, remove it !! */
		sql_remove_journal(BWDPI_ANA_DB);

		/* integrity check */
		if (sql_integrity_check(db, BWDPI_ANA_DB) == 0) goto error;

		ret = sqlite3_exec(db,
			"CREATE TABLE traffic("
			"mac TEXT,"
			"app_name VARCHAR(50),"
			"cat_name VARCHAR(50),"
			"timestamp UNSIGNED BIG INT,"
			"tx UNSIGNED BIG INT,"
			"rx UNSIGNED BIG INT)",
			NULL, NULL, &zErr);

		if (ret != SQLITE_OK) {
			if(zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX mac ON traffic(mac ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX app_name ON traffic(app_name ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX cat_name ON traffic(cat_name ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX timestamp ON traffic(timestamp ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		LIST_HEAD(app_inf_head);
		LIST_HEAD(app_cat_head);

		ret = get_fw_user_list(&usr_lst, &usr_buf_len);
		if (ret || !usr_lst) printf("Error: get user!(%d)\n", ret);

		ret = get_fw_app_bw_clear(&app_lst, &buf_len);
		if (ret) printf("Error: get app!(%d)\n", ret);

		init_app_inf(&app_inf_head);
		init_app_cat(&app_cat_head);

		if (usr_lst)
		{//LIST
			rec_max = DEVID_MAX_USER;
			rec_max2 = DEVID_APP_RATE_TABLE_POOL_SIZE;
	
			// each device
			for (i = 0; i < rec_max; i++)
			{// LOOP1
				if (usr_lst[i].available <= 0) break;
			
				memset(mac, 0 , sizeof(mac));
				snprintf(mac, sizeof(mac), MAC_OCTET_FMT, MAC_OCTET_EXPAND(usr_lst[i].mac));
				app_count = 0;

				for (j = 0; j < rec_max2; j++)
				{// LOOP2
					if (app_lst[j].available <= 0) break;
					if (usr_lst[i].uid == app_lst[j].uid)
					{// ID
						if (app_lst[j].cat_id == 0 && app_lst[j].app_id == 0)
						{
							strlcpy(cat_name , "General", sizeof(cat_name));
							strlcpy(app_name , "General", sizeof(app_name));
						}
						else
						{
							char *cat = search_app_cat(&app_cat_head, app_lst[j].cat_id);
							char *inf = search_app_inf(&app_inf_head, app_lst[j].cat_id, app_lst[j].app_id);
							if (cat == NULL)
								strlcpy(cat_name , "General", sizeof(cat_name));
							else
								strlcpy(cat_name , cat, sizeof(cat_name));

							if (inf == NULL)
								strlcpy(app_name , "General", sizeof(app_name));
							else
								strlcpy(app_name , inf, sizeof(app_name));
						}

						char sql[QUERY_LEN];
						char timestamp[16];
						memset(sql, 0, sizeof(sql));
						memset(timestamp, 0, sizeof(timestamp));

						get_timestamp(timestamp, sizeof(timestamp));
						snprintf(sql, sizeof(sql),
							"INSERT INTO traffic VALUES ('%s', '%s', '%s', '%s', '%" PRIu64 "', '%" PRIu64 "')",
							mac, app_name, cat_name, timestamp, app_lst[j].up_recent, app_lst[j].down_recent);
						BWSQL_LOG("%d/%d[%s] %s", i, j, mac, sql);
						ret = sqlite3_exec(db, sql, NULL, NULL, &zErr);
						if (zErr != NULL) sqlite3_free(zErr);
						app_count++;
					}//ID
				}// LOOP2
			}// LOOP1
		}//LIST

		free_app_inf(&app_inf_head);
		free_app_cat(&app_cat_head);

		if (app_lst) free(app_lst);
		if (usr_lst) free(usr_lst);
	}
	else if (!strcmp(action, "get"))
	{ // ACTION = get_table
		int rows;
		int cols;
		char **result;
		char sql_query[QUERY_LEN];

		memset(sql_query, 0, sizeof(sql_query));

		if (select == NULL) {
			printf("[sqlite] fail to get input of \"select\"!\n");
			goto error;
		}
		else {
			if (group == NULL && having == NULL)
				snprintf(sql_query, sizeof(sql_query), "SELECT %s FROM traffic", select);
			else if (group == NULL && having != NULL)
				snprintf(sql_query, sizeof(sql_query), "SELECT %s FROM traffic GROUP BY %s", select, group);
			else if (group != NULL && having != NULL)
				snprintf(sql_query, sizeof(sql_query), "SELECT %s FROM traffic GROUP BY %s HAVING %s", select, group, having);
			else {
				printf("[sqlite] having can't use alone!\n");
				goto error;
			}
		}

		BWSQL_LOG("sql_query = %s", sql_query);

		if (sql_get_table(db, sql_query, &result, &rows, &cols) == SQLITE_OK) {
			BWSQL_LOG("rows=%d, cols=%d", rows, cols);
			int i = 0, j = 0;
			int index = cols;
			long long int tx = 0, rx = 0;

			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					if (j == 3) tx += atoll(result[index]);
					if (j == 4) rx += atoll(result[index]);
					BWSQL_LOG("[%7d/%7d] result: %16llu / %16llu", i, j, tx, rx);
					++index;
				}
			}
			sqlite3_free_table(result);
		}
	}
	else if (!strcmp(action, "test"))
	{ // ACTION = test

		// add protection to decrease sql_injection issue
		if(!nvram_match("sqlite_full", "1")) {
			printf("%s : you can't use full test mode!!\n", __FUNCTION__);
			goto error;
		}

		int rows;
		int cols;
		char **result;
		char sql_query[QUERY_LEN];

		memset(sql_query, 0, sizeof(sql_query));
		snprintf(sql_query, sizeof(sql_query), "%s", full);
		
		if (sql_get_table(db, sql_query, &result, &rows, &cols) == SQLITE_OK) {
			int i = 0, j = 0;
			int index = cols;

			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					printf("[%7d/%7d] result: %s / %s\n", i, j, result[j], result[index]);
					++index;
				}
			}
			sqlite3_free_table(result);
		}
	}
	else if(!strcmp(action, "rename"))
	{ // ACTION = rename
		// step1. rename to another table
		if (sqlite3_exec(db, "ALTER TABLE traffic RENAME TO test",  NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("1 - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		// step2. create new one
		ret = sqlite3_exec(db,
			"CREATE TABLE traffic("
			"mac TEXT,"
			"app_name VARCHAR(50),"
			"cat_name VARCHAR(50),"
			"timestamp UNSIGNED BIG INT,"
			"tx UNSIGNED BIG INT,"
			"rx UNSIGNED BIG INT)",
			NULL, NULL, &zErr);

		if (ret != SQLITE_OK) {
			if (zErr != NULL) {
				printf("2 - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		// step3. insert old table data into new one
		ret = sqlite3_exec(db,
			"INSERT INTO traffic(mac, app_name, cat_name, timestamp, tx, rx) "
			"SELECT mac, app_name, cat_name, timestamp, tx, rx "
			"FROM test",
			NULL, NULL, &zErr);

		if (ret != SQLITE_OK) {
			if (zErr != NULL) {
				printf("3 - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		// step4. drop old table
		if (sqlite3_exec(db, "DROP TABLE test", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("4. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		// step5. add index
		if (sqlite3_exec(db, "CREATE INDEX mac ON traffic(mac ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-1. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX app_name ON traffic(app_name ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-2. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX cat_name ON traffic(cat_name ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-3. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX timestamp ON traffic(timestamp ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-4. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}
	}
	else if (!strcmp(action, "size"))
	{ // ACTION = size
		long int size = 0;
		int count = 0;
		time_t timestamp = get_last_month_timestamp();
		int checked;

		/* if *-journal exists, remove it !! */
		sql_remove_journal(BWDPI_ANA_DB);

		/* integrity check */
		if (sql_integrity_check(db, BWDPI_ANA_DB) == 0) goto error;

		if (having == NULL)
			size = 0;
		else
			size = atol(having);

		if (size == 0) goto error;
		if (size < 8) size = 8; // the smallest size : 8KB
		checked = check_filesize_over(BWDPI_ANA_DB, size);
		BWSQL_DBG("%s, %ld, checked=%d\n", having, size, checked);

		while (checked) {
			count++;
			// step1. get timestamp
			if (count > 1) timestamp = timestamp + (DAY_SEC * 5);
			printf("%s-%d: over size %ld, timestamp=%ld\n", __FUNCTION__, count, size, timestamp);

			char sql[QUERY_LEN];
			memset(sql, 0, sizeof(sql));
			snprintf(sql, sizeof(sql), "DELETE from traffic WHERE timestamp < %ld", timestamp);
			printf("start to delete some rules from %s because of over size\n", BWDPI_ANA_DB);

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
			checked = check_filesize_over(BWDPI_ANA_DB, size);
		}
	}

	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
	return 1;

error:
	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
	return 0;
}

static void show_help()
{
	printf("Usage :\n");
	printf("  bwdpi_sqlite -s [select] -g [get_table] -e [exec] -p [path] -a [group] -b [having] -t [test mode] -r [rename]\n");
	printf("  ex:\n");
	printf("  save data            : bwdpi_sqlite -e\n");
	printf("  get  data            : bwdpi_sqlite -s [select] -g [get_table] -p [path] -a [group] -b [having]\n");
	printf("  test mode when query : bwdpi_sqlite -t [query string]\n");
	printf("  rename database      : bwdpi_sqlite -r\n");
	printf("  database limit       : bwdpi_sqlite -d [file size: KB]\n");
}

int traffic_analyzer_main(int argc, char **argv)
{
	int c;
	char *select = NULL, *action = NULL, *path = NULL, *group = NULL, *having = NULL, *full = NULL;

	if (dump_dpi_support(INDEX_TRAFFIC_ANALYZER) == 0) {
		printf("%s: Traffic analyzer is disabled in software spec.\n", __FUNCTION__);
		return 0;
	}

	if (argc == 1) {
		show_help();
		return 0;
	}

	while ((c = getopt(argc, argv, "s:p:get:ha:b:rd:")) != -1)
	{
		switch(c)
		{
			case 's':
				select = optarg;
				break;
			case 'g':
				action = "get";
				break;
			case 'e':
				action = "exe";
				break;
			case 't':
				action = "test";
				full = optarg;
				break;
			case 'p':
				path = optarg;
				break;
			case 'h':
				show_help();
				break;
			case 'a':
				group = optarg;
				break;
			case 'b':
				having = optarg;
				break;
			case 'r':
				action = "rename";
				break;
			case 'd':
				action = "size";
				having = optarg;
				break;
			case '?':
				printf("%s: option %c has wrong command\n", __FUNCTION__, optopt);
				return -1;
			default:
				show_help();
				break;
		}
	}

	return table_main(select, action, path, group, having, full);
}
