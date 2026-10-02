/*
	AiProtectionMonitor.c
*/

#include <inttypes.h>

#include "bwdpi.h"
#include "bwdpi_sqlite.h"

#define SHIFT_T         130
#define HOST_LEN        64

static void AiProtectionMonitor_savelog(sqlite3 *db, char *sql, const char *log)
{
	int rows;
	int cols;
	char **result;
	int is_first = 1;

	if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
	{
		int i = 0;
		int index = cols;
		for (i = 0; i < rows; i++) {
			char date[30];
			char info[300];

			if (is_first) {
				snprintf(info, sizeof(info),
					"echo \"Event Date           Event type                               Source           Destination \" >> %s", log);
				system(info); // for append log into file, must use system, eval can't do that
				is_first = 0;
			}

			memset(date, 0, sizeof(date));
			StampToDate(atol(result[index]), date);
			snprintf(info, sizeof(info), "echo \"%-20s %-40s %-20s %-s\" >> %s"
				, date, AiProtectionMontior_GetType(result[index+1]), result[index+2], result[index+3], log);
			system(info); // for append log into file, must use system, eval can't do that
			//printf("[%d] %s %s %s %s\n", i, result[index], result[index+1], result[index+2], result[index+3]);
			index += cols;
		}
			sqlite3_free_table(result);
	}
	printf("save log into %s\n", log);
}

static void AiProtectionMonitor_PrintResult(char **result, int rows, int cols)
{
	int i = 0, j = 0;
	int index = cols;

	for (i = 0; i < rows; i++) {
		for (j = 0; j < cols; j++) {
			printf("[%d/%d] result=%s\n", i, j, result[index]);
			++index;
		}
	}
}

static void ProcessRevert(int pid, char *type, char *file_lock, const char *file_pid)
{
	char cmd[64] = {0};

	BWMON_DBG(" pid=%d, type=%s, PID=%s, LOCK=%s\n", pid, type, file_lock, file_pid);
	/* workaround : kill the stuck process and remove file_lock / file_pid and free memory */
	eval("rm", "-rf", file_lock);
	snprintf(cmd, sizeof(cmd), "kill %d", pid);
	system(cmd);
	f_write_string("/proc/sys/vm/drop_caches", "1", 0, 0);
	unlink(file_pid);
	logmessage("BWDPI", "[%s] Revert process and free memory (pid=%d)\n", type, pid);
}

static inline int ProcessGetPidFILE(const char *file_name)
{
	FILE *fp = NULL;
	int result = -1;

	fp = fopen(file_name, "r");
	if (fp == NULL) return -1;
	fscanf(fp, "%d", &result);
	fclose(fp);

	return result;
}

void ProcessCheckPid(char *type)
{
	char *FILE_PID = NULL;
	char *FILE_LOCK = NULL;

	if (!strcmp(type, "BWMON")) {
		FILE_PID = BWMON_PID;
		FILE_LOCK = BWMON_LOCK;
	}
	else if (!strcmp(type, "BWHIS")) {
		FILE_PID = BWHIS_PID;
		FILE_LOCK = BWHIS_LOCK;
	}
	else {
		return;
	}

	int pid = ProcessGetPidFILE(FILE_PID);
	FILE *fp = NULL;

	if (pid == -1 || !f_exists(FILE_PID)) {
		fp = fopen(FILE_PID, "w");
		if (fp == NULL) exit(0);
		pid = getpid();
		fprintf(fp, "%d", pid);
		if (fp) fclose(fp);
		BWMON_DBG("[%s] pid=%d\n", type, pid);
	}
	else {
		ProcessRevert(pid, type, FILE_LOCK, FILE_PID);

		/* create new PID */
		fp = fopen(FILE_PID, "w");
		if (fp == NULL) exit(0);
		pid = getpid();
		fprintf(fp, "%d", pid);
		if (fp) fclose(fp);
		BWMON_DBG("[%s] new pid=%d\n", type, pid);
	}
}

static int AiProctionMonitor_Action(char *action, char *option, char *time, char *type, char *event)
{
	int lock;
	int ret;
	long int size;
	char *zErr;
	char *path = BWDPI_MON_DB;
	sqlite3 *db = NULL;

	if (action == NULL) {
		printf("%s: action = do nothing\n", __FUNCTION__);
		return 0;
	}

	// check and create path and then chmod 666
	if (!f_exists(BWDPI_DB_DIR))
		mkdir(BWDPI_DB_DIR, 0666);

	if (!f_exists(BWDPI_MON_DIR))
		mkdir(BWDPI_MON_DIR, 0666);

	if (!f_exists(path)) {
		eval("touch", path);
		chmod(path, 0666);
	}

	if (IS_IDPFW() == 0 || check_tdts_module_exist() == 0) {
		BWDPI_DBG(" fail to get /dev/idpfw\n");
		return 0;
	}

	/* write process PID and revert */
	ProcessCheckPid("BWMON");

	lock = file_lock("AiProtectionMonitor");
	ret = sqlite3_open(path, &db);
	
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		goto error;
	}

	if (!strcmp(action, "exe"))
	{
		/* if *-journal exists, remove it !! */
		sql_remove_journal(BWDPI_MON_DB);

		/* integrity check */
		if (sql_integrity_check(db, BWDPI_MON_DB) == 0) goto error;

		ret = sqlite3_exec(db,
			"CREATE TABLE monitor("
			"timestamp UNSIGNED BIG INT,"
			"type VARCHAR(2),"
			"mac VARCHAR(18),"
			"src VARCHAR(64),"
			"dst VARCHAR(64),"
			"id VARCHAR(10),"
			"dir VARCHAR(2),"
			"cat_id VARCHAR(4),"
			"severity VARCHAR(2))",
			NULL, NULL, &zErr);

		if (ret != SQLITE_OK) {
			if(zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX timestamp ON monitor(timestamp ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX type ON monitor(type ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX mac ON monitor(mac ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX src ON monitor(src ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX dst ON monitor(dst ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX id ON monitor(id ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX dir ON monitor(dir ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX cat_id ON monitor(cat_id ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		if (sqlite3_exec(db, "CREATE INDEX severity ON monitor(severity ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}
		
		char sql[QUERY_LEN];
		int type, id, final_t = 0;
		int rows;
		int cols;
		char **result;

		// search the last event and find the timestamp (for non-VP)
		snprintf(sql, sizeof(sql)-1, "SELECT timestamp FROM monitor WHERE (type == 1 OR type == 2) ORDER BY timestamp DESC LIMIT 1");
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			AiProtectionMonitor_result(&final_t, result, rows, cols, 1);
			sqlite3_free_table(result);
		}

		/* NOTE: search ban illegal or spam rule id */
		if (sqlite3_exec(db, "DELETE FROM monitor WHERE (id = 1133710 OR id = 1132778 OR id = 1133304)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) sqlite3_free(zErr);
		}

		/* GET non-VP protection event */
		unsigned int e, ioc_buf;
		char *buf;
		udb_url_ioctl_list_t *tbl = NULL;
		ret = get_fw_wrs_url_list((void **) &buf, &ioc_buf);

		if (ret)
			printf("Error: get user!(%d)\n", ret);

		if (buf)
		{
			tbl = (udb_url_ioctl_list_t *) buf;

			for (e = 0; e < tbl->entry_cnt; e++)
			{
				// compare with the final timestamp in database
				if (tbl->entry[e].time < final_t) continue;

				// action : block, if not, continue
				if ((tbl->entry[e].action != 1)) continue;

				/*
					type 1 = C&C
					type 2 = mals
					type 3 = VP

					20170606 : add new id 94, 95 into mals
					94 : scam
					95 : ransomware

					20210705 : change id 2 into mals
					2  : illegal
				*/
				id = tbl->entry[e].cat_id;
				if (id == 91)
					type = 1;
				else if (id == 2 || id == 73 || id == 74 || id == 75 || id == 76 || id == 77 ||
					id == 78 || id == 79 || id == 80 || id == 81 || id == 82 || id == 83 ||
					id == 84 || id == 85 || id == 86 || id == 88 || id == 92 || id == 94 ||
					id == 95)
					type = 2;
				else
					continue;

				/* if database is empty, use wrs_*_t as final_t */
				int cc_t = nvram_get_int("wrs_cc_t");
				if (type == 1 && cc_t > final_t) {
					final_t = cc_t;
					BWMON_DBG("[CC] final_t=%d\n", final_t);
					if (tbl->entry[e].time < final_t) continue;
				}

				int mals_t = nvram_get_int("wrs_mals_t");
				if (type == 2 && mals_t > final_t) {
					final_t = mals_t;
					BWMON_DBG("[MALS] final_t=%d\n", final_t);
					if (tbl->entry[e].time < final_t) continue;
				}

				snprintf(sql, sizeof(sql)-1, "INSERT INTO monitor VALUES ('%" PRIu64 "', '%d', \'"MAC_OCTET_FMT"\', \'"MAC_OCTET_FMT"\', '%s', '%d', '', '', '')",
					tbl->entry[e].time, type, MAC_OCTET_EXPAND(tbl->entry[e].mac), MAC_OCTET_EXPAND(tbl->entry[e].mac), tbl->entry[e].domain, id);

				BWMON_DBG("%s\n", sql);
				BWMON_LOG("%s\n", sql);

				sqlite3_exec(db, sql, NULL, NULL, &zErr);
			}
			free(buf);
		}

		// search the last event and find the timestamp (for VP)
		snprintf(sql, sizeof(sql)-1, "SELECT timestamp FROM monitor WHERE type = 3 ORDER BY timestamp DESC LIMIT 1");
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			AiProtectionMonitor_result(&final_t, result, rows, cols, 1);
			sqlite3_free_table(result);
		}

		/* GET VP protection event */
		if (dump_dpi_support(INDEX_VP)) { // dump_dpi_support(INDEX_VP)
		ret = get_fw_vp_list((void **) &buf, &ioc_buf);

		if (ret)
			printf("Error: get user!(%d)\n", ret);

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

			LIST_HEAD(rule_head);
			init_rule_db(&rule_head);

			for (i = 0; i < entry_cnt; i++)
			{
				/*
					type 1 = C&C
					type 2 = mals
					type 3 = VP
				*/
				type = 3;
				ioc_ent = (udb_vp_ioc_entry_t *) (buf + tbl_used_len);

				/* if database is empty, use wrs_*_t as final_t */
				int vp_t = nvram_get_int("wrs_vp_t");
				if (type == 3 && vp_t > final_t) {
					final_t = vp_t;
					BWMON_DBG("[VP] final_t=%d\n", final_t);
				}

				// compare with the final timestamp in database
				if (ioc_ent->btime < final_t) {
					tbl_used_len += sizeof(udb_vp_ioc_entry_t);
					continue;
				}

				// action : block, if not, continue
				if ((ioc_ent->action != 1)) {
					tbl_used_len += sizeof(udb_vp_ioc_entry_t);
					continue;
				}

				/*
					dir : direction of attack
					0 : attacker
					1 : victim
				*/
				int dir = ioc_ent->role; // tdts module
				int rul_id = ioc_ent->rule_id; // rule id

				char mac_buf[18];
				char mac_orig[18];
				char src_host[HOST_LEN];
				char dst_host[HOST_LEN];
				char *p_host = NULL;

				/* NOTE: ban illegal or spam rule id */
				if (rul_id == 1133710 || rul_id == 1132778 || rul_id == 1133304) {
					tbl_used_len += sizeof(udb_vp_ioc_entry_t);
					continue;
				}

				/* transfer mac into hostname */
				snprintf(mac_buf, sizeof(mac_buf), MAC_OCTET_FMT, MAC_OCTET_EXPAND(ioc_ent->mac));
				snprintf(mac_orig, sizeof(mac_orig), "%s", mac_buf);
				erase_symbol(mac_buf, ":");
				p_host = search_mnt(mac_buf);

				if (4 == ioc_ent->ip_ver)
					snprintf(src_host, sizeof(src_host)-1, IPV4_OCTET_FMT, IPV4_OCTET_EXPAND(ioc_ent->sip));
				else if (6 == ioc_ent->ip_ver)
					snprintf(src_host, sizeof(src_host)-1, IPV6_OCTET_FMT, IPV6_OCTET_EXPAND(ioc_ent->sip));

				if (4 == ioc_ent->ip_ver)
					snprintf(dst_host, sizeof(dst_host)-1, IPV4_OCTET_FMT, IPV4_OCTET_EXPAND(ioc_ent->dip));
				else if (6 == ioc_ent->ip_ver)
					snprintf(dst_host, sizeof(dst_host)-1, IPV6_OCTET_FMT, IPV6_OCTET_EXPAND(ioc_ent->dip));

				if (dir == 0 && p_host != NULL) { // attacker : change src mac into hostname
					snprintf(src_host, sizeof(src_host)-1, "%s", p_host);
				}
				else if (dir == 1 && p_host != NULL) { // victim : change dst mac into hostname
					snprintf(dst_host, sizeof(dst_host)-1, "%s", p_host);
				}

				/* severity message needs TrendMicro support */
				char severity[2];
				unsigned int io_severity = ioc_ent->severity;
				BWMON_DBG("io_severity=%u, ioc->severity=%u\n", io_severity, ioc_ent->severity);
				if (io_severity == 0)
					snprintf(severity, sizeof(severity), "L");
				else if (io_severity == 1 || io_severity == 2)
					snprintf(severity, sizeof(severity), "M");
				else if (io_severity == 4 || io_severity == 5)
					snprintf(severity, sizeof(severity), "H");
				else
					snprintf(severity, sizeof(severity), "M");

				unsigned int cat_id = ioc_ent->cat_id;  // cat id
				BWMON_DBG("mac_buf = %s, p_host = %s, src_host = %s, dst_host = %s, dir = %d, cat_id = %d, severity=%s\n", mac_buf, p_host, src_host, dst_host, dir, cat_id, severity);

				snprintf(sql, sizeof(sql)-1,
					"INSERT INTO monitor VALUES ('%" PRIu64 "', '%d', '%s', '%s', '%s', '%d', '%d', '%u', '%s')",
					ioc_ent->btime, type, mac_orig, src_host, dst_host, ioc_ent->rule_id, dir, cat_id, severity);

				BWMON_DBG("%s\n", sql);
				BWMON_LOG("%s\n", sql);
				sqlite3_exec(db, sql, NULL, NULL, &zErr);
				tbl_used_len += sizeof(udb_vp_ioc_entry_t);
			}
			free(buf);
			free_rule_db(&rule_head);
		}
		} // dump_dpi_support(INDEX_VP)
	}
	else if (!strcmp(action, "get"))
	{
		// do nothing
	}
	else if (!strcmp(action, "count"))
	{
		char sql[QUERY_LEN];
		int rows;
		int cols;
		char **result;
		int cc_n = 0, vp_n = 0, mal_n = 0;
		char *t = NULL;

		/*
			type 1 = C&C
			type 2 = mals
			type 3 = VP
		*/

		// the numbers of CC event
		t = nvram_safe_get("wrs_cc_t");
		if (!strcmp(t, "")) printf("forget to setup wrs_cc_t\n");
		snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = 1 AND timestamp > '%s'", t);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			AiProtectionMonitor_result(&cc_n, result, rows, cols, 0);
			sqlite3_free_table(result);
		}

		// the numbers of Mals event
		t = nvram_safe_get("wrs_mals_t");
		if (!strcmp(t, "")) printf("forget to setup wrs_mals_t\n");
		snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = 2 AND timestamp > '%s'", t);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			AiProtectionMonitor_result(&mal_n, result, rows, cols, 0);
			sqlite3_free_table(result);
		}
		
		// the numbers of VP event
		t = nvram_safe_get("wrs_vp_t");
		if (!strcmp(t, "")) printf("forget to setup wrs_vp_t\n");
		snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = 3 AND timestamp > '%s'", t);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			AiProtectionMonitor_result(&vp_n, result, rows, cols, 0);
			sqlite3_free_table(result);
		}
		printf("cc / mals / vp : %3d, %3d, %3d\n", cc_n , mal_n, vp_n);
	}
	else if (!strcmp(action, "clean"))
	{
		char sql[QUERY_LEN];
		snprintf(sql, sizeof(sql)-1, "DELETE FROM monitor WHERE type = '%s'", time);
		sqlite3_exec(db, sql, NULL, NULL, &zErr);
	}
	else if (!strcmp(action, "size"))
	{
		char sql[QUERY_LEN];
		int rows;
		int cols;
		char **result;
		int tt, checked;

		/* if *-journal exists, remove it !! */
		sql_remove_journal(BWDPI_MON_DB);

		/* integrity check */
		if (sql_integrity_check(db, BWDPI_MON_DB) == 0) goto error;

		if (option == NULL)
			size = 0;
		else
			size = atol(option);

		if (size == 0) goto error;
		if (size < 8) size = 8; // the smallest size : 8KB

		checked = check_filesize_over(BWDPI_MON_DB, size);
		BWMON_DBG("%s, %ld, checked=%d\n", option, size, checked);

		while (checked) {
			// step1. get timestamp
			snprintf(sql, sizeof(sql)-1, "SELECT timestamp FROM monitor ORDER BY timestamp ASC LIMIT 1");
			if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
			{
				AiProtectionMonitor_result(&tt, result, rows, cols, 0);
				sqlite3_free_table(result);
			}
			BWMON_DBG("tt = %d\n", tt);

			tt += DAY_SEC * 5;
			snprintf(sql, sizeof(sql), "DELETE from monitor WHERE timestamp < %d", tt);
			BWMON_DBG("sql = %s\n", sql);

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
			checked = check_filesize_over(BWDPI_MON_DB, size);
		}
	}
	else if (!strcmp(action, "log"))
	{
		long int t;
		char sql[QUERY_LEN];
		int enabled = nvram_get_int("wrs_mail_bit");

		if (time == NULL)
			t = 0;
		else
			t = atol(time);
		BWMON_DBG("%s, %ld\n", time, t);

		if (t == 0) goto error;

		if (enabled & 0x01) { // CC
			snprintf(sql, sizeof(sql)-1,
				"SELECT timestamp, type, src, dst FROM monitor WHERE type=1 AND (timestamp > %ld AND timestamp < %ld) ORDER BY timestamp DESC", t-SHIFT_T, t);
			printf("sql = \"%s\"\n", sql);

			AiProtectionMonitor_savelog(db, sql, BWDPI_MON_CC);
		}

		if (enabled & 0x02) { // VP
			snprintf(sql, sizeof(sql)-1,
				"SELECT timestamp, type, src, dst FROM monitor WHERE type=3 AND (timestamp > %ld AND timestamp < %ld) ORDER BY timestamp DESC", t-SHIFT_T, t);
			printf("sql = \"%s\"\n", sql);

			AiProtectionMonitor_savelog(db, sql, BWDPI_MON_VP);
		}

		if (enabled & 0x04) { // MALS
			snprintf(sql, sizeof(sql)-1,
				"SELECT timestamp, type, src, dst FROM monitor WHERE type=2 AND (timestamp > %ld AND timestamp < %ld) ORDER BY timestamp DESC", t-SHIFT_T, t);
			printf("sql = \"%s\"\n", sql);

			AiProtectionMonitor_savelog(db, sql, BWDPI_MON_MALS);
		}
	}
	else if (!strcmp(action, "backup"))
	{
		// not ready
	}
	else if (!strcmp(action, "hook"))
	{
		int num = 0;
		if (!strcmp(type, "cc")) num = 1;
		else if (!strcmp(type, "mals"))	num = 2;
		else if (!strcmp(type, "vp")) num = 3;

		if (num == 0) {
			printf("No such type in database!\n");
			goto error;
		}

		long int t;
		if (time == NULL)
			t = 0;
		else
			t = atol(time);

		char ips[12];
		if (event == NULL) {
			if (num == 3 && (t > 0))
				snprintf(ips, sizeof(ips)-1, "ips");
			else if ((num == 1 || num == 2) && (t > 0))
				snprintf(ips, sizeof(ips)-1, "non-ips");
			else
				memset(ips, 0, sizeof(ips));
		}
		else {
			snprintf(ips, sizeof(ips)-1, event);
		}

		printf("num=%d, t=%ld, event=%s, ips=%s\n", num, t, event, ips);

		char sql[QUERY_LEN];
		int rows;
		int cols;
		char **result;

		if (!strcmp(ips, "mac")) {
			char *tt = NULL;
			if (num == 1) tt = nvram_safe_get("wrs_cc_t");
			if (num == 2) tt = nvram_safe_get("wrs_mals_t");
			if (num == 3) tt = nvram_safe_get("wrs_vp_t");

			snprintf(sql, sizeof(sql)-1, "SELECT mac, COUNT(*) FROM monitor WHERE type = '%d' AND timestamp > '%s' GROUP BY mac ORDER BY COUNT(*) DESC", num, tt);
			if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
			{
				AiProtectionMonitor_PrintResult(result, rows, cols);
				sqlite3_free_table(result);
			}
		}
		else if (!strcmp(ips, "all") && (num == 1 || num == 2)) {
			snprintf(sql, sizeof(sql)-1, "SELECT timestamp, id, src, dst FROM monitor WHERE type = '%d' ORDER BY timestamp DESC", num);
			if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
			{
				AiProtectionMonitor_PrintResult(result, rows, cols);
				sqlite3_free_table(result);
			}
		}
		else if (!strcmp(ips, "all") && (num == 3)) { // vp
			snprintf(sql, sizeof(sql)-1, "SELECT timestamp, severity, src, dst, id, dir FROM monitor WHERE type = '%d' ORDER BY timestamp DESC", num);
			if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
			{
				AiProtectionMonitor_PrintResult(result, rows, cols);
				sqlite3_free_table(result);
			}
		}
		else if (!strcmp(ips, "ips")) { // vp
			long int date_s, date_l, start;
			date_l = Date_Of_Timestamp(t);
			date_s = date_l- DAY_SEC*6;
			printf("t=%ld, date_l=%ld, date_s=%ld\n", t, date_l, date_s);

			// severity : H
			date_s = date_l- DAY_SEC*6;
			printf("severity : H\n");
			for (start = date_s; start < t; start += DAY_SEC) {
				snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND severity = 'H' AND timestamp > '%ld' AND timestamp < '%ld'",
				num, start, start + DAY_SEC);
				if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
				{
					AiProtectionMonitor_PrintResult(result, rows, cols);
					sqlite3_free_table(result);
				}
			}

			// severity : M
			date_s = date_l- DAY_SEC*6;
			printf("severity : M\n");
			for (start = date_s; start < t; start += DAY_SEC) {
				snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND severity = 'M' AND timestamp > '%ld' AND timestamp < '%ld'",
				num, start, start + DAY_SEC);
				if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
				{
					AiProtectionMonitor_PrintResult(result, rows, cols);
					sqlite3_free_table(result);
				}
			}

			// severity : L
			date_s = date_l- DAY_SEC*6;
			printf("severity : L\n");
			for (start = date_s; start < t; start += DAY_SEC) {
				snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND severity = 'L' AND timestamp > '%ld' AND timestamp < '%ld'",
				num, start, start + DAY_SEC);
				if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
				{
					AiProtectionMonitor_PrintResult(result, rows, cols);
					sqlite3_free_table(result);
				}
			}

		}
		else if (!strcmp(ips, "non-ips")) { // mals and cc
			long int date_s, date_l, start;
			date_l = Date_Of_Timestamp(t);
			date_s = date_l- DAY_SEC*6;
			printf("t=%ld, date_l=%ld, date_s=%ld\n", t, date_l, date_s);

			date_s = date_l- DAY_SEC*6;
			printf("no-severity : mals or cc\n");
			for (start = date_s; start < t; start += DAY_SEC) {
				snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND timestamp > '%ld' AND timestamp < '%ld'",
				num, start, start + DAY_SEC);
				if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
				{
					AiProtectionMonitor_PrintResult(result, rows, cols);
					sqlite3_free_table(result);
				}
			}
		}
		else {
			printf("No such hook query!\n");
		}
	}
	else if(!strcmp(action, "rename"))
	{
		// step1. rename to another table
		if (sqlite3_exec(db, "ALTER TABLE monitor RENAME TO test",  NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("1 - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		// step2. create new one
		ret = sqlite3_exec(db,
			"CREATE TABLE monitor("
			"timestamp UNSIGNED BIG INT,"
			"type VARCHAR(2),"
			"mac VARCHAR(18),"
			"src VARCHAR(64),"
			"dst VARCHAR(64),"
			"id VARCHAR(10),"
			"dir VARCHAR(2),"
			"cat_id VARCHAR(4),"
			"severity VARCHAR(2))",
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
			"INSERT INTO monitor(timestamp, type, mac, src, dst, id, dir, severity) "
			"SELECT timestamp, type, mac, src, dst, id, dir, severity "
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
		if (sqlite3_exec(db, "CREATE INDEX timestamp ON monitor(timestamp ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-1. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX type ON monitor(type ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-2. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX mac ON monitor(mac ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-3. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX src ON monitor(src ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-4. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX dst ON monitor(dst ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-5. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX id ON monitor(id ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-6. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX dir ON monitor(dir ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-7. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX cat_id ON monitor(cat_id ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-8. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}

		if (sqlite3_exec(db, "CREATE INDEX severity ON monitor(severity ASC)", NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("5-9. - SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				goto error;
			}
		}
	}

	unlink(BWMON_PID);
	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
	return 1;

error:
	unlink(BWMON_PID);
	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
	return 0;
}

static void show_help()
{
	printf("Usage :\n");
	printf("  AiProtectionMonitor -e\n");
	printf("  AiProtectionMonitor -g\n");
	printf("  AiProtectionMonitor -c : count\n");
	printf("  AiProtectionMonitor -z -t [type : 1/2/3]: clean\n");
	printf("  AiProtectionMonitor -l -t [timesatmp]: mail log\n");
	printf("  AiProtectionMonitor -s [size], unit: KB\n");
	printf("  AiProtectionMonitor -b : backup\n");
	printf("  AiProtectionMonitor -d [type] -n [event]: hook debug\n");
	printf("  AiProtectionMonitor -r : rename db into new one PCONTROL3\n");
}

int aiprotection_monitor_main(int argc, char **argv)
{
	int c;
	char *action = NULL, *option = NULL, *time = NULL, *type = NULL, *event = NULL;

	if (dump_dpi_support(INDEX_MALS) == 0 && dump_dpi_support(INDEX_VP) == 0 && dump_dpi_support(INDEX_CC) == 0) {
		printf("%s: AiProtection is disabled in software spec.\n", __FUNCTION__);
		return 0;
	}

	if (argc == 1) {
		show_help();
		return 0;
	}

	while ((c = getopt(argc, argv, "egczs:lt:bd:n:r")) != -1)
	{
		switch(c)
		{
			case 'e':
				action = "exe";
				break;
			case 'g':
				action = "get";
				break;
			case 'c':
				action = "count";
				break;
			case 'z':
				action = "clean";
				break;
			case 's':
				action = "size";
				option = optarg;
				break;
			case 'l':
				action = "log";
				break;
			case 't':
				time = optarg;
				break;
			case 'b':
				action = "backup";
				break;
			case 'd':
				action = "hook";
				type = optarg;
				break;
			case 'n':
				event = optarg;
				break;
			case 'r':
				action = "rename";
				break;
			case '?':
				printf("%s: option %c has wrong command\n", __FUNCTION__, optopt);
				return -1;
			default:
				show_help();
				break;
		}
	}

	return AiProctionMonitor_Action(action, option, time, type, event);
}
