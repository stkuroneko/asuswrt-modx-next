/*
	sqlite_stat.c
*/

#include "bwdpi.h"
#include "bwdpi_sqlite.h"

#define MAX_SIZE 1024
#define ID_FILE  "/tmp/bwdpi/bwdpi.rule.db"
#define ID_SIZE  512

/*
	find today's timestamp
	ex.
	timestamp -> YYYY-MM-DD 00:00:00 -> timestamp
	now    : 1472021966
	date   : 2016-08-24 14:59:26 +8:00
	date   : 2016-08-24 00:00:00 +8:00
	t_t    : 1471968000
*/
time_t Date_Of_Timestamp(time_t now)
{
	struct tm local, t;
	time_t t_t = 0;
	
	// get timestamp and tm
	localtime_r(&now, &local);

	// copy t from local
	t.tm_year = local.tm_year;
	t.tm_mon = local.tm_mon;
	t.tm_mday = local.tm_mday;
	t.tm_hour = 0;
	t.tm_min = 0;
	t.tm_sec = 0;

	// transfer tm to timestamp
	t_t = mktime(&t);

	return t_t;
}

char *AiProtectionMontior_GetType(char *c)
{
	if (!strcmp(c, "1"))
		return "Infected Device Prevention and Blocking";
	else if (!strcmp(c, "2"))
		return  "Malicious Sites Blocking";
	else if (!strcmp(c, "3"))
		return  "Vulnerability Protection";
	else 
		return NULL;
}

void AiProtectionMonitor_result(int *tmp, char **result, int rows, int cols, int shift)
{
	// normal  usage : shift = 0
	// final_t usage : shift = 1
	int i = 0, j = 0;
	int index = cols;

	for (i = 0; i < rows; i++) {
		for (j = 0; j < cols; j++) {
			*tmp = safe_atoi(result[1]) + shift;
			BWMON_LOG("%d\n", *tmp);
			++index;
		}
	}
}

int sql_get_table(sqlite3 *db, const char *sql, char ***pazResult, int *pnRow, int *pnColumn)
{
	int ret;
	char *errMsg = NULL;
	
	ret = sqlite3_get_table(db, sql, pazResult, pnRow, pnColumn, &errMsg);
	if (ret != SQLITE_OK)
	{
		if (errMsg) sqlite3_free(errMsg);
	}

	return ret;
}

/* ---- Get client list (mac) from DB START ---- */
void bwdpi_maclist_db(char *type, int *retval, webs_t wp)
{
	int ret;
	char *path = NULL;
	char *table = NULL;
	sqlite3 *db = NULL;

	if (!strcmp(type, "TrafficAnalyzer")) {
		path  = BWDPI_ANA_DB;
		table = "traffic";
	}
	else if (!strcmp(type, "WebHistory")) {
		path = BWDPI_HIS_DB;
		table = "history";
	}
	else if (!strcmp(type, "AiProtectionMonitor")) {
		path = BWDPI_MON_DB;
		table = "monitor";
	}
	else {
		goto error;
	}

	ret = sqlite3_open(path, &db);
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		goto error;
	}

	char sql[QUERY_LEN] = {0};
	int rows;
	int cols;
	char **result;
	int is_first;

	*retval += websWrite(wp, "[");

	*retval += websWrite(wp, "[");
	snprintf(sql, sizeof(sql), "SELECT DISTINCT mac FROM %s ORDER BY mac ASC", table);
	//BWSQL_LOG("sql=%s, path=%s, table=%s\n",sql, path, table);

	if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
	{
		BWSQL_LOG("rows=%d, cols=%d", rows, cols);
		int i = 0;
		int j = 0;
		int index = cols;
		is_first = 1;

		for (i = 0; i < rows; i++) {
			for (j = 0; j < cols; j++) {
				BWSQL_LOG("[%d/%d] result: %s/%s", i, j, result[j], result[index]);
				if (is_first) {
					*retval += websWrite(wp, "\"%s\"", result[index]);
					is_first = 0;
				}
				else {
					*retval += websWrite(wp, ", \"%s\"", result[index]);
				}
				++index;
			}
		}
		sqlite3_free_table(result);
	}
	*retval += websWrite(wp, "]");

	*retval += websWrite(wp, "]");
	if (db != NULL) sqlite3_close(db);
	return;

error:
	if (db != NULL) sqlite3_close(db);
	*retval += websWrite(wp, "[");
	*retval += websWrite(wp, "]");
	return;

}
/* ---- Get client list (mac) from DB END   ---- */

/* ---- Traffic Analyzer START ---- */
void bwdpi_appStat(char *buff, char *group, char *where, char *having, int len)
{
	int lock; // file lock
	int ret;
	char *db_path = NULL;
	sqlite3 *db = NULL;
	int rows;
	int cols;
	long long int tx = 0, rx = 0;
	int first_row = 1;
	char **result;
	char sql_query[QUERY_LEN];
	char select[48];
	char mac[18];
	char app_name[40];
	char buff_t[LEN_MAX];

	memset(select, 0, sizeof(select));
	memset(sql_query, 0, sizeof(sql_query));
	memset(mac, 0, sizeof(mac));
	memset(app_name, 0, sizeof(app_name));
	memset(buff_t, 0, sizeof(buff_t));

	db_path = BWDPI_ANA_DB;

	lock = file_lock("TrafficAnalyzer");
	ret = sqlite3_open(db_path, &db);

	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		if (db != NULL) sqlite3_close(db);
		file_unlock(lock);
		return;
	}

	// initial SELECT string
	snprintf(select, sizeof(select), "mac, app_name, timestamp, SUM(tx), SUM(rx)");

	// append WHERE / GROUP / HAVING string into query string
	if (group != NULL) {
		if (having == NULL && !strcmp(where, ""))
			snprintf(sql_query, sizeof(sql_query), "SELECT %s FROM traffic GROUP BY %s", select, group);
		else if (having != NULL && !strcmp(where, ""))
			snprintf(sql_query, sizeof(sql_query), "SELECT %s FROM %s GROUP BY %s", select, having, group);
		else if (having != NULL && strcmp(where, ""))
			snprintf(sql_query, sizeof(sql_query), "SELECT %s FROM %s WHERE %s GROUP BY %s", select, having, where, group);
	}
	else {
		if (db != NULL) sqlite3_close(db);
		file_unlock(lock);
		return;
	}
	
	BWSQL_LOG("sql_query = %s", sql_query);

	if (sql_get_table(db, sql_query, &result, &rows, &cols) == SQLITE_OK)
	{
		BWSQL_LOG("rows=%d, cols=%d", rows, cols);
		int i = 0;
		int j = 0;
		int index = cols;

		if (!strcmp(group, "timestamp"))
		{
			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					BWSQL_LOG("[%d/%d] result: %s/%s", i, j, result[j], result[index]);
					if (j == 3) tx += atoll(result[index]);
					if (j == 4) rx += atoll(result[index]);
					++index;
				}
			}
			snprintf(buff, len, "[%llu, %llu]", tx, rx);
		}
		else if (!strcmp(group, "mac"))
		{
			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					BWSQL_LOG("[%d/%d] result: %s/%s", i, j, result[j], result[index]);
					if (j == 0) strlcpy(mac, result[index], sizeof(mac));
					if (j == 3) tx = atoll(result[index]);
					if (j == 4) rx = atoll(result[index]);
					++index;
				}

				if (first_row) {
					first_row = 0;
					snprintf(buff, len, "[\"%s\", %llu, %llu]", mac, tx, rx);
				}
				else {
					snprintf(buff_t, len, "%s", buff);
					snprintf(buff, len, "%s, [\"%s\", %llu, %llu]", buff_t, mac, tx, rx);
				}
				BWSQL_LOG("[sqlite] buff = %s", buff);
			}
		}
		else if(!strcmp(group, "app_name"))
		{
			for (i = 0; i < rows; i++) {
				for (j = 0; j < cols; j++) {
					BWSQL_LOG("[%d/%d] result: %s/%s", i, j, result[j], result[index]);
					if (j == 1) strlcpy(app_name, result[index], sizeof(app_name));
					if (j == 3) tx = atoll(result[index]);
					if (j == 4) rx = atoll(result[index]);
					++index;
				}

				if(first_row) {
					first_row = 0;
					snprintf(buff, len, "[\"%s\", %llu, %llu]", app_name, tx, rx);
				}
				else {
					snprintf(buff_t, len, "%s", buff);
					snprintf(buff, len, "%s, [\"%s\", %llu, %llu]", buff_t, app_name, tx, rx);
				}
				BWSQL_LOG("[sqlite] buff = %s", buff);
			}
		}

		BWSQL_LOG("[sqlite] buff = %s", buff);
		
		sqlite3_free_table(result);
	}
	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
}

/*
	type : 
		0 : app, 1 : mac
	client :
		all , macaddr=XX:XX:XX:XX:XX:XX, app_name=XXXX
	mode :
		day , hour , detail
	dura :
		7 / 24 / 31
	date :
		timestamp
*/
void sqlite_Stat_hook(int type, char *client, char *mode, char *dura, char *date, int *retval, webs_t wp)
{
	int date_min = 0, date_max = 0, date_init = 0;
	int i = 0;
	int first_row = 1;
	char group[64];
	char having[256];
	char where[64];
	char buff[LEN_MAX]; //group =  mac / app_name, maybe buff isn't enough, keep observing...
	int dura_int = 0;

	//BWSQL_LOG("type=%d, client=%s, mode=%s, dura=%s, date=%s", type, client, mode, dura, date);

	date_init = safe_atoi(date) + 30; // allow 30 secs delay to collect right data in time interval
	memset(group, 0, sizeof(group));
	memset(having, 0, sizeof(having));
	memset(where, 0, sizeof(where));
	memset(buff, 0, sizeof(buff));
	
	// client = all, mode != detail, type = 0 or 1
	if (!strcmp(client, "all") && strcmp(mode, "detail"))
	{
		snprintf(group, sizeof(group), "timestamp");
	}
	// client = all, mode = detail, type = 0
	else if (!strcmp(client, "all") && !strcmp(mode, "detail") && type == 0)
	{
		snprintf(group, sizeof(group), "mac");
	}
	// client = all, mode = detail, type = 1
	else if (!strcmp(client, "all") && !strcmp(mode, "detail") && type == 1)
	{
		snprintf(group, sizeof(group), "app_name");
	}
	// client != all, mode != detail, type = 0
	else if (strcmp(client, "all") && strcmp(mode, "detail") && type == 0)
	{
		snprintf(group, sizeof(group), "timestamp");
		snprintf(where, sizeof(where), "app_name=\"%s\"", client);
	}
	// client != all, mode != detail, type = 1
	else if (strcmp(client, "all") && strcmp(mode, "detail") && type == 1)
	{
		snprintf(group, sizeof(group), "timestamp");
		snprintf(where, sizeof(where), "mac=\"%s\"", client);
	}
	// client != all, mode != detail, type = 2
	else if (strcmp(client, "all") && strcmp(mode, "detail") && type == 2)
	{
		snprintf(group, sizeof(group), "app_name");
		snprintf(where, sizeof(where), "mac=\"%s\"", client);
	}
	// client != all, mode = detail, type = 0
	else if (strcmp(client, "all") && !strcmp(mode, "detail") && type == 0)
	{
		snprintf(group, sizeof(group), "mac");
		snprintf(where, sizeof(where), "app_name=\"%s\"", client);
	}
	// client != all, mode = detail, type = 1
	else if (strcmp(client, "all") && !strcmp(mode, "detail") && type == 1)
	{
		snprintf(group, sizeof(group), "app_name");
		snprintf(where, sizeof(where), "mac=\"%s\"", client);
	}
	else {
		printf("[sqlite] no such case!\n");
	}

	if (!strcmp(mode, "hour") && !strcmp(dura, "24"))
	{// day
		*retval += websWrite(wp, "[");
		for (i = 0; i < 24; i++) {
			memset(buff, 0, sizeof(buff));
			date_min = date_init - HOURSEC * (24 -i);
			date_max = date_init - HOURSEC * (23 -i);
			snprintf(having, sizeof(having), "(SELECT * FROM traffic WHERE timestamp BETWEEN '%d' AND '%d')", date_min, date_max);
			bwdpi_appStat(buff, group, where, having, sizeof(buff));
			if (first_row) {
				first_row = 0;
				*retval += websWrite(wp, buff);
			}
			else
				*retval += websWrite(wp, ", %s", buff);
				
		}
		*retval += websWrite(wp, "]");
	}
	else if (!strcmp(mode, "hour") && type == 2)
	{// 8 hours
		dura_int = atoi(dura);
		if (dura_int < 0 || dura_int >8)
			dura_int = 1;

		*retval += websWrite(wp, "[");
		for (i = 0; i < dura_int; i++) {
			memset(buff, 0, sizeof(buff));
			date_min = date_init - HOURSEC * (dura_int -i);
			date_max = date_init - HOURSEC * ((dura_int -1)-i);
			snprintf(having, sizeof(having), "(SELECT * FROM traffic WHERE timestamp BETWEEN '%d' AND '%d')", date_min, date_max);
			bwdpi_appStat(buff, group, where, having, sizeof(buff));
			if (first_row) {
				first_row = 0;
				*retval += websWrite(wp, "[%s]", buff);
			}
			else
				*retval += websWrite(wp, ", [%s]", buff);
		}
		*retval += websWrite(wp, "]");
	}
	else if (!strcmp(mode, "day") && !strcmp(dura, "7"))
	{// week
		*retval += websWrite(wp, "[");
		for (i = 0; i < 7; i++) {
			memset(buff, 0, sizeof(buff));
			date_min = date_init - DAY_SEC * (7 - i);
			date_max = date_init - DAY_SEC * (6 - i);
			snprintf(having, sizeof(having), "(SELECT * FROM traffic WHERE timestamp BETWEEN '%d' AND '%d')", date_min, date_max);
			bwdpi_appStat(buff, group, where, having, sizeof(buff));
			if (first_row) {
				first_row = 0;
				*retval += websWrite(wp, buff);
			}
			else
				*retval += websWrite(wp, ", %s", buff);
				
		}
		*retval += websWrite(wp, "]");
	}
	else if (!strcmp(mode, "day") && !strcmp(dura, "31"))
	{// month
		*retval += websWrite(wp, "[");
		for (i = 0; i < 31; i++) {
			memset(buff, 0, sizeof(buff));
			date_min = date_init - DAY_SEC * (31 - i);
			date_max = date_init - DAY_SEC * (30 - i);
			snprintf(having, sizeof(having), "(SELECT * FROM traffic WHERE timestamp BETWEEN '%d' AND '%d')", date_min, date_max);
			bwdpi_appStat(buff, group, where, having, sizeof(buff));
			if (first_row) {
				first_row = 0;
				*retval += websWrite(wp, buff);
			}
			else
				*retval += websWrite(wp, ", %s", buff);
				
		}
		*retval += websWrite(wp, "]");
	}
	else if (!strcmp(mode, "detail") && !strcmp(dura, "24"))
	{// detail for daily
		*retval += websWrite(wp, "[");
		date_min = date_init - DAY_SEC;
		date_max = date_init;
		snprintf(having, sizeof(having), "(SELECT * FROM traffic WHERE timestamp BETWEEN '%d' AND '%d')", date_min, date_max);
		bwdpi_appStat(buff, group, where, having, sizeof(buff));
		*retval += websWrite(wp, buff);
		*retval += websWrite(wp, "]");
	}
	else if (!strcmp(mode, "detail") && !strcmp(dura, "7"))
	{// detail for weekly
		*retval += websWrite(wp, "[");
		date_min = date_init - DAY_SEC * 7;
		date_max = date_init;
		snprintf(having, sizeof(having), "(SELECT * FROM traffic WHERE timestamp BETWEEN '%d' AND '%d')", date_min, date_max);
		bwdpi_appStat(buff, group, where, having, sizeof(buff));
		*retval += websWrite(wp, buff);
		*retval += websWrite(wp, "]");
	}
	else if (!strcmp(mode, "detail") && !strcmp(dura, "31"))
	{// detail for monthly
		*retval += websWrite(wp, "[");
		date_min = date_init - MON_SEC;
		date_max = date_init;
		snprintf(having, sizeof(having), "(SELECT * FROM traffic WHERE timestamp BETWEEN '%d' AND '%d')", date_min, date_max);
		bwdpi_appStat(buff, group, where, having, sizeof(buff));
		*retval += websWrite(wp, buff);
		*retval += websWrite(wp, "]");
	}
}
/* ---- Traffic Analyzer END ---- */

/* ---- Web History    START ---- */
void bwdpi_HistoryStat(char *buff, char *_mac, int p, int num, int len)
{
	int lock;
	int first_row = 1;
	int rows;
	int cols;
	char **result;
	char sql[QUERY_LEN];
	char tmp[160];
	char buff_t[LEN_MAX];
	char *path = BWDPI_HIS_DB;
	sqlite3 *db = NULL;
	int ret = 0;

	//BWSQL_LOG("mac=%s, p=%d, num=%d", _mac, p, num);

	memset(sql, 0, sizeof(sql));
	memset(buff_t, 0, sizeof(buff_t));

	lock = file_lock("web_history");
	ret = sqlite3_open(path, &db);
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		if (db != NULL) sqlite3_close(db);
		file_unlock(lock);
		return;
	}

	if (!strcmp(_mac, "all"))
		snprintf(sql, sizeof(sql), "SELECT * FROM history ORDER BY timestamp DESC");
	else
		snprintf(sql, sizeof(sql), "SELECT * FROM history WHERE mac='%s' ORDER BY timestamp DESC", _mac);

	if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK) {
		BWSQL_LOG("rows=%d, cols=%d", rows, cols);
		int i = 0, j = 0;
		int index = 0;
		int C_MIN = 0, C_MAX = 0;

		// search data between (p-1)*num ~ (p*num-1)
		// ex. p = 2, num = 50, get data 50~99
		// ex. p = 3, num = 30, get data 60~89

		if (p == 0) {
			C_MIN = 0;
			C_MAX = rows;
			index = cols;
		}
		else if (p > 0) {
			C_MIN = (p-1) * num;
			C_MAX = p * num;
			index = 3 * C_MIN + cols;
		}

		BWSQL_LOG("C_MIX=%d, C_MAX=%d, index=%d", C_MIN, C_MAX, index);

		if (C_MAX > rows)
			C_MAX = rows;

		for (i = C_MIN; i < C_MAX; i++)
		{
			// reset tmp
			memset(tmp, 0, sizeof(tmp));

			for (j = 0; j < cols; j++)
			{
				if (first_row && j == 0)
				{
					first_row = 0;
					snprintf(tmp, sizeof(tmp)-1, "[\"%s\"", result[index]);
				}
				else if (!first_row && j == 0)
				{
					snprintf(buff_t, sizeof(buff_t), "%s", tmp);
					snprintf(tmp, sizeof(tmp)-1, "%s, [\"%s\"", buff_t, result[index]);
				}

				snprintf(buff_t, sizeof(buff_t), "%s", tmp);
				if (j == 1) snprintf(tmp, sizeof(tmp)-1, "%s, \"%s\"", buff_t, result[index]);
				snprintf(buff_t, sizeof(buff_t), "%s", tmp);
				if (j == 2) snprintf(tmp, sizeof(tmp)-1, "%s, \"%s\"]", buff_t, result[index]);
				++index;
			}
			BWSQL_LOG("[%5d] tmp = %s", i, tmp);
			if (!strcmp(buff, ""))
				snprintf(buff, len, "%s", tmp);
			else {
				snprintf(buff_t, sizeof(buff_t), "%s", buff);
				snprintf(buff, len, "%s%s", buff_t, tmp);
			}
		}
		sqlite3_free_table(result);
	}
	if (db != NULL) sqlite3_close(db);
	file_unlock(lock);
}

void get_web_hook(char *mac, char *page, char *num, int *retval, webs_t wp)
{
	char buff[LEN_MAX];	// MAX >= (18+32+100)*50 = 7500
	int p;	// page number
	int n;	// the numbers in each page

	memset(buff, 0, sizeof(buff));

	if (!strcmp(mac, ""))
		mac = "all";

	if(!strcmp(page, ""))
		p = 0;
	else
		p = safe_atoi(page);

	if(!strcmp(num, ""))
		n = 50;
	else {
		n = safe_atoi(num);
		if (n > 50) n = 50;
	}

	*retval += websWrite(wp, "[");
	bwdpi_HistoryStat(buff, mac, p, n, sizeof(buff)-1);
	*retval += websWrite(wp, buff);
	*retval += websWrite(wp, "]");
}
/* ---- Web History      END ---- */

/* ---- AiProtection Monitor START ---- */

/*
	transfer ID value into Description
	key    : ID
	val    : return description's buffer
	len_t  : the size of description's buffer
*/
static void transfer_ID_into_Desc(char *key, char *val, int len_t)
{
	FILE *fp = NULL;
	char buf[ID_SIZE];
	char *name, *value;
	int len = 0;

	if (!f_exists(ID_FILE)) {
		printf("Can't find the rule database\n");
		return;
	}

	if ((fp = fopen(ID_FILE, "r")) == NULL) {
		printf("fail to open %s\n", ID_FILE);
		return;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		value = buf;
		name = strsep(&value, ",");

		len = strlen(value);
		*(value + len - 1) = '\0';

		if (!strcmp(name, key)) {
			strlcpy(val, value, len_t);
			BWMON_LOG("key = %s, name=%s, value=%s, len=%d\n", key, name, value, len);
			break;
		}
	}

	if (fp) fclose(fp);
}

void bwdpi_monitor_stat(int *retval, webs_t wp)
{
	// AiProtectionMonitor -c
	int ret;
	char *path = BWDPI_MON_DB;
	sqlite3 *db = NULL;

	ret = sqlite3_open(path, &db);
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		*retval += websWrite(wp, "{");
		*retval += websWrite(wp, "\"mals_n\":\"0\",");
		*retval += websWrite(wp, "\"vp_n\":\"0\",");
		*retval += websWrite(wp, "\"cc_n\":\"0\"");
		*retval += websWrite(wp, "}");
		return;
	}

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
	if (db != NULL) sqlite3_close(db);

	BWMON_DBG("mal, vp, cc = %d, %d, %d\n", mal_n, vp_n, cc_n);
	
	*retval += websWrite(wp, "{");
	*retval += websWrite(wp, "\"mals_n\":\"%d\",", mal_n);
	*retval += websWrite(wp, "\"vp_n\":\"%d\",", vp_n);
	*retval += websWrite(wp, "\"cc_n\":\"%d\"", cc_n);
	*retval += websWrite(wp, "}");
}

void bwdpi_monitor_info(char *type, char *event, int *retval, webs_t wp)
{
	// AiProtection -d [type] -n [event]
	// type = mals / vp / cc
	// event = mac / all
	int ret;
	char *path = BWDPI_MON_DB;
	sqlite3 *db = NULL;

	ret = sqlite3_open(path, &db);
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		return;
	}

	int num = 0;
	if (!strcmp(type, "cc")) num = 1;
	else if (!strcmp(type, "mals"))	num = 2;
	else if (!strcmp(type, "vp")) num = 3;

	if (num == 0) goto error;

	char sql[QUERY_LEN];
	int rows;
	int cols;
	char **result;

	//BWMON_LOG("num=%d, event=%s\n", num, event);

	*retval += websWrite(wp, "[");
	if (!strcmp(event, "mac")) {
		char *tt = NULL;
		if (num == 1) tt = nvram_safe_get("wrs_cc_t");
		if (num == 2) tt = nvram_safe_get("wrs_mals_t");
		if (num == 3) tt = nvram_safe_get("wrs_vp_t");

		snprintf(sql, sizeof(sql)-1, "SELECT mac, COUNT(*) FROM monitor WHERE type = '%d' AND timestamp > '%s' GROUP BY mac ORDER BY COUNT(*) DESC", num, tt);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			int i = 0;
			int is_first = 1;

			for (i = 0; i < rows; i++) {
				if (is_first) {
					*retval += websWrite(wp, "[\"%s\", \"%s\"]", result[cols*(i+1)], result[cols*(i+1)+1]);
					is_first = 0;
				}
				else
					*retval += websWrite(wp, ", [\"%s\", \"%s\"]", result[cols*(i+1)], result[cols*(i+1)+1]);
				BWMON_LOG("i=%d, cols=%d, rows=%d, [\"%s\", \"%s\"]\n", i, cols, rows, result[cols*(i+1)], result[cols*(i+1)+1]);
			}

			sqlite3_free_table(result);
		}
	}
	else if (!strcmp(event, "all") && (num == 1 || num == 2)) {
		snprintf(sql, sizeof(sql)-1, "SELECT timestamp, id, src, dst FROM monitor WHERE type = '%d' ORDER BY timestamp DESC", num);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			int i = 0;
			int is_first = 1;

			for (i = 0; i < rows; i++) {
				// transfer timestamp to date
				char date_t[30];
				memset(date_t, 0, sizeof(date_t));
				StampToDate(atol(result[cols*(i+1)]), date_t);

				if (is_first) {
					*retval += websWrite(wp, "[\"%s\", \"%s\", \"%s\", \"%s\"]", date_t, result[cols*(i+1)+1], result[cols*(i+1)+2], result[cols*(i+1)+3]);
					is_first = 0;
				}
				else
					*retval += websWrite(wp, ", [\"%s\", \"%s\", \"%s\", \"%s\"]", date_t, result[cols*(i+1)+1], result[cols*(i+1)+2], result[cols*(i+1)+3]);
					BWMON_LOG("i=%d, cols=%d, rows=%d, [\"%s\", \"%s\", \"%s\", \"%s\"]\n",
						i, cols, rows, date_t, result[cols*(i+1)+1], result[cols*(i+1)+2], result[cols*(i+1)+3]);
			}

			sqlite3_free_table(result);
		}
	}
	else if (!strcmp(event, "all") && (num == 3)) { // vp
		snprintf(sql, sizeof(sql)-1, "SELECT timestamp, severity, src, dst, id, dir, cat_id FROM monitor WHERE type = '%d' ORDER BY timestamp DESC", num);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			int i = 0;
			int is_first = 1;
			char val[ID_SIZE];

			// TODO : add cat_id arrary

			/*
				dir : direction of attack
				0 : attacker
				1 : victim
				this value not to transfer due to multi-languages.
			*/

			for (i = 0; i < rows; i++) {
				// transfer timestamp to date
				char date_t[30];
				memset(date_t, 0, sizeof(date_t));
				StampToDate(atol(result[cols*(i+1)]), date_t);

				memset(val, 0, sizeof(val));
				transfer_ID_into_Desc(result[cols*(i+1)+4], val, ID_SIZE);

				if (is_first) {
					*retval += websWrite(wp, "[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%x\"]",
						date_t, result[cols*(i+1)+1], result[cols*(i+1)+2], result[cols*(i+1)+3], val, result[cols*(i+1)+5], result[cols*(i+1)+4], safe_atoi(result[cols*(i+1)+6]));
					is_first = 0;
				}
				else {
					*retval += websWrite(wp, ", [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%x\"]",
						date_t, result[cols*(i+1)+1], result[cols*(i+1)+2], result[cols*(i+1)+3], val, result[cols*(i+1)+5], result[cols*(i+1)+4], safe_atoi(result[cols*(i+1)+6]));
				}

				BWMON_LOG("i=%d, cols=%d, rows=%d, [\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%x\']\n",
					i, cols, rows, date_t, result[cols*(i+1)+1], result[cols*(i+1)+2], result[cols*(i+1)+3], val, result[cols*(i+1)+5], result[cols*(i+1)+4], safe_atoi(result[cols*(i+1)+6]));

			}

			sqlite3_free_table(result);
		}
	}
	*retval += websWrite(wp, "]");
	if (db != NULL) sqlite3_close(db);
	return;

error:
	if (db != NULL) sqlite3_close(db);
	*retval += websWrite(wp, "[");
	*retval += websWrite(wp, "]");
	return;
}

void bwdpi_monitor_ips(char *type, char *date, int *retval, webs_t wp)
{
	// AiProtection -d [type] -t [date]
	// type = vp
	int ret;
	char *path = BWDPI_MON_DB;
	sqlite3 *db = NULL;

	ret = sqlite3_open(path, &db);
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		return;
	}

	int num = 0;
	long int t;
	long int date_s, date_l, start;

	if (!strcmp(type, "vp")) num = 3;
	if (num != 3 || date == NULL) goto error;
	if (date != NULL) t = atol(date);

	date_l = Date_Of_Timestamp(t);
	date_s = date_l - DAY_SEC*6;
	BWMON_DBG("num=%d, t=%ld, date_l=%ld, date_s=%ld\n", num, t, date_l, date_s);

	char sql[QUERY_LEN];
	int rows;
	int cols;
	char **result;
	int is_first;

	*retval += websWrite(wp, "[");

	// severity : H
	date_s = date_l - DAY_SEC*6;
	is_first = 1;
	*retval += websWrite(wp, "[");
	for (start = date_s; start < t; start += DAY_SEC) {
		snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND severity = 'H' AND timestamp > '%ld' AND timestamp < '%ld'",
		num, start, start + DAY_SEC);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			if (is_first) {
				*retval += websWrite(wp, "\"%s\"", result[1]);
				is_first = 0;
			}
			else
				*retval += websWrite(wp, ", \"%s\"", result[1]);
			BWMON_LOG("cols=%d, rows=%d, result=%s\n", cols, rows, result[1]);
			sqlite3_free_table(result);
		}
	}
	*retval += websWrite(wp, "]");

	// severity : M
	date_s = date_l - DAY_SEC*6;
	is_first = 1;
	*retval += websWrite(wp, ", [");
	for (start = date_s; start < t; start += DAY_SEC) {
		snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND severity = 'M' AND timestamp > '%ld' AND timestamp < '%ld'",
		num, start, start + DAY_SEC);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			if (is_first) {
				*retval += websWrite(wp, "\"%s\"", result[1]);
				is_first = 0;
			}
			else
				*retval += websWrite(wp, ", \"%s\"", result[1]);
			BWMON_LOG("cols=%d, rows=%d, result=%s\n", cols, rows, result[1]);
			sqlite3_free_table(result);
		}
	}
	*retval += websWrite(wp, "]");

	// severity : L
	date_s = date_l - DAY_SEC*6;
	is_first = 1;
	*retval += websWrite(wp, ", [");
	for (start = date_s; start < t; start += DAY_SEC) {
		snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND severity = 'L' AND timestamp > '%ld' AND timestamp < '%ld'",
		num, start, start + DAY_SEC);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			if (is_first) {
				*retval += websWrite(wp, "\"%s\"", result[1]);
				is_first = 0;
			}
			else
				*retval += websWrite(wp, ", \"%s\"", result[1]);
			BWMON_LOG("cols=%d, rows=%d, result=%s\n", cols, rows, result[1]);
			sqlite3_free_table(result);
		}
	}
	*retval += websWrite(wp, "]");

	*retval += websWrite(wp, "]");
	if (db != NULL) sqlite3_close(db);
	return;

error:
	if (db != NULL) sqlite3_close(db);
	*retval += websWrite(wp, "[");
	*retval += websWrite(wp, "]");
	return;
}

void bwdpi_monitor_nonips(char *type, char *date, int *retval, webs_t wp)
{
	// AiProtection -d [type] -t [date]
	// type = mals or cc
	int ret;
	char *path = BWDPI_MON_DB;
	sqlite3 *db = NULL;

	ret = sqlite3_open(path, &db);
	if (ret) {
		printf("Can't open database %s\n", sqlite3_errmsg(db));
		return;
	}

	int num = 0;
	long int t;
	long int date_s, date_l, start;

	if (!strcmp(type, "mals")) num = 2;
	if (!strcmp(type, "cc")) num = 1;
	if (num == 3 || date == NULL) goto error;
	if (date != NULL) t = atol(date);

	date_l = Date_Of_Timestamp(t);
	date_s = date_l - DAY_SEC*6;
	BWMON_DBG("num=%d, t=%ld, date_l=%ld, date_s=%ld\n", num, t, date_l, date_s);

	char sql[QUERY_LEN];
	int rows;
	int cols;
	char **result;
	int is_first;

	*retval += websWrite(wp, "[");

	date_s = date_l - DAY_SEC*6;
	is_first = 1;
	*retval += websWrite(wp, "[");
	for (start = date_s; start < t; start += DAY_SEC) {
		snprintf(sql, sizeof(sql)-1, "SELECT COUNT(*) FROM monitor WHERE type = '%d' AND timestamp > '%ld' AND timestamp < '%ld'",
		num, start, start + DAY_SEC);
		if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
		{
			if (is_first) {
				*retval += websWrite(wp, "\"%s\"", result[1]);
				is_first = 0;
			}
			else
				*retval += websWrite(wp, ", \"%s\"", result[1]);
			BWMON_LOG("cols=%d, rows=%d, result=%s\n", cols, rows, result[1]);
			sqlite3_free_table(result);
		}
	}
	*retval += websWrite(wp, "]");

	*retval += websWrite(wp, "]");
	if (db != NULL) sqlite3_close(db);
	return;

error:
	if (db != NULL) sqlite3_close(db);
	*retval += websWrite(wp, "[");
	*retval += websWrite(wp, "]");
	return;
}
/* ---- AiProtection Monitor END   ---- */
