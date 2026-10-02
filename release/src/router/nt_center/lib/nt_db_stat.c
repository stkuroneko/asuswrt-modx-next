/*
	notification center database
	- hook or httpd usage API
	- only read and delete
*/

#include <libnt.h>

#define MyDBG(fmt,args...) \
	if(isFileExist(NOTIFY_DB_DEBUG) > 0) { \
		Debug2Console("[nt_db_stat][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}

#define NT_DB_SIZE     64
#define DAY_SEC        86400
#define QUERY_LEN      1024
#define NT_DB_MAX_SISE 512  // unit : KB

#define _DB_VARCHAR(x) "VARCHAR("#x")"
#define DB_VARCHAR(x)  _DB_VARCHAR(x) /* transform marco */

/* error code */
enum {
	NTDB_NO_ERROR       = 0, // no error
	NTDB_FAILED_DELETE  = 1, // can't delete
	NTDB_FAILED_COMPACT = 2  // can't compact
};

NOTIFY_DATABASE_T *event_listcreate(NOTIFY_DATABASE_T input)
{
	NOTIFY_DATABASE_T *new=malloc(sizeof(*new));
	
	memcpy(new,&input,sizeof(*new));
	return new;
}

NOTIFY_DATABASE_T *initial_db_input()
{
	NOTIFY_DATABASE_T *input;
	input = malloc(sizeof(NOTIFY_DATABASE_T));
	if (!input) 
		return NULL;
	memset(input, 0, sizeof(NOTIFY_DATABASE_T));
	return input;
}

void db_input_free(NOTIFY_DATABASE_T *input)
{
	if(input) free(input);
}

static void DatabaseAddLinkedList(struct list *event_list, NOTIFY_DATABASE_T event_t)
{
	NOTIFY_DATABASE_T *sevent_t;
	
	if(event_list)
	{
		sevent_t = NULL;
		sevent_t = event_listcreate(event_t);
		if(sevent_t)
			listnode_add(event_list, (void*)sevent_t);
	
	}
}

void NT_DBFree(struct list *event_list)
{
	list_delete(event_list);
}

static int sqlite_result_check(int ret, char *zErr)
{
	if(ret != SQLITE_OK){
		if(zErr != NULL){
			MyDBG("SQL error: %s\n", zErr);
			sqlite3_free(zErr);
			return 0;
		}
	}
	return 1;
}

static int sqlite_delete_fun(sqlite3 *db, NOTIFY_DATABASE_T *input, char *zErr)
{
	char sql[NOTIFY_DB_QLEN];
	int ret = 1; // 0 : success, 1: fail
	
	/* query condition */
	if(input->tstamp == 0 || input->event == 0){
		MyDBG("MSUT input tstamp and event to delete\n");
		return 0;
	}
	snprintf(sql, sizeof(sql), "DELETE from nt_center WHERE tstamp='%ld' AND event='%x'", input->tstamp, input->event);
	
	/* execute to delete */
	ret = sqlite3_exec(db, sql, NULL, NULL, &zErr);
	if(sqlite_result_check(ret, zErr) == 0) return 0;
	
	/* compact database */
	/* TODO : need to add more mechanism to compact database */
	snprintf(sql, sizeof(sql), "VACUUM;");
	ret = sqlite3_exec(db, sql, NULL, NULL, &zErr);
	if(sqlite_result_check(ret, zErr) == 0) return 0;
	
	if(ret == 0) MyDBG("delete data success!!\n");
	
	return ret;
}

static int check_filesize_over(char *path, long int size)
{
	struct stat st;
	off_t cursize;

	stat(path, &st);
	cursize = st.st_size;

	size = size * 1024; // KB

	if(cursize > size)
		return 1;
	else
		return 0;
}

static time_t get_last_month_timestamp()
{
	struct tm local, t;
	time_t now, t_t = 0;
			
	// get timestamp and tm
	time(&now);
	localtime_r(&now, &local);

	// copy t from local
	t.tm_year = local.tm_year;
	t.tm_mon = local.tm_mon;
	t.tm_mday = 1;
	t.tm_hour = 0;
	t.tm_min = 0;
	t.tm_sec = 0;

	// transfer tm to timestamp
	t_t = mktime(&t);

	return t_t;
}

static int nt_compact_database(sqlite3 *db, int size)
{
	if (size <= 8) size = 8; // minimal size : 8KB

	char *zErr = NULL;
	int status = NTDB_NO_ERROR; // no error

	char path[NT_DB_SIZE] = {0};
	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), NOTIFY_DB_FOLDER"nt_center.db");

	int count = 0;
	time_t timestamp = get_last_month_timestamp();
	int checked = check_filesize_over(path, size);

	while (checked) {
		count++;

		// step1. get timestamp
		if (count > 1) timestamp = timestamp + (DAY_SEC * 5);
		MyDBG("[%3d] over size %ld, timestamp=%ld\n", count, size, timestamp);

		char sql[QUERY_LEN] = {0};
		memset(sql, 0, sizeof(sql));
		snprintf(sql, sizeof(sql), "DELETE from nt_center WHERE tstamp < %ld", timestamp);
		MyDBG("start to delete some rules from %s because of over size\n", path);

		// step2. execute to delete
		if (sqlite3_exec(db, sql,  NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				status = NTDB_FAILED_DELETE;
				goto error;
			}
		}

		// step3. compact file
		if (sqlite3_exec(db, "VACUUM;",  NULL, NULL, &zErr) != SQLITE_OK) {
			if (zErr != NULL) {
				printf("SQL error: %s\n", zErr);
				sqlite3_free(zErr);
				status = NTDB_FAILED_COMPACT;
				goto error;
			}
		}

		// step4. check again
		checked = check_filesize_over(path, size);
	}

error:
	/* error handle */
	MyDBG("FAIL reson=%d\n", status);
	return status;
}

static int sql_get_table(sqlite3 *db, const char *sql, char ***pazResult, int *pnRow, int *pnColumn)
{
	int ret;
	char *errMsg = NULL;
	
	ret = sqlite3_get_table(db, sql, pazResult, pnRow, pnColumn, &errMsg);
	if( ret != SQLITE_OK )
	{
		if (errMsg) sqlite3_free(errMsg);
	}
	
	return ret;
}

int NT_DBCommand(char *action, NOTIFY_DATABASE_T *input)
{
	int ret = 0; // error code
	int lock = 0;
	char path[NT_DB_SIZE];
	char cmd[256];
	char *zErr = NULL;
	sqlite3 *db = NULL;
	
	lock = xfile_lock("nt_db");
	
	/* create db folder */
	if(!isDirectoryExist(NOTIFY_DB_FOLDER)) {
		snprintf(cmd, sizeof(cmd), "mkdir -p %s", NOTIFY_DB_FOLDER);
		system(cmd);
		MyDBG("cmd : %s\n", cmd);
	}
	
	snprintf(path, sizeof(path), NOTIFY_DB_FOLDER"nt_center.db");
	if(!isFileExist(path)) {
		snprintf(cmd, sizeof(cmd), "touch %s", NOTIFY_DB_FOLDER);
		system(cmd);
		MyDBG("cmd : %s\n", cmd);
	}
	
	MyDBG("path : %s\n", path);
	ret = sqlite3_open(path, &db);
	if(ret){
		MyDBG("can't open database, return\n");
		goto error;
	}

	if (action == NULL) goto error;
	
	if(!strcasecmp(action, "write"))
	{
		if(input->tstamp == 0) {
			MyDBG("Error tstamp CANT BE ZERO. return\n");
			goto error;
		}
		
		/* initial format */
		sqlite3_exec(db,
			"CREATE TABLE nt_center("
			"tstamp "DB_VARCHAR(12)","
			"event "DB_VARCHAR(8)","
			"status "DB_VARCHAR(1)","
			"msg "DB_VARCHAR(MAX_EVENT_INFO_LEN)")",
			NULL, NULL, &zErr);
		if(zErr != NULL) sqlite3_free(zErr); // not to show error message
		
		/* index : tstamp */
		sqlite3_exec(db, "CREATE INDEX tstamp ON nt_center(tstamp ASC)", NULL, NULL, &zErr);
		if(zErr != NULL) sqlite3_free(zErr); // not to show error message
		
		/* index : event */
		sqlite3_exec(db, "CREATE INDEX event ON nt_center(event ASC)", NULL, NULL, &zErr);
		if(zErr != NULL) sqlite3_free(zErr); // not to show error message
		
		/* msg */
		char tmp[MAX_EVENT_INFO_LEN];
		if(!strcmp(input->msg, ""))
			snprintf(tmp, sizeof(tmp), "%s", "");
		else
			snprintf(tmp, sizeof(tmp), "%s", input->msg);
		
		/* save data into database */
		char sql[NOTIFY_DB_QLEN];
		snprintf(sql, sizeof(sql),
			"INSERT INTO nt_center VALUES ('%ld', '%x', '%d', '%s')", input->tstamp, input->event, input->status, tmp);
		
		/* execute to save */
		ret = sqlite3_exec(db, sql, NULL, NULL, &zErr);
		if(sqlite_result_check(ret, zErr) == 0) goto error;

		/* compact databae */
		if (nt_compact_database(db, NT_DB_MAX_SISE) > 0) goto error;
	}
	else if(!strcasecmp(action, "read"))
	{
		int rows;
		int cols;
		char **res;
		
		/* result */
		char sql[NOTIFY_DB_QLEN];
		snprintf(sql, sizeof(sql), "SELECT * FROM nt_center ORDER BY tstamp DESC");
		ret = sql_get_table(db, sql, &res, &rows, &cols);
		if(ret == SQLITE_OK){
			int i = 0, j = 0;
			int index = cols;
			for(i = 0; i < rows; i++){
				for(j = 0; j < cols; j++){
					MyDBG("[%7d/%7d] result: %s\n", i, j, res[index]);
					++index;
				}
			}
			sqlite3_free_table(res);
		}
	}
	else if(!strcasecmp(action, "delete"))
	{
		if (sqlite_delete_fun(db, input, zErr) == 1) goto error;
	}
	else if(!strcasecmp(action, "count"))
	{
		int rows;
		int cols;
		char **res;
		
		/* result */
		char sql[NOTIFY_DB_QLEN];
		snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM nt_center");
		ret = sql_get_table(db, sql, &res, &rows, &cols);
		if(ret == SQLITE_OK){
			int i = 0, j = 0;
			int index = cols;
			for(i = 0; i < rows; i++){
				for(j = 0; j < cols; j++){
					MyDBG("[%7d/%7d] count = %s\n", i, j, res[index]);
					++index;
				}
			}
			sqlite3_free_table(res);
		}
	}
	else{
		MyDBG("Error action\n");
	}
	
/* error : close database and unlock file */
error:
	if (zErr != NULL) sqlite3_free(zErr);
	if (db != NULL) sqlite3_close(db);
	xfile_unlock(lock);
	return ret;
}

int NT_DBAction(struct list *event_list, char *action, NOTIFY_DATABASE_T *input, char *count)
{
	int ret = -1; // error code
	int lock = 0;
	char path[NT_DB_SIZE];
	char *zErr = NULL;
	sqlite3 *db = NULL;
	
	lock = xfile_lock("nt_db");
	
	snprintf(path, sizeof(path), NOTIFY_DB_FOLDER"nt_center.db");
	if(!isFileExist(path)){
		MyDBG("%s no database!\n", path);
		goto error;
	}
	
	ret = sqlite3_open(path, &db);
	if(ret){
		MyDBG("can't open database, return\n");
		goto error;
	}

	if (action == NULL) goto error;
	
	if(!strcasecmp(action, "write"))
	{
		/* msg */
		char tmp[MAX_EVENT_INFO_LEN];
		if(!strcmp(input->msg, ""))
			snprintf(tmp, sizeof(tmp), "%s", "");
		else
			snprintf(tmp, sizeof(tmp), "%s", input->msg);
		
		if(input->tstamp == 0) {
			MyDBG("Error tstamp CANT BE ZERO. return\n");
			goto error;
		}
		
		/* upadte status into database */
		char sql[NOTIFY_DB_QLEN];
		snprintf(sql, sizeof(sql), "UPDATE nt_center SET status='%d' WHERE tstamp='%ld'", input->status, input->tstamp);
		MyDBG("sql=%s\n", sql);
		
		/* execute to update */
		ret = sqlite3_exec(db, sql, NULL, NULL, &zErr);
		if(sqlite_result_check(ret, zErr) == 0) goto error;
		
		if(ret == 0) MyDBG("update status success!!\n");

		/* compact databae */
		if (nt_compact_database(db, NT_DB_MAX_SISE) > 0) goto error;
	}
	else if(!strcasecmp(action, "read"))
	{
		int rows;
		int cols;
		char **res;
		char sql[NOTIFY_DB_QLEN];
		char limit[48];
		NOTIFY_DATABASE_T event_t;

		if (count == NULL || !strcmp(count, "all") || !strcmp(count, "")) {
			memset(limit, 0, sizeof(limit));
		}
		else {
			// forbid count < 1
			if (strtol(count, NULL, 10) < 1) {
				MyDBG("The input of count should be bigger than 0!!\n");
				goto error;
			}

			if (strlen(count) > sizeof("4294967295")) {
				MyDBG("The input of count is out of range (2^32)!!\n");
				goto error;
			}
			else {
				snprintf(limit, sizeof(limit), "LIMIT %s", count);
			}
		}
		
		/* result */
		snprintf(sql, sizeof(sql), "SELECT * FROM nt_center ORDER BY tstamp DESC %s", limit);
		if(sql_get_table(db, sql, &res, &rows, &cols) == SQLITE_OK){
			int i = 0, j = 0;
			int index = cols;
			for(i = 0; i < rows; i++)
			{
				/* MUST initial event_t */
				memset(&event_t, 0, sizeof(NOTIFY_DATABASE_T));
				
				for(j = 0; j < cols; j++){
					MyDBG("[%7d/%7d] result: %s\n", i, j, res[index]);
					if(j == 0) event_t.tstamp = strtol(res[index], NULL, 10);
					if(j == 1) event_t.event = strtol(res[index], NULL, 16);
					if(j == 2) event_t.status = strtol(res[index], NULL, 10);
					if(j == 3) strncpy(event_t.msg, res[index], sizeof(event_t.msg)-1);
					++index;
				}
				DatabaseAddLinkedList(event_list, event_t);
			}
			sqlite3_free_table(res);
		}
		ret = 0;
	}
	else if(!strcasecmp(action, "delete"))
	{
		if (sqlite_delete_fun(db, input, zErr) == 1){
			ret = 0;
			goto error;
		}
	}
	else{
		MyDBG("Error action\n");
	}
	
/* error : close database and unlock file */
error:
	if (zErr != NULL) sqlite3_free(zErr);
	if (db != NULL) sqlite3_close(db);
	xfile_unlock(lock);
	return ret;
}

int NT_DBActionAPP(struct list *event_list, char *action, NOTIFY_DATABASE_T *input, char *page, char *count)
{
	int ret = -1; // error code
	int lock = 0;
	char path[NT_DB_SIZE];
	char *zErr = NULL;
	sqlite3 *db = NULL;
	int p = -1, c = -1;
	
	lock = xfile_lock("nt_db");
	
	snprintf(path, sizeof(path), NOTIFY_DB_FOLDER"nt_center.db");
	if(!isFileExist(path)){
		MyDBG("%s no database!\n", path);
		goto error;
	}
	
	ret = sqlite3_open(path, &db);
	if(ret){
		MyDBG("can't open database, return\n");
		goto error;
	}

	MyDBG("a=%s, t=%ld, e=%x, s=%d, p=%s, m=%s\n", action, input->tstamp, input->event, input->status, page, count);
	if (action == NULL) goto error;

	if(!strcasecmp(action, "write"))
	{
		/* msg */
		char tmp[MAX_EVENT_INFO_LEN];
		if(!strcmp(input->msg, ""))
			snprintf(tmp, sizeof(tmp), "%s", "");
		else
			snprintf(tmp, sizeof(tmp), "%s", input->msg);
		
		if(input->tstamp == 0) {
			MyDBG("Error tstamp CANT BE ZERO. return\n");
			goto error;
		}
		
		/* upadte status into database */
		char sql[NOTIFY_DB_QLEN];
		snprintf(sql, sizeof(sql), "UPDATE nt_center SET status='%d' WHERE tstamp='%ld'", input->status, input->tstamp);
		MyDBG("sql=%s\n", sql);
		
		/* execute to update */
		ret = sqlite3_exec(db, sql, NULL, NULL, &zErr);
		if(sqlite_result_check(ret, zErr) == 0) goto error;
		
		if(ret == 0) MyDBG("update status success!!\n");

		/* compact databae */
		if (nt_compact_database(db, NT_DB_MAX_SISE) > 0) goto error;
	}
	else if(!strcasecmp(action, "read"))
	{
		int rows;
		int cols;
		char **res;
		char sql[NOTIFY_DB_QLEN];
		NOTIFY_DATABASE_T event_t;
		char rule1[60];
		char rule2[80];
		int stat = -1;
		int stat_f = 0;

		// check input "status" first
		stat = input->status;
		if (stat == 0 || stat == 1) stat_f = 1;

		// rule 1. check event and status
		if (input->event != 0 && stat_f == 0)
			snprintf(rule1, sizeof(rule1), "WHERE event = %x", input->event);
		else if (input->event == 0 && stat_f == 1)
			snprintf(rule1, sizeof(rule1), "WHERE status = %d", stat);
		else if (input->event != 0 && stat_f == 1)
			snprintf(rule1, sizeof(rule1), "WHERE event = %x AND status = %d", input->event, stat);
		else
			memset(rule1, 0, sizeof(rule1));

		//MyDBG("rule1=%s\n", rule1);

		// rule 2. check tstamp
		if (input->tstamp != 0 && strcmp(rule1, ""))
			snprintf(rule2, sizeof(rule2), "%s AND tstamp > %ld", rule1, input->tstamp);
		else if (input->tstamp != 0 && !strcmp(rule1, ""))
			snprintf(rule2, sizeof(rule2), "WHERE tstamp > %ld", input->tstamp);
		else
			snprintf(rule2, sizeof(rule2), "%s", rule1);

		//MyDBG("rule2=%s\n", rule2);

		// rule 3. check (page, count)
		if (page != NULL && count != NULL) {
			p = strtol(page, NULL, 10);
			c = strtol(count, NULL, 10);
		}
		else if (page != NULL && count == NULL) {
			p = strtol(page, NULL, 10);
			c = 6;
		}
		else {
			p = 1;
			c = 6;
			MyDBG("no limited!\n");
		}

		/* result */
		snprintf(sql, sizeof(sql), "SELECT * FROM nt_center %s ORDER BY tstamp DESC", rule2);
		MyDBG("sql=%s\n", sql);
		if(sql_get_table(db, sql, &res, &rows, &cols) == SQLITE_OK){
			int i = 0, j = 0;
			int index = 0;
			int C_MIN = 0, C_MAX = 0;

			if (p == 0) {
				C_MIN = 0;
				C_MAX = rows;
				index = cols;
			}
			else if (p > 0) {
				C_MIN = (p-1) * c;
				C_MAX = p * c;
				index = 3 * C_MIN + cols;
			}

			if (C_MAX > rows)
				C_MAX = rows;

			for (i = C_MIN; i < C_MAX; i++)
			{
				/* MUST initial event_t */
				memset(&event_t, 0, sizeof(NOTIFY_DATABASE_T));
				
				for(j = 0; j < cols; j++){
					//MyDBG("[%7d/%7d] result: %s\n", i, j, res[index]);
					if(j == 0) event_t.tstamp = strtol(res[index], NULL, 10);
					if(j == 1) event_t.event = strtol(res[index], NULL, 16);
					if(j == 2) event_t.status = strtol(res[index], NULL, 10);
					if(j == 3) strncpy(event_t.msg, res[index], sizeof(event_t.msg)-1);
					++index;
				}
				DatabaseAddLinkedList(event_list, event_t);
			}
			sqlite3_free_table(res);
		}
		ret = 0;
	}
	else if(!strcasecmp(action, "wan_stat"))
	{
		int rows;
		int cols;
		char **res;
		char sql[NOTIFY_DB_QLEN];
		NOTIFY_DATABASE_T event_t;
		char rule[240];

		// wan event
		snprintf(rule, sizeof(rule), "event = 10001 OR event = 10002 OR event = 10015 OR event = 10016 OR event = 10017 OR event = 10018 OR event = 10019 OR event = \"1001a\" OR event = \"1001b\" OR event = \"1001c\"");
		snprintf(sql, sizeof(sql), "SELECT * FROM nt_center WHERE %s ORDER BY tstamp DESC LIMIT 1", rule);
		MyDBG("sql=%s\n", sql);

		if(sql_get_table(db, sql, &res, &rows, &cols) == SQLITE_OK){
			int i = 0, j = 0;
			int index = cols;
			for(i = 0; i < rows; i++)
			{
				/* MUST initial event_t */
				memset(&event_t, 0, sizeof(NOTIFY_DATABASE_T));
				
				for(j = 0; j < cols; j++){
					//MyDBG("[%7d/%7d] result: %s\n", i, j, res[index]);
					if(j == 0) event_t.tstamp = strtol(res[index], NULL, 10);
					if(j == 1) event_t.event = strtol(res[index], NULL, 16);
					if(j == 2) event_t.status = strtol(res[index], NULL, 10);
					if(j == 3) strncpy(event_t.msg, res[index], sizeof(event_t.msg)-1);
					++index;
				}
				DatabaseAddLinkedList(event_list, event_t);
			}
			sqlite3_free_table(res);
		}
		ret = 0;
	}
	else if(!strcasecmp(action, "delete"))
	{
		if (sqlite_delete_fun(db, input, zErr) == 1){
			ret = 0;
			goto error;
		}
	}
	else{
		MyDBG("Error action\n");
	}

/* error : close database and unlock file */
error:
	if (zErr != NULL) sqlite3_free(zErr);
	if (db != NULL) sqlite3_close(db);
	xfile_unlock(lock);
	return ret;
}

/*
	NT_DBCount will return the amount of events in database
	if fails, will return -1
*/
int NT_DBCount()
{
	int ret = -1;
	char path[NT_DB_SIZE];
	char *zErr = NULL;
	sqlite3 *db = NULL;
	
	snprintf(path, sizeof(path), NOTIFY_DB_FOLDER"nt_center.db");
	if(!isFileExist(path)){
		MyDBG("%s no database!\n", path);
		goto error;
	}

	ret = sqlite3_open(path, &db);
	if(ret){
		MyDBG("can't open database, return\n");
		goto error;
	}

	int rows;
	int cols;
	char **res;
		
	/* result */
	char sql[NOTIFY_DB_QLEN];
	snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM nt_center");
	ret = sql_get_table(db, sql, &res, &rows, &cols);
	if(ret == SQLITE_OK){
		ret = strtol(res[1], NULL, 10);
		MyDBG("count = %d\n", ret);
		sqlite3_free_table(res);
	}

/* error : close database and unlock file */
error:
	if (zErr != NULL) sqlite3_free(zErr);
	if (db != NULL) sqlite3_close(db);
	return ret;
}
