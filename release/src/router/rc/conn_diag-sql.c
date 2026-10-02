#include <unistd.h>
#include <shared.h>
#include <shutils.h>
#include <conn_diag.h>
#include <conn_diag-sql.h>
#include <json.h>


#define DIAG_LOG_BCOUNT 4 // FIELD>node type>node IP>node MAC

char *fields_basic[] = {"time", "event_name", "node_type", "node_ip", "node_mac", NULL};

char *fields_SYS[] = {"fw_ver", "tcode", "AiProtection", "usb_mode", "acceleration", "oops", NULL};
char *fields_SYS2[] = {"cpu_freq", "memfree", "cpu_temp", "temp_2g", "temp_5g", "temp_5g1", NULL};
char *fields_WIFISYS[] = {"info_2g", "info_5g", "info_5g1", NULL};
//#ifdef RTCONFIG_BCMARM
char *fields_WIFISYS2[] = {"band", "ifname", "mac", "noise", "mcs", "capability", "subif_count", "subif_ssid", "chanim", "tx_rate", "rx_rate", "tx_byte", "rx_byte", NULL};
//#else
//char *fields_WIFISYS2[] = {"band", "ifname", "mac", "noise", "mcs", "tx_rate", "rx_rate", "tx_byte", "rx_byte", NULL};
//#endif
char *fields_STAINFO[] = {"sta_mac", "sta_band", "sta_rssi", "sta_active", "sta_tx", "sta_rx", "sta_tbyte", "sta_rbyte", "sta_tx_nrate", "sta_rx_nrate", NULL};
char *fields_WLCE[] = {"sta_mac", "sta_band", "last_act", "count_auth", "count_deauth", "count_assoc", "count_disassoc", "count_reassoc", NULL};
char *fields_TG_ROAMING[] = {"sta_mac", "sta_band", "sta_rssi", "tg_time", "user_low_rssi", "rssi_cnt", "idle_period", "idle_start", NULL};
char *fields_ROAMING[] = {"sta_mac", "sta_rssi", "tg_time", "candidate_rssi_criteria", "candidate_mac", "candidate_rssi", "ret_11v", "present_ap", NULL};
char *fields_NET[] = {"wan_unit", "link_wan", "runIP", "runMASK", "runGATE", "got_Route", "got_Redirect", "ret_dns", "ret_ping", NULL};
#ifdef RTCONFIG_BCMBSD
char *fields_TG_BSD[] = {"sta_mac", "tg_time", "from_chanspec", "to_chanspec", "reason", NULL};
#endif
char *fields_ETHINFO[] = {"type", "tx_rate", "rx_rate", "tx_byte", "rx_byte", NULL};
char *fields_PORTINFO[] = {"label_name", "cap_name", "status", "link_speed", "duplex", "tx_packets", "rx_packets", "tx_bytes", "rx_bytes", "crc_errors", NULL};

typedef struct {
	const char *event_name;
	int field_num;
	char **fields;
} event_type;

const event_type diag_events[] = {
	{ DIAG_EVENT_SYS, 6, fields_SYS },
	{ DIAG_EVENT_SYS2, 6, fields_SYS2 },
	{ DIAG_EVENT_WIFISYS, 3, fields_WIFISYS },
//#ifdef RTCONFIG_BCMARM
	{ DIAG_EVENT_WIFISYS2, 13, fields_WIFISYS2 },
//#else
//	{ DIAG_EVENT_WIFISYS2, 9, fields_WIFISYS2 },
//#endif
	{ DIAG_EVENT_STAINFO, 10, fields_STAINFO },
	{ DIAG_EVENT_WLCE, 8, fields_WLCE },
	{ DIAG_EVENT_TG_ROAMING, 8, fields_TG_ROAMING },
	{ DIAG_EVENT_ROAMING, 8, fields_ROAMING },
	{ DIAG_EVENT_NET, 9, fields_NET },
#ifdef RTCONFIG_BCMBSD
	{ DIAG_EVENT_TG_BSD, 5, fields_TG_BSD },
#endif
	{ DIAG_EVENT_ETHINFO, 5, fields_ETHINFO },
	{ DIAG_EVENT_PORTINFO, 10, fields_PORTINFO },
	{ NULL, -1 }
};

static pthread_mutex_t diag_db_save_lock = PTHREAD_MUTEX_INITIALIZER;


void diag_log_status(){
	diag_dbg = nvram_get_int("diag_dbg");
	diag_syslog = nvram_get_int("diag_syslog2");
	diag_max_db_size = nvram_get_int("diag_max_db_size") ? nvram_get_int("diag_max_db_size") : MAX_DB_SIZE;
	diag_max_db_count = nvram_get_int("diag_max_db_count") ? nvram_get_int("diag_max_db_count") : MAX_DB_COUNT;
	diag_portinfo = nvram_get_int("diag_portinfo");

	//DIAG_LOG(LOG_INFO, "diag_max_db_size=%d, diag_max_db_count=%d", diag_max_db_size, diag_max_db_count);
}

int l_exists(const char *path)  //  link only
{
	struct stat st;
	return (stat(path, &st) == 0) && (S_ISLNK(st.st_mode));
}

int get_ts_from_db_name(char *str, unsigned long *ts1, unsigned long *ts2) {
	char *ptr;
	int ts_count = 0;

	if(!(ptr = strstr(str, DIAG_TAB_NAME)))
		return 0;

	ts_count = sscanf(str, "conn_diag_%lu_%lu%*s", ts1, ts2);
	if (ts_count == 0) {
		*ts1 = 0;
		*ts2 = 0;
	} else if (ts_count == 1)
		*ts2 = 0;
	return ts_count;
}

time_t getZeroTimeonDay(unsigned long ts){
	time_t current_time, zero_time;

	if(ts > 0)
		current_time = ts;
	else
		current_time = time(NULL);
	zero_time = (((current_time/675)>>7)*675)<<7;

	return zero_time;
}

char *get_dbfile_at_ts(unsigned long ts, unsigned long ts2, char *buf, int buflen){
	if(ts2 > 0)
		snprintf(buf, buflen, "%s_%lu_%lu", DIAG_TAB_NAME, ts, ts2);
	else
		snprintf(buf, buflen, "%s_%lu", DIAG_TAB_NAME, ts);

	return buf;
}

char *get_dbpath_at_ts(unsigned long ts, unsigned long ts2, char *buf, int buflen){
	char dbfile[PATH_MAX];

	get_dbfile_at_ts(ts, ts2, dbfile, sizeof(dbfile));
	snprintf(buf, buflen, "%s/%s.db", DIAG_DB_DIR, dbfile);

	return buf;
}

#ifdef RTCONFIG_UPLOADER
char *get_downpath_at_ts(unsigned long ts, unsigned long ts2, char *buf, int buflen){
	char dbfile[PATH_MAX];

	get_dbfile_at_ts(ts, ts2, dbfile, sizeof(dbfile));
	snprintf(buf, buflen, "%s/%s.db", DIAG_CLOUD_DOWNLOAD, dbfile);

	return buf;
}

char *get_uppath_at_ts(unsigned long ts, unsigned long ts2, char *buf, int buflen){
	char dbfile[PATH_MAX];

	get_dbfile_at_ts(ts, ts2, dbfile, sizeof(dbfile));
	snprintf(buf, buflen, "%s/%s.db", DIAG_CLOUD_UPLOAD, dbfile);

	return buf;
}

int run_upload_file_at_ts(unsigned long ts, unsigned long ts2){
	char dbpath[PATH_MAX];
	char link_path[PATH_MAX];

	get_dbpath_at_ts(ts, ts2, dbpath, sizeof(dbpath));
	get_uppath_at_ts(ts, ts2, link_path, sizeof(link_path));

	symlink(dbpath, link_path);

	return 0;
}

int run_upload_file_by_name(const char *uploaded_file){
	char link_path[PATH_MAX], *file;

	if(uploaded_file == NULL)
		return -1;

	file = rindex(uploaded_file, '/');
	if(file == NULL)
		file = (char *)uploaded_file;

	snprintf(link_path, sizeof(link_path), "%s/%s", DIAG_CLOUD_UPLOAD, file);

	symlink(uploaded_file, link_path);

	return 0;
}

int run_download_file_at_ts(unsigned long ts, unsigned long ts2){
	char link_path[PATH_MAX];

	if(ts <= 0)
		return -1;

	get_downpath_at_ts(ts, ts2, link_path, sizeof(link_path));

	symlink(DIAG_CLOUD_DOWNLOAD, link_path);

	return 0;
}

int run_download_file_by_name(const char *downloaded_file){
	char link_path[PATH_MAX], *file;

	if(downloaded_file == NULL)
		return -1;

	file = rindex(downloaded_file, '/');
	if(file == NULL)
		file = (char *)downloaded_file;

	snprintf(link_path, sizeof(link_path), "%s/%s", DIAG_CLOUD_DOWNLOAD, file);

	symlink(DIAG_CLOUD_DOWNLOAD, link_path);

	return 0;
}
#endif

int is_valid_event(const char *name){
	const event_type *ptr;
	int got_event = 0;

	for(ptr = diag_events; ptr->event_name; ++ptr)
		if(!strcmp(name, ptr->event_name)){
			got_event = 1;
			break;
		}

	return got_event;
}

/*int sort_by_mtime(d1, d2)
	const void *d1;
	const void *d2;
{
	int rval;
	struct stat attrib1, attrib2;
	char file1[PATH_MAX], file2[PATH_MAX];

	snprintf(file1, sizeof(file1), "%s/%s", DIAG_DB_DIR, (*(struct dirent **)d1)->d_name);
	snprintf(file2, sizeof(file2), "%s/%s", DIAG_DB_DIR, (*(struct dirent **)d2)->d_name);

    rval = stat(file1, &attrib1);
    if (rval) {
		DIAG_LOG(LOG_INFO, "stat %s fiailed. %s", file1, strerror(errno));
		return 0;
	}
    rval = stat(file2, &attrib2);
    if (rval) {
		DIAG_LOG(LOG_INFO, "stat %s fiailed. %s", file2, strerror(errno));
		return 0;
	}

    if (attrib1.st_mtime < attrib2.st_mtime)
		return -1;
    else if (attrib1.st_mtime == attrib2.st_mtime)
		return 0;
    else
		return 1;
}*/

/*
 * Sort by alpha but handle the following special case. Let
 * conn_diag_1590624000.db > conn_diag_1590624000_1590710020.db
 * conn_diag_1590624000_1590710020.db < conn_diag_1590624000.db
 */
int special_alphasort(d1, d2)
	const void *d1;
	const void *d2;
{
	int len1, len2;
	len1 = strlen((*(struct dirent **)d1)->d_name);
	len2 = strlen((*(struct dirent **)d2)->d_name);
	if (len1 > 3 && len1 < len2 && 
		!strncmp((*(struct dirent **)d1)->d_name, (*(struct dirent **)d2)->d_name, (len1-3))) {
		return 1;
	} else if (len2 > 3 && len2 < len1 && 
		!strncmp((*(struct dirent **)d2)->d_name, (*(struct dirent **)d1)->d_name, (len2-3))) {
		return -1;
	} else {
		return(strcmp((*(struct dirent **)d1)->d_name,
			(*(struct dirent **)d2)->d_name));
	}
}

int init_data_in_sql(sqlite3 **db){
	char cmd[PATH_MAX], *zErr;

	snprintf(cmd, sizeof(cmd),
			"CREATE TABLE %s("
			"time UNSIGNED BIG INT,"
			"event_name TEXT,"
			"node_type TEXT,"
			"node_ip TEXT,"
			"node_mac TEXT,"
			"json_msg TEXT)", DIAG_TAB_NAME);
	sqlite3_exec(*db, cmd, NULL, NULL, &zErr);
	if(zErr != NULL){
		DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
		sqlite3_free(zErr);
		goto ERROR_init;
	}

	snprintf(cmd, sizeof(cmd), "CREATE INDEX event_time ON %s(time ASC)", DIAG_TAB_NAME);
	sqlite3_exec(*db, cmd, NULL, NULL, &zErr);
	if(zErr != NULL){
		DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
		sqlite3_free(zErr);
		goto ERROR_init;
	}

	snprintf(cmd, sizeof(cmd), "CREATE INDEX event_name ON %s(event_name ASC)", DIAG_TAB_NAME);
	sqlite3_exec(*db, cmd, NULL, NULL, &zErr);
	if(zErr != NULL){
		DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
		sqlite3_free(zErr);
		goto ERROR_init;
	}

	return 0;

ERROR_init:
	return -1;
}

int open_file_in_sql(sqlite3 **db, const int save, unsigned long specific_ts){
	int ret;
	unsigned long ts = 0;
	char db_path[PATH_MAX], *ptr_db_path;
	int need_init_table = INIT_DB_NO;
	unsigned long fsize = 0;
#ifdef RTCONFIG_UPLOADER
	char cloud_path[PATH_MAX], *ptr_cloud_path, *ptr_db_old;
#endif

	if(!d_exists(SYS_DIR))
		mkdir(SYS_DIR, 0666);
	if(!d_exists(DIAG_DB_DIR))
		mkdir(DIAG_DB_DIR, 0777);

#ifdef RTCONFIG_UPLOADER
	if(!d_exists(DIAG_CLOUD_DIR))
		mkdir(DIAG_CLOUD_DIR, 0777);
	if(!d_exists(DIAG_CLOUD_UPLOAD))
		mkdir(DIAG_CLOUD_UPLOAD, 0777);
	if(!d_exists(DIAG_CLOUD_DOWNLOAD))
		mkdir(DIAG_CLOUD_DOWNLOAD, 0777);
#endif

	if(save && (ptr_db_path = nvram_get("diag_db_path")) && *ptr_db_path){
#ifdef RTCONFIG_UPLOADER
		ptr_cloud_path = nvram_get("diag_cloud_path");
#endif
	}
	else{
		if(specific_ts)
			ts = getZeroTimeonDay(specific_ts);
		else
			ts = getZeroTimeonDay(0);
		get_dbpath_at_ts(ts, 0, db_path, sizeof(db_path));
		ptr_db_path = db_path;

#ifdef RTCONFIG_UPLOADER
		get_downpath_at_ts(ts, 0, cloud_path, sizeof(cloud_path));
		ptr_cloud_path = cloud_path;

		if(f_exists(ptr_cloud_path) && !l_exists(ptr_cloud_path)){
			if(f_exists(ptr_db_path)){
				if((fsize = f_size(ptr_db_path)) > 0)
					// merge ptr_db_path to ptr_cloud_path, because ptr_cloud_path should be older than ptr_db_path.
					merge_data_in_sql(ptr_cloud_path, ptr_db_path);
				unlink(ptr_db_path);
			}

			eval("mv", ptr_cloud_path, ptr_db_path);
		}
		else
#endif
		{
			if(!f_exists(ptr_db_path) || (fsize = f_size(ptr_db_path)) <= 0){
#ifdef RTCONFIG_UPLOADER
				if(!f_exists(ptr_cloud_path))
					run_download_file_by_name(ptr_cloud_path);
#endif

				if(!save)
					return 0;

				need_init_table = INIT_DB_YES;
			}
		}

		if(!specific_ts){
#ifdef RTCONFIG_UPLOADER
			if((ptr_db_old = nvram_get("diag_db_path_old")) != NULL && *ptr_db_old && strcmp(ptr_db_path, ptr_db_old))
				run_upload_file_by_name(ptr_db_old);
			nvram_set("diag_cloud_path", ptr_cloud_path);
#endif

			nvram_set("diag_db_path", ptr_db_path);
		}
	}

#if 1
	// limit the size of a single db file.
	time_t now;
	char backup_path[PATH_MAX];
	//DIAG_LOG(LOG_INFO, "save=%d, need_init_table=%d, fsize=%d, diag_max_db_size=%d\n", save, need_init_table, fsize, diag_max_db_size);

	if(save && need_init_table == INIT_DB_NO && fsize > diag_max_db_size){
		now = time(NULL);
		get_dbpath_at_ts(ts, now, backup_path, sizeof(backup_path));

		DIAG_LOG(LOG_INFO, "***** Backup the db file as %s...\n", backup_path);

		unlink(backup_path);
		rename(ptr_db_path, backup_path);

#ifdef RTCONFIG_UPLOADER
		run_upload_file_at_ts(ts, now);
#else
		char *backup_dir;
		if((backup_dir = nvram_get("diag_backup_dir")) && *backup_dir && d_exists(backup_dir))
			eval("mv", backup_path, backup_dir);
#endif

		need_init_table = INIT_DB_YES;
	}
#endif

	if(need_init_table == INIT_DB_YES){
		unlink(ptr_db_path);
		eval("touch", ptr_db_path);
		chmod(ptr_db_path, 0666);
	}

	ret = sqlite3_open(ptr_db_path, &(*db));
	if(ret != SQLITE_OK){
		DIAG_LOG(LOG_INFO, "Can't open database %s\n", sqlite3_errmsg(*db));
		return -1;
	}

	if(need_init_table == INIT_DB_YES)
		init_data_in_sql(db);

	struct dirent **filelist;
	int i, n = scandir(DIAG_DB_DIR, &filelist, 0, special_alphasort);
	if (n < 0)
		DIAG_LOG(LOG_INFO, "scandir fiailed. %s", strerror(errno));
	else {
		char file_path[PATH_MAX];
		for (i = 0; i < n; i++) {
			if (!strcmp(filelist[i]->d_name, ".") || !strcmp(filelist[i]->d_name, "..") || strstr(filelist[i]->d_name, "-journal"))
				goto NEXT_FILE;

			if ((n - i) > diag_max_db_count) {
				snprintf(file_path, sizeof(file_path), "%s/%s", DIAG_DB_DIR, filelist[i]->d_name);
				unlink(file_path);
				DIAG_LOG(LOG_INFO, "unlink %s", file_path);
			}
NEXT_FILE:
			free(filelist[i]);
		}
		free(filelist);
	}

	DIAG_LOG(LOG_INFO, "Built the SQL file of conn_diag.");
	return 0;
}

char *get_fields_json_msg(const unsigned int timestamp, int field_num, char **fields, char *raw, char *json_msg, int msg_len){
	struct json_object *root = NULL;
	char word[MAX_DATA], *next_word = NULL;
	char word2[MAX_DATA], *next_word2;
	int count;
	char buf[32], *ptr = NULL;

	root = json_object_new_object();
	if(root == NULL){
		/* can't create json object */
		return NULL;
	}

	foreach_60(word2, raw, next_word2){
		count = 0;
		foreach_62(word, word2, next_word){
			// FIELD>node type>node IP>node MAC>...
			if(count < DIAG_LOG_BCOUNT){
				if(count == 0){
					snprintf(buf, sizeof(buf), "%u", timestamp);
					json_object_object_add(root, fields_basic[count], json_object_new_string(buf));	
				}

				json_object_object_add(root, fields_basic[count+1], json_object_new_string(word));
			}
			else {
				if ((count - DIAG_LOG_BCOUNT) < field_num)
					json_object_object_add(root, fields[count-DIAG_LOG_BCOUNT], json_object_new_string(word));
				else {
					DIAG_LOG(LOG_INFO, "The quantity of field is too much.");
					break;
				}
			}

			++count;
		}

		ptr = (char *)json_object_get_string(root);
		if(ptr == NULL){
			if (root)
				json_object_put(root);
			return NULL;
		}
	}

	snprintf(json_msg, msg_len, "%s", ptr);

	if (root)
		json_object_put(root);

	return json_msg;
}

char *get_event_json_msg(const unsigned int timestamp, const char *event, char *raw, char *json_msg, int msg_len){
	const event_type *ptr;

	for(ptr = diag_events; ptr->event_name; ++ptr){
		if(!strcmp(event, ptr->event_name))
			return get_fields_json_msg(timestamp, ptr->field_num, ptr->fields, raw, json_msg, msg_len);
	}

	return NULL;
}

int save_data_in_sql(const char *event, char *raw){
	int lock = -1;
	int openned_file = -1, ret = -1;
	sqlite3 *db = NULL;
	time_t now;
	char json_msg[PATH_MAX], *ptr_json;
	char word[MAX_DATA], *next_word = NULL;
	char word2[MAX_DATA], *next_word2;
	int count;
	char cmd[PATH_MAX], *ptr;
	int len;
	char *zErr = NULL;

	if(event && *event && !is_valid_event(event))
		goto FINISHED_save;

	pthread_mutex_lock(&diag_db_save_lock);

	if((lock = file_lock(DIAG_FILE_LOCK)) == -1)
		goto FINISHED_save;

	openned_file = open_file_in_sql(&db, 1, 0);
	if(openned_file != SQLITE_OK)
		goto FINISHED_save;

	now = time(NULL);

	memset(cmd, 0, sizeof(cmd));

	len = 0;
	ptr = cmd;
	count = 0;
	foreach_60(word2, raw, next_word2){
		foreach_62(word, word2, next_word){
			// FIELD>node type>node IP>node MAC>...
			if(count < DIAG_LOG_BCOUNT){
				if(count == 0){
					if(strcmp(word, event)){
						DIAG_LOG(LOG_DEBUG, "event(%s)'s data isn't matched!\n", event);
						goto FINISHED_save;
					}

					snprintf(ptr, sizeof(cmd)-len, "INSERT INTO %s VALUES ('%lu'", DIAG_TAB_NAME, now);
					len += strlen(ptr);
					ptr = cmd+len;
				}

				snprintf(ptr, sizeof(cmd)-len, ", '%s'", word);
				len += strlen(ptr);
				ptr = cmd+len;
			}
			else{
				ptr_json = get_event_json_msg(now, event, raw, json_msg, sizeof(json_msg));
				snprintf(ptr, sizeof(cmd)-len, ", '%s')", ptr_json);

				break;
			}

			++count;
		}
	}

	ret = sqlite3_exec(db, cmd, NULL, NULL, &zErr);
	if(zErr != NULL){
		DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
		sqlite3_free(zErr);
	}

FINISHED_save:
	if(openned_file == SQLITE_OK)
		sqlite3_close(db);

	if(lock > 0)
		file_unlock(lock);

	pthread_mutex_unlock(&diag_db_save_lock);

	return ret;
}

int specific_data_on_day(unsigned long specific_ts, const char *where, int *row_count, int *field_count, char ***raw){
	int lock = -1;
	int openned_file = -1, ret = -1;
	sqlite3 *db = NULL;
	char cmd[PATH_MAX], *ptr;
	int len;
	char *zErr = NULL;

	if((lock = file_lock(DIAG_FILE_LOCK)) == -1)
		goto FINISHED_get;

	openned_file = open_file_in_sql(&db, 0, specific_ts);
	if(openned_file != SQLITE_OK)
		goto FINISHED_get;

	len = 0;
	ptr = cmd;

	snprintf(ptr, sizeof(cmd)-len, "SELECT * FROM %s", DIAG_TAB_NAME);
	len = strlen(cmd);
	ptr = cmd+len;

	if(where && *where){
		snprintf(ptr, sizeof(cmd)-len, " where %s", where);
		len = strlen(cmd);
		ptr = cmd+len;
	}

	fprintf(stdout, "cmd=%s.\n", cmd);
	ret = sqlite3_get_table(db, cmd, raw, row_count, field_count, &zErr);
	if(zErr != NULL){
		DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
		sqlite3_free(zErr);
	}

FINISHED_get:
	if(openned_file == SQLITE_OK)
		sqlite3_close(db);

	if(lock > 0)
		file_unlock(lock);

	return ret;
}

int get_data_from_diag(unsigned long specific_ts, const char *event, const char *node_ip, const char *node_mac, int json,
		int *row_count, int *field_count, char ***raw){
	int lock = -1;
	int openned_file = -1, ret = -1;
	sqlite3 *db = NULL;
	char json_msg[10];
	int need_and = 0;
	char cmd[PATH_MAX], *ptr;
	int len;
	char *zErr = NULL;

	if(event && *event && !is_valid_event(event))
		goto FINISHED_get;

	if((lock = file_lock(DIAG_FILE_LOCK)) == -1)
		goto FINISHED_get;

	openned_file = open_file_in_sql(&db, 0, specific_ts);
	if(openned_file != SQLITE_OK)
		goto FINISHED_get;

	len = 0;
	ptr = cmd;

	if(json)
		snprintf(json_msg, sizeof(json_msg), "json_msg");
	else
		snprintf(json_msg, sizeof(json_msg), "*");

	snprintf(ptr, sizeof(cmd)-len, "SELECT %s FROM %s", json_msg, DIAG_TAB_NAME);
	len = strlen(cmd);
	ptr = cmd+len;

	if((event && *event) || (node_ip && *node_ip) || (node_mac && *node_mac)){
		snprintf(ptr, sizeof(cmd)-len, " where ");
		len = strlen(cmd);
		ptr = cmd+len;
	}

	if(event && *event){
		snprintf(ptr, sizeof(cmd)-len, "event_name like '%s'", event);
		len = strlen(cmd);
		ptr = cmd+len;

		need_and = 1;
	}

	if(node_ip && *node_ip){
		if(need_and){
			snprintf(ptr, sizeof(cmd)-len, " AND ");
			len = strlen(cmd);
			ptr = cmd+len;
		}

		snprintf(ptr, sizeof(cmd)-len, "node_ip like '%s'", node_ip);
		len = strlen(cmd);
		ptr = cmd+len;

		need_and = 1;
	}

	if(node_mac && *node_mac){
		if(need_and){
			snprintf(ptr, sizeof(cmd)-len, " AND ");
			len = strlen(cmd);
			ptr = cmd+len;
		}

		snprintf(ptr, sizeof(cmd)-len, "node_mac like '%s'", node_mac);
		len = strlen(cmd);
		ptr = cmd+len;

		need_and = 1;
	}

	if (specific_ts) {
		if(need_and){
			snprintf(ptr, sizeof(cmd)-len, " AND ");
			len = strlen(cmd);
			ptr = cmd+len;
		}

		snprintf(ptr, sizeof(cmd)-len, "time >= %lu", specific_ts);
		len = strlen(cmd);
		ptr = cmd+len;

		need_and = 1;
	}

	fprintf(stdout, "cmd=%s.\n", cmd);
	ret = sqlite3_get_table(db, cmd, raw, row_count, field_count, &zErr);
	if(zErr != NULL){
		DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
		sqlite3_free(zErr);
	}

FINISHED_get:
	if(openned_file == SQLITE_OK)
		sqlite3_close(db);

	if(lock > 0)
		file_unlock(lock);

	return ret;
}

int get_data_from_diag2(unsigned long start_ts, unsigned long end_ts, const char *event, const char *node_ip, const char *node_mac, int json,
		json_result_t **json_result) {
	int lock = -1;
	sqlite3 *db = NULL;
	char json_msg[10];
	int need_and = 0;
	char cmd[PATH_MAX], *ptr;
	int len;
	char *zErr = NULL;
	struct dirent **filelist;
	json_result_t **tmp_json_result = NULL;
	int i, n;
	unsigned long start_zt, end_zt;

	fprintf(stderr, "diag_dbg=%d\n", diag_dbg);

	if(event && *event && !is_valid_event(event))
		goto FINISHED_get;

	if((lock = file_lock(DIAG_FILE_LOCK)) == -1)
		goto FINISHED_get;

	/*if (!end_ts)
		end_ts = ULONG_MAX;*/

	n = scandir(DIAG_DB_DIR, &filelist, 0, special_alphasort);
	if (n < 0)
		DIAG_LOG(LOG_INFO, "scandir fiailed. %s", strerror(errno));
	else {
		tmp_json_result = json_result;
		for (i = 0; i < n; i++) {
			unsigned long ts1, ts2;
			int ts_count = 0;

			DIAG_LOG(LOG_INFO, "%s", filelist[i]->d_name);

			if (!strcmp(filelist[i]->d_name, ".") || !strcmp(filelist[i]->d_name, ".."))
				goto NEXT_FILE;

			// If not start with conn_diag_, skip it.
			if (strncmp(filelist[i]->d_name, "conn_diag_", 10))
				goto NEXT_FILE;

			ts_count = get_ts_from_db_name(filelist[i]->d_name, &ts1, &ts2);
			if (ts_count != 1 && ts_count != 2)
				goto NEXT_FILE;

			if (ts_count == 1)
				ts2 = ts1 + 86400;

			start_zt = getZeroTimeonDay(start_ts);
			end_zt = getZeroTimeonDay(end_ts);
			if ((end_ts == 0 && start_ts <= ts2) || 
				(end_ts > 0 && 
					((ts_count == 1 && (ts1 == start_zt || (ts1 <= start_ts && ts2 >= end_ts))) || 
					(start_zt < ts1 && ts1 < end_zt) || 
					(ts_count == 2 && ((ts1 == start_zt && ts2 >= start_ts) || (ts1 == end_zt && ts2 <= end_ts)))
					))) {
				char db_path[PATH_MAX];
				int ret;
				int row_count, field_count;
				char **raw;
				snprintf(db_path, sizeof(db_path), "%s/%s", DIAG_DB_DIR, filelist[i]->d_name);
				//DIAG_LOG(LOG_INFO, "db_path=%s\n", db_path);
				ret = sqlite3_open(db_path, &db);
				if(ret != SQLITE_OK){
					DIAG_LOG(LOG_INFO, "Can't open database %s", sqlite3_errmsg(db));
					goto NEXT_FILE;
				}

				len = 0;
				ptr = cmd;

				if(json)
					snprintf(json_msg, sizeof(json_msg), "json_msg");
				else
					snprintf(json_msg, sizeof(json_msg), "*");

				snprintf(ptr, sizeof(cmd)-len, "SELECT %s FROM %s", json_msg, DIAG_TAB_NAME);
				len = strlen(cmd);
				ptr = cmd+len;

				if((event && *event) || (node_ip && *node_ip) || (node_mac && *node_mac)){
					snprintf(ptr, sizeof(cmd)-len, " where ");
					len = strlen(cmd);
					ptr = cmd+len;
				}

				if(event && *event){
					snprintf(ptr, sizeof(cmd)-len, "event_name like '%s'", event);
					len = strlen(cmd);
					ptr = cmd+len;

					need_and = 1;
				}

				if(node_ip && *node_ip){
					if(need_and){
						snprintf(ptr, sizeof(cmd)-len, " AND ");
						len = strlen(cmd);
						ptr = cmd+len;
					}

					snprintf(ptr, sizeof(cmd)-len, "node_ip like '%s'", node_ip);
					len = strlen(cmd);
					ptr = cmd+len;

					need_and = 1;
				}

				if(node_mac && *node_mac){
					if(need_and){
						snprintf(ptr, sizeof(cmd)-len, " AND ");
						len = strlen(cmd);
						ptr = cmd+len;
					}

					snprintf(ptr, sizeof(cmd)-len, "node_mac like '%s'", node_mac);
					len = strlen(cmd);
					ptr = cmd+len;

					need_and = 1;
				}

				if (start_ts) {
					if(need_and){
						snprintf(ptr, sizeof(cmd)-len, " AND ");
						len = strlen(cmd);
						ptr = cmd+len;
					}

					snprintf(ptr, sizeof(cmd)-len, "time >= %lu", start_ts);
					len = strlen(cmd);
					ptr = cmd+len;

					need_and = 1;
				}

				if (end_ts) {
					if(need_and){
						snprintf(ptr, sizeof(cmd)-len, " AND ");
						len = strlen(cmd);
						ptr = cmd+len;
					}

					snprintf(ptr, sizeof(cmd)-len, "time < %lu", end_ts);
					len = strlen(cmd);
					ptr = cmd+len;

					need_and = 1;
				}

				DIAG_LOG(LOG_INFO, "cmd=%s.", cmd);
				ret = sqlite3_get_table(db, cmd, &raw, &row_count, &field_count, &zErr);
				if(zErr != NULL){
					DIAG_LOG(LOG_DEBUG, "SQL error: %s", zErr);
					sqlite3_free(zErr);
					sqlite3_close(db);
					goto NEXT_FILE;
				}

				if (!row_count) {
					sqlite3_free_table(raw);
					DIAG_LOG(LOG_INFO, "no data in db.");
				} else {
					if (!(*tmp_json_result))
						*tmp_json_result = (json_result_t *)malloc(sizeof(json_result_t));

					snprintf((*tmp_json_result)->db_path, sizeof((*tmp_json_result)->db_path), "%s", filelist[i]->d_name);
					(*tmp_json_result)->row_count = row_count;
					(*tmp_json_result)->col_count = field_count;
					(*tmp_json_result)->result = raw;
					(*tmp_json_result)->next = NULL;
					while(*tmp_json_result != NULL)
						tmp_json_result = &((*tmp_json_result)->next);
					DIAG_LOG(LOG_INFO, "%d data in db.", row_count);
				}

				sqlite3_close(db);
			}

NEXT_FILE:
			free(filelist[i]);
		}
		free(filelist);
	}

FINISHED_get:

	if(lock > 0)
		file_unlock(lock);

	return SQLITE_OK;
}

void free_json_result(json_result_t **json_result) {
	json_result_t *tmp_to_free, *tmp;
	if (!json_result)
		return;

	tmp_to_free = *json_result;
	while (tmp_to_free) {
		sqlite3_free_table(tmp_to_free->result);
		tmp = tmp_to_free;
		tmp_to_free = tmp_to_free->next;
		free(tmp);
	}
}

int get_sql_on_day(unsigned long specific_ts, const char *event, const char *node_ip, const char *node_mac,
		int *row_count, int *field_count, char ***raw){
	int ret = get_data_from_diag(specific_ts, event, node_ip, node_mac, 0, row_count, field_count, raw);

	return ret;
}

int get_json_on_day(unsigned long specific_ts, const char *event, const char *node_ip, const char *node_mac,
		int *row_count, int *field_count, char ***raw){
	int ret = get_data_from_diag(specific_ts, event, node_ip, node_mac, 1, row_count, field_count, raw);

	return ret;
}

int get_json_in_period(unsigned long start_ts, unsigned long end_ts, const char *event, const char *node_ip, const char *node_mac,
		json_result_t **json_result){
	int ret = get_data_from_diag2(start_ts, end_ts, event, node_ip, node_mac, 1, json_result);

	return ret;
}

int merge_data_in_sql(const char *dst_file, const char *src_file){
	sqlite3 *db;
	char cmd[PATH_MAX], *zErr;
	int ret;

	ret = sqlite3_open(dst_file, &db);
	if(ret != SQLITE_OK)
		DIAG_LOG(LOG_INFO, "Can't open database %s\n", sqlite3_errmsg(db));

	if(ret == SQLITE_OK){
		snprintf(cmd, sizeof(cmd), "ATTACH DATABASE '%s' AS other;", src_file);
		ret = sqlite3_exec(db, cmd, NULL, NULL, &zErr);
		if(zErr != NULL){
			DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
			sqlite3_free(zErr);
		}
	}

	if(ret == SQLITE_OK){
		snprintf(cmd, sizeof(cmd), "INSERT INTO %s select * from other.%s;", DIAG_TAB_NAME, DIAG_TAB_NAME);
		ret = sqlite3_exec(db, cmd, NULL, NULL, &zErr);
		if(zErr != NULL){
			DIAG_LOG(LOG_DEBUG, "SQL error: %s\n", zErr);
			sqlite3_free(zErr);
		}
	}

	sqlite3_close(db);

	return ret;
}
