/*
 * Copyright 2018, ASUSTeK Inc.
 * All Rights Reserved.

	watchdog_check.c for rc/watchdog.c
	purpose : built in shared library for avoiding third party porting
*/

#include "bwdpi.h"

/*
	signature protection function
	1 : allowd
	0 : forbidden
*/
static int bwdpi_signature_protection()
{
	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return 0;
	}

	if (check_bwdpi_nvram_setting() == 0) return 0;

	char dpi[16];
	char sig[16];
	char *a = NULL, *b = NULL, *c = NULL;
	char *d = NULL, *e = NULL;
	int i = 0 ,j = 0, k = 0;
	int m = 0, n = 0;

	strlcpy(dpi, nvram_safe_get("bwdpi_dpi_ver"), sizeof(dpi));
	strlcpy(sig, nvram_safe_get("bwdpi_sig_ver"), sizeof(sig));

	BWSIG_DBG("signature protection starting!");

	if (model_protection() == 0) {
		BWSIG_DBG("NOT to support this model");
		return 0;
	}

	if ((vstrsep(dpi, ".", &a, &b, &c)) != 3) {
		BWSIG_DBG("DPI engine version WRONG format");
		return 0;
	}

	if ((vstrsep(sig, ".", &d, &e)) != 2) {
		BWSIG_DBG("SIG version WRONG format");
		return 0;
	}

	i = atoi(a);
	j = atoi(b);
	k = atoi(c);
	m = atoi(d);
	n = atoi(e);

	BWSIG_DBG("i=%d, j=%d, k=%d, m=%d, n=%d", i, j, k , m, n);

	if (i == 0 && j == 0) {
		// kernel dependent version
		BWSIG_DBG("DEP module");
		if (m == 1)
			return 1;
		else {
			BWSIG_DBG("DEP module : NOT to support fullset signature\n");
			return 0;
		}
	}
	else if (i > 0 || j > 0) {
		// kernel independent version
		BWSIG_DBG("INDEP module\n");
		if (m > 1)
			return 1;
		else {
			BWSIG_DBG("DEP module : MUST use fullset signature\n");
			return 0;
		}
	}
	else {
		// do nothing
		BWSIG_DBG("engine version is ILLEGAL!!\n");
		return 0;
	}

	return 1;
}

/*
	signature update via shell script
*/
void auto_sig_check()
{
	static int period = 5757;
	static int bootup_check = 1;
	static int periodic_check = 0;
	int cycle_manual = nvram_get_int("sig_check_period");
	int cycle = (cycle_manual > 1) ? cycle_manual : 5760;
	time_t now;
	struct tm *tm;

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	if (!nvram_get_int("ntp_ready"))
		return;

	if (!bootup_check && !periodic_check)
	{
		time(&now);
		tm = localtime(&now);

		if ((tm->tm_hour == 2))	// every 48 hours at 2 am
		{
			periodic_check = 1;
			period = -1;
		}
	}

	if (bootup_check || periodic_check)
		period = (period + 1) % cycle;
	else
		return;

	if (!bwdpi_signature_protection()) {
		BWSIG_DBG("signature protection return 0\n");
		return;
	}

	if (!period)
	{
		if (bootup_check)
			bootup_check = 0;

		eval("/usr/sbin/sig_update.sh");

		if (nvram_get_int("sig_state_update") &&
		    !nvram_get_int("sig_state_error") &&
		    strlen(nvram_safe_get("sig_state_info")))
		{
			BWSIG_DBG("retrieve sig information\n");

			if (!nvram_get_int("sig_state_flag"))
			{
				BWSIG_DBG("NOT need to upgrade signature\n");
				return;
			}

			nvram_set_int("auto_sig_upgrade", 1);

			eval("/usr/sbin/sig_upgrade.sh");

			if (nvram_get_int("sig_state_error"))
			{
				BWSIG_DBG("FAIL to execute sig_upgrade.sh\n");
				goto ERROR;
			}
		}
		else
			BWSIG_DBG("CAN'T retrieve sig information\n");
ERROR:
		nvram_set_int("auto_sig_upgrade", 0);
	}
}

/*
	save web history database
*/
void web_history_save()
{
	static int period = 0;
	int cycle = 4;

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	// step1. check web history enable or not
	if (nvram_get_int("bwdpi_wh_enable") == 0 || dump_dpi_support(INDEX_WEB_HISTORY) == 0) {
		BWSQL_LOG("web history function disabled");
		return;
	}

	// step2. check ntp sync
	if (!nvram_get_int("ntp_ready")) {
		BWSQL_LOG("NTP isn't ready");
		return;
	}

	// step3. do cycle
	period = (period + 1) % cycle;

	// step4. save web history database
	if (!period)
	{
		eval("WebHistory", "-e");
		eval("WebHistory", "-s", BWDPI_HIS_DB_SIZE);
		BWSQL_LOG("SAVE database");
	}
}

#define MON_CHECK_FILE    "/tmp/MON_CHECK_FILE"
static int check_db_index(const char *path, const char *key)
{
	int ret = 0;
	char buf[100] = {0};

	// DB doesn't exist
	if (!f_exists(path)) return 1;

	snprintf(buf, sizeof(buf), "echo -n `cat %s | grep %s` > %s", path, key, MON_CHECK_FILE);
	system(buf);
	memset(buf, 0, sizeof(buf));
	if (f_read_string(MON_CHECK_FILE, buf, sizeof(buf) > 0)) {
		ret = 2;
	}

	// remove MON_CHECK_FILE
	if (f_exists(MON_CHECK_FILE)) unlink(MON_CHECK_FILE);

	BWMON_DBG(" path=%s, key=%s, ret=%d\n", path, key, ret);

	return ret;
}

/*
	AiProetecion v2.0
*/
void AiProtectionMonitor_mail_log()
{
	static int period = 0;
	int cycle = 4; // 4*30 = 120 sec
	int is_first = 1;

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	if (check_bwdpi_nvram_setting() == 0)
	{
		return ;
	}

	// step1. check ntp sync
	if (!nvram_get_int("ntp_ready"))
	{
		BWMON_LOG("NTP isn't ready\n");
		return;
	}

	// step2. do cycle
	period = (period + 1) % cycle;

	// step3. save Mals / CC / IPS database
	if (check_wrs_switch() && (!period))
	{
		char tt[16];
		time_t now;

		time(&now);
		snprintf(tt, sizeof(tt), "%lu", now);

		if (is_first) {
			if (check_db_index(BWDPI_MON_DB, "cat_id") == 0) {
				eval("AiProtectionMonitor", "-r"); // rename db
				BWMON_DBG(" update db with new old with cat_id\n");
			}
			is_first = 0;
		}

		eval("AiProtectionMonitor", "-e");
		if (nvram_get_int("wrs_mail_bit")) {
			eval("AiProtectionMonitor", "-l", "-t", tt);
		}
		eval("AiProtectionMonitor", "-s", BWDPI_MON_DB_SIZE);
		BWMON_LOG("Save database");
	}
}

#define MAX_COUNT 15
void tm_eula_check()
{
	char *cmd[] = {"shn_ctrl", "-a", "set_eula_agreed", NULL};
	int pid;
	int count = 0;

	int is_eula = nvram_get_int("TM_EULA");

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	if (check_bwdpi_nvram_setting() == 0) {
		return;
	}

	if (f_exists(DCD_EULA) || !pids(DATACOLLD) || is_eula == 0) {
		return;
	}

	if (is_eula) {
		while (count < MAX_COUNT) {
			BWDPI_DBG("check eula, count=%d ...\n", count);
			_eval(cmd, NULL, 0, &pid);
			sleep(1);
			count++;
			if (f_exists(DCD_EULA)) {
				BWDPI_DBG("set_eula_agreed ...\n");
				break;
			}
			if (count == MAX_COUNT) {
				BWDPI_DBG("check_eula timeout ...\n");
				break;
			}
		}
	}
}
