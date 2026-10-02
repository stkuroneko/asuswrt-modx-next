#include "rc.h"

#ifdef RTCONFIG_DSL_BCM
#include <sys/sysinfo.h>
#endif

#define DIAG	"DSL Diagnostic"

#ifdef RTCONFIG_DSL_TCLINUX
#define DEFAULT_TCC_INI_FILE	"/tmp/adsl/TCC.INI"
void generate_tcc_ini(int);
#endif

void stop_dsl_diag(void)
{
#if defined(RTCONFIG_DSL_TCXLINUX)
	eval("req_dsl_drv", "runtcc");
	if(check_if_file_exist(DEFAULT_TCC_INI_FILE))
		unlink(DEFAULT_TCC_INI_FILE);
	eval("req_dsl_drv", "dumptcc");
#elif defined(RTCONFIG_DSL_BCM)
	killall_tk("dsl_diag");
#endif

	if(nvram_match("dslx_diag_state", "2")) {	//run TCC.INI completed
#ifdef RTCONFIG_FRS_FEEDBACK
		//send diag mail
		if (fork() == 0)
		{
			sleep(10);
			while (nvram_get_int("link_internet") != 2)
				sleep(1);
			start_sendDSLdiag();
			if (nvram_get_int("dsltmp_diag_confxdsl"))
				config_xdsl();
		}
#endif
	}
	else if(nvram_match("dslx_diag_state", "6")) {	//run TCC.INI fail
		;//notification
	}
	else {
		nvram_set("dslx_diag_state", "0");
	}
	nvram_set("dslx_diag_enable", "0");
	nvram_commit();
	if (nvram_get_int("dslx_diag_state") != 2 && nvram_get_int("dsltmp_diag_confxdsl"))
		config_xdsl();
}

int start_dsl_diag(void)
{
	char *mnt_dir = nvram_safe_get("dsltmp_diag_log_path");
	char diag_log_dir[256] = {0};
	char file_path[512] = {0};
	int duration = 3600;
	char *fb_availability;

	if(!mnt_dir) {
		logmessage(DIAG, "check failed");
		return -1;
	}
	if(!check_if_dir_exist(mnt_dir)) {
		logmessage(DIAG, "No USB disk mounted");
		return -1;
	}

	snprintf(diag_log_dir, sizeof(diag_log_dir), "%s/%s", mnt_dir, DSL_DIAG_DIR);
	_dprintf("%s: log path: %s\n", __FUNCTION__, diag_log_dir);

	if(!check_if_dir_exist(diag_log_dir)) {
		if(mkdir(diag_log_dir, 0777)) {
			logmessage(DIAG, "Create diagnostic directory failed");
			return -1;
		}
	}

#ifdef RTCONFIG_DSL_TCLINUX
	eval("req_dsl_drv", "dla", "off");
#endif

	nvram_set("dslx_diag_state", "1");
	nvram_commit();	//diagnostic takes long time and may reboot/power cycle... restart by state

	if (0 == (duration = nvram_get_int("dslx_diag_duration_dbg")))
	{
		duration = nvram_get_int("dslx_diag_duration");
		fb_availability = nvram_safe_get("fb_availability");

		if(!duration) {
			if(!strncmp(fb_availability, "Occasional_interruptions", 2))
				duration = 86400;
			else if(!strncmp(fb_availability, "Frequent_interruptions", 2))
				duration = 43200;
			else
				duration = 3600;
		}
	}

	snprintf(file_path, sizeof(file_path), "%s/%s", diag_log_dir, DSL_DIAG_FILE);

#ifdef RTCONFIG_DSL_TCLINUX
	eval("req_dsl_drv", "dumptcc", file_path);

	snprintf(file_path, sizeof(file_path), "%s/TCC.ini", diag_log_dir);
	if(check_if_file_exist(file_path)) {
		return eval("req_dsl_drv", "runtcc", file_path);
	}

	snprintf(file_path, sizeof(file_path), "%s/TCC.INI", diag_log_dir);
	if(check_if_file_exist(file_path)) {
		return eval("req_dsl_drv", "runtcc", file_path);
	}

	generate_tcc_ini(duration);
	return eval("req_dsl_drv", "runtcc", DEFAULT_TCC_INI_FILE);
#endif
#ifdef RTCONFIG_DSL_BCM
	struct sysinfo si;
	char d_str[16] = {0};
	char *dsl_diag_argv[] = {"dsl_diag", "-d", d_str, "-o", file_path, NULL, NULL};
	int pid;

	killall_tk("dsl_diag");
	sysinfo(&si);
	nvram_set_int("dslx_diag_end_uptime", duration + si.uptime + 30);
	snprintf(d_str, sizeof(d_str), "%d", duration);
	if (duration > 3600 && nvram_get_int("dslx_diag_duration") == 0)
		dsl_diag_argv[5] = "-r";

	return _eval(dsl_diag_argv, NULL, 0, &pid);
#endif
}

#ifdef RTCONFIG_DSL_TCLINUX
void generate_tcc_ini(int common_delay_time)
{
	FILE *fp;
	fp = fopen(DEFAULT_TCC_INI_FILE, "w");
	if(fp) {
		fputs(
			"<DIAG ACTION>\r\n"

			"w tc sh fw\r\n"
			"@delay 2\r\n"
			"w dmt set debug 1\r\n"
			"w rt db on\r\n"
			"@delay 2\r\n"
			"w ad cl\r\n"
			"@delay 2\r\n"

			"w ad r\r\n"
			"@delay 240\r\n"
			"w rt db off\r\n"
			"@delay 1\r\n"
			"w ad diag\r\n"
			"@delay 60\r\n"
			"w hwdmt afe sh param\r\n"
			"@delay 2\r\n"
			"w rt db on\r\n"
			, fp);

		fprintf(fp, "@delay %d\r\n", common_delay_time);

		fputs(
			"w ad p\r\n"
			"@delay 1\r\n"
			"w rt db off\r\n"

			"</DIAG ACTION>\r\n"
			, fp);

		fclose(fp);
	}
	else
		logmessage(DIAG, "Generate TCC.INI failed");
}
#endif
