/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include <shared.h>
#include "auto_det.h"

#define ATM_DETECT_FILE     "/www/Detect_list.txt"
#define ATM_DETECT_PVC_MAX  8
#define ATM_DETECT_LIST_MAX 80

static int do_term = 0;
static int do_alrm = 0;

atm_pvc_t atm_detect_list[ATM_DETECT_LIST_MAX];

void atm_load_detect_list()
{
	FILE *fp;
	int i = 0, j = 0;
	char buf[32] = {0};
	int skip_pvc_set = 0;

	fp = fopen(ATM_DETECT_FILE, "r");
	if (fp)
	{
		memset(atm_detect_list, 0, sizeof(atm_detect_list));
		while (fgets(buf, sizeof(buf), fp))
		{
			if (i == ATM_DETECT_LIST_MAX)
			{
				printf("AUTODET: pvc list array too small\n");
				break;
			}
			if ( 4 != sscanf(buf, "%d,%d,%d,%d",
				&atm_detect_list[i].vpi, &atm_detect_list[i].vci, &atm_detect_list[i].proto, &atm_detect_list[i].encap))
			{
				printf("AUTODET: read pvc list file failed\n");
				continue;
			}

			//handle pppoe and dhcp only.
			if (atm_detect_list[i].proto == ATM_PROTO_PPPOE || atm_detect_list[i].proto == ATM_PROTO_DHCP)
			{
				// detect pppoe and dhcp concurrently. skip same vpi,vci,encap
				skip_pvc_set = 0;
				for (j = 0; j < i; j++)
				{
					if (atm_detect_list[j].vpi == atm_detect_list[i].vpi
					 && atm_detect_list[j].vci == atm_detect_list[i].vci
					 && atm_detect_list[j].encap == atm_detect_list[i].encap)
					{
						skip_pvc_set = 1;
						break;
					}
				}
				if (skip_pvc_set)
					continue;
				else
					i++;
			}
		}
		fclose(fp);
	}
}

void atm_auto_det(const char* list_file)
{
	int i, j;
	int detect_result = DSL_AUTODET_STATE_FAIL;
	int got_inf = 0;

	set_atm_pvc_result(0, 0, 0);

	// load detect pvc list
	atm_load_detect_list();

	// detect
	for (i = 0; atm_detect_list[i].vci != 0 && do_term != 1; i += ATM_DETECT_PVC_MAX)
	{
		char iface[ATM_DETECT_PVC_MAX][16] = {0};
		const char *detect_ifnames[ATM_DETECT_PVC_MAX];
		char cmd[128] = {0};

		// create atm interface
		for (j = 0; j < ATM_DETECT_PVC_MAX && atm_detect_list[i+j].vci != 0; j++)
		{
			//printf("%d: %d,%d,%d,%d\n", i+j, atm_detect_list[i+j].vpi, atm_detect_list[i+j].vci, atm_detect_list[i+j].proto, atm_detect_list[i+j].encap);
			create_atm_intf(&atm_detect_list[i+j], iface[j], sizeof(iface[j]));
			snprintf(cmd, sizeof(cmd), "ifconfig %s up", iface[j]);
			system(cmd);
		}

		// detect
		for (j = 0; j < ATM_DETECT_PVC_MAX; j++)
			detect_ifnames[j] = iface[j];
		detect_result = discover_interfaces(ATM_DETECT_PVC_MAX, detect_ifnames, 1, &got_inf);
		printf("detect_result: %d %d\n", detect_result, got_inf);

		// delete atm interface
		for (j = 0; j < ATM_DETECT_PVC_MAX && atm_detect_list[i+j].vci != 0; j++)
		{
			delete_atm_intf(&atm_detect_list[i+j], iface[j]);
		}

		if (detect_result > 0)
		{
			printf("\n=====\ndetect: %d.%d.%d, result: %d\n=====\n"
				, atm_detect_list[i+got_inf].vpi
				, atm_detect_list[i+got_inf].vci
				, atm_detect_list[i+got_inf].encap
				, detect_result);
			set_atm_pvc_result(atm_detect_list[i+got_inf].vpi, atm_detect_list[i+got_inf].vci, atm_detect_list[i+got_inf].encap);
			//transfer result
			if (detect_result >= 2)
				detect_result = DSL_AUTODET_STATE_PPPOE;
			else
				detect_result = DSL_AUTODET_STATE_DHCP;
			break;
		}
		else
		{
			detect_result = DSL_AUTODET_STATE_FAIL;
		}
	}

	set_autodet_state(detect_result);
}

void stop_dslwan()
{
	char *rc_service = NULL;
#if defined(RTCONFIG_DUALWAN)
	if (get_dualwan_secondary() == WANS_DUALWAN_IF_DSL)
		rc_service = "stop_dslwan_if 1";
	else
		rc_service = "stop_dslwan_if 0";
#else
	rc_service = "stop_dslwan_if 0";
#endif
	notify_rc(rc_service);
}

void start_dslwan()
{
	char *rc_service = NULL;
#if defined(RTCONFIG_DUALWAN)
	if (get_dualwan_secondary() == WANS_DUALWAN_IF_DSL)
		rc_service = "start_dslwan_if 1";
	else
		rc_service = "start_dslwan_if 0";
#else
	rc_service = "start_dslwan_if 0";
#endif
	notify_rc(rc_service);
}

void eth_auto_det()
{
	char iface[16] = {0};
	int detect_result = 0;

	get_eth_wan_interface(iface, sizeof(iface));

	detect_result = discover_interface(iface, 1);

	printf("detect: %s result: %d\n", iface, detect_result);

	if (detect_result == 1)
		set_autodet_state_eth(AUTODET_STATE_FINISHED_OK, AUTODET_STATE_FINISHED_OK);
	else if (detect_result == 2)
		set_autodet_state_eth(AUTODET_STATE_FINISHED_WITHPPPOE, AUTODET_STATE_FINISHED_OK);
	else if (detect_result == 3)
		set_autodet_state_eth(AUTODET_STATE_FINISHED_OK, AUTODET_STATE_FINISHED_WITHPPPOE);
	else
		set_autodet_state_eth(AUTODET_STATE_FINISHED_FAIL, AUTODET_STATE_FINISHED_FAIL);
}

void signal_handler(int signum)
{
	if (signum == SIGTERM || signum == SIGINT)
		do_term = 1;
	else if (signum == SIGALRM)
	{
		if(do_alrm == 0)
			do_alrm = 1;
	}
	else
		printf("AUTODET: ignore signal: %d\n", signum);
}

static void alarmtimer(unsigned long sec, unsigned long usec)
{
	struct itimerval itv;

	itv.it_value.tv_sec = sec;
	itv.it_value.tv_usec = usec;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static void reg_signal()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &signal_handler;
	
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	alarmtimer(5, 0);
}

int main (int argc, char **argv)
{
	autodet_conf_t config;

	memset(&config, 0, sizeof(config));
	init_config(&config);

	reg_signal();

	set_autodet_state_eth(AUTODET_STATE_INITIALIZING, AUTODET_STATE_INITIALIZING);
	set_autodet_state(DSL_AUTODET_STATE_DETECTING);

	while(1)
	{
		if (config.wans_cap & WANSCAP_WAN && is_eth_wan_link_up())
			config.wans_l2det |= WANSCAP_WAN;

		if (config.wans_cap & WANSCAP_DSL && is_dsl_plugged())
			config.wans_l2det |= WANSCAP_DSL;

		// wait DSL only until new multi-wan QIS.
		if (config.wans_l2det & WANSCAP_DSL)
			break;

		pause();
		if(do_term)
		{
			set_autodet_state_eth(AUTODET_STATE_FINISHED_NOLINK, AUTODET_STATE_FINISHED_OK);
			set_autodet_state(DSL_AUTODET_STATE_NOLINK);
			goto END;
		}
	}

	// ETH WAN
	if (config.wans_l2det & WANSCAP_WAN)
	{
		eth_auto_det();
	}
	else
	{
		set_autodet_state_eth(AUTODET_STATE_FINISHED_NOLINK, AUTODET_STATE_FINISHED_OK);
	}

	// DSL
	if (config.wans_l2det & WANSCAP_DSL)
	{
		while (!is_dsl_link_up())
		{
			pause();
			if(do_term)
				goto END;
		}

		if (is_vdsl())
		{
			set_wan_type(DSL_AUTODET_WAN_TYPE_PTM);
		}
		else
		{
			set_wan_type(DSL_AUTODET_WAN_TYPE_ATM);

			// stop dslwan
			stop_dslwan();

			// atm auto detection
			atm_auto_det(ATM_DETECT_FILE);

			// restore dslwan
			start_dslwan();
		}
	}
	else
	{
		set_autodet_state(DSL_AUTODET_STATE_NONE);
	}

END:
	return 0;
}
