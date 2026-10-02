/*
 * Copyright 2019, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

/* Adaptive Bandwidth Control */

#include <stdio.h>
#include <rc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <wlioctl.h>
#include <wlutils.h>
#include "amas_adtbw.h"

static struct itimerval itv;
static int amas_adtbw_tick = 0;
static int amas_adtbw_hit_cnt = 0;
static chanspec_t chanspec_pre = 0;
static int conduct_bgdfs = 0;
static int dfs_radar_detect = 0;
#ifdef RTCONFIG_ADTBW_AFTER_RADARDETECTED
int amas_adtbw_skip;
static int dfs_radar_detect_tick=0;
static int dfs_radar_detect_with_extend_v1=0;
static int dfs_radar_check_interval_cnt = 0;
#endif //RTCONFIG_ADTBW_AFTER_RADARDETECTED

static void alarmtimer(unsigned long sec, unsigned long usec)
{
	itv.it_value.tv_sec  = sec;
	itv.it_value.tv_usec = usec;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static void amas_adtbw_led_ctrl(void)
{
	time_t now = uptime();
	time_t gap = 0;

	adtbw_state.led_state = LED_NO_ACTION;
	/* Warm Up stage. persist led solid green at least [AMAS_ADTBW_DFT_TIMEOUT_WARM_UP] seconds */
	if(adtbw_state.first_re_assoc && now > adtbw_state.time_first_re_assoc) {
	    gap = now - adtbw_state.time_first_re_assoc;
	    if(gap <= AMAS_ADTBW_DFT_TIMEOUT_WARM_UP && !conduct_bgdfs && !nvram_get_int("amas_adtbw_bw160")) {
		adtbw_state.led_state = LED_WARM_UP;
	    }
	}

	/* CAC(ZWDFS) stage. persist led solid green until CAC complete or abort */
	if(conduct_bgdfs) {
	    adtbw_state.led_state = LED_CAC;
	}

	/* 160MHz stage. persist led solid green until RE reconect or timeout */
	if(nvram_get_int("amas_adtbw_bw160")) {
	    gap = now - adtbw_state.time_switch_160m;
	    if(gap < AMAS_ADTBW_DFT_POLL_INTERVAL) { // add delay to update re_count
		adtbw_state.led_state = LED_BW160;
	    }
	    else if(gap <= AMAS_ADTBW_DFT_TIMEOUT_SWITCH && !adtbw_state.re_count) {
		adtbw_state.led_state = LED_BW160;
	    }
	}

	if(adtbw_state.led_state != LED_NO_ACTION){
	    nvram_set("amas_adtbw_led", "1");
	}
	else
	    nvram_unset("amas_adtbw_led");
}

static void amas_adtbw_exit(int sig)
{
	alarmtimer(0, 0);
	nvram_unset("amas_adtbw_led");
	nvram_unset("amas_adtbw_bw160");
	dbG("amas_adtbw exit...\n");
	remove("/var/run/amas_adtbw.pid");
	exit(0);
}



static void amas_adtbw_monitor(int sig)
{
	chanspec_t chanspec;
	int sw_imdtly = 0;
	int ret = AMAS_ADTBW_BW_SWITCH_SUCCESS;

	amas_adtbw_led_ctrl();


#ifdef RTCONFIG_ADTBW_AFTER_RADARDETECTED
	int to_160=0;
	char abtbw_prefix[16];
	char abtbw_chanspec[32];
	int abtbw_bw;
	int abtbw_bw_cap;
	uint8 channel_cur;
	chanspec_t user_chanspec;

	if( dfs_radar_detect_with_extend_v1 ) {
		dfs_radar_detect_tick = (dfs_radar_detect_tick + 1) % ((adtbw_state.dfs_block_remain * 60));
		if(dfs_radar_detect_tick)
			return;
		//_dprintf("dfs_radar_detect_with_extend_v1 dfs_radar_detect_tick 0\n");
		AMAS_ADTBW_SYSLOG("[ADTBW]Radar timeout\n");
	} else if( dfs_radar_check_interval_cnt > 800 ) {
		dfs_radar_check_interval_cnt = 0;
		if(!dfs_radar_detect_with_extend_v1) {
			if(amas_adtbw_check_radar_stat() == AMAS_ADTBW_BW_SWITCH_RADAR_DET) {
				dfs_radar_detect_tick = 0;
				dfs_radar_detect_with_extend_v1 = 1;
				AMAS_ADTBW_SYSLOG("[ADTBW]Radar detected, wait for radar timeout\n");
				return;
			}
		}
	} else {
		//_dprintf("dfs_radar_check_interval_cnt %d\n",dfs_radar_check_interval_cnt);
		dfs_radar_check_interval_cnt++;
	}

	if( dfs_radar_detect_with_extend_v1 ) {
		//check again
		//_dprintf("dfs_radar_detect_with_extend_v1 check\n");
		if(amas_adtbw_check_radar_stat() == AMAS_ADTBW_BW_SWITCH_RADAR_DET) {
			//_dprintf("dfs_radar_detect_with_extend_v1 again\n");
			AMAS_ADTBW_SYSLOG("[ADTBW]Radar detected again, wait for radar timeout\n");
			dfs_radar_detect_tick = 0;
			dfs_radar_detect_with_extend_v1 = 1;
			return;
		}

		//check chanspec
		snprintf(abtbw_prefix, sizeof(abtbw_prefix), "wl%d_", adtbw_config.unit);
		abtbw_bw = nvram_get_int(strcat_safe(abtbw_prefix, "bw"));
		snprintf(abtbw_chanspec,sizeof(abtbw_chanspec),"%s", nvram_safe_get(strcat_safe(abtbw_prefix, "chanspec")));
		abtbw_bw_cap = nvram_get_int(strcat_safe(abtbw_prefix, "bw_cap"));
		if( abtbw_bw == 0 && !strcmp(abtbw_chanspec,"0") ) {//user all auto
			if(abtbw_bw_cap & 0x8){
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 160\n");
				to_160 = 1;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(CHSPEC_IS160(amas_adtbw_get_chanspec(adtbw_config.ifname)))
				{
					//donothing
				} else {
					ret = amas_adtbw_do_bw_switch_after_radar(chanspec,0, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}
			} else if(abtbw_bw_cap &0x4 ){//80
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 80\n");
				to_160 = 0;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(CHSPEC_IS80(amas_adtbw_get_chanspec(adtbw_config.ifname)))
				{
					//donothing
				} else {
					//_dprintf("dfs_radar_detect_with_extend_v1 amas_adtbw_do_bw_switch_after_radar 80\n");
					ret = amas_adtbw_do_bw_switch_after_radar(chanspec,0, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}
			} else {
				//donothing
			}
		} else if( (abtbw_bw == 5) && !strcmp(abtbw_chanspec,"0") ) { //channel auto bw 160
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 160\n");
				to_160 = 1;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(CHSPEC_IS160(amas_adtbw_get_chanspec(adtbw_config.ifname)))
				{
					//donothing
				} else {
					//_dprintf("dfs_radar_detect_with_extend_v1 amas_adtbw_do_bw_switch_after_radar to_160\n");
					ret = amas_adtbw_do_bw_switch_after_radar(chanspec,0, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}
		} else if( (abtbw_bw == 3) && !strcmp(abtbw_chanspec,"0") ) { //channel auto bw 80
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 80\n");
				to_160 = 0;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(CHSPEC_IS80(amas_adtbw_get_chanspec(adtbw_config.ifname)))
				{
					//donothing
				} else {
					//_dprintf("dfs_radar_detect_with_extend_v1 amas_adtbw_do_bw_switch_after_radar 80\n");
					ret = amas_adtbw_do_bw_switch_after_radar(chanspec,0, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}
		} else if( (abtbw_bw == 5) ) { //bw 160
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 160\n");
				to_160 = 1;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(check_chanspec_if_match_usersetting (adtbw_config.unit,chanspec,&user_chanspec))
				{
					//donothing
				} else {
					//_dprintf("dfs_radar_detect_with_extend_v1 amas_adtbw_do_bw_switch_after_radar to_160\n");
					ret = amas_adtbw_do_bw_switch_after_radar(user_chanspec,1, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}
		} else if( (abtbw_bw == 3) ) { //bw 80
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 80\n");
				to_160 = 0;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(check_chanspec_if_match_usersetting (adtbw_config.unit,chanspec,&user_chanspec))
				{
					//donothing
				} else {
					//_dprintf("dfs_radar_detect_with_extend_v1 amas_adtbw_do_bw_switch_after_radar to 80\n");
					ret = amas_adtbw_do_bw_switch_after_radar(user_chanspec,1, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}			
		} else if( (abtbw_bw == 0) ) { //bw auto
			if(abtbw_bw_cap & 0x8){//160
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 160\n");
				to_160 = 1;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(check_chanspec_if_match_usersetting (adtbw_config.unit,chanspec,&user_chanspec))
				{
					//donothing
				} else {
					//_dprintf("dfs_radar_detect_with_extend_v1 amas_adtbw_do_bw_switch_after_radar to_160\n");
					ret = amas_adtbw_do_bw_switch_after_radar(user_chanspec,1, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}
			} else if(abtbw_bw_cap &0x4 ){//80
				AMAS_ADTBW_SYSLOG("[ADTBW]Try to extend bw to 80\n");
				to_160 = 0;
				chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
				if(check_chanspec_if_match_usersetting (adtbw_config.unit,chanspec,&user_chanspec))
				{
					//donothing
				} else {
					//_dprintf("dfs_radar_detect_with_extend_v1 amas_adtbw_do_bw_switch_after_radar to 80\n");
					ret = amas_adtbw_do_bw_switch_after_radar(user_chanspec,1, to_160);
					AMAS_ADTBW_SYSLOG("[ADTBW]ret %d\n",ret);
				}
			} else if(abtbw_bw_cap &0x2 ){//40
				
			} else {

			}			
		}	
		//if(){
			dfs_radar_detect_with_extend_v1=0;
		//}
	} else {
		if(amas_adtbw_skip)
			return;

#endif //RTCONFIG_ADTBW_AFTER_RADARDETECTED
	if(conduct_bgdfs) {
		if(!amas_adtbw_conduct_cac()) {
			conduct_bgdfs = 0;
			if(CHSPEC_IS160(amas_adtbw_get_chanspec(adtbw_config.ifname))) {
				nvram_set("amas_adtbw_bw160", "1");
				adtbw_state.time_switch_160m = uptime();
			} else
				nvram_set("amas_adtbw_bw160", "0");
		} else {
			return;
		}
	}

	amas_adtbw_tick = (amas_adtbw_tick + 1) % (dfs_radar_detect ? (adtbw_state.dfs_block_remain * 60) : adtbw_config.poll_itval);
	if(amas_adtbw_tick)
	    return;

	AMAS_ADTBW_DBG("-----------------------------------------------\n");
	chanspec = amas_adtbw_get_chanspec(adtbw_config.ifname);
	if(chanspec != chanspec_pre) {
		chanspec_pre = chanspec;
		if(amas_adtbw_hit_cnt)
			amas_adtbw_hit_cnt = 0;
		if(nvram_match("amas_adtbw_bw160", "1") && !CHSPEC_IS160(chanspec))
		    	nvram_set("amas_adtbw_bw160", "0");
	}

	if(dfs_radar_detect) {
	    dfs_radar_detect = 0;
	    adtbw_state.dfs_block_remain = 0;
	}

	if(amas_adtbw_dont_check(chanspec)) {
	    if(amas_adtbw_hit_cnt)
		amas_adtbw_hit_cnt = 0;
	    return;
	}

	if (amas_adtbw_check_bw_switch(chanspec, &sw_imdtly))
		amas_adtbw_hit_cnt++;
	else
	    	amas_adtbw_hit_cnt = 0;
	AMAS_ADTBW_DBG("amas_adtbw_hit_cnt: %d\n", amas_adtbw_hit_cnt);

	if( chanspec_pre == amas_adtbw_get_chanspec(adtbw_config.ifname) && 
	    (amas_adtbw_hit_cnt > (CHSPEC_IS80(chanspec) ? adtbw_config.hit_bw80 : adtbw_config.hit_bw160) || sw_imdtly))
	{
		AMAS_ADTBW_DBG("!!! DO BW SWITCH %s !!!\n", sw_imdtly?"(IMMEDIATELY)":"");
		ret = amas_adtbw_do_bw_switch(chanspec, CHSPEC_IS80(chanspec));
		amas_adtbw_hit_cnt = 0;

		if(CHSPEC_IS80(chanspec) && !sw_imdtly) {
		    if(ret == AMAS_ADTBW_BW_SWITCH_SUCCESS) {
		    	conduct_bgdfs = 1;
			adtbw_state.stop_switch_160m = 1; // only attempt ZWDFS to 160MHz once
		    }
		    else if(ret == AMAS_ADTBW_BW_SWITCH_RADAR_DET) {
			dfs_radar_detect = 1;
			if(!adtbw_state.dfs_block_remain)
			    adtbw_state.dfs_block_remain = 1;
		    }
		}
	}
#ifdef RTCONFIG_ADTBW_AFTER_RADARDETECTED
	}
#endif //RTCONFIG_ADTBW_AFTER_RADARDETECTED
	return;	
}

void stop_amas_adtbw(void)
{
    	if (pids("amas_adtbw"))
	    killall_tk("amas_adtbw");
}

void start_amas_adtbw(void)
{
	char *adtbw_argv[] = {"amas_adtbw", NULL};
	pid_t pid;

	stop_amas_adtbw();
	_eval(adtbw_argv, NULL, 0, &pid);
}

void amas_adtbw_get_config(void)
{
    	char* str;
	char tmp[32];

	if(!strncmp(nvram_safe_get("territory_code"), "US", 2))
	    	adtbw_config.sku = AMAS_ADTBW_SKU_US;
	else if(!strncmp(nvram_safe_get("territory_code"), "EU", 2))
	    	adtbw_config.sku = AMAS_ADTBW_SKU_EU;
	else
	    	adtbw_config.sku = AMAS_ADTBW_SKU_UNSUPPORT;


	str = nvram_safe_get("amas_adtbw_poll_itval");
	adtbw_config.poll_itval = strlen(str) > 0 ? atoi(str) : AMAS_ADTBW_DFT_POLL_INTERVAL;

	if(num_of_wl_if() > 2)
		adtbw_config.unit = 2;
	else
		adtbw_config.unit = 1;

	snprintf(tmp, sizeof(tmp), "wl%d_ifname", adtbw_config.unit);
	snprintf(adtbw_config.ifname, sizeof(adtbw_config.ifname), "%s", nvram_safe_get(tmp));

	str = nvram_safe_get("amas_adtbw_multi_re");
	adtbw_config.multiple_re = strlen(str) > 0 ? atoi(str) : 0;
	str = nvram_safe_get("amas_adtbw_hit_bw80");
	adtbw_config.hit_bw80 = strlen(str) > 0 ? atoi(str) : AMAS_ADTBW_DFT_BW80_HIT_THRESH;
	str = nvram_safe_get("amas_adtbw_hit_bw160");
	adtbw_config.hit_bw160 = strlen(str) > 0 ? atoi(str) : AMAS_ADTBW_DFT_BW160_HIT_THRESH;
	str = nvram_safe_get("amas_adtbw_rssi_bw80");
	adtbw_config.rssi_bw80 = strlen(str) > 0 ? atoi(str) : 
	    ((adtbw_config.sku == AMAS_ADTBW_SKU_EU) ? AMAS_ADTBW_DFT_BW80_RSSI_THRESH_EU : AMAS_ADTBW_DFT_BW80_RSSI_THRESH_US);
	str = nvram_safe_get("amas_adtbw_rssi_bw160");
	adtbw_config.rssi_bw160 = strlen(str) > 0 ? atoi(str) : 
	    ((adtbw_config.sku == AMAS_ADTBW_SKU_EU) ? AMAS_ADTBW_DFT_BW160_RSSI_THRESH_EU : AMAS_ADTBW_DFT_BW160_RSSI_THRESH_US);

	AMAS_ADTBW_DBG("%d:[%s][sku:%d] itval: %d rssi_80: %d, rssi_160: %d, hit_80: %d, hit_160: %d\n",
			adtbw_config.unit,
			adtbw_config.ifname,
			adtbw_config.sku,
			adtbw_config.poll_itval,
			adtbw_config.rssi_bw80,
			adtbw_config.rssi_bw160,
			adtbw_config.hit_bw80,
			adtbw_config.hit_bw160);
}

void amas_adtbw_init_state(void) {

    	nvram_unset("amas_adtbw_led");
	nvram_unset("amas_adtbw_bw160");
	adtbw_state.time_first_re_assoc = time(NULL);
	adtbw_state.time_switch_160m = time(NULL);
	adtbw_state.first_re_assoc = 0;
	adtbw_state.re_count = 0;
	adtbw_state.stop_switch_160m = 0;
	adtbw_state.dfs_block_remain = 0;
}

int amas_adtbw_main(int argc, char *argv[])
{
	FILE *fp;
	sigset_t sigs_to_catch;

	if ((fp = fopen("/var/run/amas_adtbw.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	amas_adtbw_dbg = nvram_get_int("amas_adtbw_dbg");
	amas_adtbw_syslog = nvram_get_int("amas_adtbw_syslog");

	/* retrieve configuration */
	amas_adtbw_get_config();
	amas_adtbw_init_state();

	if (!amas_adtbw_enable())
#ifndef RTCONFIG_ADTBW_AFTER_RADARDETECTED		
		amas_adtbw_exit(0);
#else
	{
		amas_adtbw_skip = 1;
	} else {
		amas_adtbw_skip = 0;
	}

	if(!amas_adtbw_enable_after_radar())
		amas_adtbw_exit(0);

#endif //RTCONFIG_ADTBW_AFTER_RADARDETECTED

	dbG("amas_adtbw start...\n");

        /* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGALRM, amas_adtbw_monitor);
	signal(SIGTERM, amas_adtbw_exit);

	alarmtimer(AMAS_ADTBW_TIMER, 0);

	while (1)
	{
		pause();
	}

	return 0;
}

