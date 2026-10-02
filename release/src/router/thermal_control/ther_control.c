#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>

#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include "autoconf.h"
#include "ther_control.h"

char state_str[STATE_FORCE_PROTECT+1][20] = {"init", "ctrl", "protect", "force", "protect(f)"};
static int output = 0;

//-----------------------------------------------------------------------------------------
struct ther_info_s wlan0 = {
	.name = "wlan0",
	.idx = 0,
};

#if (NUM_WLAN_INTERFACE > 1)
struct ther_info_s wlan1 = {
	.name = "wlan1",
	.idx = 1,
};
#endif

#if (NUM_WLAN_INTERFACE > 2)
struct ther_info_s wlan2 = {
	.name = "wlan2",
	.idx = 2,
};
#endif

struct ther_info_s *wlan[NUM_WLAN_INTERFACE] = { 
	&wlan0
	#if (NUM_WLAN_INTERFACE > 1)
	, &wlan1
	#endif
	#if (NUM_WLAN_INTERFACE > 2)
	, &wlan2 
	#endif
	};

//-----------------------------------------------------------------------------------------
void therctl_outprint(int show, const char *fmt, ...)
{
	static int line_cnt = 0;

	char printf_buf[256], echo_buf[384];
	va_list args;
	time_t curtime;
	int reset = 0;

	va_start(args, fmt);
	vsprintf(printf_buf, fmt, args);
	va_end(args);

	/* output to console */
	if (show) printf("%s", printf_buf);

	/* output to log file */
	if (output) {
		line_cnt++;
		if (line_cnt == 1)  {
			reset = 1;
		}
		else if (line_cnt > MAX_LOG_ENTRY) {
			line_cnt = 0;
			reset = 1;
		}
		time(&curtime);
		sprintf(echo_buf, "echo -n '[%s", ctime(&curtime));
		sprintf(echo_buf+strlen(echo_buf)-1, "] %s' %s %s", printf_buf, reset?">":">>", OUTLOG_PATH);
		system(echo_buf);
	}
}

//-----------------------------------------------------------------------------------------
void thermal_ctl(struct ther_info_s *info, int idx, int value)
{
	int skfd;
	struct iwreq wrq;
	struct ther_func_s *func = &info->func;
	skfd = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(wrq.ifr_name, info->name, IFNAMSIZ);
	
	/* check exist */
	if (ioctl(skfd, SIOCGIWNAME, &wrq) < 0) {
		perror("SIOCGIWNAME, Error: ");
		goto fail;
	}

	func->id = idx;
	func->val = value;

	if (idx == THERCTL_GETVAL && value == THERGETVAL_ALLMIB) {
		wrq.u.data.pointer = (void *)info;
		wrq.u.data.length = sizeof(struct ther_info_s);
	}
	else {
		wrq.u.data.pointer = (void *)func;
		wrq.u.data.length = sizeof(struct ther_func_s);
	}

	if (ioctl(skfd, SIOCTHERMALCTL, &wrq) < 0) {
		perror("SIOCTHERMALCTL, Error: ");
		goto fail;
	}

fail:
	close(skfd);
}

unsigned char getval_allmib(struct ther_info_s *info)
{
	thermal_ctl(info, THERCTL_GETVAL, THERGETVAL_ALLMIB);
	return 0;
}

void set_update_ther(struct ther_info_s *info, int val)
{
	info->control.update_ther = val;
	thermal_ctl(info, THERCTL_UPDATE_THER, val);
}

int set_bandwidth(struct ther_info_s *info, int val)
{
	if (val != info->bw.pre_val) {
		therctl_print3("%s Bandwidth degradation", val?"Enable":"Disable");
		info->bw.pre_val = val;
		thermal_ctl(info, THERCTL_BANDWIDTH, val);
	}
	return 0;
}

int set_power(struct ther_info_s *info, int val)
{
	if (val != info->power.pre_val) {
		therctl_print3("%s Tx power degradation", val?"Enable":"Disable");
		info->power.pre_val = val;
		thermal_ctl(info, THERCTL_POWER, val);
	}
	return 0;
}

int set_path(struct ther_info_s *info, int val)
{
	if (val != info->txpath.pre_val) {
		therctl_print3("%s TXpath reduce", val?"Enable":"Disable");
		info->txpath.pre_val = val;
		thermal_ctl(info, THERCTL_SET_PATH, val);
	}
	return 0;
}

int set_funcoff(struct ther_info_s *info, int val)
{
	if (val != info->funcoff.pre_val) {
		therctl_print3("%s funcoff", val?"Enable":"Disable");
		info->funcoff.pre_val = val;
		thermal_ctl(info, THERCTL_FUNC_OFF, val);
	}
	return 0;
}

int set_limit_tp(struct ther_info_s *info, int val)
{
	if (val != info->tp.pre_val) {
		info->tp.val = val;
		if (val)
			therctl_print3("Enable Tx Duty Cycle with Level %d", info->tp.val);
		else
			therctl_print3("Disable Tx Duty Cycle");
		info->tp.pre_val = val;
		thermal_ctl(info, THERCTL_LIMIT_TP, val);
	}
	return 0;
}

int set_txduty(struct ther_info_s *info, int val)
{
	if (val != info->fwduty.pre_val) {
		info->fwduty.val = val;
		if (val)
			therctl_print3("Enable FW Tx Duty Cycle, level %d", info->fwduty.val);
		else
			therctl_print3("Disable FW Tx Duty Cycle");
		info->fwduty.pre_val = val;
		thermal_ctl(info, THERCTL_TX_DUTY, info->fwduty.val);
	}
	return 0;
}

int getval_cur_ther(struct ther_info_s *info)
{
	thermal_ctl(info, THERCTL_GETVAL, THERGETVAL_DELTA);
	return info->func.sint;	
}

//-----------------------------------------------------------------------------------------
int read_config(char *path)
{
	struct ther_info_s *info;
	int i, ther_max=0, ther_hi=0, ther_low=0;
	int funcoff=0, fwduty=0, txpath=0, power=0, ret=0;
	char name[16], buffer[2048];
	FILE* fp;

	printf("-----------------------------------------------------------------------------------\n");
	printf("Start Thermal Control\n");
	printf("-----------------------------------------------------------------------------------\n");
	fp = fopen(path, "r");
	if (!fp) {
		printf("no %s\n", path);
		ret = 1;
	}
	else {
		while(fgets(buffer, 2048, (FILE*) fp)) {
			sscanf(buffer, "%s %d %d %d %d %d %d %d",
					name, &ther_max, &ther_hi, &ther_low, &funcoff, &fwduty, &txpath, &power);
			if (0)printf("==> { %s,  %d,	  %d,	 %d,	%d, 	   %d,		  %d,		 %d },\n",
					name, ther_max, ther_hi, ther_low, funcoff, fwduty, txpath, power);

			for (i=0; i<NUM_WLAN_INTERFACE ; i++) {
				info = wlan[i];
				if (strcmp(name, info->name) == 0) {
					info->tp.enable = ((fwduty==1)?1:0);
					info->fwduty.enable = ((fwduty==2)?1:0);
				
					info->funcoff.enable = funcoff;
					info->txpath.enable = txpath;
					info->power.enable = power;
				
					info->control.ther_max = ther_max;
					info->control.ther_hi  = ther_hi;
					info->control.ther_low = ther_low;

					printf("%s: ther_max=%d, ther_hi=%d, ther_low=%d (funcoff=%d limit=%d fwduty=%d txpath=%d power=%d)\n", 
						info->name, info->control.ther_max, info->control.ther_hi, info->control.ther_low,
						info->funcoff.enable, info->tp.enable, info->fwduty.enable, info->txpath.enable, info->power.enable);
					break;
				}
			}
		}
		fclose(fp);
	}
	printf("-----------------------------------------------------------------------------------\n\n\n");

	return ret;
}

void output_status(void)
{
	int i = 0;
	struct ther_info_s *info = NULL;
	char buf[256], state[64];
	sprintf(buf, "echo 'ther_control_status:");
	for (i=0; i<NUM_WLAN_INTERFACE ; i++) {
		info = wlan[i];

		switch (info->control.state) {
		case STATE_INIT:
			sprintf(buf+strlen(buf), " wlan%d[%s]", i, info->control.ther_dm?state_str[info->control.state]:"X");
			break;
		case STATE_THERMAL_CONTROL:
		case STATE_FORCE_CONTROL:
			sprintf(state, "%s, lv:%d", state_str[info->control.state], 
				info->fwduty.enable?info->fwduty.val:info->tp.val);
			sprintf(buf+strlen(buf), " wlan%d[%s]", i, info->control.ther_dm?state:"X");
			break;
		case STATE_THERMAL_PROTECT:
		case STATE_FORCE_PROTECT:
			sprintf(buf+strlen(buf), " wlan%d[%s]", i, info->control.ther_dm?state_str[info->control.state]:"X");
			break;
		}
	}
	sprintf(buf+strlen(buf), "' > %s", STATUS_PATH);
	system(buf);
}

//--------------------------------------------------------------------------------------------
void apply_control_setting(struct ther_info_s *info)
{
	(info->tp.enable)?set_limit_tp(info, info->control.level):0;
	(info->fwduty.enable)?set_txduty(info, info->control.level):0;
	(info->power.enable)?set_power(info, info->power.val):0;
	(info->txpath.enable)?set_path(info, info->txpath.val):0;
	(info->funcoff.enable)?set_funcoff(info, info->funcoff.val):0;
	(info->bw.enable)?set_bandwidth(info, info->bw.val):0;
}

void clean_control_setting(struct ther_info_s *info)
{
	therctl_print("Clean Thermal Setting\n");
	info->control.state = STATE_INIT;

	info->control.trigger = 0;
	info->control.level = 0;

	(info->tp.enable)?((info->tp.val = 0)&(info->tp.pre_val = 1)):0;
	(info->fwduty.enable)?((info->fwduty.val = 0)&(info->fwduty.pre_val = 1)):0;
	(info->power.enable)?((info->power.val = 0)&(info->power.pre_val = 1)):0;
	(info->txpath.enable)?((info->txpath.val = 0)&(info->txpath.pre_val = 1)):0;
	(info->bw.enable)?((info->bw.val = 0)&(info->bw.pre_val = 1)):0;
	(info->funcoff.enable)?((info->funcoff.val = 0)&(info->funcoff.pre_val = 1)):0;
}

void ther_dm_onoff(struct ther_info_s *info)
{
	getval_allmib(info);

	/* decides mechanism on off */
	if (info->control.ther_dm != info->control.pre_ther_dm) {
		if (info->control.ther_dm) {
			info->control.ther_max_avg = 0;
		}
	
		clean_control_setting(info);
		info->control.pre_ther_dm = info->control.ther_dm;
	}
}

void update_avg_ther(struct ther_info_s *info)
{
	unsigned int i = 0, ther_sum = 0;
	char str[60];

	/* save ther */
	info->control.ther_saved[info->control.ther_saved_idx] = info->control.cur_ther;
	(info->control.ther_saved_idx < MAX_SAVED_THER - 1)?(info->control.ther_saved_idx++):(info->control.ther_saved_idx = 0);

	/* avg ther */
	for (i=0; i<MAX_SAVED_THER; i++) {
		ther_sum += info->control.ther_saved[i];
	}
	info->control.ther_avg = ther_sum / MAX_SAVED_THER;
	if (info->control.ther_avg > info->control.ther_max_avg)
		info->control.ther_max_avg = info->control.ther_avg;

	/* for debug show */
	if (info->control.dbg & DBG_OUT_USER) {	
		if (info->control.state == STATE_THERMAL_CONTROL || info->control.state == STATE_FORCE_CONTROL)
			sprintf(str, "%s/lv%d", state_str[info->control.state], info->fwduty.enable?info->fwduty.val:info->tp.val);
		else 
			sprintf(str, "%s", state_str[info->control.state]);

		therctl_print2("[%d] Ther:%d(avg:%d)(max:%d), (tx:%d rx:%d), (state:%s max-%d hi-%d low-%d)\n",
			info->control.countdown, info->control.cur_ther, info->control.ther_avg, info->control.ther_max_avg,
			info->control.tx_tp, info->control.rx_tp,
			info->control.ther_dm?str:"X", info->control.ther_max, info->control.ther_hi, info->control.ther_low);
	}
}

void reset_to_init_state(struct ther_info_s *info)
{
	therctl_print("Enter Initial State\n");
	info->control.state = STATE_INIT;

	info->control.trigger = 0;
	info->control.level = 0;

	info->power.enable?info->power.val = 0:0;
	info->txpath.enable?info->txpath.val = 0:0;
	info->bw.enable?info->bw.val = 0:0;
}

void handle_init_state(struct ther_info_s *info)
{
	if (info->control.ther_avg > info->control.ther_hi) {
		therctl_print("Enter Thermal Control State\n");
		info->control.state = STATE_THERMAL_CONTROL;
		info->control.countdown = MAX_SAVED_THER;

		if (info->tp.enable == 0 && info->fwduty.enable == 0) {
			info->control.level = FUNCOFF_LIMIT_LEVEL;
			info->control.countdown = 0;
		}
		else
			info->control.level++;
	}
}

void handle_specific_limit_level(struct ther_info_s *info)
{
	int i = 0;
	if (info->control.level > FUNCOFF_LIMIT_LEVEL) { 
		info->control.level = MAX_TP_LIMIT_LEVEL;
		if (info->control.ther_avg > info->control.ther_max) {
			info->funcoff.enable?(info->funcoff.val = 1):0;
			info->control.state = STATE_THERMAL_PROTECT;
		}
	} else if (info->control.level >= FORCE_TRIGGER_LEVEL) {
		for (i=0; i<NUM_WLAN_INTERFACE; i++) {
			struct ther_info_s *trigger_info = wlan[i];
			if (i!=info->idx && trigger_info->control.tx_tp > FORCE_TX_TP) {
				if (trigger_info->control.state < STATE_FORCE_CONTROL)
					trigger_info->control.state = STATE_FORCE_CONTROL;
				trigger_info->control.trigger = 1;
			}
			else {
				trigger_info->control.trigger = 0;
			}
		}
	} else if (info->control.level == OTHER_METHOD_LEVEL) {
		info->power.enable?info->power.val = 2:0;
		info->txpath.enable?info->txpath.val = 1:0;
		info->bw.enable?info->bw.val = 1:0;
	}
}

void handle_control_state(struct ther_info_s *info)
{
	int i = 0;
	if (info->control.countdown == 0) {
		if (info->control.ther_avg > info->control.ther_hi) {
			info->control.level++;
			handle_specific_limit_level(info);
		} else if (info->control.ther_avg < info->control.ther_hi && info->funcoff.val) {
			/* disable funcoff */
			info->funcoff.enable?info->funcoff.val = 0:0;
			info->control.state = STATE_THERMAL_CONTROL;

			if (info->tp.enable == 0 && info->fwduty.enable == 0) {
				info->control.state = STATE_INIT;
			}		
		}
		else if (info->control.ther_avg < info->control.ther_low) {
			reset_to_init_state(info);
			for (i=0; i<NUM_WLAN_INTERFACE; i++) {
				struct ther_info_s *trigger_info = wlan[i];
				if (trigger_info->control.state >= STATE_FORCE_CONTROL) {
					trigger_info->control.trigger = -1;
					reset_to_init_state(trigger_info);
				}
			}
		}

		info->control.countdown = MAX_SAVED_THER;
	} else {
		info->control.countdown--;
	}
}

void handle_force_control_slef_check(struct ther_info_s *info)
{
	info->control.countdown = MAX_SAVED_THER;
	if (info->control.ther_avg > info->control.ther_hi) {
		info->control.level++;
		if (info->control.level > FUNCOFF_LIMIT_LEVEL) {
			info->control.level = MAX_TP_LIMIT_LEVEL;
			if (info->control.ther_avg > info->control.ther_max) {
				/* enable funcoff */
				info->funcoff.enable?info->funcoff.val = 1:0;
				info->control.state = STATE_FORCE_PROTECT;
			}
		}
	}
	else if (info->control.ther_avg < info->control.ther_hi) {
		/* disable funcoff */
		info->control.state = STATE_FORCE_CONTROL;
		info->funcoff.enable?info->funcoff.val = 0:0;
	}
}

void handle_force_control(struct ther_info_s *info)
{
	info->control.countdown--;
	if (info->control.state >= STATE_FORCE_CONTROL) {
		if (info->control.trigger > 0) {
			info->control.level++;
			if (info->control.level > FUNCOFF_LIMIT_LEVEL) {
				info->control.level = MAX_TP_LIMIT_LEVEL;
				if (info->control.ther_avg > info->control.ther_max) {
					/* enable funcoff */
					info->funcoff.enable?info->funcoff.val = 1:0;
					info->control.state = STATE_FORCE_PROTECT;
				}
			}		
			info->control.countdown = MAX_SAVED_THER;
		}
		else if (info->control.trigger < 0) {
			reset_to_init_state(info);
		}
		else if (info->control.countdown == 0) {
			//self check?
			handle_force_control_slef_check(info);
		}
	
		info->control.trigger = 0;
	}
}

void main_loop(void)
{
	struct ther_info_s *info = NULL;
	int idx = 0;

	do {
		info = wlan[idx];
		/* decides mechanism on off */
		ther_dm_onoff(info);

		/* avg ther */
		update_avg_ther(info);

		if (info->control.ther_dm) {
			switch (info->control.state) {
			case STATE_INIT:
				handle_init_state(info);
				break;
			case STATE_THERMAL_CONTROL:
			case STATE_THERMAL_PROTECT:
				handle_control_state(info);
				break;
			case STATE_FORCE_CONTROL:
			case STATE_FORCE_PROTECT:
				handle_force_control(info);
				break;
			}
		}

		idx++;
	} while (idx < NUM_WLAN_INTERFACE);

	for (idx=0; idx<NUM_WLAN_INTERFACE; idx++) {
		info = wlan[idx];
		apply_control_setting(info);
	}
	output_status();
	sleep(1);
}

//--------------------------------------------------------------------------------------------
int main(int argc, char **argv)
{
	int i = 0;
	struct ther_info_s *info = NULL;

	if (read_config(THERCONF_PATH))
		return 1;

	/* reset ther_dm */
	for (i=0; i<NUM_WLAN_INTERFACE ; i++) {
		info = wlan[i];
		getval_allmib(info);
		info->control.pre_ther_dm = info->control.ther_dm;
		clean_control_setting(info);
		apply_control_setting(info);
	}
	output = 1;

	while (1) {
		main_loop();
	}

	return 0;
}

