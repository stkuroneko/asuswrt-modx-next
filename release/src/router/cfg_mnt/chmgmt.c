#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <net/if.h>
#include <shared.h>
#include <shutils.h>
#include <pthread.h>
#include "encrypt_main.h"
#include "chmgmt.h"
#include "cfg_common.h"
#include "cfg_radardet.h"
#ifdef RTCONFIG_QCA
#include <qca.h>
#endif

/************************************************************************
*				E X T E R N A L   R E F E R E N C E S
************************************************************************/
extern int wl_get_chans_info(int unit, char* buf, size_t len);
extern int wl_get_chconf(const char* ifname, chmgmt_chconf_t* chconf);
extern int wl_set_chconf(const char* ifname, const chmgmt_chconf_t chconf);

/************************************************************************
*		P R I V A T E   F U N C T I O N   D E C L A R A T I O N S
************************************************************************/
static int _chmgmt_load_avbl_chan(chmgmt_chinfo_t* chan_info, size_t n);
#if !defined(RTCONFIG_AVBLCHAN)
static chmgmt_chconf_t _chmgmt_ch_sel(const chmgmt_chinfo_t* chan_info, size_t n);
#endif
static int _chmgmt_valid_chconf(chmgmt_chconf_t chconf, chmgmt_chinfo_t* chan_info, size_t n);

/************************************************************************
*				P R I V A T E   D A T A
************************************************************************/
static char old_ch_data[MAX_CH_DATA_BUFLEN] = {0};
static int bw160_enable = 0;

/************************************************************************
*				P U B L I C   F U N C T I O N
************************************************************************/

/*
 * Description:
 *   get device channel list
 *   data format: TBD
 * 
 * Arguments:
 *   buf: pointer of buffer
 *   len: size of buffer
 * 
 * Return:
 *   1: channel info updated
 *   0: channel info not updated
 *  -1: error
 */
int chmgmt_get_chan_info(char *buf, size_t len)
{
	if( wl_get_chans_info(-1, buf, len) < 0 )
	{
		DBG_ERR("get chan info failed");
		return -1;
	}

	if(strcmp(old_ch_data, buf))
	{
		DBG_INFO("channel info updated");
		strlcpy(old_ch_data, buf, sizeof(old_ch_data));
		return 1;
	}
	else
	{
		DBG_INFO("channel info not updated");
		return 0;
	}
}

static int all_channel_detect_radar_check(chmgmt_chinfo_t* avbl_ch, size_t n){
	int i;

	for(i=0;i<n;i++){
		if(avbl_ch[i] != 0)
			return 0;
	}

	return 1;
}

/*
 * Description:
 *   Find 5g unit.
 *   For one 5g band, check 5g band type matched.
 *   For more 5g band, check 5g band type and channel >= 100 both matched.
 *
 * Arguments:
 *   none
 *
 * Return:
 *   5g unit: -1 means can't find
 */
int chmgmt_get_5g_unit()
{
	chmgmt_chconf_t cur_chconf;
	char word[64], *next = NULL, tmp[64], wl_ifnames[64], wl_prefix[sizeof("wlXXXX_")];
	int unit = 0, num5g = num_of_5g_if(), unit5g = -1, nband = 0;

	/* find 5g/5g high unit */
	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
		nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));

		if (nband == 1 && nvram_get_int(strcat_r(wl_prefix, "radio", tmp)) == 1) {	/* for 5g band */
			if (num5g == 1) {	/* one 5g band */
				unit5g = unit;
				break;
			}
			else if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
				DBG_INFO("current channel (%d)", CHCONF_CH(cur_chconf));
				if (CHCONF_CH(cur_chconf) >= THRESHOLD_5G_LOW_HIGH) {	/* check 5g high band */
					unit5g = unit;
					break;
				}
			}
		}

		unit++;
	}

	return unit5g;
}

/*
 * Description:
 *   Called by master, will do channel selection and change channel if necessary
 * 
 * Arguments:
 *   none
 * 
 * Return:
 *   1: channel will be change
 *   0: channel will not be change
 *  -1: error
 */
int chmgmt_notify()
{
	chmgmt_chinfo_t avbl_ch[MAX_CH_NUM] = {0};
#if !defined(RTCONFIG_AVBLCHAN)
	chmgmt_chconf_t cur_chconf, sel_chconf;
	char* ifname;
#endif
	char wl_prefix[8] = {0}, tmp[64];
	char value[512];
	int unit5g = chmgmt_get_5g_unit();

	DBG_INFO("5g unit (%d)", unit5g);
	if (unit5g == -1) {
		DBG_ERR("can't find 5g unit");
		return -1;
	}
	snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit5g);

	//auto channel only
#ifdef SUPPORT_TRI_BAND
#if defined(RTCONFIG_WIFI_SON)
	if(nvram_match("wifison_ready", "1"))
	{
		if(nvram_get_int(strcat_r(wl_prefix, "channel", tmp)) != 0)
			return 0;
		else
			goto skipchan;
	}
#endif
#endif
#if defined(BLUECAVE) || defined(RTCONFIG_QCA)
	if(nvram_get_int(strcat_r(wl_prefix, "channel", tmp)) != 0)
#else
	if(nvram_get_int(strcat_r(wl_prefix, "chanspec", tmp)) != 0)
#endif
	{
		return 0;
	}

	// bw 160 enable
	bw160_enable = nvram_pf_get_int(wl_prefix, "bw_160");


#if defined(RTCONFIG_WIFI_SON)
skipchan:
#endif 
	//load channel data
	if(_chmgmt_load_avbl_chan(avbl_ch, MAX_CH_NUM) < 0)
		return -1;

	if(all_channel_detect_radar_check(avbl_ch, MAX_CH_NUM))
	{
		//syslog(LOG_NOTICE,"all channel detect radar\n");
		snprintf(value, sizeof(value), "{\"%s\":{\"%s\":\"%d\"}}",CFG_PREFIX, "EID", EID_CD_CFG_RADAR_ALL);
		cm_sendEventToConnDiag(value);
	}

#if !defined(RTCONFIG_AVBLCHAN)
	//need to change or not
#ifdef SUPPORT_TRI_BAND
#if defined(RTCONFIG_WIFI_SON)
	if(nvram_match("wifison_ready", "1"))
		ifname = nvram_safe_get("wl1_ifname");
	else
#endif
#endif
	ifname = nvram_safe_get(strcat_r(wl_prefix, "ifname", tmp));

	if(wl_get_chconf(ifname, &cur_chconf) < 0)
	{
		DBG_ERR("get channel failed");
		return -1;
	}


	if(!_chmgmt_valid_chconf(cur_chconf, avbl_ch, MAX_CH_NUM))
	{

		//channel selection
		sel_chconf = _chmgmt_ch_sel(avbl_ch, MAX_CH_NUM);
		DBG_INFO("select channel : %d(%d/%d)", CHCONF_CH(sel_chconf), chmgmt_get_ctl_ch(sel_chconf), chmgmt_get_bw(sel_chconf));
		DBG_INFO("current channel : %d(%d/%d)", CHCONF_CH(cur_chconf), chmgmt_get_ctl_ch(cur_chconf), chmgmt_get_bw(cur_chconf));

		//change channel
		wl_set_chconf(ifname, sel_chconf);

		DBG_INFO("channel changed\n");
	}
	else
	{
		DBG_INFO("current channel %d/%d, no valid channel to change to", chmgmt_get_ctl_ch(cur_chconf), chmgmt_get_bw(cur_chconf));
	}
#endif


	return 1;
}

int chmgmt_get_ctl_ch(chmgmt_chconf_t chconf)
{
	int lowest_ch;
	int bw;

	if (CHCONF_BW_IS20(chconf))
	{
		return CHCONF_CH(chconf);
	}
	else
	{
		bw = chmgmt_get_bw(chconf);
		if(bw < 20)
			return -1;

		lowest_ch = CHCONF_CH(chconf) - ((bw - 20)/2/5);
		return (lowest_ch + CHCONF_SB(chconf) * CH_APART_20M);
	}
}

int chmgmt_get_bw(chmgmt_chconf_t chconf)
{
	const int chconf_bw_int[] = {5, 10, 20, 40, 80, 160, 0, 0};

	return chconf_bw_int[CHCONF_BW(chconf)];
}

/************************************************************************
*				P R I V A T E   F U N C T I O N
************************************************************************/
static int _chmgmt_load_avbl_chan(chmgmt_chinfo_t* avbl_ch, size_t n)
{
	json_object *fileRoot = NULL;
	char uMac[32] = {0};
	json_object *channelObj = NULL;
	char ch_data[MAX_CH_DATA_BUFLEN] = {0};
	char szChan[16];
	char *next = NULL;
	uint32_t chan_status = 0, chan_num = 0;
	int avbl_ch_cnt[MAX_CH_NUM] = {0};
	int avbl_dev_cnt = 0;
	int i;
	int fmtver = 0;
	char *data_start;

	pthread_mutex_lock(&radarDetLock);
	fileRoot = json_object_from_file(RADARDET_LIST_JSON_PATH);
	if (!fileRoot)
	{
		DBG_ERR("error of channel list file");
		pthread_mutex_unlock(&radarDetLock);
		return (-1);
	}

	json_object_object_foreach(fileRoot, key, val)
	{
		strlcpy(uMac, key, sizeof(uMac));
		if( 0 == cm_checkClientStatus(uMac) )
		{
			DBG_INFO("Invalid device: %s", uMac);
			continue;
		}

		avbl_dev_cnt++;

		json_object_object_get_ex(val, CFG_STR_CHANNEL, &channelObj);
		strlcpy(ch_data, json_object_get_string(channelObj), sizeof(ch_data));

		if(sscanf(ch_data, "%d %*s", &fmtver) != 1)
		{
			fmtver = CHINFO_CMNFMT_V1;
			data_start = ch_data;
		}
		else
		{
			data_start = strchr(ch_data, ' ') + 1;
		}

		if(fmtver == CHINFO_CMNFMT_V1)
		{
			foreach(szChan, data_start, next)
			{
				if(sscanf(szChan, "%05u%03u", &chan_status, &chan_num) == 2)
				{
					if(chan_num > n -1)
						continue;
					avbl_ch[chan_num] |= chan_status;
					avbl_ch_cnt[chan_num]++;
				}
			}
		}
	}

	for(i=0; i<n; i++)
	{
		if(	(avbl_ch[i]
			&& avbl_ch[i] & CHINFO_BLK)
			|| (avbl_ch_cnt[i] != avbl_dev_cnt)
		) {
			avbl_ch[i] = 0;
		}
	}

	json_object_put(fileRoot);
	pthread_mutex_unlock(&radarDetLock);
	return (0);
}

#if !defined(RTCONFIG_AVBLCHAN)
static chmgmt_chconf_t _chmgmt_ch_sel(const chmgmt_chinfo_t* avbl_ch, size_t n)
{
	uint8_t ch20[MAX_CH_NUM] = {0}, ch40[MAX_CH_NUM] = {0}, ch80[MAX_CH_NUM] = {0},  ch160[MAX_CH_NUM] = {0};
	uint8_t ch20_cnt = 2, ch40_cnt = 0, ch80_cnt = 0, ch160_cnt = 0;
	int i;
	unsigned long sn;
	int rand_idx = 0;
	chmgmt_chconf_t chconf = 0;

#if defined(RTCONFIG_BW160M)
	if (bw160_enable)
	for(i=0; i<n;)
	{
		if(avbl_ch[LL_SB(i)]
			&& avbl_ch[UU_SB(i)]
			&& avbl_ch[LU_SB(i)]
			&& avbl_ch[UL_SB(i)]
			&& avbl_ch[LL160_SB(i)]
			&& avbl_ch[UU160_SB(i)]
			&& avbl_ch[LU160_SB(i)]
			&& avbl_ch[UL160_SB(i)]
		)
		{
			DBG_INFO("160M ch : %d", i);
			ch160[i] = 1;
			ch160_cnt++;
			i += CH_APART_160M;
		}
		else
		{
			i++;
		}
	}
#endif

	for(i=0; i<n;)
	{
		if(avbl_ch[LL_SB(i)]
			&& avbl_ch[UU_SB(i)]
			&& avbl_ch[LU_SB(i)]
			&& avbl_ch[UL_SB(i)]
		)
		{			
			DBG_INFO("80M ch : %d", i);
			ch80[i] = 1;
			ch80_cnt++;
			i += CH_APART_80M;
		}
		else
		{
			i++;
		}
	}


	for(i=0; i<n;)
	{
		if(avbl_ch[LO_SB(i)]
			&& avbl_ch[UP_SB(i)]
		)
		{
			DBG_INFO("40M ch : %d", i);
			ch40[i] = 1;
			ch40_cnt++;
			i += CH_APART_40M;
		}
		else
		{
			i++;
		}
	}

	for(i=0; i<n;)
	{
		if(avbl_ch[i])
		{
			DBG_INFO("20M ch : %d", i);
			ch20[i] = 1;
			ch20_cnt++;
			i += CH_APART_20M;
		}
		else
		{
			i++;
		}
	}

	f_read("/dev/urandom", &sn, sizeof(sn));
#if defined(RTCONFIG_BW160M)	
	if(ch160_cnt)
	{
		rand_idx = sn % ch160_cnt;
		for(i=0; i<MAX_CH_NUM; i++)
		{
			if(ch160[i])
			{
				if(0 == rand_idx--)
				{
					CHCONF_CH_SET(chconf, i);
					CHCONF_SB_SET(chconf, sn & CHCONF_SB_MASK);
					CHCONF_BW_SET160(chconf);
				}
			}
		}
	}	
	else 
#endif		
	if(ch80_cnt)
	{
		rand_idx = sn % ch80_cnt;
		for(i=0; i<MAX_CH_NUM; i++)
		{
			if(ch80[i])
			{
				if(0 == rand_idx--)
				{
					CHCONF_CH_SET(chconf, i);
					CHCONF_SB_SET(chconf, sn & CHCONF_SB_MASK80);
					CHCONF_BW_SET80(chconf);
				}
			}
		}
	}
	else if(ch40_cnt)
	{
		rand_idx = sn % ch40_cnt;
		for(i=0; i<MAX_CH_NUM; i++)
		{
			if(ch40[i])
			{
				if(0 == rand_idx--)
				{
					CHCONF_CH_SET(chconf, i);
					CHCONF_SB_SET(chconf, sn & CHCONF_SB_MASK40);
					CHCONF_BW_SET40(chconf);
				}
			}
		}
	}
	else if(ch20_cnt)
	{
		rand_idx = sn % ch20_cnt;
		for(i=0; i<MAX_CH_NUM; i++)
		{
			if(ch20[i])
			{
				if(0 == rand_idx--)
				{
					CHCONF_CH_SET(chconf, i);
					CHCONF_BW_SET20(chconf);
				}
			}
		}
	}

	return (chconf);
}

static int _chmgmt_valid_chconf(chmgmt_chconf_t chconf, chmgmt_chinfo_t* avbl_ch, size_t n)
{
	if(CHCONF_BW_IS20(chconf))
	{
		if(!avbl_ch[CHCONF_CH(chconf)])
		{
			DBG_INFO("invalid ch in %d", CHCONF_CH(chconf));
			return 0;
		}
	}
	else if(CHCONF_BW_IS40(chconf))
	{
		if (!avbl_ch[LO_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[UP_SB(CHCONF_CH(chconf))]
		)
		{
			DBG_INFO("invalid ch in %d, %d", LO_SB(CHCONF_CH(chconf)), UP_SB(CHCONF_CH(chconf)));
			return 0;
		}
	}
	else if(CHCONF_BW_IS80(chconf))
	{
		if (!avbl_ch[LL_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[LU_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[UL_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[UU_SB(CHCONF_CH(chconf))]
		)
		{
			DBG_INFO("invalid ch in %d, %d, %d, %d", LL_SB(CHCONF_CH(chconf)), LU_SB(CHCONF_CH(chconf)), UL_SB(CHCONF_CH(chconf)), UU_SB(CHCONF_CH(chconf)));
			return 0;
		}
	}
#if defined(RTCONFIG_BW160M)		
	else if (CHCONF_BW_IS160(chconf))
	{
		if (!avbl_ch[LL_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[LU_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[UL_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[UU_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[LL160_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[UU160_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[LU160_SB(CHCONF_CH(chconf))]
			|| !avbl_ch[UL160_SB(CHCONF_CH(chconf))]
		)
		{
			DBG_INFO("invalid ch in %d, %d, %d, %d, %d, %d, %d, %d", LL_SB(CHCONF_CH(chconf)), LU_SB(CHCONF_CH(chconf)), UL_SB(CHCONF_CH(chconf)), UU_SB(CHCONF_CH(chconf)), LL160_SB(CHCONF_CH(chconf)), UU160_SB(CHCONF_CH(chconf)), LU160_SB(CHCONF_CH(chconf)), UL160_SB(CHCONF_CH(chconf)));
			cprintf("%d invalid ch in %d, %d, %d, %d, %d, %d, %d, %d\n\n", __LINE__, LL_SB(CHCONF_CH(chconf)), LU_SB(CHCONF_CH(chconf)), UL_SB(CHCONF_CH(chconf)), UU_SB(CHCONF_CH(chconf)), LL160_SB(CHCONF_CH(chconf)), UU160_SB(CHCONF_CH(chconf)), LU160_SB(CHCONF_CH(chconf)), UL160_SB(CHCONF_CH(chconf)));

			return 0;
		}
	}	
#endif
	return (1);
}
#endif	/* !RTCONFIG_AVBLCHAN */
