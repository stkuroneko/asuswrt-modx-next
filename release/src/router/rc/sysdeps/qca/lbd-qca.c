#include <rc.h>
#include <qca.h>

enum LBD_CONFIG_T
{
	LBD_CONFIG = 0,
	LBD_ADV,
	LBD_IDLESTEER,
	LBD_ACTIVESTEER,
	LBD_OFFLOAD,
	LBD_IAS,
	LBD_STADB,
	LBD_STEEREXEC,
	LBD_APSTEER,
	LBD_STAMONITOR,
	LBD_BANDMONITOR,
	LBD_ESTIMATOR,
	LBD_STEERALG,
	LBD_DIAGLOG,
	LBD_PERSIST,

	LBD_CONFIG_END
};

enum LBD_OPTION_T
{
// config 'config'
	Enable = 0,
	MatchingSSID,
	PHYBasedPrioritization,
	BlacklistOtherESS, 
	InactDetectionFromTx,
	UnifiedStatsEnable,
// IdleSteer 'IdleSteer'
	RSSISteeringPoint_DG, 
	RSSISteeringPoint_UG,
	NormalInactTimeout,
	OverloadInactTimeout,
	InactCheckInterval,
	AuthAllow,
// ActiveSteer 'ActiveSteer'
	TxRateXingThreshold_UG,
	RateRSSIXingThreshold_UG,
	TxRateXingThreshold_DG,
	RateRSSIXingThreshold_DG,
// Offload 'Offload'
	MUAvgPeriod, 
	MUOverloadThreshold_W2,
	MUOverloadThreshold_W5,
	MUSafetyThreshold_W2,
	MUSafetyThreshold_W5,
	OffloadingMinRSSI,
// IAS 'IAS'
	Enable_W2,
	Enable_W5,
	MaxPollutionTime,
	UseBestEffort,
// StaDB 'StaDB'
	IncludeOutOfNetwork,
	TrackRemoteAssoc,
	MarkAdvClientAsDualBand,
// SteerExec 'SteerExec'
	SteeringProhibitTime,
	BTMSteeringProhibitShortTime,
	DisableLegacySteering,
// APSteer 'APSteer'
	LowRSSIAPSteerThreshold_CAP,
	LowRSSIAPSteerThreshold_RE,
	APSteerToRootMinRSSIIncThreshold,
	APSteerToLeafMinRSSIIncThreshold,
	APSteerToPeerMinRSSIIncThreshold,
	DownlinkRSSIThreshold_W5,
// config 'config_Adv'
	AgeLimit,
// StaDB 'StaDB_Adv'
	AgingSizeThreshold,
	AgingFrequency,
	OutOfNetworkMaxAge,
	InNetworkMaxAge,
	NumRemoteBSSes,
	PopulateNonServingPHYInfo,
// StaMonitor 'StaMonitor_Adv'
	RSSIMeasureSamples_W2,
	RSSIMeasureSamples_W5,
// BandMonitor 'BandMonitor_Adv'
	ProbeCountThreshold,
	MUCheckInterval_W2,
	MUCheckInterval_W5,
	MUReportPeriod,
	LoadBalancingAllowedMaxPeriod,
	NumRemoteChannels,
// Estimator_Adv 'Estimator_Adv'
	RSSIDiff_EstW5FromW2,
	RSSIDiff_EstW2FromW5,
	StatsSampleInterval,
	Max11kUnfriendly,
	ProhibitTimeShort11k,
	ProhibitTimeLong11k,
	PhyRateScalingForAirtime,
	EnableContinuousThroughput,
	InterferenceDetectionEnable_W2,
	InterferenceDetectionEnable_W5,
	BcnrptActiveDuration,
	BcnrptPassiveDuration,
	FastPollutionDetectBufSize,
	NormalPollutionDetectBufSize,
	PollutionDetectThreshold,
	PollutionClearThreshold,
	InterferenceAgeLimit,
	IASLowRSSIThreshold,
	IASMaxRateFactor,
	IASMinDeltaBytes,
	IASMinDeltaPackets,
	IASEnableSingleBandDetect,
// SteerExec 'SteerExec_Adv'
	TSteering,
	InitialAuthRejCoalesceTime,
	AuthRejMax,
	SteeringUnfriendlyTime,
	MaxSteeringUnfriendly,
	TargetLowRSSIThreshold_W2,
	TargetLowRSSIThreshold_W5,
	BlacklistTime,
	BTMResponseTime,
	BTMAssociationTime,
	BTMAlsoBlacklist,
	BTMUnfriendlyTime,
	MaxBTMUnfriendly,
	MaxBTMActiveUnfriendly,
	MinRSSIBestEffort,
	LowRSSIXingThreshold,
	StartInBTMActiveState,
	Delay24GProbeRSSIThreshold,
	Delay24GProbeTimeWindow,
	Delay24GProbeMinReqCount,
	MaxConsecutiveBTMFailuresAsActive,
// SteerAlg_Adv 'SteerAlg_Adv'
	MinTxRateIncreaseThreshold,
	MaxSteeringTargetCount,
	ApplyEstimatedAirTimeOnSteering,
// DiagLog 'DiagLog'
	EnableLog,
	LogServerIP,
	LogServerPort,
	LogLevelWlanIF,
	LogLevelBandMon,
	LogLevelStaDB,
	LogLevelSteerExec,
	LogLevelStaMon,
	LogLevelEstimator,
	LogLevelDiagLog,
// Persist 'Persist'
	PersistPeriod,

	LBD_OPTION_END
};

struct lbd_config {
	int config;
	int config_t;
	int option;
	char *opt_val;
};

struct lbd_config lbd_configs[] = {
	{ LBD_CONFIG,		LBD_CONFIG,		Enable,					"0" },
	{ LBD_CONFIG,		LBD_CONFIG,		MatchingSSID,				"" },
	{ LBD_CONFIG,		LBD_CONFIG,		PHYBasedPrioritization,			"1" },
	{ LBD_CONFIG,		LBD_CONFIG,		BlacklistOtherESS,			"0" },
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
	{ LBD_CONFIG,		LBD_CONFIG,		InactDetectionFromTx,			"0" },
	{ LBD_CONFIG,		LBD_CONFIG,		UnifiedStatsEnable,			"0" },
#endif
	{ LBD_IDLESTEER,	LBD_CONFIG,		RSSISteeringPoint_DG,			"5" },
	{ LBD_IDLESTEER,	LBD_CONFIG,		RSSISteeringPoint_UG,			"20" },
	{ LBD_IDLESTEER,	LBD_CONFIG,		NormalInactTimeout,			"10" },
	{ LBD_IDLESTEER,	LBD_CONFIG,		OverloadInactTimeout,			"10" },
	{ LBD_IDLESTEER,	LBD_CONFIG,		InactCheckInterval,			"1" },
	{ LBD_IDLESTEER,	LBD_CONFIG,		AuthAllow,				"0" },
	{ LBD_ACTIVESTEER,	LBD_CONFIG,		TxRateXingThreshold_UG,			"50000" },
	{ LBD_ACTIVESTEER,	LBD_CONFIG,		RateRSSIXingThreshold_UG,		"30" },
	{ LBD_ACTIVESTEER,	LBD_CONFIG,		TxRateXingThreshold_DG,			"6000" },
	{ LBD_ACTIVESTEER,	LBD_CONFIG,		RateRSSIXingThreshold_DG,		"0" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUAvgPeriod,				"60" },
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W2,			"30" },	/* SPF8.0 CSU3: 70 */
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W5,			"90" },	/* SPF8.0 CSU3: 70 */
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUSafetyThreshold_W2,			"20" },	/* SPF8.0 CSU3: 50 */
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUSafetyThreshold_W5,			"50" },	/* SPF8.0 CSu3: 60 */
#else	/* !RTCONFIG_WIFI_QCN5024_QCN5054 */
#if defined(MAPAC1750)
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W2,			"30" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W5,			"90" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUSafetyThreshold_W2,			"20" },
#elif defined(MAPAC2200)
#if defined(RTCONFIG_AMAS)
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W2,			"30" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W5,			"90" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUSafetyThreshold_W2,			"20" },
#else
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W2,			"50" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W5,			"80" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUSafetyThreshold_W2,			"40" },
#endif
#else
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W2,			"70" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUOverloadThreshold_W5,			"70" },
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUSafetyThreshold_W2,			"60" },
#endif
	{ LBD_OFFLOAD,		LBD_CONFIG,		MUSafetyThreshold_W5,			"50" },
#endif	/* RTCONFIG_WIFI_QCN5024_QCN5054 */
#if defined(RTCONFIG_AMAS)
	{ LBD_OFFLOAD,		LBD_CONFIG,		OffloadingMinRSSI,			"10" },
#else
	{ LBD_OFFLOAD,		LBD_CONFIG,		OffloadingMinRSSI,			"20" },
#endif
	{ LBD_IAS,		LBD_CONFIG,		Enable_W2,				"1" },
	{ LBD_IAS,		LBD_CONFIG,		Enable_W5,				"1" },
	{ LBD_IAS,		LBD_CONFIG,		MaxPollutionTime,			"1200" },
	{ LBD_IAS,		LBD_CONFIG,		UseBestEffort,				"0" },
	{ LBD_STADB,		LBD_CONFIG,		IncludeOutOfNetwork,			"1" },
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
	{ LBD_STADB,		LBD_CONFIG,		TrackRemoteAssoc,			"0" },
#endif
	{ LBD_STADB,		LBD_CONFIG,		MarkAdvClientAsDualBand,		"0" },
	{ LBD_STEEREXEC,	LBD_CONFIG,		SteeringProhibitTime,			"300" },
	{ LBD_STEEREXEC,	LBD_CONFIG,		BTMSteeringProhibitShortTime,		"30" },
	{ LBD_STEEREXEC,	LBD_CONFIG,		DisableLegacySteering,			"0" },
	{ LBD_APSTEER,		LBD_CONFIG,		LowRSSIAPSteerThreshold_CAP,		"20" },
	{ LBD_APSTEER,		LBD_CONFIG,		LowRSSIAPSteerThreshold_RE,		"45" },
	{ LBD_APSTEER,		LBD_CONFIG,		APSteerToRootMinRSSIIncThreshold,	"5" },
#if defined(MAPAC1750)
	{ LBD_APSTEER,		LBD_CONFIG,		APSteerToLeafMinRSSIIncThreshold,	"5" },
#elif defined(MAPAC2200)
	{ LBD_APSTEER,		LBD_CONFIG,		APSteerToLeafMinRSSIIncThreshold,	"7" },
#else
	{ LBD_APSTEER,		LBD_CONFIG,		APSteerToLeafMinRSSIIncThreshold,	"10" },
#endif
	{ LBD_APSTEER,		LBD_CONFIG,		APSteerToPeerMinRSSIIncThreshold,	"10" },
	{ LBD_APSTEER,		LBD_CONFIG,		DownlinkRSSIThreshold_W5,		"-65" },
	{ LBD_CONFIG,		LBD_ADV,		AgeLimit,				"5" },
	{ LBD_STADB,		LBD_ADV,		AgingSizeThreshold,			"100" },
	{ LBD_STADB,		LBD_ADV,		AgingFrequency,				"60" },
	{ LBD_STADB,		LBD_ADV,		OutOfNetworkMaxAge,			"300" },
	{ LBD_STADB,		LBD_ADV,		InNetworkMaxAge,			"2592000" },
	{ LBD_STADB,		LBD_ADV,		NumRemoteBSSes,				"4" },
	{ LBD_STADB,		LBD_ADV,		PopulateNonServingPHYInfo,		"1" },
	{ LBD_STAMONITOR,	LBD_ADV,		RSSIMeasureSamples_W2,			"5" },
	{ LBD_STAMONITOR,	LBD_ADV,		RSSIMeasureSamples_W5,			"5" },
	{ LBD_BANDMONITOR,	LBD_ADV,		ProbeCountThreshold,			"1" },
	{ LBD_BANDMONITOR,	LBD_ADV,		MUCheckInterval_W2,			"10" },
	{ LBD_BANDMONITOR,	LBD_ADV,		MUCheckInterval_W5,			"10" },
#if defined(RTCONFIG_AMAS)
	{ LBD_BANDMONITOR,	LBD_ADV,		MUReportPeriod,				"20" },
#else
	{ LBD_BANDMONITOR,	LBD_ADV,		MUReportPeriod,				"30" },
#endif
	{ LBD_BANDMONITOR,	LBD_ADV,		LoadBalancingAllowedMaxPeriod,		"15" },
	{ LBD_BANDMONITOR,	LBD_ADV,		NumRemoteChannels,			"3" },
	{ LBD_ESTIMATOR,	LBD_ADV,		RSSIDiff_EstW5FromW2,			"-15" },
	{ LBD_ESTIMATOR,	LBD_ADV,		RSSIDiff_EstW2FromW5,			"5" },
	{ LBD_ESTIMATOR,	LBD_ADV,		ProbeCountThreshold,			"3" },
	{ LBD_ESTIMATOR,	LBD_ADV,		StatsSampleInterval,			"1" },
	{ LBD_ESTIMATOR,	LBD_ADV,		Max11kUnfriendly,			"10" },
	{ LBD_ESTIMATOR,	LBD_ADV,		ProhibitTimeShort11k,			"30" },
	{ LBD_ESTIMATOR,	LBD_ADV,		ProhibitTimeLong11k,			"300" },
	{ LBD_ESTIMATOR,	LBD_ADV,		PhyRateScalingForAirtime,		"50" },
	{ LBD_ESTIMATOR,	LBD_ADV,		EnableContinuousThroughput,		"0" },
	{ LBD_ESTIMATOR,	LBD_ADV,		InterferenceDetectionEnable_W2,		"1" },
	{ LBD_ESTIMATOR,	LBD_ADV,		InterferenceDetectionEnable_W5,		"1" },
	{ LBD_ESTIMATOR,	LBD_ADV,		BcnrptActiveDuration,			"50" },
	{ LBD_ESTIMATOR,	LBD_ADV,		BcnrptPassiveDuration,			"200" },
	{ LBD_ESTIMATOR,	LBD_ADV,		FastPollutionDetectBufSize,		"10" },
	{ LBD_ESTIMATOR,	LBD_ADV,		NormalPollutionDetectBufSize,		"10" },
	{ LBD_ESTIMATOR,	LBD_ADV,		PollutionDetectThreshold,		"60" },
	{ LBD_ESTIMATOR,	LBD_ADV,		PollutionClearThreshold,		"40" },
	{ LBD_ESTIMATOR,	LBD_ADV,		InterferenceAgeLimit,			"15" },
	{ LBD_ESTIMATOR,	LBD_ADV,		IASLowRSSIThreshold,			"12" },
	{ LBD_ESTIMATOR,	LBD_ADV,		IASMaxRateFactor,			"88" },
	{ LBD_ESTIMATOR,	LBD_ADV,		IASMinDeltaBytes,			"2000" },
	{ LBD_ESTIMATOR,	LBD_ADV,		IASMinDeltaPackets,			"10" },
	{ LBD_ESTIMATOR,	LBD_ADV,		IASEnableSingleBandDetect,		"10" },
	{ LBD_STEEREXEC,	LBD_ADV,		TSteering,				"15" },
	{ LBD_STEEREXEC,	LBD_ADV,		InitialAuthRejCoalesceTime,		"2" },
	{ LBD_STEEREXEC,	LBD_ADV,		AuthRejMax,				"3" },
	{ LBD_STEEREXEC,	LBD_ADV,		SteeringUnfriendlyTime,			"600" },
	{ LBD_STEEREXEC,	LBD_ADV,		MaxSteeringUnfriendly,			"604800" },
	{ LBD_STEEREXEC,	LBD_ADV,		TargetLowRSSIThreshold_W2,		"5" },
	{ LBD_STEEREXEC,	LBD_ADV,		TargetLowRSSIThreshold_W5,		"15" },
	{ LBD_STEEREXEC,	LBD_ADV,		BlacklistTime,				"900" },
	{ LBD_STEEREXEC,	LBD_ADV,		BTMResponseTime,			"10" },
	{ LBD_STEEREXEC,	LBD_ADV,		BTMAssociationTime,			"6" },
	{ LBD_STEEREXEC,	LBD_ADV,		BTMAlsoBlacklist,			"1" },
	{ LBD_STEEREXEC,	LBD_ADV,		BTMUnfriendlyTime,			"600" },
	{ LBD_STEEREXEC,	LBD_ADV,		MaxBTMUnfriendly,			"86400" },
	{ LBD_STEEREXEC,	LBD_ADV,		MaxBTMActiveUnfriendly,			"604800" },
	{ LBD_STEEREXEC,	LBD_ADV,		MinRSSIBestEffort,			"12" },
	{ LBD_STEEREXEC,	LBD_ADV,		LowRSSIXingThreshold,			"10" },
	{ LBD_STEEREXEC,	LBD_ADV,		StartInBTMActiveState,			"0" },
	{ LBD_STEEREXEC,	LBD_ADV,		Delay24GProbeRSSIThreshold,		"35" },
	{ LBD_STEEREXEC,	LBD_ADV,		Delay24GProbeTimeWindow,		"0" },
	{ LBD_STEEREXEC,	LBD_ADV,		Delay24GProbeMinReqCount,		"0" },
	{ LBD_STEEREXEC,	LBD_ADV,		MaxConsecutiveBTMFailuresAsActive,	"0" },
	{ LBD_STEERALG,		LBD_ADV,		MinTxRateIncreaseThreshold,		"53" },
	{ LBD_STEERALG,		LBD_ADV,		MaxSteeringTargetCount,			"1" },
	{ LBD_STEERALG,		LBD_ADV,		ApplyEstimatedAirTimeOnSteering,	"1" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		EnableLog,				"0" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogServerIP,				"192.168.1.1" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogServerPort,				"7788" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogLevelWlanIF,				"2" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogLevelBandMon,			"2" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogLevelStaDB,				"2" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogLevelSteerExec,			"2" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogLevelStaMon,				"2" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogLevelEstimator,			"2" },
	{ LBD_DIAGLOG,		LBD_CONFIG,		LogLevelDiagLog,			"2" },
	{ LBD_PERSIST,		LBD_CONFIG,		PersistPeriod,				"3600" },
	
	{ LBD_CONFIG_END, 	0,			0,					NULL}
};

static int get_configs_val(int conf, int conf_t, int opt) {
	struct lbd_config *configs;
	int val = 0;

#if defined(RTCONFIG_HAS_5G_2)
	if (conf==LBD_CONFIG && conf_t==LBD_CONFIG && opt==PHYBasedPrioritization) {
		return 0;
	}
#endif

	for (configs=&lbd_configs[0]; configs->config<LBD_CONFIG_END; configs++) {
		if (conf == configs->config
			&& conf_t == configs->config_t 
			&& opt == configs->option ) {
			val = safe_atoi(configs->opt_val);
			break;
		}
	}
	
	return val;
}

/*
static char *get_configs_str(int conf, int conf_t, int opt) {
	struct lbd_config *configs;

	for (configs=&lbd_configs[0]; configs->config<LBD_CONFIG_END; configs++) {
		if (conf == configs->config
			&& conf_t == configs->config_t 
			&& opt == configs->option ) {
			break;
		}
	}
	
	return configs->opt_val;
}
*/

char *get_iwconfig_essid(char *wlanif, char *ssid)
{
        FILE *fp;
        char buf[2048];
        char *pt1, *pt2;
        int len;

	memset(buf, '\0', sizeof(buf));
	*ssid = '\0';

	snprintf(buf, sizeof(buf), "iwconfig %s", wlanif);
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "ESSID:");
			if (pt1) {
				pt2 = pt1 + strlen("ESSID:") + 1;
				pt1 = strtok(pt2, " ");
				strncpy(ssid, pt1, strlen(pt1)-1);
			}
		}
	}

	return ssid;
}

static int get_wlan_interface(FILE *fp)
{
	char *athif = "ath";
	char word[16], wlanif[256], wlanbasic[16], ssid[64], tmp[64];
	char *next;
	int err = 0;
	int len = 0;

	memset(wlanif, '\0', sizeof(wlanif));
	memset(wlanbasic, '\0', sizeof(wlanbasic));
	memset(ssid, '\0', sizeof(ssid));

	strncpy(wlanbasic, WIF_2G, strlen(WIF_2G));
	get_iwconfig_essid(wlanbasic, ssid);
	if (!strlen(ssid)) {
		err = 1;
		return err;
	}

	foreach(word, nvram_safe_get("lan_ifnames"), next) {
		if (strstr(word, athif) && strlen(word)<5) { /* ignore guest interface */
			memset(tmp, '\0', sizeof(tmp));
			if (!strcmp(ssid, get_iwconfig_essid(word, tmp))) {
				if (len) len += snprintf(wlanif+len, sizeof(wlanif)-len, ",");
				len += snprintf(wlanif+len, sizeof(wlanif)-len, "wifi%c:%s", word[strlen(athif)], word);
			}
		}
	}
	fprintf(fp, "WlanInterfaces=%s\n", wlanif);

	return err;
}

static int get_rssi_est(int val1, int val2)
{
	int val = 0;

	if (val1>val2 && val1<(val2+255)) {
		val = val1 - val2;
	}
	else if (val1 <= val2) {
		;
	}
	else if (val1 >= (val2+255)) {
		val = 255;
	}

	return val;
}

static void add_ias_curve(FILE *fp)
{
	char *section[] = {	"IASCurve_24G_20M_1SS", "IASCurve_24G_20M_2SS", "IASCurve_5G_40M_1SS", 
				"IASCurve_5G_40M_2SS", "IASCurve_5G_80M_1SS", "IASCurve_5G_80M_2SS", NULL };
	char *opt_val[][2]={
			{"_d0",		"0"},
			{"_rd1",	"0"},
			{"_md1",	"0"},
			{"_rd2",	"0"},
			{"_rmd1",	"0"},
			{"_md2",	"0"},
			{ NULL,		NULL }
	};
	int index=0, index_v;

	while (section[index]!=NULL) {
		index_v = 0;
		while (opt_val[index_v][0]!=NULL) {
			fprintf(fp, "%s%s=%s\n", section[index], opt_val[index_v][0], opt_val[index_v][1]);
			index_v++;
		}
		index++;
	}

	return;
}

int gen_lbd_config_file(void)
{
	FILE *fp;
	int multi_ap_mode = 0;
	int ias_curve = 0;
	int err = 0;

	if ((fp = fopen(LBD_PATH, "w+")) != NULL) {
/* Add Head */
		fprintf(fp, ";\n");
		fprintf(fp, ";  Automatically generated lbd config file,do not change it.\n");
		fprintf(fp, ";\n");
		fprintf(fp, ";WLANIF                 list of wlan interfaces\n");
		fprintf(fp, ";WLANIF2G               wlan driver interface for 2.4 GHz band\n");
		fprintf(fp, ";WLANIF5G               wlan driver interface for 5 GHz band\n");
		fprintf(fp, ";STADB:                 station database\n");
		fprintf(fp, ";STAMON:                station monitor\n");
		fprintf(fp, ";BANDMON:               band monitor\n");
		fprintf(fp, ";ESTIMATOR:             rate estimator\n");
		fprintf(fp, ";STEEREXEC:             steering executor\n");
		fprintf(fp, ";STEERALG:              steering algorithm\n");
		fprintf(fp, ";DIAGLOG:               diagnostic logging\n");
/* [WLANIF] */  //Wait to solve
		fprintf(fp, "\n");
		fprintf(fp, "[WLANIF]\n");
		if (get_wlan_interface(fp)) {
			fclose(fp);
			unlink(LBD_PATH);
			err = 1;
			return err;
		}
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) \
 || defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "WlanInterfacesExcluded=\n");
#endif
/* [WLANIF2G] */
		fprintf(fp, "\n");
		fprintf(fp, "[WLANIF2G]\n");
		fprintf(fp, "InterferenceDetectionEnable=%d\n", get_configs_val(LBD_IAS, LBD_CONFIG, Enable_W2));
		fprintf(fp, "InactIdleThreshold=%d\n", 		get_configs_val(LBD_IDLESTEER, LBD_CONFIG, NormalInactTimeout));
		fprintf(fp, "InactOverloadThreshold=%d\n",  	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, OverloadInactTimeout));
		fprintf(fp, "InactCheckInterval=%d\n",      	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, InactCheckInterval));
		fprintf(fp, "AuthAllow=%d\n",      		get_configs_val(LBD_IDLESTEER, LBD_CONFIG, AuthAllow));
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) \
 || defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "BlacklistOtherESS=%d\n",      	get_configs_val(LBD_CONFIG, LBD_CONFIG, BlacklistOtherESS));
#endif
		fprintf(fp, "InactRSSIXingHighThreshold=%d\n", 	get_rssi_est(get_configs_val(LBD_IDLESTEER, LBD_CONFIG, RSSISteeringPoint_UG), get_configs_val(LBD_ESTIMATOR, LBD_ADV, RSSIDiff_EstW5FromW2)));
		fprintf(fp, "LowRSSIXingThreshold=%d\n",      	get_configs_val(LBD_STEEREXEC, LBD_ADV, LowRSSIXingThreshold));
		fprintf(fp, "BcnrptActiveDuration=%d\n",      	get_configs_val(LBD_ESTIMATOR, LBD_ADV, BcnrptActiveDuration));
		fprintf(fp, "BcnrptPassiveDuration=%d\n",      	get_configs_val(LBD_ESTIMATOR, LBD_ADV, BcnrptPassiveDuration));
		fprintf(fp, "HighTxRateXingThreshold=%d\n",    	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, TxRateXingThreshold_UG));
		fprintf(fp, "HighRateRSSIXingThreshold=%d\n",  	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, RateRSSIXingThreshold_UG));
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "InactDetectionFromTx=%d\n",  	get_configs_val(LBD_CONFIG, LBD_CONFIG, InactDetectionFromTx));
		fprintf(fp, "UnifiedStatsEnable=%d\n",  	get_configs_val(LBD_CONFIG, LBD_CONFIG, UnifiedStatsEnable));
#endif
		fprintf(fp, "MUCheckInterval=%d\n",      	get_configs_val(LBD_BANDMONITOR, LBD_ADV, MUCheckInterval_W2));
		fprintf(fp, "MUAvgPeriod=%d\n",      		get_configs_val(LBD_OFFLOAD, LBD_CONFIG, MUAvgPeriod));
		fprintf(fp, "Delay24GProbeRSSIThreshold=%d\n",  get_configs_val(LBD_STEEREXEC, LBD_ADV, Delay24GProbeRSSIThreshold));
		fprintf(fp, "Delay24GProbeTimeWindow=%d\n",     get_configs_val(LBD_STEEREXEC, LBD_ADV, Delay24GProbeTimeWindow));
		fprintf(fp, "Delay24GProbeMinReqCount=%d\n",    get_configs_val(LBD_STEEREXEC, LBD_ADV, Delay24GProbeMinReqCount));
/* [WLANIF5G] */
		fprintf(fp, "\n");
		fprintf(fp, "[WLANIF5G]\n");
		fprintf(fp, "InterferenceDetectionEnable=%d\n", get_configs_val(LBD_IAS, LBD_CONFIG, Enable_W5));
		fprintf(fp, "InactIdleThreshold=%d\n", 		get_configs_val(LBD_IDLESTEER, LBD_CONFIG, NormalInactTimeout));
		fprintf(fp, "InactOverloadThreshold=%d\n",  	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, OverloadInactTimeout));
		fprintf(fp, "InactCheckInterval=%d\n",      	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, InactCheckInterval));
		fprintf(fp, "AuthAllow=%d\n",      		get_configs_val(LBD_IDLESTEER, LBD_CONFIG, AuthAllow));
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) \
 || defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "BlacklistOtherESS=%d\n",      	get_configs_val(LBD_CONFIG, LBD_CONFIG, BlacklistOtherESS));
#endif
		fprintf(fp, "InactRSSIXingHighThreshold=%d\n", 	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, RSSISteeringPoint_UG));
		fprintf(fp, "InactRSSIXingLowThreshold=%d\n", 	get_rssi_est(get_configs_val(LBD_IDLESTEER, LBD_CONFIG, RSSISteeringPoint_DG), get_configs_val(LBD_ESTIMATOR, LBD_ADV, RSSIDiff_EstW2FromW5)));
		fprintf(fp, "LowRSSIXingThreshold=%d\n",      	get_configs_val(LBD_STEEREXEC, LBD_ADV, LowRSSIXingThreshold));
		fprintf(fp, "BcnrptActiveDuration=%d\n",      	get_configs_val(LBD_ESTIMATOR, LBD_ADV, BcnrptActiveDuration));
		fprintf(fp, "BcnrptPassiveDuration=%d\n",      	get_configs_val(LBD_ESTIMATOR, LBD_ADV, BcnrptPassiveDuration));
		fprintf(fp, "LowTxRateXingThreshold=%d\n",    	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, TxRateXingThreshold_DG));
		fprintf(fp, "LowRateRSSIXingThreshold=%d\n",  	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, RateRSSIXingThreshold_DG));
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "InactDetectionFromTx=%d\n",  	get_configs_val(LBD_CONFIG, LBD_CONFIG, InactDetectionFromTx));
		fprintf(fp, "UnifiedStatsEnable=%d\n",  	get_configs_val(LBD_CONFIG, LBD_CONFIG, UnifiedStatsEnable));
#endif
		fprintf(fp, "MUCheckInterval=%d\n",      	get_configs_val(LBD_BANDMONITOR, LBD_ADV, MUCheckInterval_W5));
		fprintf(fp, "MUAvgPeriod=%d\n",      		get_configs_val(LBD_OFFLOAD, LBD_CONFIG, MUAvgPeriod));
/* [STADB] */
		fprintf(fp, "\n");
		fprintf(fp, "[STADB]\n");
		fprintf(fp, "IncludeOutOfNetwork=%d\n",		get_configs_val(LBD_STADB, LBD_CONFIG, IncludeOutOfNetwork));
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "TrackRemoteAssoc=%d\n",		get_configs_val(LBD_STADB, LBD_CONFIG, TrackRemoteAssoc));
#endif
		fprintf(fp, "AgingSizeThreshold=%d\n",		get_configs_val(LBD_STADB, LBD_ADV, AgingSizeThreshold));
		fprintf(fp, "AgingFrequency=%d\n",		get_configs_val(LBD_STADB, LBD_ADV, AgingFrequency));
		fprintf(fp, "OutOfNetworkMaxAge=%d\n",		get_configs_val(LBD_STADB, LBD_ADV, OutOfNetworkMaxAge));
		fprintf(fp, "InNetworkMaxAge=%d\n",		get_configs_val(LBD_STADB, LBD_ADV, InNetworkMaxAge));
		fprintf(fp, "ProbeMaxInterval=%d\n",      	get_configs_val(LBD_CONFIG, LBD_ADV, AgeLimit));
#if !defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "NumRemoteBSSes=%d\n",      	get_configs_val(LBD_STADB, LBD_ADV, NumRemoteBSSes));
#endif
		fprintf(fp, "MarkAdvClientAsDualBand=%d\n",     get_configs_val(LBD_STADB, LBD_CONFIG, MarkAdvClientAsDualBand));
		fprintf(fp, "PopulateNonServingPHYInfo=%d\n",  	get_configs_val(LBD_STADB, LBD_ADV, PopulateNonServingPHYInfo));
/* [STAMON] */
		fprintf(fp, "\n");
		fprintf(fp, "[STAMON]\n");
		fprintf(fp, "RSSIMeasureSamples_W2=%d\n",	get_configs_val(LBD_STAMONITOR, LBD_ADV, RSSIMeasureSamples_W2));
		fprintf(fp, "RSSIMeasureSamples_W5=%d\n",	get_configs_val(LBD_STAMONITOR, LBD_ADV, RSSIMeasureSamples_W5));
		fprintf(fp, "AgeLimit=%d\n",			get_configs_val(LBD_CONFIG, LBD_ADV, AgeLimit));
		fprintf(fp, "HighTxRateXingThreshold=%d\n",	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, TxRateXingThreshold_UG));
		fprintf(fp, "HighRateRSSIXingThreshold=%d\n",	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, RateRSSIXingThreshold_UG));
		fprintf(fp, "LowTxRateXingThreshold=%d\n",	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, TxRateXingThreshold_DG));
		fprintf(fp, "LowRateRSSIXingThreshold=%d\n",	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, RateRSSIXingThreshold_DG));
#if !defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "RSSISteeringPoint_DG=%d\n",      	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, RSSISteeringPoint_DG));
#endif

/* [BANDMON] */
		fprintf(fp, "\n");
		fprintf(fp, "[BANDMON]\n");
		fprintf(fp, "MUOverloadThreshold_W2=30\n");
		fprintf(fp, "MUOverloadThreshold_W5=90\n");
		fprintf(fp, "MUSafetyThreshold_W2=20\n");
		fprintf(fp, "MUSafetyThreshold_W5=%d\n",	get_configs_val(LBD_OFFLOAD, LBD_CONFIG, MUSafetyThreshold_W5));
		fprintf(fp, "RSSISafetyThreshold=%d\n",		get_configs_val(LBD_OFFLOAD, LBD_CONFIG, OffloadingMinRSSI));
		fprintf(fp, "RSSIMaxAge=%d\n",	get_configs_val(LBD_CONFIG, LBD_ADV, AgeLimit));
		fprintf(fp, "ProbeCountThreshold=%d\n",	get_configs_val(LBD_BANDMONITOR, LBD_ADV, ProbeCountThreshold));
#if !defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "LoadBalancingAllowedMaxPeriod=%d\n",	get_configs_val(LBD_BANDMONITOR, LBD_ADV, LoadBalancingAllowedMaxPeriod));
		fprintf(fp, "NumRemoteChannels=%d\n",		get_configs_val(LBD_BANDMONITOR, LBD_ADV, NumRemoteChannels));
#endif
/* [ESTIMATOR] */
		fprintf(fp, "\n");
		fprintf(fp, "[ESTIMATOR]\n");
		fprintf(fp, "AgeLimit=%d\n",			get_configs_val(LBD_CONFIG, LBD_ADV, AgeLimit));
		fprintf(fp, "RSSIDiff_EstW5FromW2=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, RSSIDiff_EstW5FromW2));
		fprintf(fp, "RSSIDiff_EstW2FromW5=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, RSSIDiff_EstW2FromW5));
		fprintf(fp, "ProbeCountThreshold=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, ProbeCountThreshold));
		fprintf(fp, "StatsSampleInterval=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, StatsSampleInterval));
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) \
 || defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "Max11kUnfriendly=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, Max11kUnfriendly));
#endif
		fprintf(fp, "11kProhibitTimeShort=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, ProhibitTimeShort11k));
		fprintf(fp, "11kProhibitTimeLong=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, ProhibitTimeLong11k));
		fprintf(fp, "PhyRateScalingForAirtime=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, PhyRateScalingForAirtime));
		fprintf(fp, "EnableContinuousThroughput=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, EnableContinuousThroughput));
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "InterferenceDetectionEnable_W2=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, InterferenceDetectionEnable_W2));
		fprintf(fp, "InterferenceDetectionEnable_W5=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, InterferenceDetectionEnable_W5));
#endif
		fprintf(fp, "MaxPollutionTime=%d\n",		get_configs_val(LBD_IAS, LBD_CONFIG, MaxPollutionTime));
		fprintf(fp, "FastPollutionDetectBufSize=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, FastPollutionDetectBufSize));
		fprintf(fp, "NormalPollutionDetectBufSize=%d\n",get_configs_val(LBD_ESTIMATOR, LBD_ADV, NormalPollutionDetectBufSize));
		fprintf(fp, "PollutionDetectThreshold=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, PollutionDetectThreshold));
		fprintf(fp, "PollutionClearThreshold=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, PollutionClearThreshold));
		fprintf(fp, "InterferenceAgeLimit=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, InterferenceAgeLimit));
		fprintf(fp, "IASLowRSSIThreshold=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, IASLowRSSIThreshold));
		fprintf(fp, "IASMaxRateFactor=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, IASMaxRateFactor));
		fprintf(fp, "IASMinDeltaPackets=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, IASMinDeltaPackets));
		fprintf(fp, "IASMinDeltaBytes=%d\n",		get_configs_val(LBD_ESTIMATOR, LBD_ADV, IASMinDeltaBytes));
		if (multi_ap_mode) {
			fprintf(fp, "IASEnableSingleBandDetect=%d\n",	get_configs_val(LBD_ESTIMATOR, LBD_ADV, IASEnableSingleBandDetect));
		}
		if (ias_curve) add_ias_curve(fp);
/* [STEEREXEC] */
		fprintf(fp, "\n");
		fprintf(fp, "[STEEREXEC]\n");
		fprintf(fp, "SteeringProhibitTime=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_CONFIG, SteeringProhibitTime));
		fprintf(fp, "TSteering=%d\n",			get_configs_val(LBD_STEEREXEC, LBD_ADV, TSteering));
		fprintf(fp, "InitialAuthRejCoalesceTime=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, InitialAuthRejCoalesceTime));
		fprintf(fp, "AuthRejMax=%d\n",			get_configs_val(LBD_STEEREXEC, LBD_ADV, AuthRejMax));
		fprintf(fp, "SteeringUnfriendlyTime=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, SteeringUnfriendlyTime));
		fprintf(fp, "MaxSteeringUnfriendly=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, MaxSteeringUnfriendly));
		fprintf(fp, "LowRSSIXingThreshold_W2=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, LowRSSIXingThreshold));
		fprintf(fp, "LowRSSIXingThreshold_W5=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, LowRSSIXingThreshold));
		fprintf(fp, "TargetLowRSSIThreshold_W2=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, TargetLowRSSIThreshold_W2));
		fprintf(fp, "TargetLowRSSIThreshold_W5=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, TargetLowRSSIThreshold_W5));
		fprintf(fp, "BlacklistTime=%d\n",		get_configs_val(LBD_STEEREXEC, LBD_ADV, BlacklistTime));
		fprintf(fp, "BTMResponseTime=%d\n",		get_configs_val(LBD_STEEREXEC, LBD_ADV, BTMResponseTime));
		fprintf(fp, "BTMAssociationTime=%d\n",		get_configs_val(LBD_STEEREXEC, LBD_ADV, BTMAssociationTime));
		fprintf(fp, "BTMAlsoBlacklist=%d\n",		get_configs_val(LBD_STEEREXEC, LBD_ADV, BTMAlsoBlacklist));
		fprintf(fp, "BTMUnfriendlyTime=%d\n",		get_configs_val(LBD_STEEREXEC, LBD_ADV, BTMUnfriendlyTime));
		fprintf(fp, "BTMSteeringProhibitShortTime=%d\n",get_configs_val(LBD_STEEREXEC, LBD_CONFIG, BTMSteeringProhibitShortTime));
		fprintf(fp, "MaxBTMUnfriendly=%d\n",		get_configs_val(LBD_STEEREXEC, LBD_ADV, MaxBTMUnfriendly));
		fprintf(fp, "MaxBTMActiveUnfriendly=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, MaxBTMActiveUnfriendly));
		fprintf(fp, "AgeLimit=%d\n",			get_configs_val(LBD_CONFIG, LBD_ADV, AgeLimit));
		fprintf(fp, "MinRSSIBestEffort=%d\n",		get_configs_val(LBD_STEEREXEC, LBD_ADV, MinRSSIBestEffort));
		fprintf(fp, "IASUseBestEffort=%d\n",		get_configs_val(LBD_IAS, LBD_CONFIG, UseBestEffort));
		fprintf(fp, "StartInBTMActiveState=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, StartInBTMActiveState));
		if (multi_ap_mode) {
			fprintf(fp, "MaxConsecutiveBTMFailuresAsActive=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_ADV, MaxConsecutiveBTMFailuresAsActive));
			fprintf(fp, "DisableLegacySteering=%d\n",	get_configs_val(LBD_STEEREXEC, LBD_CONFIG, DisableLegacySteering));
		}
/* [STEERALG] */
		fprintf(fp, "\n");
		fprintf(fp, "[STEERALG]\n");
		fprintf(fp, "InactRSSIXingThreshold_W2=%d\n",	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, RSSISteeringPoint_DG));
		fprintf(fp, "InactRSSIXingThreshold_W5=%d\n",	get_configs_val(LBD_IDLESTEER, LBD_CONFIG, RSSISteeringPoint_UG));
		fprintf(fp, "HighTxRateXingThreshold=%d\n",    	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, TxRateXingThreshold_UG));
		fprintf(fp, "HighRateRSSIXingThreshold=%d\n",  	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, RateRSSIXingThreshold_UG));
		fprintf(fp, "LowTxRateXingThreshold=%d\n",    	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, TxRateXingThreshold_DG));
		fprintf(fp, "LowRateRSSIXingThreshold=%d\n",   	get_configs_val(LBD_ACTIVESTEER, LBD_CONFIG, RateRSSIXingThreshold_DG));
		fprintf(fp, "MinTxRateIncreaseThreshold=%d\n",	get_configs_val(LBD_STEERALG, LBD_ADV, MinTxRateIncreaseThreshold));
		fprintf(fp, "AgeLimit=%d\n",			get_configs_val(LBD_CONFIG, LBD_ADV, AgeLimit));
		fprintf(fp, "PHYBasedPrioritization=%d\n",	get_configs_val(LBD_CONFIG, LBD_CONFIG, PHYBasedPrioritization));
		fprintf(fp, "RSSISafetyThreshold=%d\n",		get_configs_val(LBD_OFFLOAD, LBD_CONFIG, OffloadingMinRSSI));
		fprintf(fp, "MaxSteeringTargetCount=%d\n",	get_configs_val(LBD_STEERALG, LBD_ADV, MaxSteeringTargetCount));
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) || defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
		fprintf(fp, "ApplyEstimatedAirTimeOnSteering=%d\n",	get_configs_val(LBD_STEERALG, LBD_ADV, ApplyEstimatedAirTimeOnSteering));
#endif
		fprintf(fp, "APSteerToLeafMinRSSIIncThreshold=%d\n",	get_configs_val(LBD_APSTEER, LBD_CONFIG, APSteerToLeafMinRSSIIncThreshold));
		fprintf(fp, "DownlinkRSSIThreshold_W5=%d\n",	get_configs_val(LBD_APSTEER, LBD_CONFIG, DownlinkRSSIThreshold_W5));
/* [DIAGLOG] */
/* Disable the LBD log server.
		fprintf(fp, "\n");
		fprintf(fp, "[DIAGLOG]\n");
		fprintf(fp, "EnableLog=%d\n",			get_configs_val(LBD_DIAGLOG, LBD_CONFIG, EnableLog));
		fprintf(fp, "LogServerIP=%s\n",			nvram_safe_get("lan_ipaddr"));
		fprintf(fp, "LogServerPort=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogServerPort));
		fprintf(fp, "LogLevelWlanIF=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogLevelWlanIF));
		fprintf(fp, "LogLevelBandMon=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogLevelBandMon));
		fprintf(fp, "LogLevelStaDB=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogLevelStaDB));
		fprintf(fp, "LogLevelSteerExec=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogLevelSteerExec));
		fprintf(fp, "LogLevelStaMon=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogLevelStaMon));
		fprintf(fp, "LogLevelEstimator=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogLevelEstimator));
		fprintf(fp, "LogLevelDiagLog=%d\n",		get_configs_val(LBD_DIAGLOG, LBD_CONFIG, LogLevelDiagLog));
*/
	}

	fclose(fp);
	return err;
}

int dis_steer(void)
{
        char *nv, *nvp, *b;
        char *reMac, *mac2g, *mac5g, *timestamp;
        nv = nvp = get_cfg_relist(0);
        if (nv) {
		sleep(3); //lbd ready
                while ((b = strsep(&nvp, "<")) != NULL) {
                        if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
                                continue;
			set_steer(reMac,1);
			set_steer(mac2g,1);
			set_steer(mac5g,1);
                }
                free(nv);
        }
	return 0;
}
