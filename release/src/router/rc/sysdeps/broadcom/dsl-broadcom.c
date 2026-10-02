/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include "rc.h"

#ifdef RTCONFIG_DSL_HOST
#include <AdslMibDef.h>
#include <adsldrv.h>
#include <sys/ioctl.h>

enum {
	ATM_QOS_UBR_NO_PCR,
	ATM_QOS_UBR,
	ATM_QOS_CBR,
	ATM_QOS_VBR,
	ATM_QOS_GFR,
	ATM_QOS_NRT_VBR
};

static char xtm_tuple[MAX_PVC][32] = {0};
#define DEFAULT_PTM_TUPLE "1.1"
#endif

#ifdef RTCONFIG_DSL_HOST
void set_xtm_intf()
{
	char *argv_xtm_intf[] = {"xtmctl", "operate", "intf",
			"--state", "1", "enable"
			, NULL};

	_eval(argv_xtm_intf, NULL, 0, NULL);
}

void set_atm_tdte(XTM_PARAM *p, int idx)
{
	char cmd[128] = {0};
	int tdte_idx = idx + 1;// idx: 0 ~ 7 -> 1 ~ 8

	//tmp
	if(idx == 0 && nvram_match("success_start_service", "0"))
	{
		snprintf(cmd, sizeof(cmd), "xtmctl operate tdte --add ubr");
		_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
		system(cmd);
	}

	snprintf(cmd, sizeof(cmd), "xtmctl operate tdte --delete %d", tdte_idx);
	_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	switch(p->svc_cat)
	{
	case ATM_QOS_UBR_NO_PCR:
		snprintf(cmd, sizeof(cmd), "xtmctl operate tdte --add ubr");
		break;
	case ATM_QOS_UBR:
		snprintf(cmd, sizeof(cmd), "xtmctl operate tdte --add ubr_pcr %d", p->pcr);
		break;
	case ATM_QOS_CBR:
		snprintf(cmd, sizeof(cmd), "xtmctl operate tdte --add cbr %d", p->pcr);
		break;
	case ATM_QOS_VBR:
		snprintf(cmd, sizeof(cmd), "xtmctl operate tdte --add rtvbr %d %d %d", p->pcr, p->scr, p->mbs);
		break;
	case ATM_QOS_NRT_VBR:
		snprintf(cmd, sizeof(cmd), "xtmctl operate tdte --add nrtvbr %d %d %d", p->pcr, p->scr, p->mbs);
		break;
	default:
		_dprintf("%s:%d: not support\n", __FUNCTION__, __LINE__);
		break;
	}
	_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	system(cmd);

}

/*
 * For dslX, create real interface xtmX. (phy_ifname)
 * For WAN interface, create virtual interface wanX
 * if vpi and vci of dslY is same with dslX, set interface xtmX for dslY
 * Fixed dsl0 for internet (default route), i.e. xtm0
 */
static int _get_atm_same_pvc(int vpi, int vci, int idx)
{
	int i;
	char prefix[8] = {0};
	int tmpvpi = 0;
	int tmpvci = 0;

	for(i = 0; i < idx; i++)
	{
		snprintf(prefix, sizeof(prefix), "dsl%d_", i);
		tmpvpi = nvram_pf_get_int(prefix, "vpi");
		tmpvci = nvram_pf_get_int(prefix, "vci");
		if(tmpvpi == vpi && tmpvci == vci)
			return i;
	}
	return -1;
}

void set_atm_conn(XTM_PARAM *p, int idx)
{
	char cmd[256] = {0};
	char atm_tuple[32] = {0};
	int port_mask = 1;
	int tdte_idx = idx + 1;// idx: 0 ~ 7 -> 1 ~ 8
	char encap[16] = {0};
	int mp_prio = 0; // 0 ~ 7
	int mp_wght = 1; // 1 ~ 63
	int q_prio =  0; // 0 ~ 7
	int q_wght = 1; // 1 ~ 63
	char ifname[8] = {0};
	int same_pvc_idx = -1;

	//phy_ifname
	same_pvc_idx = _get_atm_same_pvc(p->vpi, p->vci, idx);
	if(same_pvc_idx != -1)
	{
		//same vpi,vci
		snprintf(ifname, sizeof(ifname), "atm%d", same_pvc_idx);
		strlcpy(p->phy_ifname, ifname, sizeof(p->phy_ifname));
		return;
	}
	else
	{
		snprintf(ifname, sizeof(ifname), "atm%d", idx);
		strlcpy(p->phy_ifname, ifname, sizeof(p->phy_ifname));
	}

	// conn
	if(p->encap == 0)
	{
		if( strstr(p->proto, "pppoa") )
			strlcpy(encap, "llcencaps_ppp", sizeof(encap));
		else if( strstr(p->proto, "ipoa") )
			strlcpy(encap, "llcsnap_rtip", sizeof(encap));
		else
			strlcpy(encap, "llcsnap_eth", sizeof(encap));
	}
	else
	{
		if( strstr(p->proto, "pppoa") )
			strlcpy(encap, "vcmux_pppoa", sizeof(encap));
		else if( strstr(p->proto, "ipoa") )
			strlcpy(encap, "vcmux_ipoa", sizeof(encap));
		else
			strlcpy(encap, "vcmux_eth", sizeof(encap));
	}

	snprintf(atm_tuple, sizeof(atm_tuple), "%d.%d.%d", port_mask, p->vpi, p->vci);

	if (strlen(xtm_tuple[idx]))
	{
		snprintf(cmd, sizeof(cmd), "xtmctl operate conn --delete %s --deletenetdev %s", xtm_tuple[idx], xtm_tuple[idx]);
		_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
		system(cmd);
	}

	snprintf(cmd, sizeof(cmd), "xtmctl operate conn"
				" --add %s aal5 %s %d %d %d"
				" --addq %s %d wrr %d dt"
				" --createnetdev %s %s"
		, atm_tuple, encap, mp_prio, mp_wght, tdte_idx
		, atm_tuple, q_prio, q_wght
		, atm_tuple, ifname
		);
	_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	system(cmd);

	strlcpy(xtm_tuple[idx], atm_tuple, sizeof(xtm_tuple[idx]));
}

void config_ptm_queue(QOS_Q_PARAM *p)
{
	char cmd[256] = {0};
	int q_prio =  0; // 0 ~ 7
	int q_wght = 1; // 1 ~ 63
	int mbr_kbps = 0; // 0 = no shaping
	int pbr_kbps = 0; // 0 = no shaping
	int mbs_byte = 0;
	int qid = nvram_get_int("dslx_ptm_qid");

	q_prio = qid;
	mbr_kbps = p->min_rate ? : 0;
	pbr_kbps = p->max_rate ? : 0;
	mbs_byte = (p->burst >= 1600) ? p->burst : 3000;

	snprintf(cmd, sizeof(cmd), "xtmctl operate conn"
				" --addq %s %d wrr %d dt %d %d %d"
		, DEFAULT_PTM_TUPLE, q_prio, q_wght, mbr_kbps, pbr_kbps, mbs_byte
		);
	//_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	system(cmd);

	snprintf(cmd, sizeof(cmd), "xtmctl operate conn --deleteq %s %d", DEFAULT_PTM_TUPLE, qid);
	//_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	system(cmd);
	nvram_set_int("dslx_ptm_qid", qid ? 0 : 1);
}

void set_ptm_conn(XTM_PARAM *p, int idx)
{
	char cmd[256] = {0};
	char ptm_tuple[32] = {0};
	int port_mask = 1;
	int ptmpri_mask = 1;
	int q_prio =  0; // 0 ~ 7
	int q_wght = 1; // 1 ~ 63
	int mbr_kbps = p->mbr; // 0 = no shaping
	int pbr_kbps = p->pbr; // 0 = no shaping
	int mbs_byte = p->mbs;
	char ifname[8] = {"ptm0"};

	//phy_ifname
	strlcpy(p->phy_ifname, ifname, sizeof(p->phy_ifname));

	//currently only ptm0
	if(idx) return;

	// conn
	snprintf(ptm_tuple, sizeof(ptm_tuple), "%d.%d", port_mask, ptmpri_mask);

	if (strlen(xtm_tuple[idx]))
	{
		snprintf(cmd, sizeof(cmd), "xtmctl operate conn --delete %s --deletenetdev %s", xtm_tuple[idx], xtm_tuple[idx]);
		_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
		system(cmd);
	}

	snprintf(cmd, sizeof(cmd), "xtmctl operate conn"
				" --add %s"
				" --addq %s %d wrr %d dt %d %d %d"
				" --createnetdev %s %s"
		, ptm_tuple
		, ptm_tuple, q_prio, q_wght, mbr_kbps, pbr_kbps, mbs_byte
		, ptm_tuple, ifname
		);
	_dprintf("%s:%d: cmd: %s\n", __FUNCTION__, __LINE__, cmd);
	system(cmd);

	strlcpy(xtm_tuple[idx], ptm_tuple, sizeof(xtm_tuple[idx]));
	nvram_set("dslx_ptm_qid", "0");
}

static int _get_xdsl_obj(char *obj, size_t obj_len, char *data, size_t *data_len)
{
	ADSLDRV_GET_OBJ Arg;
	int fd = -1;
	int ret = -1;

	fd = open("/dev/bcmadsl0", O_RDWR);
	if (fd != -1)
	{
		Arg.objId = obj;
		Arg.objIdLen = obj_len;
		Arg.dataBuf = data;
		Arg.dataBufLen = *data_len;
		ioctl( fd, ADSLIOCTL_GET_OBJ_VALUE, &Arg );
		close(fd);

		*data_len = Arg.dataBufLen;
		if (Arg.bvStatus != BCMADSL_STATUS_ERROR)
			ret = 0;
	}

	return (ret);
}

static int _get_xdsl_priv_obj_by_id(char *data, size_t *num, char id)
{
	char obj[] = { kOidAdslPrivate, id };
	return _get_xdsl_obj(obj, sizeof(obj), data, num);
}

static int _set_xdsl_obj(char *obj, size_t obj_len, char *data, size_t *data_len)
{
	ADSLDRV_GET_OBJ Arg;
	int fd = -1;
	int ret = -1;

	fd = open("/dev/bcmadsl0", O_RDWR);
	if (fd != -1)
	{
		Arg.objId = obj;
		Arg.objIdLen = obj_len;
		Arg.dataBuf = data;
		Arg.dataBufLen = *data_len;
		ioctl( fd, ADSLIOCTL_SET_OBJ_VALUE, &Arg );
		close(fd);

		*data_len = Arg.dataBufLen;
		if (Arg.bvStatus != BCMADSL_STATUS_ERROR)
			ret = 0;
	}

	return (ret);
}

static int _set_xdsl_oem_param(int id, const char *data, size_t data_len)
{
	ADSLDRV_SET_OEM_PARAM Arg;
	int fd = -1;
	int ret = -1;

	fd = open("/dev/bcmadsl0", O_RDWR);
	if (fd != -1)
	{
		Arg.paramId = id;
		Arg.buf = data;
		Arg.len = data_len;
		ioctl( fd, ADSLIOCTL_SET_OEM_PARAM, &Arg );
		close(fd);

		if (Arg.bvStatus != BCMADSL_STATUS_ERROR)
			ret = 0;
	}

	return (ret);
}

void set_vendor_id(const char* vendor_id)
{
	size_t len = 0;
	if (vendor_id && (len = strlen(vendor_id)))
		len = len <= kAdslPhysVendorIdLen ? len : kAdslPhysVendorIdLen;
	_set_xdsl_oem_param(ADSL_OEM_EOC_VENDOR_ID, vendor_id, len);
}

void set_version(const char* version)
{
	size_t len = 0;
	if (version && (len = strlen(version)))
		len = len <= kAdslPhysVersionNumLen ? len : kAdslPhysVersionNumLen;
	_set_xdsl_oem_param(ADSL_OEM_EOC_VERSION, version, len);
}

void set_serial_no(const char* serial_no)
{
	size_t len = 0;
	if (serial_no && (len = strlen(serial_no)))
		len = len <= kAdslPhysSerialNumLen ? len : kAdslPhysSerialNumLen;
	_set_xdsl_oem_param(ADSL_OEM_EOC_SERIAL_NUMBER, serial_no, len);
}

void get_xdsl_info(XDSL_INFO *info)
{
	adslMibInfo adslMib;
	size_t adslMib_len = sizeof(adslMib);
	char vectState;
	size_t vectState_len = sizeof(vectState);

	if (_get_xdsl_obj(NULL, 0, (char *)&adslMib, &adslMib_len) == 0)
	{
		// Line status
		switch (adslMib.adslTrainingState)
		{
			case kAdslTrainingIdle:
				info->line_state = 0;
				break;
			case kAdslTrainingConnected:
				info->line_state = 2;
				break;
			default:
				info->line_state = 1;
				break;
		}

		// Modulation
		switch (adslMib.adslConnection.modType)
		{
			case kAdslModGdmt:
				snprintf(info->mod, sizeof(info->mod), "G.DMT");
				break;
			case kAdslModT1413:
				snprintf(info->mod, sizeof(info->mod), "T1.413");
				break;
			case kAdslModGlite:
				snprintf(info->mod, sizeof(info->mod), "G.lite");
				break;
			case kAdslModAnnexI:
				snprintf(info->mod, sizeof(info->mod), "AnnexI");
				break;
			case kAdslModAdsl2:
				snprintf(info->mod, sizeof(info->mod), "ADSL2");
				break;
			case kAdslModAdsl2p:
				snprintf(info->mod, sizeof(info->mod), "ADSL2+");
				break;
			case kAdslModReAdsl2:
				snprintf(info->mod, sizeof(info->mod), "RE-ADSL2+");
				break;
			case kVdslModVdsl2:
				snprintf(info->mod, sizeof(info->mod), "VDSL2");
				info->is_vdsl2_gfast = 1;
				break;
			case kXdslModGfast:
				snprintf(info->mod, sizeof(info->mod), "G.fast");
				info->is_vdsl2_gfast = 1;
				break;
			default:
				snprintf(info->mod, sizeof(info->mod), "Unknown");
				break;
		}

		// Annex type
		if (adslMib.xdslInfo.xdslMode & kAdsl2ModeAnnexMask)
		{
			if (*nvram_get("dsllog_drvver") == 'B')
				snprintf(info->type, sizeof(info->type), "Annex J");
			else
				snprintf(info->type, sizeof(info->type), "Annex M");
		}
		else
		{
			switch (adslMib.xdslInfo.xdslMode >> kXdslModeAnnexShift)
			{
				case kAdslTypeAnnexA:
					snprintf(info->type, sizeof(info->type), "Annex A");
					break;
				case kAdslTypeAnnexB:
					snprintf(info->type, sizeof(info->type), "Annex B");
					break;
				case kAdslTypeAnnexC:
					snprintf(info->type, sizeof(info->type), "Annex C");
					break;
				case kAdslTypeSADSL:
					snprintf(info->type, sizeof(info->type), "Annex SADSL");
					break;
				case kAdslTypeAnnexI:
					snprintf(info->type, sizeof(info->type), "Annex I");
					break;
				case kAdslTypeAnnexAB:
					snprintf(info->type, sizeof(info->type), "Annex AB");
					break;
				case kAdslTypeAnnexL:
					snprintf(info->type, sizeof(info->type), "Annex L");
					break;
				default:
					snprintf(info->type, sizeof(info->type), "Unknown");
					break;
			}
		}

		// Profile
		switch (adslMib.xdslInfo.vdsl2Profile)
		{
			case kVdslProfile8a:
				snprintf(info->profile, sizeof(info->profile), "8a");
				break;
			case kVdslProfile8b:
				snprintf(info->profile, sizeof(info->profile), "8b");
				break;
			case kVdslProfile8c:
				snprintf(info->profile, sizeof(info->profile), "8c");
				break;
			case kVdslProfile8d:
				snprintf(info->profile, sizeof(info->profile), "8d");
				break;
			case kVdslProfile12a:
				snprintf(info->profile, sizeof(info->profile), "12a");
				break;
			case kVdslProfile12b:
				snprintf(info->profile, sizeof(info->profile), "12b");
				break;
			case kVdslProfile17a:
				snprintf(info->profile, sizeof(info->profile), "17a");
				break;
			case kVdslProfile30a:
				snprintf(info->profile, sizeof(info->profile), "30a");
				break;
			case kVdslProfile35b:
				snprintf(info->profile, sizeof(info->profile), "35b");
				break;
			case kVdslProfileBrcmPriv2:
				snprintf(info->profile, sizeof(info->profile), "BrcmPriv2");
				break;
			case kGfastProfile106a:
				snprintf(info->profile, sizeof(info->profile), "Gfast 106a");
				break;
			case kGfastProfile212a:
				snprintf(info->profile, sizeof(info->profile), "Gfast 212a");
				break;
			case kGfastProfile106b:
				snprintf(info->profile, sizeof(info->profile), "Gfast 106b");
				break;
			case kGfastProfile106c:
				snprintf(info->profile, sizeof(info->profile), "Gfast 106c");
				break;
			case kGfastProfile212c:
				snprintf(info->profile, sizeof(info->profile), "Gfast 212c");
				break;
			default:
				snprintf(info->profile, sizeof(info->profile), "Unknown");
				break;
		}

		// Vectoring State
		if (_get_xdsl_priv_obj_by_id(&vectState, &vectState_len, kOIdAdslPrivGetVectState))
			_dprintf("Get Vectoring State failed\n");
		else
			switch (vectState)
			{
				case VECT_WAIT_FOR_CONFIG:
					snprintf(info->vect, sizeof(info->vect), "Wait for config");
					break;
				case VECT_FULL:
					snprintf(info->vect, sizeof(info->vect), "Full");
					break;
				case VECT_WAIT_FOR_TRIGGER:
					snprintf(info->vect, sizeof(info->vect), "Wait for trigger");
					break;
				case VECT_RUNNING:
					snprintf(info->vect, sizeof(info->vect), "Running");
					break;
				case VECT_DISABLED:
					snprintf(info->vect, sizeof(info->vect), "Disabled");
					break;
				case VECT_UNCONFIGURED:
					snprintf(info->vect, sizeof(info->vect), "Unconfigured");
					break;
				default:
					snprintf(info->vect, sizeof(info->vect), "Unknown");
					break;
			}

		// Vendor id
		memcpy(info->vid, adslMib.xdslAtucPhys.adslVendorID, sizeof(info->vid));

		// Trellis coded modulation
		if (adslMib.adslConnection.modType<kAdslModAdsl2 )
		{
			if (adslMib.adslConnection.trellisCoding ==kAdslTrellisOn)
			{
				info->tcm_up = 1;
				info->tcm_down = 1;
			}
			else
			{
				info->tcm_up = 1;
				info->tcm_down = 1;
			}
		}
		else
		{
			if ((adslMib.adslConnection.trellisCoding2 & kAdsl2TrellisTxEnabled) == 0)
				info->tcm_up = 0;
			else
				info->tcm_up = 1;
			if ((adslMib.adslConnection.trellisCoding2 & kAdsl2TrellisRxEnabled) == 0)
				info->tcm_down = 0;
			else
				info->tcm_down = 1;
		}

		// SNR margin
		snprintf(info->snrm_down, sizeof(info->snrm_down), "%s%d.%d dB"
			, (adslMib.adslPhys.adslCurrSnrMgn < 0) ? "-" : ""
			, abs(adslMib.adslPhys.adslCurrSnrMgn) / 10
			, abs(adslMib.adslPhys.adslCurrSnrMgn) % 10);
		snprintf(info->snrm_up, sizeof(info->snrm_up), "%s%d.%d dB"
			, (adslMib.adslAtucPhys.adslCurrSnrMgn < 0) ? "-" : ""
			, abs(adslMib.adslAtucPhys.adslCurrSnrMgn) / 10
			, abs(adslMib.adslAtucPhys.adslCurrSnrMgn) % 10);

		// Attenuation
		snprintf(info->attn_down, sizeof(info->attn_down), "%s%d.%d dB"
			, (adslMib.adslPhys.adslCurrAtn < 0) ? "-" : ""
			, abs(adslMib.adslPhys.adslCurrAtn) / 10
			, abs(adslMib.adslPhys.adslCurrAtn) % 10);
		snprintf(info->attn_up, sizeof(info->attn_up), "%s%d.%d dB"
			, (adslMib.adslAtucPhys.adslCurrAtn < 0) ? "-" : ""
			, abs(adslMib.adslAtucPhys.adslCurrAtn) / 10
			, abs(adslMib.adslAtucPhys.adslCurrAtn) % 10);

		// Power
		snprintf(info->pwr_up, sizeof(info->pwr_up), "%s%d.%d dBm"
			, (adslMib.adslPhys.adslCurrOutputPwr < 0) ? "-" : ""
			, abs(adslMib.adslPhys.adslCurrOutputPwr) / 10
			, abs(adslMib.adslPhys.adslCurrOutputPwr) % 10);
		snprintf(info->pwr_down, sizeof(info->pwr_down), "%s%d.%d dBm"
			, (adslMib.adslAtucPhys.adslCurrOutputPwr < 0) ? "-" : ""
			, abs(adslMib.adslAtucPhys.adslCurrOutputPwr) / 10
			, abs(adslMib.adslAtucPhys.adslCurrOutputPwr) % 10);

		// Attainable Data rate
		snprintf(info->max_rate_down, sizeof(info->max_rate_down), "%d Kbps"
			,adslMib.adslPhys.adslCurrAttainableRate / 1000);
		snprintf(info->max_rate_up, sizeof(info->max_rate_up), "%d Kbps"
			,adslMib.adslAtucPhys.adslCurrAttainableRate / 1000);

		// Data rate
		snprintf(info->rate_down, sizeof(info->rate_down), "%d Kbps"
			, adslMib.xdslInfo.dirInfo[0].lpInfo[0].dataRate);
		snprintf(info->rate_up, sizeof(info->rate_up), "%d Kbps"
			, adslMib.xdslInfo.dirInfo[1].lpInfo[0].dataRate);

		// FEC
		info->fec_down = adslMib.adslStat.rcvStat.cntRSCor;
		info->fec_up = adslMib.adslStat.xmtStat.cntRSCor;

		// HEC
		info->hec_down = adslMib.atmStat2lp[0].rcvStat.cntHEC;
		info->hec_up = adslMib.atmStat2lp[0].xmtStat.cntHEC;

		// CRC
		info->crc_down = adslMib.adslStat.rcvStat.cntSFErr;
		info->crc_up = adslMib.adslStat.xmtStat.cntSFErr;

		// ES
		info->es_down = adslMib.adslPerfData.perfSinceShowTime.adslESs;
		info->es_up = adslMib.adslTxPerfSinceShowTime.adslESs;

		// SES
		info->ses_down = adslMib.adslPerfData.perfSinceShowTime.adslSES;
		info->ses_up = adslMib.adslTxPerfSinceShowTime.adslSES;

		// G.INP
		info->ginp_down = (adslMib.xdslStat[0].ginpStat.status & 0x4)? 1: 0;
		info->ginp_up = (adslMib.xdslStat[0].ginpStat.status & 0x8)? 1: 0;

		// INP
		snprintf(info->inp_down, sizeof(info->inp_down), "%4.2f"
			, (float)adslMib.xdslInfo.dirInfo[0].lpInfo[0].INP/2);
		snprintf(info->inp_up, sizeof(info->inp_up), "%4.2f"
			, (float)adslMib.xdslInfo.dirInfo[1].lpInfo[0].INP/2);

		// INP REIN
		snprintf(info->inp_rein_down, sizeof(info->inp_rein_down), "%4.2f"
			, (float)adslMib.xdslInfo.dirInfo[0].lpInfo[0].INPrein/2);
		snprintf(info->inp_rein_up, sizeof(info->inp_rein_up), "%4.2f"
			, (float)adslMib.xdslInfo.dirInfo[1].lpInfo[0].INPrein/2);

		// interleaving depth
		info->intlv_depth_down = adslMib.xdslInfo.dirInfo[0].lpInfo[0].D;
		info->intlv_depth_up = adslMib.xdslInfo.dirInfo[1].lpInfo[0].D;

		// VDSL band status
		if((adslMib.adslConnection.modType == kVdslModVdsl2) || (adslMib.adslConnection.modType == kXdslModGfast))
		{
			int i;
			bandPlanDescriptor32 bp;
			short data[5] = {0};
			size_t bp_len = sizeof(bp);
			size_t data_len = sizeof(data);
			char obj1[] = {kOidAdslPrivate, kOidAdslPrivExtraInfo, 0};
			char obj2[] = {kOidAdslPrivate, 0};

			//Line attenuation up
			obj1[2] = kOidAdslPrivBandPlanUSNegDiscoveryPresentation;
			obj2[1] = kOidAdslPrivLATNusperband;
			if (_get_xdsl_obj(obj1, sizeof(obj1), (char *)&bp, &bp_len) == 0
			 && _get_xdsl_obj(obj2, sizeof(obj2), (char *)data, &data_len) == 0
			) {
				for (i = 0; i < 5; i++)
				{
					if (i)
						strlcat(info->latn_pb_up, ",", sizeof(info->latn_pb_up));
					if (i < bp.noOfToneGroups)
					{
						if (data[i] == 1023)
							strlcat(info->latn_pb_up, "N/A", sizeof(info->latn_pb_up));
						else
						{
							snprintf(info->latn_pb_up + strlen(info->latn_pb_up)
								, sizeof(info->latn_pb_up) - strlen(info->latn_pb_up)
								, "%s%d.%d"
								, (data[i] < 0) ? "-" : ""
								, abs(data[i]) / 10
								, abs(data[i]) % 10);
						}
					}
					else
						strlcat(info->latn_pb_up, "N/A", sizeof(info->latn_pb_up));
				}
			}
			//Line attenuation down
			obj1[1] = kOidAdslPrivBandPlanDSNegDiscoveryPresentation;
			obj2[1] = kOidAdslPrivLATNdsperband;
			if (_get_xdsl_obj(obj1, sizeof(obj1), (char *)&bp, &bp_len) == 0
			 && _get_xdsl_obj(obj2, sizeof(obj2), (char *)data, &data_len) == 0
			) {
				for (i = 0; i < 5; i++)
				{
					if (i)
						strlcat(info->latn_pb_down, ",", sizeof(info->latn_pb_down));
					if (i < bp.noOfToneGroups)
					{
						if (data[i] == 1023)
							strlcat(info->latn_pb_down, "N/A", sizeof(info->latn_pb_down));
						else
						{
							snprintf(info->latn_pb_down + strlen(info->latn_pb_down)
								, sizeof(info->latn_pb_down) - strlen(info->latn_pb_down)
								, "%s%d.%d"
								, (data[i] < 0) ? "-" : ""
								, abs(data[i]) / 10
								, abs(data[i]) % 10);
						}
					}
					else
						strlcat(info->latn_pb_down, "N/A", sizeof(info->latn_pb_down));
				}
			}

			//Signal attenuation / SNR margin up
			obj1[2] = kOidAdslPrivBandPlanUSNegPresentation;
			if (_get_xdsl_obj(obj1, sizeof(obj1), (char *)&bp, &bp_len) == 0)
			{
				//Signal attenuation  up
				obj2[1] = kOidAdslPrivSATNusperband;
				if (_get_xdsl_obj(obj2, sizeof(obj2), (char *)data, &data_len) == 0)
				{
					for (i = 0; i < 5; i++)
					{
						if (i)
							strlcat(info->satn_pb_up, ",", sizeof(info->satn_pb_up));
						if (i < bp.noOfToneGroups && bp.toneGroups[i].startTone != 0xFFFF)
						{
							if (data[i] == 1023)
								strlcat(info->satn_pb_up, "N/A", sizeof(info->satn_pb_up));
							else
							{
								snprintf(info->satn_pb_up + strlen(info->satn_pb_up)
									, sizeof(info->satn_pb_up) - strlen(info->satn_pb_up)
									, "%s%d.%d"
									, (data[i] < 0) ? "-" : ""
									, abs(data[i]) / 10
									, abs(data[i]) % 10);
							}
						}
						else
							strlcat(info->satn_pb_up, "N/A", sizeof(info->satn_pb_up));
					}
				}
				//SNR margin up
				obj2[1] = kOidAdslPrivSNRMusperband;
				if (_get_xdsl_obj(obj2, sizeof(obj2), (char *)data, &data_len) == 0)
				{
					for (i = 0; i < 5; i++)
					{
						if (i)
							strlcat(info->snrm_pb_up, ",", sizeof(info->snrm_pb_up));
						if (i < bp.noOfToneGroups && bp.toneGroups[i].startTone != 0xFFFF)
						{
							if (data[i] < -511 || data[i] > 511)
								strlcat(info->snrm_pb_up, "N/A", sizeof(info->snrm_pb_up));
							else
							{
								snprintf(info->snrm_pb_up + strlen(info->snrm_pb_up)
									, sizeof(info->snrm_pb_up) - strlen(info->snrm_pb_up)
									, "%s%d.%d"
									, (data[i] < 0) ? "-" : ""
									, abs(data[i]) / 10
									, abs(data[i]) % 10);
							}
						}
						else
							strlcat(info->snrm_pb_up, "N/A", sizeof(info->snrm_pb_up));
					}
				}
			}

			//Signal attenuation / SNR margin down
			obj1[2] = kOidAdslPrivBandPlanDSNegPresentation;
			if (_get_xdsl_obj(obj1, sizeof(obj1), (char *)&bp, &bp_len) == 0)
			{
				//Signal attenuation down
				obj2[1] = kOidAdslPrivSATNdsperband;
				if (_get_xdsl_obj(obj2, sizeof(obj2), (char *)data, &data_len) == 0)
				{
					for (i = 0; i < 5; i++)
					{
						if (i)
							strlcat(info->satn_pb_down, ",", sizeof(info->satn_pb_down));
						if (i < bp.noOfToneGroups && bp.toneGroups[i].startTone != 0xFFFF)
						{
							if (data[i] == 1023)
								strlcat(info->satn_pb_down, "N/A", sizeof(info->satn_pb_down));
							else
							{
								snprintf(info->satn_pb_down + strlen(info->satn_pb_down)
									, sizeof(info->satn_pb_down) - strlen(info->satn_pb_down)
									, "%s%d.%d"
									, (data[i] < 0) ? "-" : ""
									, abs(data[i]) / 10
									, abs(data[i]) % 10);
							}
						}
						else
							strlcat(info->satn_pb_down, "N/A", sizeof(info->satn_pb_down));
					}
				}
				//SNR margin down
				obj2[1] = kOidAdslPrivSNRMdsperband;
				if (_get_xdsl_obj(obj2, sizeof(obj2), (char *)data, &data_len) == 0)
				{
					for (i = 0; i < 5; i++)
					{
						if (i)
							strlcat(info->snrm_pb_down, ",", sizeof(info->snrm_pb_down));
						if (i < bp.noOfToneGroups && bp.toneGroups[i].startTone != 0xFFFF)
						{
							if (data[i] < -511 || data[i] > 511)
								strlcat(info->snrm_pb_down, "N/A", sizeof(info->snrm_pb_down));
							else
							{
								snprintf(info->snrm_pb_down + strlen(info->snrm_pb_down)
									, sizeof(info->snrm_pb_down) - strlen(info->snrm_pb_down)
									, "%s%d.%d"
									, (data[i] < 0) ? "-" : ""
									, abs(data[i]) / 10
									, abs(data[i]) % 10);
							}
						}
						else
							strlcat(info->snrm_pb_down, "N/A", sizeof(info->snrm_pb_down));
					}
				}
			}
		}
	}
}

int get_xdsl_ver(char *buf, size_t len)
{
	ADSLDRV_GET_VERSION Arg;
	adslVersionInfo adslVer;
	int fd = -1;
	int ret = -1;

	fd = open("/dev/bcmadsl0", O_RDWR);
	if( fd != -1 )
	{
		Arg.pAdslVer  = &adslVer;
		Arg.bvStatus = BCMADSL_STATUS_ERROR;
		ioctl( fd, ADSLIOCTL_GET_VERSION, &Arg );
		close(fd);

		if (Arg.bvStatus == BCMADSL_STATUS_ERROR)
			ret = -1;
		else
		{
			snprintf(buf, len, "%s", adslVer.phyVerStr);
			ret = 0;
		}
	}
	return (ret);
}

static int _init_xdsl_extra_info()
{
	char obj[] = { kOidAdslPrivate, kOidAdslPrivExtraInfo, kOidAdslPrivSetFlagActualGFactor };
	char data[2];
	size_t data_len = 1;

	return _set_xdsl_obj(obj, sizeof(obj), data, &data_len);
}

static void _trans_snr_data(float *dst, char *src, size_t num)
{
	short *snr = (short *)src;
	int i;

	for (i = 0; i < num; i++)
	{
		if (snr[i] < 0)
			dst[i] = 0.0;
		else
			dst[i] = (snr[i] >> 4) + 0.0625 * (snr[i] & 0xF);
		if (dst[i] > 100.0)
			dst[i] = 0.0;
	}
}

int get_xdsl_snr_us(float *data, size_t *num)
{
	char buf[32768] = {0}; //8192 x 4
	size_t buf_len = sizeof(buf);

	if (_init_xdsl_extra_info() || _get_xdsl_priv_obj_by_id(buf, &buf_len, kOidAdslPrivSNRUsPerToneGroup))
	{
		return -1;
	}
	else
	{
		buf_len >>= 1;
		if (buf_len > *num)
			buf_len = *num;
		else
			*num = buf_len;
		_trans_snr_data(data, buf, buf_len);
	}

	return 0;
}

int get_xdsl_snr_ds(float *data, size_t *num)
{
	char buf[32768] = {0}; //8192 x 4
	size_t buf_len = sizeof(buf);

	if (_init_xdsl_extra_info() || _get_xdsl_priv_obj_by_id(buf, &buf_len, kOidAdslPrivSNRDsPerToneGroup))
	{
		return -1;
	}
	else
	{
		buf_len >>= 1;
		if (buf_len > *num)
			buf_len = *num;
		else
			*num = buf_len;
		_trans_snr_data(data, buf, buf_len);
	}

	return 0;
}

int get_xdsl_bits_us(uint8_t *data, size_t *num)
{
	return (_init_xdsl_extra_info() || _get_xdsl_priv_obj_by_id((char *)data, num, kOidAdslPrivBitAllocUsPerToneGroup));
}

int get_xdsl_bits_ds(uint8_t *data, size_t *num)
{
	return (_init_xdsl_extra_info() || _get_xdsl_priv_obj_by_id((char *)data, num, kOidAdslPrivBitAllocDsPerToneGroup));
}

void set_xdsl_settings(XDSL_PARAM *p)
{
	char adsl2mod[8] = {0};
	char adsl2pmod[8] = {0};
	char* mod[] = {"t", "l", "d", adsl2mod, adsl2pmod, "dlt2pemv", "v"};
	char* vdsl_profile[] = {"0x1FF", "8a", "8b", "8c", "8d", "12a", "12b", "17a", "30a", "0x100"};

	eval("xdslctl", "connection", "--down");
	nvram_set("dsltmp_adslsyncsts", "down");
	eval("xdslctl", "start");

	snprintf(adsl2mod, sizeof(adsl2mod), "2%s%s"
		, (p->annex == DSL_ANNEX_AL || p->annex == DSL_ANNEX_ALM) ? "e":""
		, (p->annex == DSL_ANNEX_AM || p->annex == DSL_ANNEX_ALM) ? "M3":"");
	snprintf(adsl2pmod, sizeof(adsl2pmod), "p%s"
		, (p->annex == DSL_ANNEX_AM || p->annex == DSL_ANNEX_ALM) ? "M5":"");
	eval("xdslctl", "configure1", "--mod", mod[p->mod]);

	if (p->sra)
		eval("xdslctl", "configure1", "--sra", "on");
	else
		eval("xdslctl", "configure1", "--sra", "off");

	if (p->bitswap)
		eval("xdslctl", "configure1", "--bitswap", "on");
	else
		eval("xdslctl", "configure1", "--bitswap", "off");

	if (p->ginp)
		eval("xdslctl", "configure1", "--Ginp", "3");
	else
		eval("xdslctl", "configure1", "--Ginp", "0");

	if (p->snrm > 0)
	{
		char snrm_str[4] = {0};
		snprintf(snrm_str, sizeof(snrm_str), "%d", p->snrm);
		eval("xdslctl", "configure1", "--snr", snrm_str);
	}

	eval("xdslctl", "configure1", "--profile", vdsl_profile[p->vdsl_profile]);

	eval("xdslctl", "configure1", "--SOS", "on");

	eval("xdslctl", "connection", "--up");
}

#endif //RTCONFIG_DSL_HOST
