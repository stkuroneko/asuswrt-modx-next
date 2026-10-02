#include <string.h>
#include <bcmdevs.h>
#include <wlutils.h>
#include <wlioctl.h>
#include "rc.h"
#include "tcode.h"
#include "version.h"

static void set_wl_country(int unit, const char *code, const char *rev)
{
	char tmp[256], prefix[] = "wlXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	nvram_set(strcat_r(prefix, "country_code", tmp), code);
	nvram_set(strcat_r(prefix, "country_rev", tmp), rev);
}

int config_location(void)
{
	int model = get_model();
	char *tcode, location[7];
	char str_country_code[16], str_country_rev[16];
	const struct tcode_location_s *p_location;
	const struct tcode_langcode_s *p_langcode;
#ifdef RTAC68U
	unsigned int flag = hardware_flag();
#endif

	tcode = nvram_safe_get("territory_code");
	strlcpy(location, nvram_safe_get("location_code"), sizeof(location));

	if (!nvram_contains_word("rc_support", "loclist")) {
		/* check allowed location */
		for (p_langcode = tcode_langcode_list; p_langcode->model; p_langcode++) {
			if (p_langcode->model == model &&
			    strncmp(p_langcode->tcode, tcode, 2) == 0 &&
			    strcmp(p_langcode->location, location) == 0)
				break;
		}
		if (p_langcode->model == 0) {
			strcpy(location, "");
			nvram_set("location_code", "");
		}
	}
	dbG("[tcode_langcode] location is [%s]\n", location);

	if (*location == '\0') {
		dbG("[tcode] no location setting, using default location\n");
		strncpy(location, tcode, 2);
		location[2] = '\0';

		if (nvram_contains_word("rc_support", "loclist"))
			nvram_set("location_code", location);
	}
	dbG("[tcode] location is [%s]\n", location);

#ifdef RTCONFIG_AMAS
	if (is_CN_sku() && nvram_get_int("re_mode") && is_CN_location())
		strlcpy(location, "XX", sizeof(location));
#endif

	/* config reg, rev value */
	p_location = &tcode_location_list[0];
#ifdef RTCONFIG_ASUSCTRL
	if (asus_ctrl_en(ASUSCTRL_CHG_PWR))
		p_location = &asusctrl_tcode_location_list[0];
#if defined(RTAC88U) || defined(RTAC3100)
	if(!*nvram_safe_get("chiprev"))
		nvram_set("chiprev", cfe_nvram_safe_get("chiprev"));
	if(nvram_get_hex("chiprev") == 0x3)
		p_location = &legacy_tcode_location_list[0];
#endif
	_dprintf("\n%s:p_location is %s, rev is %x\n", __func__, p_location==&tcode_location_list[0]?"modern":p_location==&asusctrl_tcode_location_list[0]?"p_asusctrl":"legacy", nvram_get_hex("chiprev"));
#endif
	for (; p_location->model != 0; ++p_location) {
		if (model == p_location->model
#ifdef RTAC68U
			 && (flag & p_location->flag) != 0
#endif
		) {
			if (strcmp(p_location->location, location) == 0) {
				sprintf(str_country_code, p_location->prefix_fmt, p_location->idx_base, "ccode");
				sprintf(str_country_rev, p_location->prefix_fmt, p_location->idx_base, "regrev");

				dbG("[tcode] config location: [%s]=[%s], [%s]=[%s]\n",
					str_country_code, p_location->ccode_2g,
					str_country_rev, p_location->regrev_2g);

				nvram_set(str_country_code, p_location->ccode_2g);
				nvram_set(str_country_rev, p_location->regrev_2g);
#ifndef RTCONFIG_BCMARM
				if (nvram_get("regulation_domain") && get_model() != MODEL_RTAC53U)
					nvram_set("regulation_domain", p_location->ccode_2g);
#endif

				dbG("[tcode] set_wl_country, 0, [%s], [%s]\n",
					p_location->ccode_2g, p_location->regrev_2g);
				set_wl_country(0, p_location->ccode_2g, p_location->regrev_2g);

				/* 5G only model */
				if (p_location->ccode_5g != NULL) {
					if ( p_location->model == MODEL_RTAC1200G ||
					    p_location->model == MODEL_RTAC1200GP) {
						sprintf(str_country_code, "sb/1/ccode");
						sprintf(str_country_rev, "sb/1/regrev");
					}
					else if (p_location->model == MODEL_DSLAX82U) {
						strcpy(str_country_code, "0:ccode");
						strcpy(str_country_rev, "0:regrev");
					}
					else {
#ifndef RTAC3200
						sprintf(str_country_code, p_location->prefix_fmt, p_location->idx_base+1, "ccode");
						sprintf(str_country_rev, p_location->prefix_fmt, p_location->idx_base+1, "regrev");
#else
						sprintf(str_country_code, p_location->prefix_fmt, p_location->idx_base-1, "ccode");
						sprintf(str_country_rev, p_location->prefix_fmt, p_location->idx_base-1, "regrev");
#endif
					}

					dbG("[tcode] config location 5G: [%s]=[%s], [%s]=[%s]\n",
						str_country_code, p_location->ccode_5g,
						str_country_rev, p_location->regrev_5g);

					nvram_set(str_country_code, p_location->ccode_5g);
					nvram_set(str_country_rev, p_location->regrev_5g);
#ifndef RTCONFIG_BCMARM
					if ((nvram_get("regulation_domain_5G") || nvram_get("regulation_domain_5g")) &&
						(get_model() != MODEL_RTAC53U))
						nvram_set("regulation_domain_5G", p_location->ccode_5g);
#endif

					dbG("[tcode] set_wl_country, 1, [%s], [%s]\n",
						p_location->ccode_5g, p_location->regrev_5g);
					set_wl_country(1, p_location->ccode_5g, p_location->regrev_5g);
				}

				/* 5G band 2 only model */
				if (p_location->ccode_5g_2 != NULL) {
#ifndef RTAC3200
					sprintf(str_country_code, p_location->prefix_fmt, p_location->idx_base+2, "ccode");
					sprintf(str_country_rev, p_location->prefix_fmt, p_location->idx_base+2, "regrev");
#else
					sprintf(str_country_code, p_location->prefix_fmt, p_location->idx_base+1, "ccode");
					sprintf(str_country_rev, p_location->prefix_fmt, p_location->idx_base+1, "regrev");
#endif

					dbG("[tcode] config location 5G: [%s]=[%s], [%s]=[%s]\n",
						str_country_code, p_location->ccode_5g_2,
						str_country_rev, p_location->regrev_5g_2);

					nvram_set(str_country_code, p_location->ccode_5g_2);
					nvram_set(str_country_rev, p_location->regrev_5g_2);

					dbG("[tcode] set_wl_country, 2, [%s], [%s]\n",
						p_location->ccode_5g_2, p_location->regrev_5g_2);
					set_wl_country(2, p_location->ccode_5g_2, p_location->regrev_5g_2);
				}

				break;
			}
		}
	}

	if ( p_location->model == 0 )
		dbG("[tcode] cannot find location in list!\n");

	return 1;
}

int
check_wl_territory_code()
{
	char *TC;

	TC = nvram_safe_get("territory_code");
	if (!strlen(TC))
		return 0;

	config_location();

	return 0;
}

struct txpower_s {
	uint16 min;
	uint16 max;
	uint8 maxp2ga0;
	uint8 maxp2ga1;
	uint8 cck2gpo;
	uint16 ofdm2gpo0;
	uint16 ofdm2gpo1;
	uint16 mcs2gpo0;
	uint16 mcs2gpo1;
	uint16 mcs2gpo2;
	uint16 mcs2gpo3;
	uint16 mcs2gpo4;
	uint16 mcs2gpo5;
	uint16 mcs2gpo6;
	uint16 mcs2gpo7;
	uint8 cdd2gpo;
	uint8 stbc2gpo;
	uint8 bw402gpo;
	uint8 bwdup2gpo;
};

struct txpower_ac_s {
	uint16 min;
	uint16 max;
	uint8 maxp2ga0;
	uint8 maxp2ga1;
	uint8 maxp2ga2;
};

static const struct txpower_s txpower_list_rtn12hp[] = {
#if defined(RTCONFIG_RALINK)
#elif defined(RTCONFIG_QCA)
#else
	/* 1-20mW */
	{ 1, 20, 0x42, 0x42, 0x0, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0, 0x0, 0x0, 0x0},
	/* 20-40mW */
	{ 21, 40, 0x4A, 0x4A, 0x0, 0x2000, 0x4442, 0x2200, 0x4444, 0x2200, 0x4444, 0x4422, 0x4444, 0x4422, 0x4444, 0x0, 0x0, 0x0, 0x0},
	/* 40-60mW */
	{ 41, 60, 0x52, 0x52, 0x0, 0x2000, 0x6442, 0x2200, 0x6644, 0x2200, 0x6644, 0x4422, 0x8866, 0x4422, 0x8866, 0x0, 0x0, 0x0, 0x0},
	/* 60-80mW */
	{ 61, 79, 0x5A, 0x5A, 0x0, 0x2000, 0x6442, 0x2200, 0x6644, 0x2200, 0x6644, 0x4422, 0x8866, 0x4422, 0x8866, 0x0, 0x0, 0x0, 0x0},
	/* > 80mW */
	{ 80, 999, 0x66, 0x66, 0x0, 0x2000, 0x6442, 0x2200, 0x6644, 0x2200, 0x6644, 0x4422, 0x8866, 0x4422, 0x8866, 0x0, 0x0, 0x0, 0x0},
#endif	/* !RTCONFIG_RALINK */
	{ 0, 0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
};

static const struct txpower_s txpower_list_rtn12hp_b1[] = {
#if !defined(RTCONFIG_RALINK)
	/* 1-19mW */
	{ 1, 19, 0x3C, 0x3C, 0x0, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x4422, 0x0000, 0x4422, 0x0, 0x0, 0x0, 0x0},
	/* 20-39mW */
	{ 20, 39, 0x42, 0x42, 0x0, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x4422, 0x0000, 0x4422, 0x0, 0x0, 0x0, 0x0},
	/* 40-59mW */
	{ 40, 59, 0x4A, 0x4A, 0x0, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x4422, 0x0000, 0x4422, 0x0, 0x0, 0x0, 0x0},
	/* 60-79mW */
	{ 60, 79, 0x52, 0x52, 0x0, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x4422, 0x0000, 0x4422, 0x0, 0x0, 0x0, 0x0},
	/* > 80mW */
	{ 80, 999, 0x5E, 0x5E, 0x0, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x2200, 0x0000, 0x4422, 0x0000, 0x4422, 0x0, 0x0, 0x0, 0x0},
#endif  /* !RTCONFIG_RALINK */
	{ 0, 0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
};

static const struct txpower_ac_s txpower_list_rtac87u[] = {
#if !defined(RTCONFIG_RALINK)
	/* 1 ~ 25% */
	{ 1, 25, 70, 70, 70},
	/* 26 ~ 50% */
	{ 26, 50, 82, 82, 82},
	/* 51 ~ 75% */
	{ 51, 75, 94, 94, 94},
	/* 76 ~ 100% */
	{ 76, 100, 106, 106, 106},
#endif	/* !RTCONFIG_RALINK */
	{ 0, 0, 0x0, 0x0, 0x0 }
};

int setpoweroffset_rtn12hp(uint8 level, char *prefix2)
{
	char tmp[100], tmp2[100];
	const struct txpower_s *p;
	int model;
	model = get_model();
	dbG("[rc] setpoweroffset_rtn12hp, level[%d]\n", level);

	if (model == MODEL_RTN12HP_B1)
		p = &txpower_list_rtn12hp_b1[level];
	else
		p = &txpower_list_rtn12hp[level];

	sprintf(tmp2, "0x%02X", p->maxp2ga0);
	nvram_set(strcat_r(prefix2, "maxp2ga0", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%02X", p->maxp2ga1);
	nvram_set(strcat_r(prefix2, "maxp2ga1", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%01X", p->cck2gpo);
	nvram_set(strcat_r(prefix2, "cck2gpo", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X%04X", p->ofdm2gpo1,p->ofdm2gpo0);
	nvram_set(strcat_r(prefix2, "ofdm2gpo", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo0);
	nvram_set(strcat_r(prefix2, "mcs2gpo0", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo1);
	nvram_set(strcat_r(prefix2, "mcs2gpo1", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo2);
	nvram_set(strcat_r(prefix2, "mcs2gpo2", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo3);
	nvram_set(strcat_r(prefix2, "mcs2gpo3", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo4);
	nvram_set(strcat_r(prefix2, "mcs2gpo4", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo5);
	nvram_set(strcat_r(prefix2, "mcs2gpo5", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo6);
	nvram_set(strcat_r(prefix2, "mcs2gpo6", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%04X", p->mcs2gpo7);
	nvram_set(strcat_r(prefix2, "mcs2gpo7", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%01X", p->cdd2gpo);
	nvram_set(strcat_r(prefix2, "cddpo", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%01X", p->stbc2gpo);
	nvram_set(strcat_r(prefix2, "stbcpo", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%01X", p->bw402gpo);
	nvram_set(strcat_r(prefix2, "bw40po", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%01X", p->bwdup2gpo);
	nvram_set(strcat_r(prefix2, "bwduppo", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	return 1;
}

int setpoweroffset_rtac87u(uint8 level, char *prefix2)
{
	char tmp[100], tmp2[100];
	const struct txpower_ac_s *p;

	dbG("[%d][%s]\n", level, prefix2);

	p = &txpower_list_rtac87u[level];

	sprintf(tmp2, "0x%02X", p->maxp2ga0);
	nvram_set(strcat_r(prefix2, "maxp2ga0", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%02X", p->maxp2ga1);
	nvram_set(strcat_r(prefix2, "maxp2ga1", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	sprintf(tmp2, "0x%02X", p->maxp2ga2);
	nvram_set(strcat_r(prefix2, "maxp2ga2", tmp), tmp2);
	dbG("[rc] [%s]=[%s]\n", tmp,tmp2);

	return 1;
}

int wltxpower_rtn12hp(int txpower, char *tmp, char *prefix, char *tmp2, char *prefix2)
{
	int commit_needed = 0;
	int level;
	const struct txpower_s *p;
	int model;

#if 0	/* move to init.c */
	if (nvram_match(strcat_r(prefix, "country_code", tmp), "US"))
	{
		if (nvram_match(strcat_r(prefix, "country_rev", tmp), "37"))
		{
			nvram_set(strcat_r(prefix2, "regrev", tmp2), "16");
			commit_needed++;
		}
	}
#endif

#if 1	/* TMP, RT-N12HP */
	/* config power offset */
	level = 0;
	model = get_model();
	if (model == MODEL_RTN12HP_B1)	p = &txpower_list_rtn12hp_b1[0];
	else				p = &txpower_list_rtn12hp[0];

	for (; p && p->min; p++) {
		if (txpower >= p->min && txpower <= p->max) {
			dbG("[rc] txpoewr between: min:[%d] to max:[%d]\n",
									p->min, p->max);
			/* prefix2 is sb_1 */
			setpoweroffset_rtn12hp(level, prefix2);
			break;
		}
		level++;
	}

	if (p->min == 0)
		dbG("[rc] no correct power offset!\n");

	commit_needed = 1;
#endif

	return commit_needed;
}

int wltxpower_rtac87u(int txpower, char *prefix2)
{
	int commit_needed = 0;
	int level;
	const struct txpower_ac_s *p;

	dbG("[%d][%s]\n", txpower, prefix2);
#if 1	/* TMP, RT-AC87U */
	/* config power offset */
	level = 0;

	p = &txpower_list_rtac87u[0];
	for (; p && p->min; p++) {
		if (txpower >= p->min && txpower <= p->max) {
			dbG("txpoewr between: min:[%d] to max:[%d]\n",
									p->min, p->max);
			/* prefix2 is 0: */
			setpoweroffset_rtac87u(level, prefix2);
			break;
		}
		level++;
	}

	if (p->min == 0)
		dbG("no correct power offset!\n");

	commit_needed = 1;
#endif

	return commit_needed;
}

#define TXPWR_THRESHOLD_1	25
#define TXPWR_THRESHOLD_2	50
#define TXPWR_THRESHOLD_3	88
#define TXPWR_THRESHOLD_4	100

#if defined(RTCONFIG_HND_ROUTER_AX)
void set_wltxpower_degrade()
{
	char ifname[32], *next = NULL;
	int unit, txpower = 100;

	unit = 0;
	foreach (ifname, nvram_safe_get("wl_ifnames"), next) {
		txpower = nvram_get_int(wl_nvname("txpower", unit, 0));
		dbG("unit: %d, txpower: %d\n", unit, txpower);

		if (txpower > 90)
			eval("wl", "-i", ifname, "txpwr_degrade", "0");
		else if (txpower > 60)
			eval("wl", "-i", ifname, "txpwr_degrade", "5");	// decrease 1.25 dB
		else if (txpower > 30)
			eval("wl", "-i", ifname, "txpwr_degrade", "12");// decrease 3 dB
		else if (txpower > 15)
			eval("wl", "-i", ifname, "txpwr_degrade", "24");// decrease 6 dB
		else
			eval("wl", "-i", ifname, "txpwr_degrade", "36");// decrease 9 dB

		unit++;
	}
}
#endif

int set_wltxpower()
{
#if 0
	char ifnames[256], ifname[64];
#endif
	char name[64], *next = NULL;
	int unit = -1;
#if 0
	int subunit = -1;
#endif
	char tmp[100], prefix[]="wlXXXXXXX_";
	char tmp2[100], prefix2[]="pci/x/1/";
	int txpower = 100;
	int commit_needed = 0;
	int model;

	// generate nvram nvram according to system setting
	model = get_model();

	if (!nvram_contains_word("rc_support", "pwrctrl")) {
		dbG("[rc] no Power Control on this model\n");
		return -1;
	}

#if defined(RTCONFIG_HND_ROUTER_AX)
	set_wltxpower_degrade();
	return 0;
#endif

#if 0
	snprintf(ifnames, sizeof(ifnames), "%s %s",
		 nvram_safe_get("lan_ifnames"), nvram_safe_get("wan_ifnames"));
	remove_dups(ifnames, sizeof(ifnames));

	foreach(name, ifnames, next) {
#else
	unit = 0;
	foreach (name, nvram_safe_get("wl_ifnames"), next) {
#endif
#if 0
		if (nvifname_to_osifname(name, ifname, sizeof(ifname)) != 0)
			continue;

		if (wl_probe(ifname) || wl_ioctl(ifname, WLC_GET_INSTANCE, &unit, sizeof(unit)))
			continue;

		/* Convert eth name to wl name */
		if (osifname_to_nvifname(name, ifname, sizeof(ifname)) != 0)
			continue;

		/* Slave intefaces have a '.' in the name */
		if (strchr(ifname, '.'))
			continue;

		if (get_ifname_unit(ifname, &unit, &subunit) < 0)
			continue;
#endif

		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		switch(model) {
			case MODEL_RTN53:
			case MODEL_RTN16:
			case MODEL_RTN15U:
			case MODEL_RTN12:
			case MODEL_RTN12B1:
			case MODEL_RTN12C1:
			case MODEL_RTN12D1:
			case MODEL_RTN12VP:
			case MODEL_RTN12HP:
			case MODEL_RTN12HP_B1:
			case MODEL_APN12HP:
			case MODEL_RTN14UHP:
			case MODEL_RTN10U:
			case MODEL_RTN10P:
			case MODEL_RTN10D1:
			case MODEL_RTN10PV2:
			case MODEL_RTAC53U:
				if (unit == 0)	/* 2.4G */
					snprintf(prefix2, sizeof(prefix2), "sb/1/");
				else		/* 5G */
					snprintf(prefix2, sizeof(prefix2), "0:");
				break;

			case MODEL_RTN66U:
			case MODEL_RTAC66U:
				snprintf(prefix2, sizeof(prefix2), "pci/%d/1/", unit + 1);
				break;

			case MODEL_RTAX88U:
				snprintf(prefix2, sizeof(prefix2), "%d:", unit + 1);
 				break;

			case MODEL_RPAX56:
			case MODEL_RPAX58:
			case MODEL_RTAX55:
			case MODEL_TUFAX3000_V2:
 			case MODEL_RTAX56U:
				snprintf(prefix2, sizeof(prefix2), "sb/%d/", unit);
				break;

			case MODEL_RTN18U:
			case MODEL_RTAC68U:
			case MODEL_DSLAC68U:
			case MODEL_RTAC87U:
			case MODEL_RTAC56S:
			case MODEL_RTAC56U:
			case MODEL_RTAC88U:
			case MODEL_RTAC86U:
			case MODEL_RTAC3100:
			case MODEL_RTAC5300:
			case MODEL_GTAC5300:
 			case MODEL_RTAX95Q:
 			case MODEL_XT8PRO:
			case MODEL_XT8_V2:
 			case MODEL_RTAXE95Q:
 			case MODEL_ET8PRO:
 			case MODEL_RTAX56_XD4:
 			case MODEL_XD4PRO:
 			case MODEL_CTAX56_XD4:
			case MODEL_RTAX58U:
			case MODEL_RTAX82_XD6S:
			case MODEL_RTAX58U_V2:
			case MODEL_RTAXE7800:
			default:
				snprintf(prefix2, sizeof(prefix2), "%d:", unit);
				break;

			case MODEL_RTAC3200:
				if (unit < 2)
					snprintf(prefix2, sizeof(prefix2), "%d:", 1 - unit);
				else
					snprintf(prefix2, sizeof(prefix2), "%d:", unit);
				break;
		}

		txpower = nvram_get_int(wl_nvname("txpower", unit, 0));
		dbG("unit: %d, txpower: %d\n", unit, txpower);

		switch(model) {
			case MODEL_RTAC66U:
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x34"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x34");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x34");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x34");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x11111111");
							nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x11111111");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0x11111111");
							nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0x11111111");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0x11111111");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x40"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x40");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x40");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x40");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x74111111");
							nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x74111111");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0x77741111");
							nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0x77741111");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0x77763333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x4C"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x4C");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x4C");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x4C");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x74111111");
							nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x74111111");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0xDA741111");
							nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0xDA741111");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0xDC963333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x58"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x58");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x58");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x58");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x74111111");
							nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x74111111");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0xDA741111");
							nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0xDA741111");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0xFC963333");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2));
						commit_needed++;
					}
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "52,52,52,52"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"52,52,52,52");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"52,52,52,52");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"52,52,52,52");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x33333333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x33333333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "64,64,64,64"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"64,64,64,64");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"64,64,64,64");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"64,64,64,64");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99975333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "76,76,76,76"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"76,76,76,76");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"76,76,76,76");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"76,76,76,76");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99975333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "88,88,88,88"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"88,88,88,88");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"88,88,88,88");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"88,88,88,88");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99975333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99975333");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
						commit_needed++;
					}
				}

#if 0
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
				{
					dbG("maxp2ga0: %s\n", nvram_get(strcat_r(prefix2, "maxp2ga0", tmp2)) ? : "NULL");
					dbG("maxp2ga1: %s\n", nvram_get(strcat_r(prefix2, "maxp2ga1", tmp2)) ? : "NULL");
					dbG("maxp2ga2: %s\n", nvram_get(strcat_r(prefix2, "maxp2ga2", tmp2)) ? : "NULL");
					dbG("cckbw202gpo: %s\n", nvram_get(strcat_r(prefix2, "cckbw202gpo", tmp2)) ? : "NULL");
					dbG("cckbw20ul2gpo: %s\n", nvram_get(strcat_r(prefix2, "cckbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("legofdmbw202gpo: %s\n", nvram_get(strcat_r(prefix2, "legofdmbw202gpo", tmp2)) ? : "NULL");
					dbG("legofdmbw20ul2gpo: %s\n", nvram_get(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("mcsbw202gpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw202gpo", tmp2)) ? : "NULL");
					dbG("mcsbw20ul2gpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("mcsbw402gpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw402gpo", tmp2)) ? : "NULL");
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					dbG("maxp5ga0: %s\n", nvram_get(strcat_r(prefix2, "maxp5ga0", tmp2)) ? : "NULL");
					dbG("maxp5ga1: %s\n", nvram_get(strcat_r(prefix2, "maxp5ga1", tmp2)) ? : "NULL");
					dbG("maxp5ga2: %s\n", nvram_get(strcat_r(prefix2, "maxp5ga2", tmp2)) ? : "NULL");
					dbG("mcsbw205glpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw205glpo", tmp2)) ? : "NULL");
					dbG("mcsbw405glpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw405glpo", tmp2)) ? : "NULL");
					dbG("mcsbw805glpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw805glpo", tmp2)) ? : "NULL");
					dbG("mcsbw205gmpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw205gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw405gmpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw405gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw805gmpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw805gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw205ghpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw205ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw405ghpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw405ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw805ghpo: %s\n", nvram_get(strcat_r(prefix2, "mcsbw805ghpo", tmp2)) ? : "NULL");
				}
				dbG("ccode: %s\n", nvram_safe_get(strcat_r(prefix2, "ccode", tmp2)));
				dbG("regrev: %s\n", nvram_safe_get(strcat_r(prefix2, "regrev", tmp2)));
				dbG("country_code: %s\n", nvram_safe_get(strcat_r(prefix, "country_code", tmp)));
				dbG("country_rev: %s\n", nvram_safe_get(strcat_r(prefix, "country_rev", tmp)));
#endif
				break;

			case MODEL_RTN18U:

				if (txpower < TXPWR_THRESHOLD_1)
				{
					if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "58"))
					{
						nvram_set(strcat_r(prefix2,"maxp2ga0", tmp2), "58");
						nvram_set(strcat_r(prefix2,"maxp2ga1", tmp2), "58");
						nvram_set(strcat_r(prefix2,"maxp2ga2", tmp2), "58");
						nvram_set(strcat_r(prefix2,"mcsbw202gpo", tmp2), "0x66642000");
						nvram_set(strcat_r(prefix2,"mcsbw402gpo", tmp2), "0x66642000");
						nvram_set(strcat_r(prefix2,"dot11agofdmhrbw202gpo", tmp2), "0x6533");
						commit_needed++;
					}
				}
				else if (txpower < TXPWR_THRESHOLD_2)
				{
					if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "70"))
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "70");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x6533");
						commit_needed++;
					}
				}
				else if (txpower < TXPWR_THRESHOLD_3)
				{
					if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "82"))
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "82");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x6533");
						commit_needed++;
					}
				}
				else if (txpower < TXPWR_THRESHOLD_4)
				{
					if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "94"))
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "94");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x6533");
						commit_needed++;
					}
				}
				else	// txpower = 100%
				{
					if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "106"))
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "106");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "106");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "106");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xA8642000");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x6533");
						commit_needed++;
					}
				}

				break;

			case MODEL_DSLAC68U:
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))	// 2.4G, same with RT-AC68U
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "58"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"58");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"58");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"58");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x66653320");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x66653320");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "70"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"70");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"70");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"70");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "82"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"82");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"82");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"82");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "94"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"94");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"94");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"94");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "106"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"106");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"106");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"106");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x88653320");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "58,58,58,58"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x33333311");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99986422");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,94,94"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,94,94");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,94,94");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,94,94");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "106,106,106,106"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"106,106,106,106");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"106,106,106,106");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"106,106,106,106");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCAA86422");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
				}

				break;

			case MODEL_RTAC3200:
				if (unit == 0)	// 2.4G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "58"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"58");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"58");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"58");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x66420000");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x66420000");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x2000");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "70"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"70");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"70");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"70");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x87542000");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x87542000");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x2000");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "82"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"82");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"82");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"82");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x87542000");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x87542000");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x2000");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "94"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"94");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"94");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"94");
							nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x87542000");
							nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x87542000");
							nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x2000");
							nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
							nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2));
						commit_needed++;
					}
				}
				else if (unit == 1)	// 5G low
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "58,58,58,58"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x66643200");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x66643200");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x66643200");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xA8643200");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x66643200");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xA8643200");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,90,90"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,90,90");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,90,90");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,90,90");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x66643200");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xA8643200");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x66664200");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x66663200");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xfffda844");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
						commit_needed++;
					}
				}
				else if (unit == 2)	// 5G high
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "58,58,58,58"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"58,58,58,58");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x66542100");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x66542100");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x66542100");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xA6542100");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xA6542100");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xA6542100");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,94,94"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,94,94");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,94,94");
							nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,94,94");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xAA975420");
							nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
						commit_needed++;
					}
				}

#if 0
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
				{
					dbG("maxp2ga0: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga0", tmp2)) ? : "NULL");
					dbG("maxp2ga1: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga1", tmp2)) ? : "NULL");
					dbG("maxp2ga2: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga2", tmp2)) ? : "NULL");
					dbG("cckbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "cckbw202gpo", tmp2)) ? : "NULL");
					dbG("cckbw20ul2gpo: %s\n",	nvram_get(strcat_r(prefix2, "cckbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("mcsbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw202gpo", tmp2)) ? : "NULL");
					dbG("mcsbw402gpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw402gpo", tmp2)) ? : "NULL");
					dbG("dot11agofdmhrbw202gpo: %s\n",nvram_get(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2)) ? : "NULL");
					dbG("ofdmlrbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2)) ? : "NULL");
					dbG("dot11agduphrpo: %s\n",	nvram_get(strcat_r(prefix2, "dot11agduphrpo", tmp2)) ? : "NULL");
					dbG("dot11agduplrpo: %s\n",	nvram_get(strcat_r(prefix2, "dot11agduplrpo", tmp2)) ? : "NULL");
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					dbG("maxp5ga0: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga0", tmp2)) ? : "NULL");
					dbG("maxp5ga1: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga1", tmp2)) ? : "NULL");
					dbG("maxp5ga2: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga2", tmp2)) ? : "NULL");

					dbG("mcsbw205glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205glpo", tmp2)) ? : "NULL");
					dbG("mcsbw405glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405glpo", tmp2)) ? : "NULL");
					dbG("mcsbw805glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw805glpo", tmp2)) ? : "NULL");
					dbG("mcsbw1605glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw1605glpo", tmp2)) ? : "NULL");

					dbG("mcsbw205gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw405gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw805gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw805gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw1605gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw1605gmpo", tmp2)) ? : "NULL");

					dbG("mcsbw205ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw405ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw805ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw805ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw1605ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw1605ghpo", tmp2)) ? : "NULL");
				}

				dbG("ccode: %s\n", nvram_safe_get(strcat_r(prefix2, "ccode", tmp2)));
				dbG("regrev: %s\n", nvram_safe_get(strcat_r(prefix2, "regrev", tmp2)));
				dbG("country_code: %s\n", nvram_safe_get(strcat_r(prefix, "country_code", tmp)));
				dbG("country_rev: %s\n", nvram_safe_get(strcat_r(prefix, "country_rev", tmp)));
#endif
				break;

#ifdef RTAC68U
			case MODEL_RTAC68U:
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))	// 2.4G
				{
					if (is_ac66u_v2_series()) {

						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "58"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"52");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"52");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"52");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x00000000");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x0000");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "70"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"74");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"74");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"74");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x75310000");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x75310000");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x0000");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "82"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"86");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"86");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"86");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x75310000");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x75310000");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x0000");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "94"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"98");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"98");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"98");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x75310000");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x75310000");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x0000");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							if ((!strcmp(get_productid(), "RT-AC66U_B1") ||
							     !strcmp(get_productid(), "RT-AC1750_B1")) &&
								(nvram_get_double("HW_ver") < 2.00)) {
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"106");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"106");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"106");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0x4444");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0x4444");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x75444444");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x75444444");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x4444");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0x0044");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
							} else {
								cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2));
							}
							commit_needed++;
						}

					} else {

						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "58"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"58");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"58");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"58");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x66653320");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "70"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"70");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"70");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"70");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x88653320");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "82"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"82");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"82");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"82");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x88653320");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "94"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),			"94");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),			"94");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),			"94");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),		"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),		"0x88653320");
								nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2),	"0x6533");
								nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2),		"0");
								nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2),		"0");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "sb20in40hrpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "sb20in40lrpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "dot11agduphrpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "dot11agduplrpo", tmp2));
							commit_needed++;
						}

					}
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					if (is_ac66u_v2_series()) {

						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "52,52,52,52") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x00000000")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"52,52,52,52");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"52,52,52,52");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"52,52,52,52");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x00000000");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x99864200")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCA864200")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,94,94") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCA864200")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCA864200");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							if ((!strcmp(get_productid(), "RT-AC66U_B1") ||
							     !strcmp(get_productid(), "RT-AC1750_B1")) &&
								(nvram_get_double("HW_ver") < 2.00)) {
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"106,106,106,106");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"106,106,106,106");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"106,106,106,106");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCA866666");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
							} else {
								cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
								cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
							}
							commit_needed++;
						}

					} else if (nvram_match(strcat_r(prefix, "country_code", tmp), "Q2")) {

						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "58,58,58,58") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x33333311")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x33333311");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x99986422")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99986422");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCAA86422")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,94,94") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCAA86422")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCAA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
							commit_needed++;
						}

					} else if (nvram_get_int("PA") == 5636) {

						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "58,58,58,58") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xDCAA8640")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xDCAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xDECA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xDEAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCA886420");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xDCAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xDCA88420");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xDCAA6420");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xDCAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xDCA86440");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xECAA8640")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xEECA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xFEAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCA886420");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xECA88420");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xECAA6420");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xECA86440");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xECAA8640")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xEECA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xFEAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCA886420");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xECA88420");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xECAA6420");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xECA86440");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,94,94") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xECAA8640")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xEECA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xFEAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCA886420");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xECA88420");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xECAA6420");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xECAA8640");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xECA86440");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
							commit_needed++;
						}

					} else if (nvram_get_int("PA") == 5542) {

						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "58,58,58,58") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCCA86422")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xCCA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xECA86422")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xECA86422")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!(nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,94,94") &&
							      nvram_match(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xECA86422")))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0xECA86422");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
							commit_needed++;
						}

					} else {

						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "58,58,58,58"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"58,58,58,58");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x66653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "70,70,70,70"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"70,70,70,70");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "82,82,82,82"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"82,82,82,82");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "94,94,94,94"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"94,94,94,94");
								nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2),	"0");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x88653320");
								nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2),	"0");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
							commit_needed++;
						}

					}
				}

#if 0
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
				{
					dbG("maxp2ga0: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga0", tmp2)) ? : "NULL");
					dbG("maxp2ga1: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga1", tmp2)) ? : "NULL");
					dbG("maxp2ga2: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga2", tmp2)) ? : "NULL");
					dbG("cckbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "cckbw202gpo", tmp2)) ? : "NULL");
					dbG("cckbw20ul2gpo: %s\n",	nvram_get(strcat_r(prefix2, "cckbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("mcsbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw202gpo", tmp2)) ? : "NULL");
					dbG("mcsbw402gpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw402gpo", tmp2)) ? : "NULL");
					dbG("dot11agofdmhrbw202gpo: %s\n", nvram_get(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2)) ? : "NULL");
					dbG("ofdmlrbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2)) ? : "NULL");
					dbG("sb20in40hrpo: %s\n",	nvram_get(strcat_r(prefix2, "sb20in40hrpo", tmp2)) ? : "NULL");
					dbG("sb20in40lrpo: %s\n",	nvram_get(strcat_r(prefix2, "sb20in40lrpo", tmp2)) ? : "NULL");
					dbG("dot11agduphrpo: %s\n",	nvram_get(strcat_r(prefix2, "dot11agduphrpo", tmp2)) ? : "NULL");
					dbG("dot11agduplrpo: %s\n",	nvram_get(strcat_r(prefix2, "dot11agduplrpo", tmp2)) ? : "NULL");
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					dbG("maxp5ga0: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga0", tmp2)) ? : "NULL");
					dbG("maxp5ga1: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga1", tmp2)) ? : "NULL");
					dbG("maxp5ga2: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga2", tmp2)) ? : "NULL");
					dbG("mcsbw205glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205glpo", tmp2)) ? : "NULL");
					dbG("mcsbw405glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405glpo", tmp2)) ? : "NULL");
					dbG("mcsbw805glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw805glpo", tmp2)) ? : "NULL");
					dbG("mcsbw1605glpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw1605glpo", tmp2)) ? : "NULL");
					dbG("mcsbw205gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw405gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw805gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw805gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw1605gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw1605gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw205ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw405ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw805ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw805ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw1605ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw1605ghpo", tmp2)) ? : "NULL");
				}

				dbG("ccode: %s\n", nvram_safe_get(strcat_r(prefix2, "ccode", tmp2)));
				dbG("regrev: %s\n", nvram_safe_get(strcat_r(prefix2, "regrev", tmp2)));
				dbG("country_code: %s\n", nvram_safe_get(strcat_r(prefix, "country_code", tmp)));
				dbG("country_rev: %s\n", nvram_safe_get(strcat_r(prefix, "country_rev", tmp)));
#endif
				break;
#endif

			case MODEL_RTAC5300:
			case MODEL_GTAC5300:
				if (unit == 0)	// 2.4G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x4210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0x66542100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0x66542100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0x66666666");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x4210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xB9872100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xB9872100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x4210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xB9872100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xB9872100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x4210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xB9872100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xB9872100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else	// 100 %
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2));
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
				}
				else if (unit == 1)	// 5GL
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0x44444444");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0x44444444");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0xAAAAAAAA");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0xAAAAAAAA");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else	// 100 %
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2));
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
				}
				else if (unit == 2)	// 5GH
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x36");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x3A");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0x44444444");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0x44443210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0x44444444");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0x66665430");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0x66665430");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0x66665430");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0x66666666");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x42");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x46");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0xAAAAAAAA");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0xAAAAAAAA");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0xCCCCCCCC");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x4E");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x52");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0xDCDCDCDC");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x5A");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x5E");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0x98653210");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0xBABABABA");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0xBA875430");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0x00000000");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0xDCDCDCDC");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else	// 100 %
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2));
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
				}

				break;


			case MODEL_RTAX88U:
				if (unit == 0)	// 2.4G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x3E");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x3E");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x3E");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x3E");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x4A");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x4A");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x4A");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x4A");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x56");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x56");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x56");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x56");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x62");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x62");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x62");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x62");
						commit_needed++;
					}
					else	// 100 %
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2));
						commit_needed++;
					}
				}
				else if (unit == 1)	// 5G
				{
				    	int _a, _b;
					if (txpower < TXPWR_THRESHOLD_1)
					{
					   	for(_a=0; _a <= 3; _a++) {
						    for(_b=0; _b <=4; _b++) {
							snprintf(tmp, sizeof(tmp), "%smaxp5gb%da%d", prefix2, _b, _a);
							nvram_set(tmp, "62");
							commit_needed++;
						    }
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
					    	for(_a=0; _a <= 3; _a++) {
						    for(_b=0; _b <=4; _b++) {
							snprintf(tmp, sizeof(tmp), "%smaxp5gb%da%d", prefix2, _b, _a);
							nvram_set(tmp, "74");
							commit_needed++;
						    }
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
					  	for(_a=0; _a <= 3; _a++) {
						    for(_b=0; _b <=4; _b++) {
							snprintf(tmp, sizeof(tmp), "%smaxp5gb%da%d", prefix2, _b, _a);
							nvram_set(tmp, "86");
							commit_needed++;
						    }
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
					   	for(_a=0; _a <= 3; _a++) {
						    for(_b=0; _b <=4; _b++) {
							snprintf(tmp, sizeof(tmp), "%smaxp5gb%da%d", prefix2, _b, _a);
							nvram_set(tmp, "98");
							commit_needed++;
						    }
						}
					}
					else	// 100 %
					{
					   	for(_a=0; _a <= 3; _a++) {
						    for(_b=0; _b <=4; _b++) {
							snprintf(tmp, sizeof(tmp), "%smaxp5gb%da%d", prefix2, _b, _a);
							cfe_nvram_set(tmp);
							commit_needed++;
						    }
						}
					}
				}

				break;


			case MODEL_RTAC88U:
			case MODEL_RTAC3100:
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))	// 2.4G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "58");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x3210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0x66532100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0x66532100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0x66666666");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "70");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x3210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0x97532100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0x97532100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0xBABABABA");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "82");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x3210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0x97532100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0x97532100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0xBABABABA");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "94");
						nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x3210");
						nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0x97532100");
						nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0x97532100");
						nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2), "0xBABABABA");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else	// 100 %
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "ofdmlrbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam2gpo", tmp2));

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "58");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "58");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0x66666666");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0x66666666");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0x66666666");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0x66666666");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0x66666530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0x66666666");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "70");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "70");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0xCCCCCCCC");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0xCCCCCCCC");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0xCCCCCCCC");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0xCCCCCCCC");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0xCCCCCCCC");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "82");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "82");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "94");
						nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "94");
						nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2), "0xCBA97530");
						nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2), "0xEDEDEDED");
						nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2), "0");

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
					else	// 100 %
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5glpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5gmpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5ghpo", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5gx1po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw205gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw405gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw805gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcsbw1605gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcs1024qam5gx2po", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "mcslr5gx2po", tmp2));

						nvram_set(strcat_r(prefix2, "mcs8poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs9poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs10poexp", tmp2), "0");
						nvram_set(strcat_r(prefix2, "mcs11poexp", tmp2), "0");
						commit_needed++;
					}
				}

				break;

#if defined(RTAC86U) || defined(GTAC2900)
			case MODEL_RTAC86U:
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x3A"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x3A");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x46"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x46");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x52"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x52");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x5e"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), "0x5e");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), "0x5e");
							nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), "0x5e");
							nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2), "0x5e");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp2ga3", tmp2));
						commit_needed++;
					}
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x3A"))
						{
							nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x3A");
							nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x3A");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x46"))
						{
							nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x46");
							nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x46");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x52"))
						{
							nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x52");
							nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x52");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x5E"))
						{
							nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2), "0x5E");
							nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2), "0x5E");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a0", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a1", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a2", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb0a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb1a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb2a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb3a3", tmp2));
						cfe_nvram_set(strcat_r(prefix2, "maxp5gb4a3", tmp2));
						commit_needed++;
					}
				}

#if 0
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
				{
					dbG("maxp2ga0: %s\n", nvram_get(strcat_r(prefix2, "maxp2ga0", tmp2)) ? : "NULL");
					dbG("maxp2ga1: %s\n", nvram_get(strcat_r(prefix2, "maxp2ga1", tmp2)) ? : "NULL");
					dbG("maxp2ga2: %s\n", nvram_get(strcat_r(prefix2, "maxp2ga2", tmp2)) ? : "NULL");
					dbG("maxp2ga3: %s\n", nvram_get(strcat_r(prefix2, "maxp2ga3", tmp2)) ? : "NULL");
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					dbG("1:maxp5gb0a0: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb0a0", tmp2)) ? : "NULL");
					dbG("1:maxp5gb1a0: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb1a0", tmp2)) ? : "NULL");
					dbG("1:maxp5gb2a0: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb2a0", tmp2)) ? : "NULL");
					dbG("1:maxp5gb3a0: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb3a0", tmp2)) ? : "NULL");
					dbG("1:maxp5gb4a0: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb4a0", tmp2)) ? : "NULL");
					dbG("1:maxp5gb0a1: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb0a1", tmp2)) ? : "NULL");
					dbG("1:maxp5gb1a1: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb1a1", tmp2)) ? : "NULL");
					dbG("1:maxp5gb2a1: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb2a1", tmp2)) ? : "NULL");
					dbG("1:maxp5gb3a1: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb3a1", tmp2)) ? : "NULL");
					dbG("1:maxp5gb4a1: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb4a1", tmp2)) ? : "NULL");
					dbG("1:maxp5gb0a2: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb0a2", tmp2)) ? : "NULL");
					dbG("1:maxp5gb1a2: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb1a2", tmp2)) ? : "NULL");
					dbG("1:maxp5gb2a2: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb2a2", tmp2)) ? : "NULL");
					dbG("1:maxp5gb3a2: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb3a2", tmp2)) ? : "NULL");
					dbG("1:maxp5gb4a2: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb4a2", tmp2)) ? : "NULL");
					dbG("1:maxp5gb0a3: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb0a3", tmp2)) ? : "NULL");
					dbG("1:maxp5gb1a3: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb1a3", tmp2)) ? : "NULL");
					dbG("1:maxp5gb2a3: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb2a3", tmp2)) ? : "NULL");
					dbG("1:maxp5gb3a3: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb3a3", tmp2)) ? : "NULL");
					dbG("1:maxp5gb4a3: %s\n", nvram_get(strcat_r(prefix2, "maxp5gb4a3", tmp2)) ? : "NULL");
				}
				dbG("ccode: %s\n", nvram_safe_get(strcat_r(prefix2, "ccode", tmp2)));
				dbG("regrev: %s\n", nvram_safe_get(strcat_r(prefix2, "regrev", tmp2)));
				dbG("country_code: %s\n", nvram_safe_get(strcat_r(prefix, "country_code", tmp)));
				dbG("country_rev: %s\n", nvram_safe_get(strcat_r(prefix, "country_rev", tmp)));
#endif

				break;
#endif

			case MODEL_RTAC56S:
			case MODEL_RTAC56U:
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))	// 2.4G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x40"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),	"0x40");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),	"0x40");
							nvram_set(strcat_r(prefix2, "cck2gpo",  tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "ofdm2gpo", tmp2),	"0x32000000");
							nvram_set(strcat_r(prefix2, "mcs2gpo0", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo1", tmp2),	"0x3332");
							nvram_set(strcat_r(prefix2, "mcs2gpo2", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo3", tmp2),	"0x3332");
							nvram_set(strcat_r(prefix2, "mcs2gpo4", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo5", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo6", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo7", tmp2),	"0x3333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x48"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),	"0x48");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),	"0x48");
							nvram_set(strcat_r(prefix2, "cck2gpo",  tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "ofdm2gpo", tmp2),	"0x32000000");
							nvram_set(strcat_r(prefix2, "mcs2gpo0", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo1", tmp2),	"0x5332");
							nvram_set(strcat_r(prefix2, "mcs2gpo2", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo3", tmp2),	"0x5332");
							nvram_set(strcat_r(prefix2, "mcs2gpo4", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo5", tmp2),	"0x7333");
							nvram_set(strcat_r(prefix2, "mcs2gpo6", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo7", tmp2),	"0x7333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x50"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),	"0x50");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),	"0x50");
							nvram_set(strcat_r(prefix2, "cck2gpo",  tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "ofdm2gpo", tmp2),	"0x32000000");
							nvram_set(strcat_r(prefix2, "mcs2gpo0", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo1", tmp2),	"0x7332");
							nvram_set(strcat_r(prefix2, "mcs2gpo2", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo3", tmp2),	"0x7332");
							nvram_set(strcat_r(prefix2, "mcs2gpo4", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo5", tmp2),	"0x9333");
							nvram_set(strcat_r(prefix2, "mcs2gpo6", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo7", tmp2),	"0x9333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x58"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),	"0x58");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),	"0x58");
							nvram_set(strcat_r(prefix2, "cck2gpo",  tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "ofdm2gpo", tmp2),	"0x32000000");
							nvram_set(strcat_r(prefix2, "mcs2gpo0", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo1", tmp2),	"0x9532");
							nvram_set(strcat_r(prefix2, "mcs2gpo2", tmp2),	"0x2222");
							nvram_set(strcat_r(prefix2, "mcs2gpo3", tmp2),	"0x9532");
							nvram_set(strcat_r(prefix2, "mcs2gpo4", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo5", tmp2),	"0xB533");
							nvram_set(strcat_r(prefix2, "mcs2gpo6", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo7", tmp2),	"0xB533");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x64"))
						{
							nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),	"0x64");
							nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),	"0x64");
							nvram_set(strcat_r(prefix2, "cck2gpo",  tmp2),	"0x1111");
							nvram_set(strcat_r(prefix2, "ofdm2gpo", tmp2),	"0x54222222");
							nvram_set(strcat_r(prefix2, "mcs2gpo0", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo1", tmp2),	"0xD954");
							nvram_set(strcat_r(prefix2, "mcs2gpo2", tmp2),	"0x3333");
							nvram_set(strcat_r(prefix2, "mcs2gpo3", tmp2),	"0xD954");
							nvram_set(strcat_r(prefix2, "mcs2gpo4", tmp2),	"0x5555");
							nvram_set(strcat_r(prefix2, "mcs2gpo5", tmp2),	"0xF955");
							nvram_set(strcat_r(prefix2, "mcs2gpo6", tmp2),	"0x5555");
							nvram_set(strcat_r(prefix2, "mcs2gpo7", tmp2),	"0xF955");
							commit_needed++;
						}
					}
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					if (txpower < TXPWR_THRESHOLD_1)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "68,68,68,68"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"68,68,68,68");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"68,68,68,68");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99753333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_2)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "76,76,76,76"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"76,76,76,76");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"76,76,76,76");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99753333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_3)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "84,84,84,84"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"84,84,84,84");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"84,84,84,84");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99753333");
							commit_needed++;
						}
					}
					else if (txpower < TXPWR_THRESHOLD_4)
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "92,92,92,92"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"92,92,92,92");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"92,92,92,92");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99753333");
							commit_needed++;
						}
					}
					else	// txpower == 80 mw
					{
						if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "100,100,100,100"))
						{
							nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"100,100,100,100");
							nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"100,100,100,100");
							nvram_set(strcat_r(prefix2, "mcsbw205glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805glpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805gmpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x99753333");
							nvram_set(strcat_r(prefix2, "mcsbw805ghpo", tmp2),	"0x99753333");
							commit_needed++;
						}
					}
				}

				break;

			case MODEL_RTN66U:
				if (nvram_match("bl_version", "1.0.0.9")) {
					if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
					{
						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x38"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x38");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x38");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x38");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x33333333");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x33333333");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0x33333333");
								nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0x33333333");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0x33333333");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x3333");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x3333");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x40"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x40");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x40");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x40");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x55555555");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x55555555");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0x77755555");
								nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0x77755555");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0x77777777");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x7777");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x2222");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x4C"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x4C");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x4C");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x4C");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x55555555");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x55555555");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0xDC955555");
								nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0xDC955555");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0xDDDD9999");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x9999");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x4444");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), "0x58"))
							{
								nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2),		"0x58");
								nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2),		"0x58");
								nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2),		"0x58");
								nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2),	"0x3333");
								nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2),	"0x55555555");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2),	"0x55555555");
								nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2),	"0xFC955555");
								nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2),	"0xFC955555");
								nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2),	"0xFFFF9999");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x9999");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x4444");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							cfe_nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "cckbw202gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "cckbw20ul2gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdmbw202gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcs32po", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2));
							commit_needed++;
						}
					}
					else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
					{
						if (txpower < TXPWR_THRESHOLD_1)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "0x30"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"0x30");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"0x30");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"0x30");
								nvram_set(strcat_r(prefix2, "legofdmbw205gmpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5gmpo", tmp2),"0x11111111");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5gmpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "maxp5gha0", tmp2),		"0x30");
								nvram_set(strcat_r(prefix2, "maxp5gha1", tmp2),		"0x30");
								nvram_set(strcat_r(prefix2, "maxp5gha2", tmp2),		"0x30");
								nvram_set(strcat_r(prefix2, "legofdmbw205ghpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5ghpo", tmp2),"0x11111111");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5ghpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x11111111");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x1111");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x0000");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_2)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "0x3A"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"0x3A");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"0x3A");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"0x3A");
								nvram_set(strcat_r(prefix2, "legofdmbw205gmpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5gmpo", tmp2),"0x65311111");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5gmpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "maxp5gha0", tmp2),		"0x3A");
								nvram_set(strcat_r(prefix2, "maxp5gha1", tmp2),		"0x3A");
								nvram_set(strcat_r(prefix2, "maxp5gha2", tmp2),		"0x3A");
								nvram_set(strcat_r(prefix2, "legofdmbw205ghpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5ghpo", tmp2),"0x65311111");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5ghpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x65311111");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x2222");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x2222");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_3)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "0x46"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"0x46");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"0x46");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"0x46");
								nvram_set(strcat_r(prefix2, "legofdmbw205gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5gmpo", tmp2),"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "maxp5gha0", tmp2),		"0x46");
								nvram_set(strcat_r(prefix2, "maxp5gha1", tmp2),		"0x46");
								nvram_set(strcat_r(prefix2, "maxp5gha2", tmp2),		"0x46");
								nvram_set(strcat_r(prefix2, "legofdmbw205ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5ghpo", tmp2),"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x2222");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x2222");
								commit_needed++;
							}
						}
						else if (txpower < TXPWR_THRESHOLD_4)
						{
							if (!nvram_match(strcat_r(prefix2, "maxp5ga0", tmp2), "0x52"))
							{
								nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2),		"0x52");
								nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2),		"0x52");
								nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2),		"0x52");
								nvram_set(strcat_r(prefix2, "legofdmbw205gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5gmpo", tmp2),"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "maxp5gha0", tmp2),		"0x52");
								nvram_set(strcat_r(prefix2, "maxp5gha1", tmp2),		"0x52");
								nvram_set(strcat_r(prefix2, "maxp5gha2", tmp2),		"0x52");
								nvram_set(strcat_r(prefix2, "legofdmbw205ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "legofdmbw20ul5ghpo", tmp2),"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw20ul5ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2),	"0x75311111");
								nvram_set(strcat_r(prefix2, "mcs32po", tmp2),		"0x2222");
								nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2),	"0x2222");
								commit_needed++;
							}
						}
						else	// txpower == 80 mw
						{
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5ga2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdmbw205gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdmbw20ul5gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw20ul5gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405gmpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5gha0", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5gha1", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "maxp5gha2", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdmbw205ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdmbw20ul5ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw205ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw20ul5ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcsbw405ghpo", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "mcs32po", tmp2));
							cfe_nvram_set(strcat_r(prefix2, "legofdm40duppo", tmp2));
							commit_needed++;
						}
					}
				}
#if 0
				if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))		// 2.4G
				{
					dbG("maxp2ga0: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga0", tmp2)) ? : "NULL");
					dbG("maxp2ga1: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga1", tmp2)) ? : "NULL");
					dbG("maxp2ga2: %s\n",		nvram_get(strcat_r(prefix2, "maxp2ga2", tmp2)) ? : "NULL");
					dbG("cckbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "cckbw202gpo", tmp2)) ? : "NULL");
					dbG("cckbw20ul2gpo: %s\n",	nvram_get(strcat_r(prefix2, "cckbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("legofdmbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "legofdmbw202gpo", tmp2)) ? : "NULL");
					dbG("legofdmbw20ul2gpo: %s\n",	nvram_get(strcat_r(prefix2, "legofdmbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("mcsbw202gpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw202gpo", tmp2)) ? : "NULL");
					dbG("mcsbw20ul2gpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw20ul2gpo", tmp2)) ? : "NULL");
					dbG("mcsbw402gpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw402gpo", tmp2)) ? : "NULL");
					dbG("mcs32po: %s\n",		nvram_get(strcat_r(prefix2, "mcs32po", tmp2)) ? : "NULL");
					dbG("legofdm40duppo: %s\n",	nvram_get(strcat_r(prefix2, "legofdm40duppo", tmp2)) ? : "NULL");
				}
				else if (nvram_match(strcat_r(prefix, "nband", tmp), "1"))	// 5G
				{
					dbG("maxp5ga0: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga0", tmp2)) ? : "NULL");
					dbG("maxp5ga1: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga1", tmp2)) ? : "NULL");
					dbG("maxp5ga2: %s\n",		nvram_get(strcat_r(prefix2, "maxp5ga2", tmp2)) ? : "NULL");
					dbG("legofdmbw205gmpo: %s\n",	nvram_get(strcat_r(prefix2, "legofdmbw205gmpo", tmp2)) ? : "NULL");
					dbG("legofdmbw20ul5gmpo: %s\n",	nvram_get(strcat_r(prefix2, "legofdmbw20ul5gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw205gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw20ul5gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw20ul5gmpo", tmp2)) ? : "NULL");
					dbG("mcsbw405gmpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405gmpo", tmp2)) ? : "NULL");
					dbG("maxp5gha0: %s\n",		nvram_get(strcat_r(prefix2, "maxp5gha0", tmp2)) ? : "NULL");
					dbG("maxp5gha1: %s\n",		nvram_get(strcat_r(prefix2, "maxp5gha1", tmp2)) ? : "NULL");
					dbG("maxp5gha2: %s\n",		nvram_get(strcat_r(prefix2, "maxp5gha2", tmp2)) ? : "NULL");
					dbG("legofdmbw205ghpo: %s\n",	nvram_get(strcat_r(prefix2, "legofdmbw205ghpo", tmp2)) ? : "NULL");
					dbG("legofdmbw20ul5ghpo: %s\n",	nvram_get(strcat_r(prefix2, "legofdmbw20ul5ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw205ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw205ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw20ul5ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw20ul5ghpo", tmp2)) ? : "NULL");
					dbG("mcsbw405ghpo: %s\n",	nvram_get(strcat_r(prefix2, "mcsbw405ghpo", tmp2)) ? : "NULL");
					dbG("mcs32po: %s\n",		nvram_get(strcat_r(prefix2, "mcs32po", tmp2)) ? : "NULL");
					dbG("legofdm40duppo: %s\n",	nvram_get(strcat_r(prefix2, "legofdm40duppo", tmp2)) ? : "NULL");
				}
				dbG("ccode: %s\n", nvram_safe_get(strcat_r(prefix2, "ccode", tmp2)));
				dbG("regrev: %s\n", nvram_safe_get(strcat_r(prefix2, "regrev", tmp2)));
				dbG("country_code: %s\n", nvram_safe_get(strcat_r(prefix, "country_code", tmp)));
				dbG("country_rev: %s\n", nvram_safe_get(strcat_r(prefix, "country_rev", tmp)));
#endif
				break;

			case MODEL_RTAC87U:
				commit_needed = wltxpower_rtac87u(txpower, prefix2);
				break;

			case MODEL_RTN12HP:
			case MODEL_RTN12HP_B1:
			case MODEL_APN12HP:
				commit_needed = wltxpower_rtn12hp(txpower, tmp, prefix, tmp2, prefix2);
				break;

			default:

				break;
		}

		unit++;
	}

	if (commit_needed)
		nvram_commit();

	return 0;
}

#ifdef RTAC68U
void
remap_country_setting(void)
{
	if (nvram_match("1:ccode", "JP") && nvram_match("1:regrev", "47"))
		nvram_set("1:regrev", "45");
}
#endif

int
reset_countrycode_2g(void)
{
	char country_code_str[32];
	int reset_ccode = 0;
	char *ptr = nvram_get("regulation_domain");

	switch(get_model()) {
		case MODEL_DSLAC68U:
		case MODEL_RTAC87U:
		case MODEL_RTAC68U:
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		case MODEL_RTN18U:
		case MODEL_RTAC5300:
		case MODEL_RTAC88U:
		case MODEL_RTAC86U:
		case MODEL_RTAC3100:
		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_RTAXE7800:
			strcpy(country_code_str, "0:ccode");
			break;

		case MODEL_RPAX56:
		case MODEL_RPAX58:
		case MODEL_RTAX55:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAX56U:
		case MODEL_DSLAX82U:
			strcpy(country_code_str, "sb/0/ccode");
			break;

		case MODEL_RTAC3200:
		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		case MODEL_ET12:
		case MODEL_XT12:
			strcpy(country_code_str, "1:ccode");
			break;

		case MODEL_RTAC53U:
			strcpy(country_code_str, "sb/1/ccode");
			break;

		default:
			strcpy(country_code_str, "regulation_domain");
			reset_ccode = 1;
			break;
	}

	if (reset_ccode) {
		switch(get_model()) {
			case MODEL_RTN66U:
			case MODEL_RTAC66U:
				if (ptr && *ptr)
					nvram_set("pci/1/1/ccode", ptr);
				else
					nvram_set("pci/1/1/ccode", "US");

				break;

			default:
				if (ptr && *ptr) {
					if ((strlen(ptr) == 6) && !strncasecmp(ptr, "0x", 2))	// legacy format
						nvram_set("sb/1/ccode", ptr+4);
					else
						nvram_set("sb/1/ccode", ptr);
				} else
					nvram_set("sb/1/ccode", "US");

				break;
		}
	}

	nvram_set("wl0_country_code", nvram_safe_get(country_code_str));

	return 0;
}

int
reset_countrycode_5g(void)
{
	char country_code_str[32];
	int reset_ccode = 0;
	int wlif_count = num_of_wl_if();

	if (wlif_count < 2)
		return 0;

	switch(get_model()) {
		case MODEL_DSLAC68U:
		case MODEL_RTAC68U:
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		case MODEL_RTAC5300:	/* chk after */
		case MODEL_RTAC87U:
		case MODEL_RTAC88U:
		case MODEL_RTAC86U:
		case MODEL_RTAC3100:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_RTAXE7800:
			strcpy(country_code_str, "1:ccode");
			break;

		case MODEL_RPAX56:
		case MODEL_RPAX58:
		case MODEL_RTAX55:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAX56U:
			strcpy(country_code_str, "sb/1/ccode");
			break;

		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		case MODEL_ET12:
		case MODEL_XT12:
			strcpy(country_code_str, "2:ccode");
			break;

		case MODEL_RTAC3200:
		case MODEL_RTAC53U:
		case MODEL_DSLAX82U:
			strcpy(country_code_str, "0:ccode");
			break;

		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
			strcpy(country_code_str, "sb/1/ccode");
			break;

		default:
			reset_ccode = 1;
			if (nvram_get("regulation_domain_5G"))
				strcpy(country_code_str, "regulation_domain_5G");
			else
				strcpy(country_code_str, "regulation_domain_5g");
			break;
	}

	if (reset_ccode) {
		switch(get_model()) {
			case MODEL_RTN66U:
			case MODEL_RTAC66U:
				if (nvram_get("regulation_domain_5G"))
					nvram_set("pci/2/1/ccode", nvram_get("regulation_domain_5G"));
				else
					nvram_set("pci/2/1/ccode", "US");

				break;

			default:
				if (nvram_get("regulation_domain_5G"))		// by ate command from asuswrt, prior than ui 2.0
					nvram_set("0:ccode", nvram_get("regulation_domain_5G"));
				else if (nvram_get("regulation_domain_5g"))	// by ate command from ui 2.0
					nvram_set("0:ccode", nvram_get("regulation_domain_5g"));
				else
					nvram_set("0:ccode", "US");

				break;
		}
	}

	nvram_set("wl1_country_code", nvram_safe_get(country_code_str));

#ifdef RTCONFIG_HAS_5G_2
	nvram_set("wl2_country_code", nvram_safe_get("wl0_country_code"));
#endif

#if defined(GTAX11000) || defined(RTAX92U) || defined(GTAXE11000) || defined(GTAX11000_PRO) || defined(ET12) || defined(XT12) || defined(GTAXE16000)
	nvram_set("wl2_country_code", nvram_safe_get("3:ccode"));
#endif
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
	nvram_set("wl2_country_code", nvram_safe_get("2:ccode"));
#endif

	return 0;
}

int
reset_countryrev_2g(void)
{
	char country_rev_str[32];

	switch(get_model()) {
		case MODEL_RTN53:
		case MODEL_RTN16:
		case MODEL_RTN15U:
		case MODEL_RTN12:
		case MODEL_RTN12B1:
		case MODEL_RTN12C1:
		case MODEL_RTN12D1:
		case MODEL_RTN12VP:
		case MODEL_RTN12HP:
		case MODEL_RTN12HP_B1:
		case MODEL_APN12HP:
		case MODEL_RTN14UHP:
		case MODEL_RTN10U:
		case MODEL_RTN10P:
		case MODEL_RTN10D1:
		case MODEL_RTN10PV2:
		case MODEL_RTAC53U:
			strcpy(country_rev_str, "sb/1/regrev");
			break;

		case MODEL_RTN66U:
		case MODEL_RTAC66U:
			strcpy(country_rev_str, "pci/1/1/regrev");
			break;

		case MODEL_DSLAC68U:
		case MODEL_RTAC87U:
		case MODEL_RTAC68U:
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		case MODEL_RTN18U:
		case MODEL_RTAC5300:
		case MODEL_GTAC5300:
		case MODEL_RTAC88U:
		case MODEL_RTAC86U:
		case MODEL_RTAC3100:
		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_RTAXE7800:
			strcpy(country_rev_str, "0:regrev");
			break;

		case MODEL_RPAX56:
		case MODEL_RPAX58:
		case MODEL_RTAX55:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAX56U:
		case MODEL_DSLAX82U:
			strcpy(country_rev_str, "sb/0/regrev");
			break;

		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		case MODEL_ET12:
		case MODEL_XT12:
			strcpy(country_rev_str, "1:regrev");
			break;

		case MODEL_RTAC3200:
			strcpy(country_rev_str, "1:regrev");
			break;
	}

	nvram_set("wl0_country_rev", nvram_safe_get(country_rev_str));

	return 0;
}

int
reset_countryrev_5g(void)
{
	char country_rev_str[32];
	int wlif_count = num_of_wl_if();

	if (wlif_count < 2)
		return 0;

	switch(get_model()) {
		case MODEL_RTAC3200:
		case MODEL_RTN53:
		case MODEL_RTAC53U:
		case MODEL_DSLAX82U:
			strcpy(country_rev_str, "0:regrev");
			break;

		case MODEL_RTN66U:
		case MODEL_RTAC66U:
			strcpy(country_rev_str, "pci/2/1/regrev");
			break;

		case MODEL_DSLAC68U:
		case MODEL_RTAC68U:
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		case MODEL_RTAC87U:
		case MODEL_RTAC5300:
		case MODEL_GTAC5300:
		case MODEL_RTAC88U:
		case MODEL_RTAC86U:
		case MODEL_RTAC3100:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_RTAXE7800:
			strcpy(country_rev_str, "1:regrev");
			break;

		case MODEL_RPAX56:
		case MODEL_RPAX58:
		case MODEL_RTAX55:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAX56U:
			strcpy(country_rev_str, "sb/1/regrev");
			break;

                case MODEL_RTAX88U:
                case MODEL_GTAX11000:
                case MODEL_RTAX92U:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		case MODEL_ET12:
		case MODEL_XT12:
                        strcpy(country_rev_str, "2:regrev");
                        break;

		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
			strcpy(country_rev_str, "sb/1/regrev");
			break;
	}

	nvram_set("wl1_country_rev", nvram_safe_get(country_rev_str));

#ifdef RTAC66U
	if (nvram_match("wl1_country_code", "EU") && nvram_match("wl1_dfs", "1"))
		nvram_set("wl1_country_rev", "31");
#endif

#ifdef RTCONFIG_HAS_5G_2
	nvram_set("wl2_country_rev", nvram_safe_get("wl0_country_rev"));
#endif

#if defined(GTAX11000) || defined(RTAX92U) || defined(GTAXE11000) || defined(GTAX11000_PRO) || defined(ET12) || defined(XT12) || defined(GTAXE16000)
	nvram_set("wl2_country_rev", nvram_safe_get("3:regrev"));
#endif
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
	nvram_set("wl2_country_rev", nvram_safe_get("2:regrev"));
#endif

	return 0;
}

#if 0
void set_cfe_nvram_hnd()	// no firmware updating
{
	char path[128];
	unsigned int val = 0;
	char v[16];

	snprintf(path, sizeof(path), "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", "/", "p", "r", "o", "c", "/", "n", "v", "r", "a", "m", "/", "n", "o", "U", "p", "d", "a", "t", "i", "n", "g", "F", "i", "r", "m", "w", "a", "r", "e");
	if (!factory_debug() && f_read_string((const char *) path, v, sizeof(v)) > 0) {
		val = atoi(v);
		if (!val)
			f_write_string(path, "1", 0, 0);
	}
}
#endif

void check_wl_country()
{
#ifdef RTAC68U
	remap_country_setting();
#endif
	reset_countrycode_2g();
	reset_countrycode_5g();
	reset_countryrev_2g();
	reset_countryrev_5g();
	check_wl_territory_code();
#if 0
	set_cfe_nvram_hnd();
#endif
}

#if defined(RTAC3200) || defined(RTAC68U) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER) || defined(DSL_AC68U)
void wl_disband5grp()
{
#ifdef RTCONFIG_HND_ROUTER_AX
	nvram_unset("sb/1/dis_ch_grp");
	nvram_unset("1:dis_ch_grp");
	nvram_unset("2:dis_ch_grp");
#if defined(GTAX11000) || defined(XT12)
	nvram_unset("3:dis_ch_grp");

	if (nvram_match("wl1_country_code", "E0") ||
	    nvram_match("wl1_country_code", "JP") ||
	    nvram_match("wl1_country_code", "KR") ||
	    nvram_match("wl1_country_code", "US") ||
	    nvram_match("wl1_country_code", "EU") ||
	    nvram_match("wl1_country_code", "TW") ||
	    nvram_match("wl1_country_code", "CN") ||
	    nvram_match("wl1_country_code", "CA"))
		nvram_set("2:dis_ch_grp", "0x18");
	else {
		if (!nvram_match("2:ccode", "ALL"))
			nvram_set("2:dis_ch_grp", "0x1e");
	}

	if (nvram_match("wl2_country_code", "E0") ||
	    nvram_match("wl2_country_code", "JP"))
		nvram_set("3:dis_ch_grp", "0x17");
	else if(nvram_match("wl2_country_code", "KR") ||
		nvram_match("wl2_country_code", "US") ||
		nvram_match("wl2_country_code", "TW") ||
		nvram_match("wl2_country_code", "CA"))
		nvram_set("3:dis_ch_grp", "0x7");
	else {
		if (!nvram_match("3:ccode", "ALL"))
			nvram_set("3:dis_ch_grp", "0xf");
	}
#elif defined(GTAX6000)
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2))
		nvram_set("2:dis_ch_grp", "0x8"); // always disable 5G band 3
	else
		nvram_unset("2:dis_ch_grp");
#elif defined(GTAX11000_PRO)
	nvram_unset("4:dis_ch_grp");

	if (nvram_match("wl1_country_code", "E0") ||
	    nvram_match("wl1_country_code", "JP") ||
	    nvram_match("wl1_country_code", "KR") ||
	    nvram_match("wl1_country_code", "US") ||
	    nvram_match("wl1_country_code", "Q1") ||
	    nvram_match("wl1_country_code", "EU") ||
	    nvram_match("wl1_country_code", "TW") ||
	    nvram_match("wl1_country_code", "CN") ||
	    nvram_match("wl1_country_code", "CA"))
		nvram_set("4:dis_ch_grp", "0x18");
	else {
		if (!nvram_match("4:ccode", "ALL"))
			nvram_set("4:dis_ch_grp", "0x1e");
	}

	if (nvram_match("wl2_country_code", "E0") ||
	    nvram_match("wl2_country_code", "JP"))
		nvram_set("2:dis_ch_grp", "0x17");
	else if(nvram_match("wl2_country_code", "KR") ||
		nvram_match("wl2_country_code", "US") ||
		nvram_match("wl2_country_code", "Q1") ||
		nvram_match("wl2_country_code", "TW") ||
		nvram_match("wl2_country_code", "CA"))
		nvram_set("2:dis_ch_grp", "0x7");
	else {
		if (!nvram_match("2:ccode", "ALL"))
			nvram_set("2:dis_ch_grp", "0xf");
	}
#elif defined(GTAXE16000)
	nvram_set("4:dis_ch_grp", "0x18");

	if (nvram_match("wl1_country_code", "E0"))
		nvram_set("2:dis_ch_grp", "0x17");
	else if(nvram_match("wl1_country_code", "KR") ||
		nvram_match("wl1_country_code", "US") ||
		nvram_match("wl1_country_code", "Q1"))
		nvram_set("2:dis_ch_grp", "0x7");
	else {
		if (!nvram_match("2:ccode", "ALL"))
			nvram_set("2:dis_ch_grp", "0xf");
	}
#elif defined(RTAX88U)
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2))
		nvram_set("2:dis_ch_grp", "0x8");
#elif defined(RTAX95Q) || defined(RTAXE95Q)
	nvram_set("1:dis_ch_grp", "0x18");
	nvram_set("2:dis_ch_grp", "0x7");
#elif defined(RTAXE95Q) || defined(ET8PRO)
	nvram_set("2:olpc_5g_th", "6");
#elif defined(RTAX55)
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2) || nvram_match("EG_mode", "1"))
		nvram_set("sb/1/dis_ch_grp", "0x8"); // always disable 5G band 3
#elif defined(RTAX56U) || defined(RTAX1800)
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2))
		nvram_set("sb/1/dis_ch_grp", "0x8"); // always disable 5G band 3
#elif defined(BCM6750) || defined(RTAX58U_V2) || defined(TUFAX3000_V2) || defined(RTAXE7800)
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2))
		nvram_set("1:dis_ch_grp", "0x8"); // always disable 5G band 3
#if defined(RTAX58U) || defined(RTAX82U)
	else if (!strncmp(nvram_safe_get("territory_code"), "CA", 2))
		nvram_set("1:dis_ch_grp", "0x8"); // specific for US/AA/TW SKU to disable 5G band3 for now until pass DFS certification
#endif
	else
		nvram_set("1:dis_ch_grp", "");
#elif defined(DSL_AX82U)
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2) || nvram_match("EG_mode", "1"))
		nvram_set("0:dis_ch_grp", "0x8"); // always disable 5G band 3
	else
		nvram_set("0:dis_ch_grp", "");
#endif

#else	// RTCONFIG_HND_ROUTER_AX
	int wlif_count = num_of_wl_if();

	if (wlif_count > 1)
#ifdef RTAC3200
	nvram_set("0:disband5grp", "");
#elif defined(GTAC5300)
	nvram_set("2:disband5grp", "");
#else
	nvram_set("1:disband5grp", "");
#endif
	if (wlif_count > 2)
#if defined(GTAC5300)
	nvram_set("3:disband5grp", "");
#else
	nvram_set("2:disband5grp", "");
#endif

#ifdef RTAC3200
	nvram_set("0:disband5grp", "0x1e");

	if (nvram_match("wl1_country_code", "E0") ||
	    nvram_match("wl1_country_code", "JP"))
		nvram_set("2:disband5grp", "0x17");
	else
		nvram_set("2:disband5grp", "0x7");
#elif defined(RTAC68U)
	if (strncmp(nvram_safe_get("territory_code"), "JP", 2) && !nvram_match("cpurev", "c0") && nvram_match("1:ccode", "JP"))
		nvram_set("1:disband5grp", "0x1e");
#elif defined(RTAC86U)
#ifdef RTCONFIG_DFS_US
	if (!strncmp(nvram_safe_get("territory_code"), "US", 2))
		nvram_set("1:disband5grp", "0xe");
#endif
#elif defined(RTAC5300)
	if (nvram_match("wl1_country_code", "E0") ||
	    nvram_match("wl1_country_code", "JP"))
		nvram_set("1:disband5grp", "0x18");
	else {
		if (!nvram_match("1:ccode", "ALL"))
			nvram_set("1:disband5grp", "0x1e");
	}

	if (nvram_match("wl2_country_code", "E0") ||
	    nvram_match("wl2_country_code", "JP"))
		nvram_set("2:disband5grp", "0x17");
	else {
		if (!nvram_match("2:ccode", "ALL"))
			nvram_set("2:disband5grp", "0xf");
	}
#elif defined(GTAC5300)
	if (nvram_match("wl1_country_code", "E0") ||
	    nvram_match("wl1_country_code", "JP") ||
	    nvram_match("wl1_country_code", "KR"))
		nvram_set("2:disband5grp", "0x18");
	else {
		if (!nvram_match("2:ccode", "ALL"))
			nvram_set("2:disband5grp", "0x1e");
	}

	if (nvram_match("wl2_country_code", "E0") ||
	    nvram_match("wl2_country_code", "JP"))
		nvram_set("3:disband5grp", "0x17");
	else if(nvram_match("wl2_country_code", "KR"))
		nvram_set("3:disband5grp", "0x7");
	else {
		if (!nvram_match("3:ccode", "ALL"))
			nvram_set("3:disband5grp", "0xf");
	}
#elif defined(RTAC88U) || defined(RTAC3100)
	if (nvram_match("1:ccode", "Q1") && nvram_match("1:regrev", "947")) {
		if (!strncmp(nvram_safe_get("territory_code"), "CN", 2))
			nvram_set("1:disband5grp", "0xf");
		else
			nvram_set("1:disband5grp", "0xe");
	}
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2))
		nvram_set("1:disband5grp", "0x18");
#elif defined(DSL_AC68U)
	if (!strncmp(nvram_safe_get("territory_code"), "IL", 2))
		nvram_set("1:disband5grp", "0x8"); //disable 5G band 3
#endif

#endif	// RTCONFIG_HND_ROUTER_AX
#ifdef RTCONFIG_ASUSCTRL
	if ( !asus_ctrl_ignore() )      // nothing set, treat it as usual.
		asus_ctrl_enband5grp(); // enable specific bands
#endif
#if defined(XT8PRO) || defined(XT8_V2)
	nvram_set("1:dis_ch_grp", "0x18");
	nvram_set("2:dis_ch_grp", "0x07");
#endif
}
#endif

int wl_dfs_support(int unit)
{
	char tmp[100], prefix[]="wlXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	if (nvram_match(strcat_r(prefix, "nband", tmp), "1") && !factory_debug() &&
		(
#ifdef DSL_AC68U
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "13")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "47"))
#elif defined RTAC68U
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "13")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "15")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "IL") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "11")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			(nvram_match(strcat_r(prefix, "country_rev", tmp), "39") || nvram_match(strcat_r(prefix, "country_rev", tmp), "45")) &&
		       (nvram_contains_word("rc_support", "dfs") || nvram_match("cpurev", "c0"))) ||
		     (((nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "33")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "36"))) &&
			is_ac66u_v2_series())
#if defined RT4GAC68U
			|| (nvram_match(strcat_r(prefix, "country_code", tmp), "GB") && nvram_match(strcat_r(prefix, "country_rev", tmp), "995"))
#endif
#elif defined RTAC3200
		       (unit == 2) &&
		      ((nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "989")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "999")))
#elif defined RTAC66U
			nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "31") &&
			nvram_match(strcat_r(prefix, "dfs", tmp), "1")
#elif defined RTN66U
			nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "0")
#elif defined RTAC1200GP
			nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "943")
#elif defined RTAC88U || defined(RTAC3100)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "962")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "94")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "984")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "745")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "TW") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "969")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "932")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "878")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "793")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "758")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "SG") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "978")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "903"))
#elif defined(RTAC5300) || defined(GTAC5300)
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "946")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "986")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "103")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "954"))
#elif defined RTAC86U
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "984")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "962")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "IL") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "0")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "94")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "0"))
#elif defined GTAC2900
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "0")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "1")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "987")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "946")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "IL") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "0")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "94")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "975")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "63")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "998"))
#elif defined(RTAX88U)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "823")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "817")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "DE") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "963")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "914")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "887")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "950")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "947")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "937"))
#elif defined(GTAX11000)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "821")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "816")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "TW") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "973")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "948")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "770")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "886")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "947")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "908")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "936"))
#elif defined(RTAX92U)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "814")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "914")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "913")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "882")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "DE") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "959")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "DE") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "958")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "905")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "904"))
#elif defined(RTAX95Q)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "767")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "755")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "740")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "888")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "923")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "924")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "864")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "933"))
#elif defined(XT8PRO)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "863")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "810")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "632")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "636")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "645")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "902")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "903")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "950"))
#elif defined(XT8_V2)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "862")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "811")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "633")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "635")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "641")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "643")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "900")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "901")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "950"))
#elif defined(RTAXE95Q)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "767")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "755")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "740")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "888")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "923")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "924")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "864")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "933"))
#elif defined(ET8PRO)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "817")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "823")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "DE") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "963")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "666")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "894")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "937")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "886")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "887")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "Q1") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "149")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "Q1") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "151")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "909")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "910")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "947")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
             nvram_match(strcat_r(prefix, "country_rev", tmp), "950"))
#elif defined(RTAX56_XD4)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "917")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "857")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "927")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "720")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "878")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "914")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "737"))
#elif defined(XD4PRO)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "819")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "905")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "906")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "947")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "950")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "DE") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "963")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "647")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "894")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "937")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "640")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "651")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "817")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "823"))
#elif defined(CTAX56_XD4)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "917")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "857")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "927")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "720")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "878")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "937")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "737"))
#elif defined(RTAX55) || defined(RTAX1800)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "849")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "915")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "916")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "711")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "871")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "915"))
#elif defined(RTAX82_XD6S)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "917")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "829")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "911")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "676")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "861")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "923")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "668")) ||
		        (nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "669")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "926"))
#elif defined(BCM6750)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "917")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "869")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "935")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "742")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "889")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "923")) ||
		        (nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "669")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "756")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "768")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "926"))
#elif defined(RTAX58U_V2)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "917")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "869")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "905")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "906")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "653")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "859")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "923")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "668")) ||
		        (nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "669")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "756")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "768"))
#elif defined(TUFAX3000_V2)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "768"))
#elif defined(RTAX86U) || defined(RTAX5700)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "859")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "929")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "947")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "717")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "872")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "876")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "936")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "733")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "741"))
#elif defined(RTAX68U) || defined(RTAC68U_V4)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "850")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "917")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "918")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "704")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "TW") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "967")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "726"))
#elif defined(RPAX56)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "712"))
#elif defined(RPAX58)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "742"))
#elif defined(RTAX56U)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "817")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "917")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CA") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "867")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "934")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "741")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "886")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "924")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "770")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "931"))
#elif defined(GTAXE11000)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "699")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "652")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "913"))
#elif defined(GTAX6000)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
                         nvram_match(strcat_r(prefix, "country_rev", tmp), "907")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "908")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "650")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "858")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "KR") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "910")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "650"))
#elif defined(GTAX11000_PRO)
			1
#elif defined(GTAXE16000)
			1
#elif defined(ET12)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "654")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "648")) 
#elif defined(XT12)
			(nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "653")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "666")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "910")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "CN") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "909")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "865")) ||
			(nvram_match(strcat_r(prefix, "country_code", tmp), "TW") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "966"))
#elif defined(DSL_AX82U)
			1
#else
			0
#endif
		)
	) {
		nvram_set(strcat_r(prefix, "reg_mode", tmp), "h");
#if defined(RTCONFIG_BCM7) || defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM9) || defined(HND_ROUTER)
		nvram_set("wl_dfs_pref", "");
#endif
		return 1;
#ifdef RTCONFIG_HND_ROUTER_AX
	} else if (
#if !defined(RTAX92U) && !defined(RTAX95Q) && !defined(XT8PRO) && !defined(XT8_V2)
		(nvram_match(strcat_r(prefix, "nband", tmp), "2")
#if defined(RTCONFIG_WIFI6E)
		|| nvram_match(strcat_r(prefix, "nband", tmp), "4")	// 6G band
#endif
		) &&
#endif
		nvram_match(strcat_r(prefix, "mode", tmp), "ap") && !factory_debug()) {
		nvram_set(strcat_r(prefix, "reg_mode", tmp), "d");
		return 1;
#endif
	} else {
		nvram_set(strcat_r(prefix, "reg_mode", tmp), "off");
		return 0;
	}
}
#if 0
void wl_CE_support(int unit)
{
	char tmp[100], prefix[]="wlXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	if (nvram_match(strcat_r(prefix, "nband", tmp), "1") && !factory_debug())
	{
#if defined RTAC88U
		if (nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "962"))
#elif defined(RTAC5300) || defined(GTAC5300) || defined(RTAX88U) || defined(GTAX11000) || defined(RTAX92U) || defined(RTAX95Q)
		if (nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "946"))
#endif
		{
			nvram_set(strcat_r(prefix, "frameburst", tmp), "off");
		}
	}
}
#endif
void wl_dfs_radarthrs_config(char *ifname, int unit)
{
	char tmp[100], prefix[]="wlXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	if (nvram_match(strcat_r(prefix, "nband", tmp), "1") && !factory_debug()) {
#if defined DSL_AC68U
		if (	nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "13"))
			eval("wl", "-i", ifname, "radarthrs",
			"0x6ac", "0x30", "0x6a8", "0x30", "0x6a8", "0x30", "0x6a8", "0x30", "0x6a4", "0x30", "0x6a0", "0x30");
#elif defined RTAC68U
		if (is_ac68u_v3_series() &&
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
                        nvram_match(strcat_r(prefix, "country_rev", tmp), "13")))
			eval("wl", "-i", ifname, "radarthrs",
			"0x69c", "0x30", "0x69c", "0x30", "0x690", "0x28", "0x6a4", "0x30", "0x6a4", "0x30", "0x694", "0x30");
		else
		if ((	nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "13")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "IL") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "11")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			(nvram_match(strcat_r(prefix, "country_rev", tmp), "39") || nvram_match(strcat_r(prefix, "country_rev", tmp), "45")) &&
		       (nvram_contains_word("rc_support", "dfs") || nvram_match("cpurev", "c0"))) ||
		     (((nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "33")) ||
		       (nvram_match(strcat_r(prefix, "country_code", tmp), "AU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "36"))) &&
			is_ac66u_v2_series()))
			eval("wl", "-i", ifname, "radarthrs",
			"0x6ac", "0x30", "0x6a8", "0x30", "0x6a8", "0x30", "0x6a4", "0x30", "0x6a4", "0x30", "0x6a0", "0x30");
#elif defined (RTAC66U) || defined (RTN66U)
		if (((get_model() == MODEL_RTAC66U) &&
			nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "31") &&
			nvram_match(strcat_r(prefix, "dfs", tmp), "1")) ||
			((get_model() == MODEL_RTN66U) &&
			nvram_match(strcat_r(prefix, "country_code", tmp), "EU") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "0")))
			eval("wl", "-i", ifname, "radarthrs",
			"0x6ac", "0x30", "0x6a8", "0x30", "0x6a8", "0x30", "0x6a8", "0x30", "0x6a4", "0x30", "0x6a0", "0x30");
#elif defined RTAC3200
		if (	nvram_match(strcat_r(prefix, "country_code", tmp), "E0") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "989") &&
			(unit == 2))
			eval("wl", "-i", ifname, "radarthrs",
			"0x698", "0x30", "0x698", "0x30", "0x68c", "0x30", "0x6d0", "0x30", "0x6d0", "0x30", "0x6c6", "0x30");
		else if (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "999"))
			eval("wl", "-i", ifname, "radarthrs",
			"0x690", "0x30", "0x68a", "0x30", "0x68e", "0x30", "0x694", "0x30", "0x693", "0x30", "0x6a8", "0x30");
#elif defined GTAX11000
		if (	nvram_match(strcat_r(prefix, "country_code", tmp), "US") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "821") &&
			(unit == 2))
                        eval("wl", "-i", ifname, "radarthrs",
                        "0x6c4", "0x30", "0x6c8", "0x30", "0x6c6", "0x30", "0x6c6", "0x30", "0x6c0", "0x30", "0x6b8", "0x30",
 			"0x6c0", "0x30", "0x6a9", "0x30");
		else if (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			 nvram_match(strcat_r(prefix, "country_rev", tmp), "908") &&
			 (unit == 2))
		    	eval("wl", "-i", ifname, "radarthrs",
			"0x6a0", "0x20", "0x6a4", "0x20", "0x6a4", "0x20", "0x6a0", "0x20", "0x6a4", "0x20", "0x6a8", "0x20",
			"0x6ac", "0x20", "0x6c0", "0x30");
#elif defined RTAX56U
		if (nvram_match(strcat_r(prefix, "country_code", tmp), "JP") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "886") &&
			(unit == 1))
				eval("wl", "-i", ifname, "radarthrs",
			"0x6c4", "0x30", "0x6c8", "0x30", "0x6a0", "0x20", "0x6c0", "0x30", "0x6c0", "0x30", "0x6c0", "0x30");
#elif defined(DSL_AX82U)
		if ((nvram_match(strcat_r(prefix, "country_code", tmp), "E0")
		  && nvram_match(strcat_r(prefix, "country_rev", tmp), "683"))
		 || (nvram_match(strcat_r(prefix, "country_code", tmp), "AU")
		  && nvram_match(strcat_r(prefix, "country_rev", tmp), "882"))
		)
			eval("wl", "-i", ifname, "radarthrs",
			"0x6d0", "0x20", "0x6d0", "0x20", "0x6d0", "0x20", "0x6d0", "0x20", "0x6d0", "0x20", "0x6d0", "0x20", "0x6d0", "0x20", "0x6d0", "0x20");
#elif defined(XT12) || defined(ET12)
		if(unit == 1)
			eval("wl", "-i", ifname, "radarthrs",
			"0x6a4", "0x20", "0x6a4", "0x20", "0x6a4", "0x20", "0x6a8", "0x30", "0x6a8", "0x30", "0x6a8", "0x30", "0x6a4", "0x20", "0x6a8", "0x30");
#endif
	}
}

void set_tcode_misc() {

	if (*nvram_safe_get("territory_code") && (strcmp(cfe_nvram_safe_get("model"),"RT-AC88U")==0||strcmp(cfe_nvram_safe_get("model"),"RT-AC3100")==0)) {
		nvram_set("0:venid", "0x14E4");
		nvram_set("1:venid", "0x14E4");
		nvram_set("0:agbg0", "0");
		nvram_set("0:agbg1", "0");
		nvram_set("0:agbg2", "0");
		nvram_set("0:agbg3", "0");
	}
}

#ifdef WLCLMLOAD
/* clm_blob files will be installed in /brcm/clm/<chipnum><extra_id>.clm */
/* wl -i <ethx> <blobfilename> will be used to download */
int download_clmblob_files()
{
	int i = 0;
	char ifname[16] = {0};
	wlc_rev_info_t revinfo;
	int err;
	const char *fmt;
	char chn[8];
	int chnlen=8;
	uint chipid;
	char blob_fname[60];

	for (i = 1; i <= DEV_NUMIFS; i++) {
		snprintf(ifname, sizeof(ifname), "eth%d", i);
		if (!wl_probe(ifname)) {
			memset(&revinfo, 0, sizeof(revinfo));
			if ((err = wl_ioctl(ifname, WLC_GET_REVINFO, &revinfo, sizeof(revinfo))) < 0) {
				//printf("\n*** BEFORE-CLMLOAD %s WLC_GET_REVINFO err=%d ", ifname, err);
			}
			else {
				//printf("\n*** BEFORE-CLMLOAD %s - chipnum = 0x%x (%d)  ", ifname, revinfo.chipnum, revinfo.chipnum);
				chipid = revinfo.chipnum;

				/* 4366_access clm_blob for any chip in the 4365 family - 4365,4366,43664 */
				if (BCM4365_CHIP(chipid))
					chipid = BCM4366_CHIP_ID;

				/* blob filename based on chipid */
				fmt = ((chipid > 0xa000) || (chipid < 0x4000)) ? "%d" : "%x";
				snprintf(chn, chnlen, fmt, chipid);

				memset(&(blob_fname[0]), 0, sizeof(blob_fname));
				if (chipid == BCM4366_CHIP_ID) {
					sprintf(blob_fname, "%s%s_access.clm_blob", "./brcm/clm/",chn);
					printf("\n Download %s to %s ......", blob_fname, ifname);
					eval("wl", "-i", ifname, "clmload", blob_fname);
				}
				else if (BCM43602_CHIP(chipid)) :
					sprintf(blob_fname, "%s%sa1_access.clm_blob", "./brcm/clm/",chn);
					printf("\n Download %s to %s ......", blob_fname, ifname);
					eval("wl", "-i", ifname, "clmload", blob_fname);
				}
				else {
					sprintf(blob_fname, "%srouter.clm_blob", "./brcm/clm/");
					printf("\n Download %s to %s ......", blob_fname, ifname);
					eval("wl", "-i", ifname, "clmload", blob_fname);
					if (revinfo.phytype == WLC_PHY_TYPE_AC) {
						printf("\n *** Is PHY_TYPE_AC %d - set vhtmode 1", revinfo.phytype);
						eval("wl", "-i", ifname, "vhtmode", "1");
					}
				}
			}
		}
	} /* for */
	return (0);
}
#endif /* WLCLMLOAD */

#ifdef RTCONFIG_BCMWL6
int hw_vht_cap()
{
#ifndef RTCONFIG_BCMARM
	int ret = 0;
#else
	int ret = 1;
#endif

	if (get_model() == MODEL_RTAC66U)
		ret = 1;
	else if ((get_model() == MODEL_RTAC68U) && !strcmp(get_productid(), "RT-N66U_C1"))
		ret = 0;

	return ret;
}
#endif
