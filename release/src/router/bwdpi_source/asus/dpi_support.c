 /*
 * Copyright 2021, ASUSTeK Inc.
 * All Rights Reserved.
 */

/*
	NOTE:
	dpi_support is a library to provide API for GUI / app to display which needed page of dpi engine, it could depend on odmpid / tcode.
*/

#include <bwdpi.h>

struct dpiSupport {
	char *model;
	char *tcode;
	int  MALS;
	int  VP;
	int  CC;
	int  adaptive_qos;
	int  traffic_analyzer;
	int  webs_filter;
	int  apps_filter;
	int  web_history;
	int  bandwidth_monitor;
};

struct dpi_TcodeBlacklist {
	char *model;
	char *tcode;
};

struct dpi_TcodeBlacklist s_tcode_blacklist_tuple[] =
{
#if defined(RTAX82_XD6) || defined(RTAX82_XD6S)
        {"ZenWiFi_XD6"        , "CH/01"    },
#endif

	// The End
	{0,0}
};

struct dpiSupport s_tcode_tuple[] =
{
	/*
	for example:
		{productid , tcode, MALS, VP, CC, adaptive_qos,	traffic_analyzer, webs_filter, apps_filter, web_history, bandwidth_monitor},
		{"RT-AC68U","US/01",   1,  1,  1,            1,                1,           1,           1,           1,                 1},
	*/

	/**********   TCODE   CASE   START   **********/
	// TODO : add tcode case here
	// test : {"RT-AC66U_B1"   ,  "US/0", 1, 1, 1, 1, 1, 0, 0, 0, 1},
	// test : {"RT-AC66U_B1"   ,  "JP/0", 1, 1, 1, 0, 0, 0, 0, 0, 1},
	/**********   TCODE   CASE   END     **********/

	// The End
	{0,0,0,0,0,0,0,0,0}
};

struct dpiSupport s_tuple[] =
{
	/*
	for example:
		{productid , tcode, MALS, VP, CC, adaptive_qos,	traffic_analyzer, webs_filter, apps_filter, web_history, bandwidth_monitor},
		{"RT-AC68U",    "",     1, 1,  1,            1,                1,           1,           1,           1,                 1},
	*/

	/**********   NORMAL  CASE   START   **********/
	// NOTE : DSL model only support asuswrt code-base
#ifdef RTAC56S
	{"RT-AC56S"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC56U
	{"RT-AC56U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC56R"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC68U
	// model alias : RT-AC68
	{"RT-AC68A"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68R"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68P"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68UF"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68U V2"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68W"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68U_White",      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68U_WHITE",      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68RW"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	// non RT-AC6U
	{"RT-AC1900"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC1900P"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC66U_B1"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC1750_B1"  ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC1900U"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC66U+"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC67U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC87U
	{"RT-AC87R"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC87U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RT4GAC68U
	{"4G-AC68U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef DSL_AC68U
	{"DSL-AC68U"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"DSL-AC68R"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC3200
	{"RT-AC3200"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC88U
	{"RT-AC88U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC3100
	{"RT-AC3100"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC5300
	{"RT-AC5300"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAC5300
	{"GT-AC5300"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC86U
	{"RT-AC86U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC2900"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"CT-AC2900"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAC2900
	{"GT-AC2900"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"GT-AC2900_SH"  ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX88U
	{"RT-AX88U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAX11000
	{"GT-AX11000"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"GT-AX11000_BO4",      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX92U
	{"RT-AX92U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX58U
	{"RT-AX58U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AX3000"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AX5400"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX58U_V2
	{"RT-AX58U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AX3000"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AX58U_V2"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX82U
	{"RT-AX82U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX82U_V2
	{"RT-AX82U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AX82U_V2"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef TUFAX3000
	{"TUF-AX3000"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef TUFAX3000_V2
	{"TUF-AX3000"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"TUF-AX3000_V2" ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAXE7800
	{"RT-AXE7800"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX86U_PRO
	{"RT-AX86U_Pro"  ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef TUFAX5400
	{"TUF-AX5400"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GSAX3000
	{"GS-AX3000"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GSAX5400
	{"GS-AX5400"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX82_XD6
        {"ZenWiFi_XD6"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"ZenWiFi_XD6E"  ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX82_XD6S
	{"ZenWiFi_XD6"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"ZenWiFi_XD6S"  ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"ZenWiFi_XD6E"  ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX95Q
	{"ZenWiFi_XT8"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef XT8PRO
	{"ZenWiFi_XT9"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef XT8_V2
	{"ZenWiFi_XT8"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAXE95Q
	{"ZenWiFi_ET8"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef ET8PRO
	{"ZenWiFi_ET8P"  ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef ET9
	{"ZenWiFi_ET9"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX56_XD4
	{"ZenWiFi_XD4"   ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef CTAX56_XD4
	{"CT-MESH1"      ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef XD4PRO
	{"ZenWiFi_XD4_Pro",      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef RTAX3000N
	{"RT-AX3000N"    ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX55_V2"    ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX58"       ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef XC5
	{"ZenWiFi_XC5"   ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef RTAX56U
	{"RT-AX56U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX55
	{"RT-AX55"       ,      "", 1, 0, 1, 1, 0, 0, 0, 1, 0},  // lite
	{"RT-AX56U_V2"   ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX1800_Plus",      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef RTAC68U_V4
	{"RT-AC68U_V4"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AC68U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX68U
	{"RT-AX68U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX86U
	{"RT-AX86U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AX5700"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"RT-AX86S"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAXE11000
	{"GT-AXE11000"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAX11000_PRO
	{"GT-AX11000_Pro",      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAX6000
	{"GT-AX6000"     ,     	"", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAXE16000
	{"GT-AXE16000"   ,     	"", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef ET12
	{"ET12"          ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"ZenWiFi_Pro_ET12",    "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef XT12
	{"XT12"          ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"ZenWiFi_Pro_XT12",    "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC85U
	{"RT-AC85U"      ,      "", 1, 1, 1, 0, 1, 1, 1, 1, 0},
	{"RT-AC65U"      ,      "", 1, 1, 1, 0, 1, 1, 1, 1, 0},
#endif
#ifdef RTACRH26
	{"RT-ACRH26"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},  // RT-ACRH26
#endif
#ifdef RT4GAC86U
	{"4G-AC86U"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef BRTAC828
	{"BRT-AC828"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX89U
	{"RT-AX89X"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef GTAXY16000
	{"GX-AXY16000"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef MAPAC2200V
	{"LYRA_VOICE"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef MAPAC1300V
	{"VOICE_MINI"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef MAPAC2200
	{"Lyra"          ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},  // MAP-AC2200
	{"HiveSpot"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},  // MAP-AC2200
#endif
#ifdef MAPAC1300
	{"Lyra_Mini"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},  // MAP-AC1300
	{"LyraMini"      ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},  // MAP-AC1300
#endif
#ifdef RTAC95U
	{"ZenWiFi_CT8"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAC59_CD6R
	{"ZenWiFi_CD6R"  ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef MAPAC1750
	{"Lyra_Trio"     ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // MAP-AC1750
#endif
#ifdef BLUECAVE
	{"BLUECAVE"      ,      "", 1, 1, 1, 0, 1, 1, 1, 1, 0},
	{"BLUE_CAVE"     ,      "", 1, 1, 1, 0, 1, 1, 1, 1, 0},
#endif
#ifdef DSL_AX82U
	{"DSL-AX82U"     ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef PLAX56_XP4
	{"ZenWiFi_XP4"   ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RT4GAX56
	{"4G-AX56"       ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef RTAX53U
	{"RT-AX53U"      ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX1800U"    ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef RTAX54
	{"RT-AX54"       ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX1800S"    ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX1800UHP"  ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX1800HP"   ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"RT-AX54HP"     ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef XD4S
	{"ZenWiFi_XD4S"    ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"ZenWiFi_XD4_Plus",      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef XD4PRO
	{"ZenWiFi_XD4_Pro",      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
	{"ZenWiFi_XD5"    ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef TUFAX4200
	{"TUF-AX4200"    ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{"TUF-AX4200Q"    ,     "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef TUFAX6000
	{"TUF-AX6000"     ,     "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
#ifdef RTAX59U
	{"RT-AX59U"      ,      "", 1, 0, 1, 0, 0, 0, 0, 0, 0},  // lite
#endif
#ifdef GT10
	{"GT10"          ,      "", 1, 1, 1, 1, 1, 1, 1, 1, 1},
#endif
	/**********   NORMAL  CASE   END     **********/

	// The End
	{0,0,0,0,0,0,0,0,0,0,0}
};

static int dump_dpi_support_index(struct dpiSupport *p, int index)
{
	if (index == 0) {
		BWSUP_DBG("%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
			p->MALS, p->VP, p->CC , p->adaptive_qos, p->traffic_analyzer, p->webs_filter, p->apps_filter, p->web_history, p->bandwidth_monitor);
		return 0;
	}
	else if (index == 1) {
		return p->MALS;
	}
	else if (index == 2) {
		return p->VP;
	}
	else if (index == 3) {
		return p->CC;
	}
	else if (index == 4) {
		return p->adaptive_qos;
	}
	else if (index == 5) {
		return p->traffic_analyzer;
	}
	else if (index == 6) {
		return p->webs_filter;
	}
	else if (index == 7) {
		return p->apps_filter;
	}
	else if (index == 8) {
		return p->web_history;
	}
	else if (index == 9) {
		return p->bandwidth_monitor;
	}
	else {
		BWSUP_DBG("We can't match the index!\n");
		return 0;
	}
}

/*
	ret = 0 : not need to block
	ret = 1 : need to block this tcode for certain model
*/
int check_tcode_blacklist()
{
	int ret = 0;
	struct dpi_TcodeBlacklist *p_tcode_support = s_tcode_blacklist_tuple;

	char *model = get_productid();
	char *tcode = nvram_safe_get("territory_code");

	// traverse s_tcode_blacklist_tuple for tcode case
	for (; p_tcode_support->model != 0; p_tcode_support++) {
		if (!strcmp(p_tcode_support->model, model) && !strcmp(p_tcode_support->tcode, tcode)) {
			ret = 1;
			break;
		}
	}

	BWSUP_DBG("[tcode blacklist] model=%s, tcode=%s, ret=%d\n", model, tcode, ret);
	return ret;
}

int dump_dpi_support(int index)
{
	struct dpiSupport *p_tcode_support = s_tcode_tuple;
	struct dpiSupport *p_support = s_tuple;
	char *productid = get_productid();
	char *tcode = nvram_safe_get("territory_code");
	int is_tcode = 0;
	int is_found = 0;
	int ret = 0;

	BWSUP_DBG("productid=%s, tcode=%s, index=%d\n", productid, tcode, index);

	// tcode blacklist case
	if (check_tcode_blacklist() == 1) {
		return 0;
	}

	// traverse s_tcode_tuple for tcode case
	for (; p_tcode_support->model != 0; p_tcode_support++) {
		if (!strcmp(p_tcode_support->model, productid) && !strcmp(p_tcode_support->tcode, tcode)) {
			ret = dump_dpi_support_index(p_tcode_support, index);
			is_tcode = 1;
			is_found = 1;
			BWSUP_DBG("[tcode  case] ret=%d, is_tcode=%d\n", ret, is_tcode);
			break;
		}
	}

	// traverse s_tuple for normal case
	if (is_tcode == 0) {
		for (; p_support->model != 0; p_support++) {
			if (!strcmp(p_support->model, productid)) {
				ret = dump_dpi_support_index(p_support, index);
				is_found = 1;
				BWSUP_DBG("[normal case] ret=%d, is_tcode=%d\n", ret, is_tcode);
				break;
			}
		}
	}

	if (is_found == 0) BWSUP_DBG("We can't found the model!\n");

	return ret;
}

void setup_dpi_support_bitmap()
{
	struct dpiSupport *p = s_tuple;
	char *productid = get_productid();
	int bitmap = 0;
	char buf[8] = {0};

	for (; p->model != 0; p++) {
		if (!strcmp(p->model, productid)) {
			bitmap = ((p->MALS << 0) |  (p->VP << 1) | (p->CC << 2) | (p->adaptive_qos << 3) |
				(p->traffic_analyzer << 4) | (p->webs_filter << 5) | (p->apps_filter << 6) |
				(p->web_history << 7) | (p->bandwidth_monitor << 8));
			snprintf(buf, sizeof(buf), "0x%x", bitmap);
			BWSUP_DBG("bitmap=%d(%x), buf=%s\n", bitmap, bitmap, buf);
			nvram_set("bwdpi_bitmap", buf);
			break;
		}
	}
}

/*
	check support model list, compare odmpid from dpi_support table
*/
int model_protection()
{
	int ret = 0;
	struct dpiSupport *p = s_tuple;
	char *productid = get_productid();

	for (; p->model != 0; p++) {
		if (!strcmp(p->model, productid)) {
			ret = 1;
			break;
		}
	}

	return ret;
}
