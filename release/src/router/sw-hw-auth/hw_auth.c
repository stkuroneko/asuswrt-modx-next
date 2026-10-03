 /*
 * Copyright 2021, ASUSTeK Inc.
 * All Rights Reserved.
 */

/* header */
#include "auth_common.h"
#include <shutils.h>
#include <shared.h>

/* define */
#define RTAC68 "RT-AC68"

#ifdef RTCONFIG_AMAS
/* struct amas_whiitelist define */
typedef struct AMAS_WHITELIST_T amas_whitelist_t;
struct AMAS_WHITELIST_T {
	char *odmpid;
	int  mode;
};

/* amas_whitelist tuple define */
struct AMAS_WHITELIST_T s_amas_whitelist_tuple[] =
{
	/******************************************************************************
		main trunk and 386 branch : the below lists are for AiMesh models
	******************************************************************************/
#ifdef RTAC68U
	/* RT-AC68U series */
	{"RT-AC68",          AMAS_CAP | AMAS_RE},      // NOTE : special logic for whole RT-AC68U series
	{"RT-AC1900",        AMAS_CAP | AMAS_RE},
	{"RT-AC1900P",       AMAS_CAP | AMAS_RE},
	{"RT-AC66U_B1",      AMAS_CAP | AMAS_RE},
	{"RT-AC1750_B1",     AMAS_CAP | AMAS_RE},
	{"RT-AC1900U",       AMAS_CAP | AMAS_RE},
	{"RT-AC66U+",        AMAS_CAP | AMAS_RE},
	{"RT-AC67U",         AMAS_CAP | AMAS_RE},
	{"RP-AC1900",        AMAS_CAP | AMAS_RE},
#endif
#ifdef DSL_AC68U
	{"DSL-AC68U",        AMAS_CAP | AMAS_RE},
	{"DSL-AC68R",        AMAS_CAP | AMAS_RE},
#endif
#ifdef RT4GAC68U
	{"4G-AC68U",         AMAS_CAP},
#endif
#ifdef RTAC88U
	{"RT-AC88U",         AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAC3100
	{"RT-AC3100",        AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAC5300
	{"RT-AC5300",        AMAS_CAP | AMAS_RE},
#endif
#ifdef GTAC5300
	{"GT-AC5300",        AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAC86U
	{"RT-AC86U",         AMAS_CAP | AMAS_RE},
	{"RT-AC2900",        AMAS_CAP | AMAS_RE},
	{"CT-AC2900",        AMAS_CAP | AMAS_RE},
#endif
#ifdef GTAC2900
	{"GT-AC2900",        AMAS_CAP | AMAS_RE},
	{"GT-AC2900_SH",     AMAS_CAP | AMAS_RE},
#endif
#ifdef MAPAC1300
	{"Lyra_Mini",        AMAS_CAP | AMAS_RE},
	{"LyraMini",         AMAS_CAP | AMAS_RE},
#endif
#ifdef MAPAC2200
	{"Lyra",             AMAS_CAP | AMAS_RE},
	{"HiveSpot",         AMAS_CAP | AMAS_RE},
#endif
#ifdef MAPAC2200V
	{"LYRA_VOICE",       AMAS_CAP | AMAS_RE},
#endif
#ifdef MAPAC1300V
	{"ZenWiFi_CV4",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAC95U
	{"ZenWiFi_CT8",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RT4GAC53U
	{"4G-AC53U",         AMAS_CAP},
#endif
#ifdef RTAC82U
	{"RT-AC2200",        AMAS_CAP | AMAS_RE},
#endif
#ifdef GTAXY16000
	{"GT-AXY16000",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX89U
	{"RT-AX89X",         AMAS_CAP | AMAS_RE},
#endif
#ifdef MAPAC1750
	{"Lyra_Trio",        AMAS_CAP | AMAS_RE},
#endif
#ifdef RPAC67
	{"RP-AC67",          AMAS_RE},
#endif
#ifdef RTAC59U
	{"RT-AC59U_V2",        AMAS_CAP | AMAS_RE},
	{"RT-AC58U_V3",        AMAS_CAP | AMAS_RE},
	{"RT-AC57U_V3",        AMAS_CAP | AMAS_RE},
	{"RT-AC1300G_PLUS_V3", AMAS_CAP | AMAS_RE},
	{"RT-ACRH12_V2",       AMAS_CAP | AMAS_RE},
#endif
#ifdef BLUECAVE
	{"BLUECAVE",         AMAS_CAP | AMAS_RE},
	{"BLUE_CAVE",        AMAS_CAP | AMAS_RE},
#endif
#ifdef RPAC55
	{"RP-AC55",          AMAS_RE},
#endif
#ifdef RPAC92
	{"RP-AC92",          AMAS_RE},
#endif
#ifdef RT4GAC56
	{"4G-AC56",          AMAS_CAP},
#endif
#ifdef RTAC59_CD6R
	{"ZenWiFi_CD6R",     AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAC59_CD6N
	{"ZenWiFi_CD6N",     AMAS_RE},
#endif

#ifdef RTAX88U
	{"RT-AX88U",         AMAS_CAP | AMAS_RE},
#endif
#ifdef GTAX11000
	{"GT-AX11000",       AMAS_CAP | AMAS_RE},
	{"GT-AX11000_BO4",   AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX92U
	{"RT-AX92U",         AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX58U
	{"RT-AX58U",         AMAS_CAP | AMAS_RE},
	{"RT-AX3000",        AMAS_CAP | AMAS_RE},
	{"RT-AX5400",        AMAS_CAP | AMAS_RE},
	{"CT-AX5400",        AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX58U_V2
	{"RT-AX58U",         AMAS_CAP | AMAS_RE},
	{"RT-AX3000",        AMAS_CAP | AMAS_RE},
	{"RT-AX58U_V2",      AMAS_CAP | AMAS_RE},
#endif
#ifdef TUFAX3000
	{"TUF-AX3000",       AMAS_CAP | AMAS_RE},
#endif
#ifdef TUFAX3000_V2
	{"TUF-AX3000",       AMAS_CAP | AMAS_RE},
	{"TUF-AX3000_V2",    AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAXE7800
	{"RT-AXE7800",       AMAS_CAP | AMAS_RE},
#endif
#ifdef GT10
	{"GT10",             AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX56U
	{"RT-AX56U",         AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX95Q
	{"ZenWiFi_XT8",      AMAS_CAP | AMAS_RE},
#endif
#ifdef XT8PRO
	{"ZenWiFi_XT9",      AMAS_CAP | AMAS_RE},
#endif
#ifdef XT8_V2
	{"ZenWiFi_XT8",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAXE95Q
	{"ZenWiFi_ET8",      AMAS_CAP | AMAS_RE},
#endif
#ifdef ET8PRO
	{"ZenWiFi_ET8P",     AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX55
	{"RT-AX55",          AMAS_CAP | AMAS_RE},
	{"RT-AX56U_V2",      AMAS_CAP | AMAS_RE},
	{"RT-AX1800_Plus",   AMAS_CAP | AMAS_RE},
#endif
#if defined(RTAX55) || defined(RTAX1800)
	{"RT-AX1800",        AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX3000N
	{"RT-AX3000N",       AMAS_CAP | AMAS_RE},
	{"RT-AX55_V2",       AMAS_CAP | AMAS_RE},
	{"RT-AX58",          AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX56_XD4
	{"ZenWiFi_XD4",      AMAS_CAP | AMAS_RE},
#endif
#ifdef XD4PRO
	{"ZenWiFi_XD4_Pro",  AMAS_CAP | AMAS_RE},
	{"ZenWiFi_XD5",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAC68U_V4
	{"RT-AC68",          AMAS_CAP | AMAS_RE},
	{"RT-AC68U_V4",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX68U
	{"RT-AX68U",         AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX86U
	{"RT-AX86U",         AMAS_CAP | AMAS_RE},
	{"RT-AX5700",        AMAS_CAP | AMAS_RE},
	{"RT-AX86S",         AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX82U
	{"RT-AX82U",         AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX82U_V2
	{"RT-AX82U",         AMAS_CAP | AMAS_RE},
	{"RT-AX82U_V2",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX82_XD6
	{"ZenWiFi_XD6",      AMAS_CAP | AMAS_RE},
	{"ZenWiFi_XD6E",      AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX82_XD6S
	{"ZenWiFi_XD6",      AMAS_CAP | AMAS_RE},
	{"ZenWiFi_XD6S",     AMAS_CAP | AMAS_RE},
	{"ZenWiFi_XD6E",     AMAS_CAP | AMAS_RE},
#endif
#ifdef DSL_AX82U
	{"DSL-AX82U",        AMAS_CAP | AMAS_RE},
	{"DSL-AX5400",       AMAS_CAP | AMAS_RE},
#endif
#ifdef RPAX56
	{"RP-AX56",          AMAS_RE},
#endif
#ifdef RPAX58
	{"RP-AX58",          AMAS_RE},
#endif
#ifdef GTAXE11000
	{"GT-AXE11000",      AMAS_CAP | AMAS_RE},
#endif
#ifdef PLAX56_XP4
	{"ZenWiFi_XP4",      AMAS_CAP | AMAS_RE},
#endif
#ifdef ETJ
	{"ETJ",              AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX57Q
	{"RT-AX57Q",         AMAS_CAP | AMAS_RE},
#endif
#ifdef GSAX3000
	{"GS-AX3000",        AMAS_CAP | AMAS_RE},
#endif
#ifdef GSAX5400
	{"GS-AX5400",        AMAS_CAP | AMAS_RE},
#endif
#ifdef TUFAX5400
	{"TUF-AX5400",       AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX53U
	{"RT-AX53U",         AMAS_CAP | AMAS_RE},
	{"RT-AX1800U",       AMAS_CAP | AMAS_RE},
#endif
#ifdef RT4GAX56
	{"4G-AX56",          AMAS_CAP},
#endif
#ifdef XD4S
	{"ZenWiFi_XD4S",     AMAS_CAP | AMAS_RE},
	{"ZenWiFi_XD4_Plus", AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX54
	{"RT-AX54",          AMAS_CAP | AMAS_RE},
	{"RT-AX1800S",       AMAS_CAP | AMAS_RE},
	{"RT-AX1800UHP",     AMAS_CAP | AMAS_RE},
	{"RT-AX1800HP",      AMAS_CAP | AMAS_RE},
	{"RT-AX54HP",        AMAS_CAP | AMAS_RE},
#endif
#ifdef CTAX56_XD4
	{"CT-MESH1",         AMAS_CAP | AMAS_RE},
#endif
#ifdef GTAX6000
	{"GT-AX6000",        AMAS_CAP | AMAS_RE},
#endif
#ifdef GTAX11000_PRO
	{"GT-AX11000_Pro",   AMAS_CAP | AMAS_RE},
#endif
#ifdef GTAXE16000
	{"GT-AXE16000",	     AMAS_CAP | AMAS_RE},
#endif
#ifdef ET12
	{"ET12",             AMAS_CAP | AMAS_RE},
	{"ZenWiFi_Pro_ET12", AMAS_CAP | AMAS_RE},
#endif
#ifdef XT12
	{"XT12",             AMAS_CAP | AMAS_RE},
	{"ZenWiFi_Pro_XT12", AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX86U_PRO
	{"RT-AX86U_Pro",     AMAS_CAP | AMAS_RE},
#endif
#ifdef TUFAX4200
	{"TUF-AX4200",       AMAS_CAP | AMAS_RE},
	{"TUF-AX4200Q",      AMAS_CAP | AMAS_RE},
#endif
#ifdef TUFAX6000
	{"TUF-AX6000",       AMAS_CAP | AMAS_RE},
#endif
#ifdef RTAX59U
	{"RT-AX59U",         AMAS_CAP | AMAS_RE},
#endif

	// The End
	{0}
};
#endif

#ifdef RTCONFIG_TUNNEL
/* struct tunnel_whiitelist define */
typedef struct TUNNEL_WHITELIST_T tunnel_whitelist_t;
struct TUNNEL_WHITELIST_T {
	char *odmpid;
};

/* tunnel_whitelist tuple define */
struct TUNNEL_WHITELIST_T s_tunnel_whitelist_tuple[] =
{
	// Don't add model with random order, this format follows hw_auth table

	/******************************************************************************
		main trunk and 382 branch : the below lists are for non-AiMesh models
	******************************************************************************/
#ifdef RTAC56U
	{"RT-AC56U"},
	{"RT-AC56R"},
#endif
#ifdef RTAC87U
	{"RT-AC87U"},
	{"RT-AC87R"},
#endif
#ifdef RTAC56S
	{"RT-AC56S"},
#endif
#ifdef RTN18U
	{"RT-N18U"},
#endif
#ifdef RTAC3200
	{"RT-AC3200"},
#endif
#ifdef RTAC1200G
	{"RT-AC1200G"},
#endif
#ifdef RTAC1200GP
	{"RT-AC1200G+"},
#endif
#ifdef RTAC85U
	{"RT-AC85U"},
	{"RT-AC65U"},
#endif
#ifdef RTAC85P
	{"RT-AC85P"},
	{"RT-AC1750U"},
	{"RT-AC65P"},
	{"RT-AC2400"},
	{"RT-AC2600"},
	{"RT-AC1700"},
#endif
#ifdef RTACRH26
	{"RT-ACRH26"},
#endif
#ifdef TUFAC1750
	{"TUF-AC1750"},
#endif
#ifdef RTAC55U
	{"RT-AC55U"},
#endif
#ifdef RTAC55UHP
	{"RT-AC55UHP"},
#endif
#ifdef RTACRH18
	{"RT-AC67P"},
	{"RT-ACRH18"},
	{"RT-AC65"},
#endif
#ifdef RT4GAX56
	{"4G-AX56"},
#endif

	/******************************************************************************
		main trunk and 386 branch : the below lists are for AiMesh models
	******************************************************************************/
#ifdef RTAC68U
	/* RT-AC68U series */
	{"RT-AC68"},      // NOTE : special logic for whole RT-AC68U series
	{"RT-AC1900"},
	{"RT-AC1900P"},
	{"RT-AC66U_B1"},
	{"RT-AC1750_B1"},
	{"RT-AC1900U"},
	{"RT-N66U_C1"},
	{"RT-AC66U+"},
	{"RT-AC67U"},
	{"RP-AC1900"},
#endif
#ifdef DSL_AC68U
	{"DSL-AC68U"},
	{"DSL-AC68R"},
#endif
#ifdef RT4GAC68U
	{"4G-AC68U"},
#endif
#ifdef RTAC88U
	{"RT-AC88U"},
#endif
#ifdef RTAC3100
	{"RT-AC3100"},
#endif
#ifdef RTAC5300
	{"RT-AC5300"},
#endif
#ifdef GTAC5300
	{"GT-AC5300"},
#endif
#ifdef RTAC86U
	{"RT-AC86U"},
	{"RT-AC2900"},
	{"CT-AC2900"},
#endif
#ifdef GTAC2900
	{"GT-AC2900"},
	{"GT-AC2900_SH"},
#endif
#ifdef MAPAC1300
	{"Lyra_Mini"},
	{"LyraMini"},
#endif
#ifdef MAPAC2200
	{"Lyra"},
	{"HiveSpot"},
#endif
#ifdef MAPAC2200V
	{"LYRA_VOICE"},
#endif
#ifdef MAPAC1300V
	{"ZenWiFi_CV4"},
#endif
#ifdef RTAC95U
	{"ZenWiFi_CT8"},
#endif
#ifdef RT4GAC53U
	{"4G-AC53U"},
#endif
#ifdef RTAC82U
	{"RT-AC2200"},
	{"RT-ACRH17"},
#endif
#ifdef GTAXY16000
	{"GT-AXY16000"},
#endif
#ifdef RTAX89U
	{"RT-AX89X"},
#endif
#ifdef MAPAC1750
	{"Lyra_Trio"},
#endif
#ifdef RTAC59U
	{"RT-AC59U_V2"},
	{"RT-AC58U_V3"},
	{"RT-AC57U_V3"},
	{"RT-AC1300G_PLUS_V3"},
	{"RT-ACRH12_V2"},
#endif
#ifdef BLUECAVE
	{"BLUECAVE"},
	{"BLUE_CAVE"},
#endif
#ifdef RPAC55
	{"RP-AC55"},
#endif
#ifdef RT4GAC86U
	{"4G-AC86U"},
#endif
#ifdef RT4GAC56
	{"4G-AC56"},
#endif
#ifdef RTAC59_CD6R
	{"ZenWiFi_CD6R"},
#endif
#ifdef RTAC59_CD6N
	{"ZenWiFi_CD6N"},
#endif

#ifdef RTAX88U
	{"RT-AX88U"},
#endif
#ifdef GTAX11000
	{"GT-AX11000"},
	{"GT-AX11000_BO4"},
#endif
#ifdef RTAX92U
	{"RT-AX92U"},
#endif
#ifdef RTAX58U
	{"RT-AX58U"},
	{"RT-AX3000"},
	{"RT-AX5400"},
	{"CT-AX5400"},
#endif
#ifdef RTAX58U_V2
	{"RT-AX58U"},
	{"RT-AX3000"},
	{"RT-AX58U_V2"},
#endif
#ifdef TUFAX3000
	{"TUF-AX3000"},
#endif
#ifdef TUFAX3000_V2
	{"TUF-AX3000"},
	{"TUF-AX3000_V2"},
#endif
#ifdef RTAXE7800
	{"RT-AXE7800"},
#endif
#ifdef GT10
	{"GT10"},
#endif
#ifdef RTAX56U
	{"RT-AX56U"},
#endif
#ifdef RTAX95Q
	{"ZenWiFi_XT8"},
#endif
#ifdef XT8PRO
	{"ZenWiFi_XT9"},
#endif
#ifdef XT8_V2
	{"ZenWiFi_XT8"},
#endif
#ifdef RTAXE95Q
	{"ZenWiFi_ET8"},
#endif
#ifdef ET8PRO
	{"ZenWiFi_ET8P"},
#endif
#ifdef RTAX55
	{"RT-AX55"},
	{"RT-AX56U_V2"},
	{"RT-AX1800_Plus"},
#endif
#if defined(RTAX55) || defined(RTAX1800)
	{"RT-AX1800"},
#endif
#ifdef RTAX3000N
	{"RT-AX3000N"},
	{"RT-AX55_V2"},
	{"RT-AX58"},
#endif
#ifdef RTAX56_XD4
	{"ZenWiFi_XD4"},
#endif
#ifdef XD4PRO
	{"ZenWiFi_XD4_Pro"},
	{"ZenWiFi_XD5"},
#endif
#ifdef RTAC68U_V4
	{"RT-AC68"},
        {"RT-AC68U_V4"},
#endif
#ifdef RTAX68U
	{"RT-AX68U"},
#endif
#ifdef RTAX86U
	{"RT-AX86U"},
	{"RT-AX5700"},
	{"RT-AX86S"},
#endif
#ifdef RTAX82U
	{"RT-AX82U"},
#endif
#ifdef RTAX82U_V2
	{"RT-AX82U"},
	{"RT-AX82U_V2"},
#endif
#ifdef RTAX82_XD6
	{"ZenWiFi_XD6"},
	{"ZenWiFi_XD6E"},
#endif
#ifdef RTAX82_XD6S
	{"ZenWiFi_XD6"},
	{"ZenWiFi_XD6S"},
	{"ZenWiFi_XD6E"},
#endif
#ifdef DSL_AX82U
	{"DSL-AX82U"},
	{"DSL-AX5400"},
#endif
#ifdef RPAX56
	{"RP-AX56"},
#endif
#ifdef RPAX58
	{"RP-AX58"},
#endif
#ifdef GTAXE11000
	{"GT-AXE11000"},
#endif
#ifdef PLAX56_XP4
	{"ZenWiFi_XP4"},
#endif
#ifdef ETJ
	{"ETJ"},
#endif
#ifdef RTAX57Q
	{"RT-AX57Q"},
#endif
#ifdef GSAX3000
	{"GS-AX3000"},
#endif
#ifdef GSAX5400
	{"GS-AX5400"},
#endif
#ifdef TUFAX5400
	{"TUF-AX5400"},
#endif
#ifdef RTAX53U
	{"RT-AX53U"},
	{"RT-AX1800U"},
#endif
#ifdef XD4S
	{"ZenWiFi_XD4S"},
	{"ZenWiFi_XD4_Plus"},
#endif
#ifdef RTAX54
	{"RT-AX54"},
	{"RT-AX1800S"},
	{"RT-AX1800UHP"},
	{"RT-AX1800HP"},
	{"RT-AX54HP"},
#endif
#ifdef CTAX56_XD4
	{"CT-MESH1"},
#endif
#ifdef GTAX6000
	{"GT-AX6000"},
#endif
#ifdef GTAX11000_PRO
	{"GT-AX11000_Pro"},
#endif
#ifdef GTAXE16000
	{"GT-AXE16000"},
#endif
#ifdef ET12
	{"ET12"},
	{"ZenWiFi_Pro_ET12"},
#endif
#ifdef XT12
	{"XT12"},
	{"ZenWiFi_Pro_XT12"},
#endif
#ifdef RTAX86U_PRO
	{"RT-AX86U_Pro"},
#endif
#ifdef TUFAX4200
	{"TUF-AX4200"},
	{"TUF-AX4200Q"},
#endif
#ifdef TUFAX6000
	{"TUF-AX6000"},
#endif
#ifdef RTAX59U
	{"RT-AX59U"},
#endif

	// The End
	{0}
};
#endif

/* struct define */
typedef struct SW_AUTH_T sw_auth_t;
struct SW_AUTH_T {
	char *app_name;
	char *app_id;
	char *app_key;
	int  third_party;
};

/* sw_auth tuple define */
struct SW_AUTH_T s_sw_auth_tuple[] =
{
	/* ASUS daemon */
	{"httpd"          , "45646223", "fk309g1sedk0353445g",     0},
#ifdef RTCONFIG_TUNNEL
	{"mastiff"        , "14354641", "mg8rla5fj94kq0kcm2z",     0},
	{"aaews"          , "89347542", "jidf0924ij4pdfg54as",     0},
#endif
#ifdef RTCONFIG_NOTIFICATION_CENTER
	{"wlc_nt"         , "25124577", "afa125g46h4yefse03t",     0},
#endif

	/* ASUS feature */
#if defined(RTCONFIG_AMAS) || defined(RTCONFIG_WIFI_SON)
	{"AMASH"          , "33716237", "g2hkhuig238789ajkhc",     0},
#endif

	/* ASUS app */
	// TODO

	/* 3rd party app */
	// TODO

	// The End
	{0,0,0,0}
};

#define GET_APP_KEY(app_id, app_key) { \
	struct SW_AUTH_T *p = s_sw_auth_tuple; \
	for (; p->app_id != 0; p++) { \
		if (!strcmp(p->app_id, app_id)) { \
			strcpy(app_key, p->app_key); \
			break; \
		} \
	} \
}

#define GET_APP_ID(app_id, app_key) { \
	struct SW_AUTH_T *p = s_sw_auth_tuple; \
	for (; p->app_key != 0; p++) { \
		if (!strcmp(p->app_key, app_key)) { \
			strcpy(app_id, p->app_id); \
			break; \
		} \
	} \
}

#define GET_APP_NAME_BY_ID(app_id, app_name) { \
	struct SW_AUTH_T *p = s_sw_auth_tuple; \
	for (; p->app_id != 0; p++) { \
		if (!strcmp(p->app_id, app_id)) { \
			strcpy(app_name, p->app_name); \
			break; \
		} \
	} \
}

#define GET_APP_NAME_BY_KEY(app_key, app_name) { \
	struct SW_AUTH_T *p = s_sw_auth_tuple; \
	for (; p->app_key != 0; p++) { \
		if (!strcmp(p->app_key, app_key)) { \
			strcpy(app_name, p->app_name); \
			break; \
		} \
	} \
}

/* DEBUG DEFINE */
#define HW_AUTH_DEBUG             "/tmp/HW_AUTH_DEBUG"
#define MyDBG(fmt,args...) \
	if(f_exists(HW_AUTH_DEBUG) > 0) { \
		printf("[HW_AUTH][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}
/* LOG DEFINE */
#define HW_AUTH_LOG               "/tmp/HW_AUTH_LOG"
#define MyLOG(fmt,args...) \
	if(f_exists(HW_AUTH_LOG) > 0) { \
		char info[1024]; \
		snprintf(info, sizeof(info), "echo \""fmt"\" >> /tmp/HW_AUTH.log", ##args); \
		system(info); \
	}

/* hw_auth_path */
#define HW_AUTH_CLM  "/tmp/hw_auth_clm"

/* struct define */
typedef struct HW_AUTH_T hw_auth_t;
struct HW_AUTH_T {
	char *productid;         // get_productid() : odmpid or productid
	char *btn_rst_gpio;
	char *btn_wps_gpio;
	char *btn_led_gpio;
	char *btn_wltog_gpio;
	char *clm_data_ver_2g;   // some models don't implement
	char *clm_data_ver_5g1;  // some models don't implement
	char *clm_data_ver_5g2;  // some models don't implement
	char *hwcode;            // hardware code : not to implement now
};

/* hw_auth tuple define */
struct HW_AUTH_T s_hw_auth_tuple[] =
{
	// Don't add model with random order, this format follows hw_auth table

	/******************************************************************************
		main trunk and 382 branch : the below lists are for non-AiMesh models
	******************************************************************************/
#ifdef RTAC56U
	{"RT-AC56U"      , "4107", "4111",     "", "4103",     "RT-AC56U", "", "", ""},
	{"RT-AC56R"      , "4107", "4111",     "", "4103",     "RT-AC56U", "", "", ""},
#endif
#ifdef RTAC87U
	{"RT-AC87R"      , "4107", "4098",    "4", "4111",     "RT-AC87U", "", "", ""},
	{"RT-AC87U"      , "4107", "4098",    "4", "4111",     "RT-AC87U", "", "", ""},
#endif
#ifdef RTAC56S
	{"RT-AC56S"      , "4107", "4111",     "", "4103",   "RT-AC56U/S", "", "", ""},
#endif
#ifdef RTN18U
	{"RT-N18U"       , "4103", "4107",     "",     "",      "RT-N18U", "", "", ""},
#endif
#ifdef RTAC3200
	{"RT-AC3200"     , "4107", "4103", "4111", "4100",    "RT-AC3200", "", "", ""},
#endif
#ifdef RTAC1200G
	{"RT-AC1200G"    , "4101", "4105",     "",     "",   "RT-AC1200G", "", "", ""},
#endif
#ifdef RTAC1200GP
	{"RT-AC1200G+"   , "4101", "4105",     "",     "",  "RT-AC1200G+", "", "", ""},
#endif
#ifdef RTAC85U
	{"RT-AC85U"      , "4112", "4114",     "",     "",     "RT-AC85U", "", "", ""},
	{"RT-AC65U"      , "4112", "4114",     "",     "",     "RT-AC85U", "", "", ""},
#endif
#ifdef RTAC85P
	{"RT-AC85P"      , "4099", "4102",     "",     "",     "RT-AC85P", "", "", ""},
	{"RT-AC1750U"    , "4099", "4102",     "",     "",     "RT-AC85P", "", "", ""},
	{"RT-AC65P"      , "4099", "4102",     "",     "",     "RT-AC85P", "", "", ""},
	{"RT-AC2400"     , "4099", "4102",     "",     "",     "RT-AC85P", "", "", ""},
	{"RT-AC2600"     , "4099", "4102",     "",     "",     "RT-AC85P", "", "", ""},
	{"RT-AC1700"     , "4099", "4102",     "",     "",     "RT-AC85P", "", "", ""},
#endif
#ifdef RTACRH26
	{"RT-ACRH26"     , "4099", "4102",     "",     "",    "RT-ACRH26", "", "", ""},
#endif
#ifdef RTAC55U
	{"RT-AC55U"      , "4113", "4112",     "",     "",             "", "", "", ""},
#endif
#ifdef RTAC55UHP
	{"RT-AC55UHP"    , "4113", "4112",     "",     "",             "", "", "", ""},
#endif
#ifdef RTACRH18
	{"RT-AC67P"      , "4103", "4101",     "",     "",             "", "", "", ""},
	{"RT-ACRH18"     , "4103", "4101",     "",     "",             "", "", "", ""},
	{"RT-AC65"       , "4103", "4101",     "",     "",             "", "", "", ""},
#endif
#ifdef RT4GAX56
	{"4G-AX56"       , "4104", "4100",     "",     "",             "", "", "", ""},
#endif
#ifdef RTAX53U
	{"RT-AX53U"      , "4112", "4111",     "",     "",             "", "", "", ""},
	{"RT-AX1800U"    , "4112", "4111",     "",     "",             "", "", "", ""},
#endif
#ifdef RTAX54
	{"RT-AX54"       , "4112", "4111",     "",     "",             "", "",  "", ""},
	{"RT-AX1800S"    , "4112", "4111",     "",     "",             "", "",  "", ""},
	{"RT-AX1800UHP"  , "4112", "4111",     "",     "",             "", "",  "", ""},
	{"RT-AX1800HP"   , "4112", "4111",     "",     "",             "", "",  "", ""},
	{"RT-AX54HP"     , "4112", "4111",     "",     "",             "", "",  "", ""},
#endif

	// TODO : add non-AiMesh model here ...

	/******************************************************************************
		main trunk and 386 branch : the below lists are for AiMesh models
	******************************************************************************/
#ifdef RTAC68U
	// RT-AC68U
	{"RT-AC68"       , "4107", "4103",    "5", "4111",     "RT-AC68U",     "RT-AC68U",             "", ""}, // NOTE : special logic for whole RT-AC68U series
	{"RT-AC1900"     , "4107", "4103",    "5", "4111",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC1900P"    , "4107", "4103",    "5", "4111",     "RT-AC68U",     "RT-AC68U",             "", ""},
	// RT-AC66U_B1 (no LED / toggle button)
	{"RT-AC66U_B1"   , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC1750_B1"  , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC1900U"    , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-N66U_C1"    , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC66U+"     , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC67U"      , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RP-AC1900"     , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
#endif
#ifdef DSL_AC68U
	{"DSL-AC68U"     , "4107", "4103",     "", "4111",    "DSL-AC68U",    "DSL-AC68U",             "", ""},
	{"DSL-AC68R"     , "4107", "4103",     "", "4111",    "DSL-AC68U",    "DSL-AC68U",             "", ""},
#endif
#ifdef RT4GAC68U
	{"4G-AC68U"      , "4107", "4103",     "", "4111",     "RT-AC68U",     "RT-AC68U",             "", ""},
#endif
#ifdef RTAC88U
	{"RT-AC88U"      , "4107", "4116", "4100", "4114",     "RT-AC88U",     "RT-AC88U",             "", ""},
#endif
#ifdef RTAC3100
	{"RT-AC3100"     , "4107", "4116", "4100", "4114",    "RT-AC3100",    "RT-AC3100",             "", ""},
#endif
#ifdef RTAC5300
	{"RT-AC5300"     , "4107", "4114", "4100", "4116",    "RT-AC5300",    "RT-AC5300",    "RT-AC5300", ""},
#endif
#ifdef GTAC5300
	{"GT-AC5300"     , "4126", "4125", "4127", "4124",    "GT-AC5300",    "GT-AC5300",    "GT-AC5300", ""},
#endif
#ifdef RTAC86U
	{"RT-AC86U"      , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
	{"RT-AC2900"     , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
	{"CT-AC2900"     , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
#endif
#ifdef GTAC2900
	{"GT-AC2900"     , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
	{"GT-AC2900_SH"  , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
#endif
#ifdef MAPAC1300
	{"Lyra_Mini"     , "4096", "4159",     "",     "",   "MAP-AC1300",             "",             "", ""},
	{"LyraMini"      , "4096", "4159",     "",     "",   "MAP-AC1300",             "",             "", ""},
#endif
#ifdef MAPAC2200
	{"Lyra"          , "4130", "4114",     "",     "",   "MAP-AC2200",             "",             "", ""},
	{"HiveSpot"      , "4130", "4114",     "",     "",   "MAP-AC2200",             "",             "", ""},
#endif
#ifdef MAPAC2200V
	{"LYRA_VOICE"    , "4130", "4114",     "",     "",  "MAP-AC2200V",             "",             "", ""},
#endif
#ifdef MAPAC1300V
	{"ZenWiFi_CV4"   ,  "255",  "255",     "",     "",  "MAP-AC1300V",             "",             "", ""},
#endif
#ifdef RTAC95U
	{"ZenWiFi_CT8"   , "4114", "4150",     "",     "",     "RT-AC95U",             "",             "", ""},
#endif
#ifdef RT4GAC53U
	{"4G-AC53U"      , "4159", "4101",     "",     "",     "4G-AC53U",             "",             "", ""},
#endif
#ifdef RTAC82U
	{"RT-AC2200"     , "4114", "4107",     "",     "",     "RT-AC82U",             "",             "", ""},
	{"RT-ACRH17"     , "4114", "4107",     "",     "",     "RT-AC82U",             "",             "", ""},
#endif
#ifdef GTAXY16000
	{"GT-AXY16000"   , "4157", "4130",     "", "4122",  "GT-AXY16000",             "",             "", ""},	/* PCB R4.00 or above, HwId: 'B' */
//	{"GT-AXY16000"   , "4154", "4130",     "", "4122",  "GT-AXY16000",             "",             "", ""},	/* PCB R1.00 ~ R3.50, HwId: empty or 'A' */
#endif
#ifdef RTAX89U
	{"RT-AX89X"      , "4157", "4130", "4121", "4122",     "RT-AX89U",             "",             "", ""},	/* PCB R4.00 or above, HwId: 'B' */
//	{"RT-AX89X"      , "4154", "4130", "4121", "4122",     "RT-AX89U,             "",             "", ""},	/* PCB R1.00 ~ R3.50, HwId: empty or 'A' */
#endif
#ifdef MAPAC1750
	{"Lyra_Trio"     , "4098", "4101",     "",     "",             "",             "",             "", ""},
#endif
#ifdef RPAC67
	{"RP-AC67"       , "4098", "4101",     "",     "",             "",             "",             "", ""},
#endif
#ifdef RTAC59U
	{"RT-AC59U_V2"       , "4113", "4097",     "",     "",         "",             "",             "", ""},
	{"RT-AC58U_V3"       , "4113", "4097",     "",     "",         "",             "",             "", ""},
	{"RT-AC57U_V3"       , "4113", "4097",     "",     "",         "",             "",             "", ""},
	{"RT-AC1300G_PLUS_V3", "4113", "4097",     "",     "",         "",             "",             "", ""},
	{"RT-ACRH12_V2"      , "4113", "4097",     "",     "",         "",             "",             "", ""},
#endif
#ifdef BLUECAVE
	{"BLUECAVE"      , "4096", "4126",     "",     "",             "",             "",             "", ""},
	{"BLUE_CAVE"     , "4096", "4126",     "",     "",             "",             "",             "", ""},
#endif
#ifdef RPAC55
	{"RP-AC55"       ,   "54", "4152",     "",     "",             "",             "",             "", ""},
#endif
#ifdef RPAC92
	{"RP-AC92"       , "4130", "4133",     "",     "",             "",             "",             "", ""},
#endif
#ifdef RT4GAC86U
	{"4G-AC86U"      , "4198", "4096",     "",     "",             "",             "",             "", ""},
#endif
#ifdef RT4GAC56
	{"4G-AC56"       , "4115", "4127",     "",     "",      "4G-AC56",             "",             "", ""},
#endif
#ifdef RTAC59_CD6R
	{"ZenWiFi_CD6R"  , "4097", "4113",     "",     "",             "",             "",             "", ""},
#endif
#ifdef RTAC59_CD6N
	{"ZenWiFi_CD6N"  , "4097", "4113",     "",     "",             "",             "",             "", ""},
#endif

#ifdef BRTAC828
	{"BRT-AC828"     , "4150", "4112",     "",     "",    "BRT-AC828",             "",             "", ""},
#endif
#ifdef RTAX88U
	{"RT-AX88U"      , "4100", "4125", "4127", "4123",     "RT-AX88U",     "RT-AX88U",             "", ""},
#endif
#ifdef GTAX11000
	{"GT-AX11000"    , "4100", "4125",     "", "4123",   "GT-AX11000",   "GT-AX11000",   "GT-AX11000", ""},
	{"GT-AX11000_BO4", "4100", "4125",     "", "4123",   "GT-AX11000",   "GT-AX11000",   "GT-AX11000", ""},
#endif
#ifdef RTAX92U
	{"RT-AX92U"      , "4119", "4118",     "",     "",     "RT-AX92U",     "RT-AX92U",     "RT-AX92U", ""},
#endif
#ifdef RTAX58U
	{"RT-AX58U"      , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"RT-AX3000"     , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"RT-AX5400"     , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"CT-AX5400"     , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""}, // Chinatel
#endif
#ifdef RTAX58U_V2
	{"RT-AX58U"      , "4105", "4104",     "",     "",     "RT-AX58U_V2",  "RT-AX58U_V2",          "", ""},
	{"RT-AX3000"     , "4105", "4104",     "",     "",     "RT-AX58U_V2",  "RT-AX58U_V2",          "", ""},
	{"RT-AX58U_V2"   , "4105", "4104",     "",     "",     "RT-AX58U_V2",  "RT-AX58U_V2",          "", ""},
#endif
#ifdef TUFAX3000
	{"TUF-AX3000"    , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
#endif
#ifdef TUFAX3000_V2
	{"TUF-AX3000"    , "4105", "4100",     "",     "",     "TUF-AX3000_V2","TUF-AX3000_V2",        "", ""},
	{"TUF-AX3000_V2" , "4105", "4100",     "",     "",     "TUF-AX3000_V2","TUF-AX3000_V2",        "", ""},
#endif
#ifdef RTAXE7800
	{"RT-AXE7800"    , "4105", "4100",     "",     "",     "RT-AXE7800",   "RT-AXE7800",           "", ""},
#endif
#ifdef GT10
	{"GT10"          , "4110", "4111",     "",     "",     "GT10",         "GT10",         "GT10",     ""},
#endif
#ifdef RTAX95Q
	{"ZenWiFi_XT8"   , "4105", "4104",     "",     "",     "RT-AX95Q",     "RT-AX95Q",     "RT-AX95Q", ""},
#endif
#ifdef XT8PRO
	{"ZenWiFi_XT9"   , "4105", "4104",     "",     "",       "XT8PRO",       "XT8PRO",       "XT8PRO", ""},
#endif
#ifdef XT8_V2
	{"ZenWiFi_XT8"   , "4105", "4104",     "",     "",       "XT8_V2",       "XT8_V2",       "XT8_V2", ""},
#endif
#ifdef RTAXE95Q
	{"ZenWiFi_ET8"   , "4105", "4104",     "",     "",    "RT-AXE95Q",    "RT-AXE95Q",    "RT-AXE95Q", ""},
#endif
#ifdef ET8PRO
	{"ZenWiFi_ET8P"  , "4105", "4104",     "",     "",       "ET8PRO",       "ET8PRO",       "ET8PRO", ""},
#endif
#ifdef RTAX56U
	{"RT-AX56U"      , "4105", "4104",     "",     "",     "RT-AX56U",     "RT-AX56U",             "", ""},
#endif
#ifdef RTAX55
	{"RT-AX55"       , "4105", "4100",     "",     "",     "RT-AX55",      "RT-AX55",              "", ""},
	{"RT-AX1800"     , "4105", "4100",     "",     "",     "RT-AX55",      "RT-AX55",              "", ""}, // Chinatel
	{"RT-AX56U_V2"   , "4105", "4100",     "",     "",     "RT-AX55",      "RT-AX55",              "", ""}, // CN only
	{"RT-AX1800_Plus", "4105", "4100",     "",     "",     "RT-AX55",      "RT-AX55",              "", ""},
#endif
#ifdef RTAX1800
	{"RT-AX1800"     , "4105", "4100",     "",     "",     "RT-AX1800",    "RT-AX1800",            "", ""},
#endif
#ifdef RTAX3000N
	{"RT-AX3000N"    , "4105", "4100",     "",     "",     "RT-AX3000N",   "RT-AX3000N",           "", ""},
	{"RT-AX55_V2"    , "4105", "4100",     "",     "",     "RT-AX3000N",   "RT-AX3000N",           "", ""},
	{"RT-AX58"       , "4105", "4100",     "",     "",     "RT-AX3000N",   "RT-AX3000N",           "", ""},
#endif
#ifdef RTAX56_XD4
	{"ZenWiFi_XD4"   , "4105", "4104",     "",     "",  "RT-AX56_XD4",  "RT-AX56_XD4",             "", ""},
#endif
#ifdef XD4S
	{"ZenWiFi_XD4S"     , "4111", "4104",     "",     "",             "", "", "", ""},
	{"ZenWiFi_XD4_Plus" , "4111", "4104",     "",     "",             "", "", "", ""},
#endif
#ifdef XD4PRO
	{"ZenWiFi_XD4_Pro", "4105", "4104",     "",     "",       "XD4PRO",       "XD4PRO",             "", ""},
	{"ZenWiFi_XD5"    , "4105", "4104",     "",     "",       "XD4PRO",       "XD4PRO",             "", ""},
#endif
#ifdef RTAC68U_V4
	{"RT-AC68"       , "4119", "4118", "4110", "4111",  "RT-AC68U_V4",  "RT-AC68U_V4",             "", ""},
	{"RT-AC68U_V4"   , "4119", "4118", "4110", "4111",  "RT-AC68U_V4",  "RT-AC68U_V4",             "", ""},
#endif
#ifdef RTAX68U
	{"RT-AX68U"      , "4119", "4118",     "",     "",     "RT-AX68U",     "RT-AX68U",             "", ""},
#endif
#ifdef RTAX86U
	{"RT-AX86U"      , "4127", "4098", "4111",     "",     "RT-AX86U",     "RT-AX86U",             "", ""},
	{"RT-AX5700"     , "4127", "4098", "4111",     "",     "RT-AX86U",     "RT-AX86U",             "", ""},
	{"RT-AX86S"      , "4119", "4118", "4110",     "",     "RT-AX86U",     "RT-AX86U",             "", ""},
#endif
#ifdef RTAX82U
	{"RT-AX82U"      , "4096", "4097", "4106",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
#endif
#ifdef RTAX82U_V2
	{"RT-AX82U"      , "4096", "4097", "4106",     "",     "RT-AX82U_V2",  "RT-AX82U_V2"           "", ""},
	{"RT-AX82U_V2"   , "4096", "4097", "4106",     "",     "RT-AX82U_V2",  "RT-AX82U_V2",          "", ""},
#endif
#ifdef RTAX82_XD6
	{"ZenWiFi_XD6"   , "4096", "4097",     "",     "",  "RT-AX82_XD6",  "RT-AX82_XD6",             "", ""},
	{"ZenWiFi_XD6E"   , "4096", "4097",     "",     "",  "RT-AX82_XD6",  "RT-AX82_XD6",             "", ""},
#endif
#ifdef RTAX82_XD6S
	{"ZenWiFi_XD6"   , "4100", "4101",     "",     "", "RT-AX82_XD6S", "RT-AX82_XD6S",             "", ""},
	{"ZenWiFi_XD6S"  , "4100", "4101",     "",     "", "RT-AX82_XD6S", "RT-AX82_XD6S",             "", ""},
	{"ZenWiFi_XD6E"  , "4100", "4101",     "",     "", "RT-AX82_XD6S", "RT-AX82_XD6S",             "", ""},
#endif
#ifdef DSL_AX82U
	{"DSL-AX82U"     , "4096", "4097",     "",     "",    "DSL-AX82U",    "DSL-AX82U",             "", ""},
	{"DSL-AX5400"    , "4096", "4097",     "",     "",    "DSL-AX82U",    "DSL-AX82U",             "", ""},
#endif
#ifdef RPAX56
	{"RP-AX56"       , "4105", "4100",     "",     "",      "RP-AX56",             "",             "", ""},
#endif
#ifdef RPAX58
	{"RP-AX58"       , "4105", "4100",     "",     "",      "RP-AX58",             "",             "", ""},
#endif
#ifdef GTAXE11000
	{"GT-AXE11000"   , "4100", "4125",     "", "4123",  "GT-AXE11000",  "GT-AXE11000",  "GT-AXE11000", ""},
#endif
#ifdef PLAX56_XP4
	{"ZenWiFi_XP4"   , "4130", "4105",     "",     "",  "PL-AX56_XP4",  "PL-AX56_XP4",             "", ""},
#endif
#ifdef ETJ
	{"ETJ"           , "4119", "4134",     "",     "",          "ETJ",          "ETJ",             "", ""},
#endif
#ifdef RTAX57Q
	{"RT-AX57Q"      , "4118", "4134",     "",     "",     "RT-AX57Q",     "RT-AX57Q",             "", ""},
#endif
#ifdef GSAX3000
	{"GS-AX3000"     , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
#endif
#ifdef GSAX5400
	{"GS-AX5400"     , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
#endif
#ifdef TUFAX5400
	{"TUF-AX5400"    , "4096", "4117",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
#endif
#ifdef CTAX56_XD4
	{"CT-MESH1"      , "4105", "4104",     "",     "",  "CT-AX56_XD4",  "CT-AX56_XD4",             "", ""},
#endif
#ifdef GTAX6000
	{"GT-AX6000"     , "4109", "4108", "4106",     "",    "GT-AX6000",    "GT-AX6000",             "", ""},
#endif
#ifdef GTAX11000_PRO
	{"GT-AX11000_Pro", "4109", "4106",     "", "255", "GT-AX11000 PRO", "GT-AX11000 PRO", "GT-AX11000 PRO", ""},
#endif
#ifdef GTAXE16000
	{"GT-AXE16000"   , "4109", "4106",     "",  "255", "GT-AXE16000", "GT-AXE16000", "GT-AXE16000", ""},
#endif
#ifdef ET12
	{"ET12"            , "4115", "4111",     "",     "",         "ET12",       "ET12",        "ET12", ""},
	{"ZenWiFi_Pro_ET12", "4115", "4111",     "",     "",         "ET12",       "ET12",        "ET12", ""},
#endif
#ifdef XT12
	{"XT12"            , "4115", "4111",     "",     "",         "XT12",       "XT12",        "XT12", ""},
	{"ZenWiFi_Pro_XT12", "4115", "4111",     "",     "",         "XT12",       "XT12",        "XT12", ""},
#endif
#ifdef RTAX86U_PRO
	{"RT-AX86U_Pro"  , "4109", "4108", "4106",     "", "RT-AX86U PRO", "RT-AX86U PRO",             "", ""},
#endif
#ifdef TUFAX4200
	{"TUF-AX4200"      , "4105", "4106",     "",     "",      "TAX4200",           "",            "", ""},
	{"TUF-AX4200Q"     , "4105", "4106",     "",     "",      "TAX4200",           "",            "", ""},
#endif
#ifdef TUFAX6000
	{"TUF-AX6000"      , "4105", "4106",     "",     "",      "TUFAX6K",           "",            "", ""},
#endif
#ifdef RTAX59U
	{"RT-AX59U"        , "4105", "4106",     "",     "",      "MTAX59",            "",            "", ""},
#endif

	// TODO : add AiMesh model here ...

	// The End
	{0,0,0,0,0,0,0,0,0}
};

char *gen_rand_value(char *input)
{
	static char ret[64];
	memset(ret, 0, sizeof(ret));

	while (1)
	{
		srand(time(NULL));
		snprintf(ret, sizeof(ret), "%d", rand());
		if (strcmp(ret, input)) break;
	}

	return ret;
}

#if defined(RTCONFIG_QCA)
static void get_val_bymodel_QCA(char *val, int len)
{
	char buf[128];
	memset(buf, 0, sizeof(buf));

	snprintf(buf, sizeof(buf), "/proc/athversion");
	if (f_read_string(buf, val, len) <= 0)
		memset(val, 0, len);
}
#endif

static void get_val_bymodel_BCM(char *ifname, char *val, int len)
{
	char buf[128];
	memset(buf, 0, sizeof(buf));

	MyDBG("ifname=%s\n", ifname);
	snprintf(buf, sizeof(buf), "wl -i %s clm_data_ver > %s", ifname, HW_AUTH_CLM);
	system(buf);
	snprintf(buf, sizeof(buf), "%s", HW_AUTH_CLM);
	if (f_read_string(buf, val, len) <= 0)
		memset(val, 0, len);
}

char *hw_component_clm_2g(int model)
{
	static char val[32];
	int len;

	memset(val, 0, sizeof(val));
	len = sizeof(val);

	switch(model) {
#if defined(RTCONFIG_QCA)
#if defined(RTCONFIG_SOC_IPQ8064) || defined(RTCONFIG_SOC_IPQ8074) || defined(RTCONFIG_SOC_IPQ60XX) || defined(RTCONFIG_SOC_IPQ50XX)
		case MODEL_PLAX56XP4:
		case MODEL_BRTAC828:
		case MODEL_GTAXY16000:
		case MODEL_RTAX89U:
		case MODEL_ETJ:
		case MODEL_RTAX57Q:
			get_val_bymodel_QCA(val, len);
			break;
#endif
#if defined(RTCONFIG_SOC_IPQ40XX)
		case MODEL_MAPAC1300:
		case MODEL_MAPAC2200:
		case MODEL_RTAC82U:
		case MODEL_RT4GAC53U:
		case MODEL_RT4GAC56:
		case MODEL_RTAC95U:
			get_val_bymodel_QCA(val, len);
			break;
#endif
#endif
#if defined(RTCONFIG_RALINK)
		case MODEL_RTAC85U:
		case MODEL_RTAC85P:
		case MODEL_RTACRH26:
		case MODEL_XD4S:
		case MODEL_TUFAX4200:
		case MODEL_TUFAX6000:
		case MODEL_RTAX59U:
			if (get_mtk_wifi_driver_version(val, sizeof(val)) == -1) {
				memset(val, 0, sizeof(val));
			}
			break;
#endif
#if defined(HND_ROUTER)
		case MODEL_GTAC5300:
			get_val_bymodel_BCM("eth6", val, len);
			break;
		case MODEL_RTAC86U:
			get_val_bymodel_BCM("eth5", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX)
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_GTAXE11000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAX6000:
		case MODEL_RTAX86U_PRO:
			get_val_bymodel_BCM("eth6", val, len);
			break;
		case MODEL_RTAX92U:
			get_val_bymodel_BCM("eth5", val, len);
			break;
		case MODEL_GTAXE16000:
			get_val_bymodel_BCM("eth7", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756)
		case MODEL_RTAX55:
		case MODEL_RTAX58U_V2:
		case MODEL_RTAX3000N:
		case MODEL_RTAX82_XD6S:
			get_val_bymodel_BCM("eth2", val, len);
			break;
		case MODEL_RTAX58U:
		case MODEL_RTAX82U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAX56U:
		case MODEL_DSLAX82U:
		case MODEL_RTAXE7800:
			get_val_bymodel_BCM("eth5", val, len);
			break;
                case MODEL_RPAX56:
                case MODEL_RPAX58:
                        get_val_bymodel_BCM("eth1", val, len);
                        break;
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_GT10:
			get_val_bymodel_BCM("eth4", val, len);
			break;
		case MODEL_RTAX56_XD4:
		case MODEL_CTAX56_XD4:
		case MODEL_XD4PRO:
			get_val_bymodel_BCM("wl0", val, len);
			break;
		case MODEL_ET12:
		case MODEL_XT12:
			get_val_bymodel_BCM("eth4", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX_6710)
		case MODEL_RTAX86U:
			if(!strcmp(get_productid(), "RT-AX86S"))
				get_val_bymodel_BCM("eth5", val, len);
			else
				get_val_bymodel_BCM("eth6", val, len);
			break;
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
			get_val_bymodel_BCM("eth5", val, len);
			break;
#endif
		default:
			get_val_bymodel_BCM("eth1", val, len);
			break;
	}

	return val;
}

char *hw_component_clm_5g1(int model)
{
	static char val[32];
	int len;

	memset(val, 0, sizeof(val));
	len = sizeof(val);
#if !defined(RTCONFIG_QCA) && !defined(RTCONFIG_RALINK) && !defined(RTCONFIG_LANTIQ)
	switch(model) {
#if defined(HND_ROUTER)
		case MODEL_GTAC5300:
			get_val_bymodel_BCM("eth7", val, len);
			break;
		case MODEL_RTAC86U:
			get_val_bymodel_BCM("eth6", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX)
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_GTAXE11000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAX6000:
		case MODEL_RTAX86U_PRO:
			get_val_bymodel_BCM("eth7", val, len);
			break;
		case MODEL_RTAX92U:
			get_val_bymodel_BCM("eth6", val, len);
			break;
		case MODEL_GTAXE16000:
			get_val_bymodel_BCM("eth8", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756)
		case MODEL_RTAX58U:
		case MODEL_RTAX82U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAX56U:
		case MODEL_DSLAX82U:
		case MODEL_RTAXE7800:
			get_val_bymodel_BCM("eth7", val, len);
			break;
		case MODEL_RPAX56:
                case MODEL_RPAX58:
			get_val_bymodel_BCM("eth2", val, len);
			break;
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_GT10:
			get_val_bymodel_BCM("eth5", val, len);
			break;
		case MODEL_RTAX56_XD4:
		case MODEL_CTAX56_XD4:
		case MODEL_XD4PRO:
			get_val_bymodel_BCM("wl1", val, len);
			break;
		case MODEL_RTAX55:
		case MODEL_RTAX58U_V2:
		case MODEL_RTAX3000N:
		case MODEL_RTAX82_XD6S:
			get_val_bymodel_BCM("eth3", val, len);
			break;
		case MODEL_ET12:
		case MODEL_XT12:
			get_val_bymodel_BCM("eth5", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX_6710)
		case MODEL_RTAX86U:
			if(!strcmp(get_productid(), "RT-AX86S"))
				get_val_bymodel_BCM("eth6", val, len);
			else
				get_val_bymodel_BCM("eth7", val, len);
			break;
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
			get_val_bymodel_BCM("eth6", val, len);
			break;
#endif
		default:
			get_val_bymodel_BCM("eth2", val, len);
			break;
	}
#else
	snprintf(val, len, "0");
#endif
	return val;
}

char *hw_component_clm_5g2(int model)
{
	static char val[32];
	int len;

	memset(val, 0, sizeof(val));
	len = sizeof(val);
#if !defined(RTCONFIG_QCA) && !defined(RTCONFIG_RALINK) && !defined(RTCONFIG_LANTIQ)
	switch(model) {
#if defined(HND_ROUTER)
		case MODEL_GTAC5300:
			get_val_bymodel_BCM("eth8", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX)
		case MODEL_GTAX11000:
		case MODEL_GTAXE11000:
		case MODEL_GTAX11000_PRO:
			get_val_bymodel_BCM("eth8", val, len);
			break;
		case MODEL_RTAX92U:
			get_val_bymodel_BCM("eth7", val, len);
			break;
		case MODEL_GTAXE16000:
			get_val_bymodel_BCM("eth9", val, len);
			break;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756)
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_ET12:
		case MODEL_XT12:
		case MODEL_RTAXE7800:
		case MODEL_GT10:
			get_val_bymodel_BCM("eth6", val, len);
			break;
#endif
		case MODEL_RTAC5300:
			get_val_bymodel_BCM("eth3", val, len);
			break;
		default:
			snprintf(val, len, "0");
			break;
	}
#else
	snprintf(val, len, "0");
#endif
	return val;
}

#define GPIO_LOWACTIVE_BIT 0x0fff

/*
	avoid GPIO changed between LOW and HIGH bit
*/
int GPIO_LOWACTIVE_COMPARE(char *src, char *dst)
{
	return (((atoi(src)&GPIO_LOWACTIVE_BIT) == (atoi(dst)&GPIO_LOWACTIVE_BIT)) ? 1 : 0);
}

char *DoHardwareComponent(char *index)
{
	static char val[32];
	char *productid = get_productid();

	memset(val, 0, sizeof(val));

	if (!strcmp(index, "productid") || !strcmp(index, "odmpid")) {
		if (!strncmp(productid, RTAC68, 7) && strncmp(productid, "RT-AC68U_V4", 11)) {
			strlcpy(val, RTAC68, sizeof(val));
		}
		else {
			strlcpy(val, productid, sizeof(val));
		}
	}
	else if (!strcmp(index, "btn_rst_gpio") || !strcmp(index, "btn_wps_gpio") || !strcmp(index, "btn_led_gpio") || !strcmp(index, "btn_wltog_gpio")) {
		strlcpy(val, nvram_safe_get(index), sizeof(val));
	}
	else if (!strcmp(index, "clm_data_ver_2g")) {
		strlcpy(val, hw_component_clm_2g(get_model()), sizeof(val));
	}
	else if (!strcmp(index, "clm_data_ver_5g1")) {
		strlcpy(val, hw_component_clm_5g1(get_model()), sizeof(val));
	}
	else if (!strcmp(index, "clm_data_ver_5g2")) {
		strlcpy(val, hw_component_clm_5g2(get_model()), sizeof(val));
	}
	else if (!strcmp(index, "hwcode")) {
		// TODO : in the future, we can add hardware code here
	}
	else {
		MyDBG("The component %s is wrong\n", index);
	}

	MyDBG("val = %s\n", val);
	return val;
}

static int DoHardwareCompare(hw_auth_t *p)
{
	int is_2g  = 0;
	int is_5g1 = 0;
	int is_5g2 = 0;
	int is_odmpid = 0;
	int is_rst = 0;
	int is_wps = 0;
	int is_led = 0;
	int is_tog = 0;
	int is_clm = 0;
	int is_hw  = 0;

	is_2g  = !strncmp(p->clm_data_ver_2g,  DoHardwareComponent("clm_data_ver_2g"),  strlen(p->clm_data_ver_2g));

	/*
		if 5g1 and 5g2 are "", we should consider it as fail case, because our logic is "OR", one condition passed means this logic "TRUE"
	*/
	if (!strcmp(p->clm_data_ver_5g1, "")) {
		is_5g1 = 0;
	}
	else {
		is_5g1 = !strncmp(p->clm_data_ver_5g1, DoHardwareComponent("clm_data_ver_5g1"), strlen(p->clm_data_ver_5g1));
	}

	if (!strcmp(p->clm_data_ver_5g2, "")) {
		is_5g2 = 0;
	}
	else {
		is_5g2 = !strncmp(p->clm_data_ver_5g2, DoHardwareComponent("clm_data_ver_5g2"), strlen(p->clm_data_ver_5g2));
	}

	is_odmpid = !strcmp(p->productid, DoHardwareComponent("odmpid"));
	is_rst = GPIO_LOWACTIVE_COMPARE(p->btn_rst_gpio, DoHardwareComponent("btn_rst_gpio"));
	is_wps = GPIO_LOWACTIVE_COMPARE(p->btn_wps_gpio, DoHardwareComponent("btn_wps_gpio"));
	is_led = GPIO_LOWACTIVE_COMPARE(p->btn_led_gpio, DoHardwareComponent("btn_led_gpio"));
	is_tog = GPIO_LOWACTIVE_COMPARE(p->btn_wltog_gpio, DoHardwareComponent("btn_wltog_gpio"));
	is_clm = is_2g | is_5g1 | is_5g2;
	is_hw  = !strcmp(p->hwcode, DoHardwareComponent("hwcode"));

	MyDBG("odmpid=%d, is_rst=%d, is_wps=%d, is_led=%d, is_tog=%d, is_clm=%d(%d/%d/%d), is_hw=%d\n",
		is_odmpid, is_rst, is_wps, is_led, is_tog, is_clm, is_2g, is_5g1, is_5g2, is_hw);
	MyLOG("is_odmpid=%d\nis_rst=%d\nis_wps=%d\nis_led=%d\nis_tog=%d\nis_clm=%d\nis_hw=%d\n",
		is_odmpid, is_rst, is_wps, is_led, is_tog, is_clm, is_hw);

	return (is_odmpid & is_rst & is_wps & is_led & is_tog & is_clm & is_hw);
}

/*
	This API is for ProgControl3, TrendMicro only syncs this table to implement, not need to rebuild library, only update encrypted file depended on our table
*/
int HwCheckResult(char *index)
{
	struct HW_AUTH_T *p = s_hw_auth_tuple;
	char *productid = get_productid();
	int is_success = 0; // flag

	if (!strncmp(productid, RTAC68, 7) && strncmp(productid, "RT-AC68U_V4", 11)) {
		productid = RTAC68;
	}

	for (; p->productid != 0; p++) {
		if (!strcmp(p->productid, productid)) {
			// check each hardware components
			is_success = DoHardwareCompare(p);
			break;
		}
	}

	return is_success;
}

/*
	The blacklist for Netgear OUI list
*/
static uint32_t blacklist1[] = {
	0x00095B << 5,
	0x000FB5 << 5,
	0x00146C << 5,
	0x00184D << 5,
	0x001B2F << 5,
	0x001E2A << 5,
	0x001F33 << 5,
	0x00223F << 5,
	0x0024B2 << 5,
	0x0026F2 << 5,
	0x008EF2 << 5,
	0x04A151 << 5,
	0x100D7F << 5,
	0x10DA43 << 5,
	0x1459C0 << 5,
	0x200CC8 << 5,
	0x204E7F << 5,
	0x20E52A << 5,
	0x28C68E << 5,
	0x2C3033 << 5,
	0x2CB05D << 5,
	0x30469A << 5,
	0x3C3786 << 5,
	0x405D82 << 5,
	0x4494FC << 5,
	0x4C60DE << 5,
	0x506A03 << 5,
	0x68FD3A << 5,
	0x744401 << 5,
	0x78D294 << 5,
	0x803773 << 5,
	0x841B5E << 5,
	0x8C3BAD << 5,
	0x9C3DCF << 5,
	0x9CD36D << 5,
	0xA00460 << 5,
	0xA021B7 << 5,
	0xA040A0 << 5,
	0xA06391 << 5,
	0xA42B8C << 5,
	0xB03956 << 5,
	0xB07FB9 << 5,
	0xB0B98A << 5,
	0xC03F0E << 5,
	0xC0FFD4 << 5,
	0xC40415 << 5,
	0xC43DC7 << 5,
	0xCC40D0 << 5,
	0xDCEF09 << 5,
	0xE0469A << 5,
	0xE091F5 << 5,
	0xE4F4C7 << 5,
	0xE8FCAF << 5,
	0xE87394 << 5,
	0
};

/*
	For loop comparing the OUI mac in blacklist and MAC
*/
static int loop_checklist(unsigned char *ea)
{
	int ret = 0;
	int i = 0;
	uint32_t *p = blacklist1;
	uint32_t next = 0;

	for (i = 0; p[i] != 0; i++) {
		next = htonl(p[i] << 3);
		/* Please don't enable debug code here to reduce the possibility to disclose componenet */
		//MyDBG(" p=%x, next=%x\n", p[i], next); // debug only
		if (memcmp(ea, &next, 3) == 0) {
			ret = 1;
			break;
		}
	}

	return ret;
}

/*
	The blacklist to block some brand models, ex. Netgear (R7000)
	shift bit is for make a "bad" OUI that disassembly can't found the keyword to trace
*/
static int blacklist_confirm()
{
	unsigned char ea_lan[6];
	unsigned char ea_wan[6];
	unsigned char ea_wl[6];

	int is_lan = 0;
	int is_wan = 0;
	int is_wl = 0;

	ether_atoe(get_lan_hwaddr(), ea_lan);
	ether_atoe(get_wan_hwaddr(), ea_wan);
	ether_atoe(get_2g_hwaddr(),  ea_wl);

	/* Please don't enable debug code here to reduce the possibility to disclose componenet */
	//MyDBG(" ea_lan=%2x:%2x:%2x:%2x:%2x:%2x\n", ea_lan[0], ea_lan[1], ea_lan[2], ea_lan[3], ea_lan[4], ea_lan[5]); // debug only
	//MyDBG(" ea_wan=%2x:%2x:%2x:%2x:%2x:%2x\n", ea_wan[0], ea_wan[1], ea_wan[2], ea_wan[3], ea_wan[4], ea_wan[5]); // debug only
	//MyDBG(" ea_wl =%2x:%2x:%2x:%2x:%2x:%2x\n", ea_wl[0], ea_wl[1], ea_wl[2], ea_wl[3], ea_wl[4], ea_wl[5]); // debug only
	is_lan = loop_checklist(ea_lan);
	is_wan = loop_checklist(ea_wan);
	is_wl  = loop_checklist(ea_wl);

	MyDBG(" is_lan=%d, is_wan=%d, is_wl=%d\n", is_lan, is_wan, is_wl);

	return (is_lan || is_wan || is_wl);
}

static int TMobile_confirm()
{
	int ret = 0;
	if (f_exists("/jffs/.sys/RT-AC68U/unlock") || nvram_get_int("fw_check")) ret = 1;

	MyDBG("TMobile ret=%d\n", ret);
	return ret;
}

char *DoHardwareCheck(char *app_key)
{
	struct HW_AUTH_T *p = s_hw_auth_tuple;

	static char ret[64];
	int is_success = 0; // flag
	int is_68 = 0;
	char app_id[32];
	char *productid = get_productid();

#if defined(GTAXY16000) || defined(RTAX89U)
	/* Backward compatible to PCB R1.00 ~ R3.50 */
	if (!strlen(nvram_safe_get("HwId")) || nvram_match("HwId", "A")) {
		for (p = s_hw_auth_tuple; p->productid; ++p) {
			if (strcmp(p->productid, "GT-AXY16000") && strcmp(p->productid, "RT-AX89X"))
				continue;
			if (!strcmp(p->btn_rst_gpio, "4154"))
				continue;

			p->btn_rst_gpio = "4154";
			//dbg("%s: Fix %s btn_rst_gpio as %s for PCB R1.00 ~ R3.50\n", __func__, p->productid, p->btn_rst_gpio);
		}

		p = s_hw_auth_tuple;
	}
#endif
#if defined(PLAX56_XP4)
	/* Backward compatible */
	if (nvram_get_int("HwVer") < 1) {
		for (p = s_hw_auth_tuple; p->productid; ++p) {
			if (strcmp(p->productid, "ZenWiFi_XP4"))
				continue;

			p->btn_rst_gpio = "";
		}

		p = s_hw_auth_tuple;
	}
#endif

	memset(ret, 0, sizeof(ret));
	memset(app_id, 0, sizeof(app_id));
	GET_APP_ID(app_id, app_key);

	// If app_id is empty, skip DoHardwareCompare.
	if (strlen(app_id) == 0)
		goto end;

	if (!strncmp(productid, RTAC68, 7) && strncmp(productid, "RT-AC68U_V4", 11)) {
		is_68 = 1;
		productid = RTAC68;
	}

	for (; p->productid != 0; p++) {
		if (!strcmp(p->productid, productid)) {
			// check each hardware components
			is_success = DoHardwareCompare(p);
			break;
		}
	}

end:
	if (is_success != 1) {
		// fail case : get a random code
		strlcpy(ret, gen_rand_value(app_id), sizeof(ret));
	}
	else if (is_success == 1) {
		// success case : get app_id
		strlcpy(ret, app_id, sizeof(ret));
	}

	MyDBG("productid=%s, is_68=%d, is_success=%d, ret=%s\n", productid, is_68, is_success, ret);
	MyLOG("is_success=%d\n", is_success);
	return ret;
}

char *hw_auth_check(char *app_id, char *app_auth_code, time_t timestamp, char *out_buf, int out_buf_size)
{
	char in_buf[128];
	char app_key[64];
	char *hw_check = NULL;
	char *auth_code = NULL;
	char *tmp;
#if defined(RTCONFIG_AMAS) || defined(RTCONFIG_TUNNEL)
	char app_name[32];
	char *odmpid = NULL;
	int is_68 = 0;
#endif
#ifdef RTCONFIG_AMAS
	struct AMAS_WHITELIST_T *whitelist = s_amas_whitelist_tuple;
	int is_amas_support = 0;
#endif
#ifdef RTCONFIG_TUNNEL
	struct TUNNEL_WHITELIST_T *t_whitelist = s_tunnel_whitelist_tuple;
	int is_tunnel_support = 0;
#endif

	// the blacklist to block some brand models, ex. Netgear (R7000)
	if (blacklist_confirm()) goto end;

	// T-Mobile model
	if (TMobile_confirm()) goto end;

	// vaildate (app_id, app_key)
	memset(app_key, 0, sizeof(app_key));
	GET_APP_KEY(app_id, app_key);
	if (strlen(app_key) == 0) goto end;
#ifdef RTCONFIG_AMAS
#ifdef RTCONFIG_WIFI_SON
 	if(!nvram_match("wifison_ready", "1"))
#endif
	{
	// validate AMAS support
	memset(app_name, 0, sizeof(app_name));
	GET_APP_NAME_BY_ID(app_id, app_name);
	odmpid = get_productid();
	if (!strncmp(odmpid, RTAC68, 7) && strncmp(odmpid, "RT-AC68U_V4", 11)) is_68 = 1;
	if (!strcmp(app_name, "AMASH")) {
		for (; whitelist->odmpid != 0; whitelist++) {
			if (is_68) {
				is_amas_support = 1;
				break;
			}
			else {
				if (!strcmp(whitelist->odmpid, odmpid)) {
					is_amas_support = 1;
					break;
				}
			}
		}

		MyDBG("is_amas_support=%d, app_name=%s, odmpid=%s, is_68=%d\n", is_amas_support, app_name, odmpid, is_68);
		if (is_amas_support == 0) goto end;
	}
	}
#endif

#ifdef RTCONFIG_TUNNEL
	// validate TUNNEL support
	memset(app_name, 0, sizeof(app_name));
	GET_APP_NAME_BY_ID(app_id, app_name);
	odmpid = get_productid();
	if (!strncmp(odmpid, RTAC68, 7) && strncmp(odmpid, "RT-AC68U_V4", 11)) is_68 = 1;
	if (!strcmp(app_name, "aaews") || !strcmp(app_name, "mastiff")) {
		for (; t_whitelist->odmpid != 0; t_whitelist++) {
			if (is_68) {
				is_tunnel_support = 1;
				break;
			}
			else {
				if (!strcmp(t_whitelist->odmpid, odmpid)) {
					is_tunnel_support = 1;
					break;
				}
			}
		}

		MyDBG("is_tunnel_support=%d, app_name=%s, odmpid=%s, is_68=%d\n", is_tunnel_support, app_name, odmpid, is_68);
		if (is_tunnel_support == 0) goto end;

		// wait for wl ready
		while (!nvram_get_int(WLREADY))
			sleep(1);
	}
#endif

	// auth_code : ts + app_key
	snprintf(in_buf, sizeof(in_buf), "%ld|%s", timestamp, app_key);
	auth_code = get_auth_code(in_buf, out_buf, out_buf_size);

	// compare app_auth_code with auth_code
	if (strcmp(app_auth_code, auth_code) != 0) goto end;

	// get hw_check (retrun APP_ID)
	hw_check = DoHardwareCheck(app_key);

	// auth_code : ts + app_key + hw_check
	snprintf(in_buf, sizeof(in_buf), "%ld|%s|%s", timestamp, app_key, hw_check);
	auth_code = get_auth_code(in_buf, out_buf, out_buf_size);

	return auth_code;

end:
	// auth_code : ts + app_key + rand code
	if (hw_check == NULL) hw_check = app_id;
	tmp = gen_rand_value(hw_check);
	snprintf(in_buf, sizeof(in_buf), "%ld|%s|%s", timestamp, app_key, tmp);
	auth_code = get_auth_code(in_buf, out_buf, out_buf_size);
	return auth_code;
}

#ifdef RTCONFIG_AMAS
/*
	getAmasSupportMode() : global API for amas usage
	0 : not support AMAS
	1 : support CAP only
	2 : support RE only
	3 : CAP + RE
 */
int getAmasSupportMode()
{
	int ret = 0;
	char *odmpid = NULL;
	struct AMAS_WHITELIST_T *whitelist = s_amas_whitelist_tuple;

	odmpid = get_productid();

	for (; whitelist->odmpid != 0; whitelist++) {
		if (!strncmp(odmpid, RTAC68, 7) && strncmp(odmpid, "RT-AC68U_V4", 11))
		{
			ret = whitelist->mode;
			break;
		}
		else if (!strcmp(whitelist->odmpid, odmpid)) 
		{
			ret = whitelist->mode;
			break;
		}
	}

	MyDBG("odmpid=%s, mode=%d\n", odmpid, ret);
	return ret;
}
#endif

/*
	API to perform sw-hw-auth check
	Arguments:
		*app_id		- APP ID
		*app_key	- APP KEY
	Return Value:
		0 : Failed
		1 : Success
 */
int auth_validate(char *app_id, char *app_key)
{
	// ===================== sw-hw-auth check start =====================
	time_t timestamp = time(NULL);
	char in_buf[128];
	char out_buf[65];
	char hw_out_buf[65];
	char *hw_auth_code = NULL;

	// initial
	memset(in_buf, 0, sizeof(in_buf));
	memset(out_buf, 0, sizeof(out_buf));
	memset(hw_out_buf, 0, sizeof(hw_out_buf));

	// use timestamp + APP_KEY to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s", timestamp, app_key);

	hw_auth_code = hw_auth_check(app_id, get_auth_code(in_buf, out_buf, sizeof(out_buf)), timestamp, hw_out_buf, sizeof(hw_out_buf));

	// use timestamp + APP_KEY + APP_ID to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s|%s", timestamp, app_key, app_id);

	// debug
	//printf("hw_auth_code1=%s\n", hw_auth_code);
	//printf("hw_auth_code2=%s\n", get_auth_code(in_buf, out_buf, sizeof(out_buf)));

	if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
		//printf("This is ASUS Router\n");
		return 1;
	}
	else {
		//printf("This is not ASUS Router\n");
		return 0;
	}
	// ===================== sw-hw-auth check end =====================
}
