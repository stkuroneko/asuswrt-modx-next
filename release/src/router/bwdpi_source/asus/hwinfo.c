/*
	hwinfo for ProgControl3
	v3.001 : 2019/07/17

	NOTE:
	1. new machanism for control ProgControl table / dpi_support table / hw-auth table
	2. new command : odmpid / hw_check_result

	Old command won't modify and maintain it anymore, all models will change into new mechanism in the future.
	Why old codes not to remove? it's because we can't update whole modules for all models at one time, so we will update tdts module with ProgControl3 by platform (src-xxxx).
*/

// header not to combine with bwdpi.h for prebuilt testing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <shared.h>

static int hwinfo_clm_data_ver()
{
	// BRCM                                   : 0
	// BRT-AC828                              : 1
	// RT-AC85U / RT-AC85P series / RT-AC65U  : 2
	// GT-AC5300 / RT-AC86U                   : 3
	// MAP-AC1300 / MAP-AC2200 / MAP-AC2200V  : 4
	// GT-AC9600                              : 5
	// BlueCave                               : 6
	// MAP-AC1750                             : 7
	// RT-AX88U / RT-AX92U / GT-AX11000       : 8
	// GT-AXY16000 /RT-AX89U                  : 9

	switch (get_model()) {
#if defined(RTCONFIG_SOC_IPQ8064)
		case MODEL_BRTAC828:
			return 1;
#endif
#if defined(RTCONFIG_RALINK)
		case MODEL_RTAC85U:
		case MODEL_RTAC85P:
		case MODEL_RTACRH26:
			return 2;
#endif
#if defined(HND_ROUTER)
		case MODEL_GTAC5300:
		case MODEL_RTAC86U:
			return 3;
#endif
#if defined(RTCONFIG_SOC_IPQ40XX)
		case MODEL_MAPAC1300:
		case MODEL_MAPAC2200:
		case MODEL_MAPAC2200V:
		case MODEL_RTAC95U:
			return 4;
#endif
#if defined(RTCONFIG_ALPINE)
		case MODEL_GTAC9600:
			return 5;
#endif
#if defined(RTCONFIG_LANTIQ)
		case MODEL_BLUECAVE:
			return 6;
#endif
#if defined(RTCONFIG_QCA956X)
		case MODEL_MAPAC1750:
			return 7;
#endif
#if defined(RTCONFIG_HND_ROUTER_AX)
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
			return 8;
#endif
#if defined(RTCONFIG_SOC_IPQ8074)
		case MODEL_GTAXY16000:
		case MODEL_RTAX89U:
			return 9;
#endif
		default:
			return 0;
	}
}

/*
	note : venidXg must use "16 digits (HEX)" for TrendMicro, it's their logic for judgement
*/
static char *hwinfo_venid5g()
{
	switch (get_model()) {
#if defined(RTCONFIG_SOC_IPQ8064)
		case MODEL_BRTAC828:
			return "0x8064\n";
#endif
#if defined(RTCONFIG_SOC_IPQ40XX)
		case MODEL_MAPAC1300:
		case MODEL_MAPAC2200:
		case MODEL_MAPAC2200V:
		case MODEL_RTAC95U:
			return "0x8064\n";
#endif
#if defined(RTCONFIG_RALINK)
		case MODEL_RTAC85U:
		case MODEL_RTAC85P:
		case MODEL_RTACRH26:
			return "0x14C3\n";
#endif
#if defined(RTCONFIG_ALPINE)
		case MODEL_GTAC9600:
			return "0x9600\n";
#endif
#if defined(RTCONFIG_LANTIQ)
		case MODEL_BLUECAVE:
			return "0x0350\n";
#endif
#if defined(RTCONFIG_QCA956X)
		case MODEL_MAPAC1750:
			return "0x9563\n";
#endif
#if defined(RTCONFIG_SOC_IPQ8074)
		case MODEL_GTAXY16000:
		case MODEL_RTAX89U:
			return "0x8074\n";
#endif
		case MODEL_RTAC87U:
		case MODEL_RTN12D1:
		case MODEL_RTN12HP:
		case MODEL_RTN18U:
			return "\n";
		default:
			return "0x14E4\n";
	}
}

static char *hwinfo_venid2g()
{
	switch (get_model()) {
#if defined(RTCONFIG_SOC_IPQ8064)
		case MODEL_BRTAC828:
			return "0x8064\n";
#endif
#if defined(RTCONFIG_SOC_IPQ40XX)
		case MODEL_MAPAC1300:
		case MODEL_MAPAC2200:
		case MODEL_MAPAC2200V:
		case MODEL_RTAC95U:
			return "0x8064\n";
#endif
#if defined(RTCONFIG_RALINK)
		case MODEL_RTAC85U:
		case MODEL_RTAC85P:
		case MODEL_RTACRH26:
			return "0x14C3\n";
#endif
#if defined(RTCONFIG_ALPINE)
		case MODEL_GTAC9600:
			return "0x9600\n";
#endif
#if defined(RTCONFIG_LANTIQ)
		case MODEL_BLUECAVE:
			return "0x0350\n";
#endif
#if defined(RTCONFIG_QCA956X)
		case MODEL_MAPAC1750:
			return "0x9563\n";
#endif
#if defined(RTCONFIG_SOC_IPQ8074)
		case MODEL_GTAXY16000:
		case MODEL_RTAX89U:
			return "0x8074\n";
#endif
		default:
			return "0x14E4\n";
	}
}

int main(int argc, char **argv)
{
	/*
		hwinfo_clm_data_ver / hwinfo_venid5g / hwinfo_venid2g no need to update in the future, it's old mechanism.
		ProgControl3 : won't use above components, it only uses odmpid and hw_check_result (hw-auth table).
	*/

	/* ProgControl2 : productid / btn_xxx_gpio / venid_xg / clm_data_ver */
	if (argc == 2 && !strcmp(argv[1], "productid"))
	{
		system("nvram get productid");
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_rst_gpio"))
	{
		system("nvram get btn_rst_gpio");
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_wps_gpio"))
	{
		system("nvram get btn_wps_gpio");
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_led_gpio"))
	{
		system("nvram get btn_led_gpio");
	}
	else if (argc == 2 && !strcmp(argv[1], "btn_wltog_gpio"))
	{
		system("nvram get btn_wltog_gpio");
	}
	else if (argc == 2 && !strcmp(argv[1], "venid2g"))
	{
		printf("%s", hwinfo_venid2g());
	}
	else if (argc == 2 && !strcmp(argv[1], "venid5g"))
	{
		printf("%s", hwinfo_venid5g());
	}
	else if (argc == 2 && !strcmp(argv[1], "clm_data_ver"))
	{
	// BRCM                                   : 0
	// BRT-AC828                              : 1
	// RT-AC85U / RT-AC85P series / RT-AC65U  : 2
	// GT-AC5300 / RT-AC86U                   : 3
	// MAP-AC1300 / MAP-AC2200 / MAP-AC2200V  : 4
	// GT-AC9600                              : 5
	// BlueCave                               : 6
	// MAP-AC1750                             : 7
	// RT-AX88U / RT-AX92U / GT-AX11000       : 8
	// GT-AXY16000 / RT-AX89U                 : 9

		if (hwinfo_clm_data_ver() == 0)
		{
			system("wl clm_data_ver");
		}
#if defined(RTCONFIG_SOC_IPQ8064)
		else if (hwinfo_clm_data_ver() == 1)
		{
			char cmd[256];
			char path[128];
			snprintf(path, sizeof(path), "/proc/athversion");
			if (f_read_string(path, cmd, sizeof(cmd)) > 0)
				printf("%s", cmd);
		}
#endif
#if defined(RTCONFIG_RALINK)
		else if (hwinfo_clm_data_ver() == 2)
		{
			char cmd[256];
			if (get_mtk_wifi_driver_version(cmd, sizeof(cmd)))
				printf("%s\n", cmd);
		}
#endif
#if defined(HND_ROUTER)
		if (hwinfo_clm_data_ver() == 3)
		{
			system("wl -i eth6 clm_data_ver");
		}
#endif
#if defined(RTCONFIG_SOC_IPQ40XX)
		else if (hwinfo_clm_data_ver() == 4)
		{
			char cmd[256];
			char path[128];
			snprintf(path, sizeof(path), "/proc/athversion");
			if (f_read_string(path, cmd, sizeof(cmd)) > 0)
				printf("%s", cmd);
		}
#endif
#if defined(RTCONFIG_ALPINE)
		else if (hwinfo_clm_data_ver() == 5)
		{
			// TODO
			printf("GT-AC9600\n");
		}
#endif
#if defined(RTCONFIG_LANTIQ)
		else if (hwinfo_clm_data_ver() == 6)
		{
			// TODO
			printf("BLUECAVE\n");
		}
#endif
#if defined(RTCONFIG_QCA956X)
		else if (hwinfo_clm_data_ver() == 7)
		{
			// TODO
			printf("MAP-AC1750\n");
		}
#endif
#if defined(RTCONFIG_HND_ROUTER_AX)
		else if (hwinfo_clm_data_ver() == 8)
		{
			system("wl -i eth6 clm_data_ver");
		}
#endif
#if defined(RTCONFIG_SOC_IPQ8074)
		else if (hwinfo_clm_data_ver() == 9)
		{
			char cmd[256];
			char path[128];
			snprintf(path, sizeof(path), "/proc/athversion");
			if (f_read_string(path, cmd, sizeof(cmd)) > 0)
				printf("%s", cmd);
		}
#endif
	}
	/* ProgControl3 : odmpid and hw_check_result */
#ifdef RTCONFIG_SW_HW_AUTH
	else if (argc == 2 && !strcmp(argv[1], "odmpid"))
	{
		printf("%s\n", DoHardwareComponent("odmpid"));
	}
	else if (argc == 2 && !strcmp(argv[1], "hw_check_result"))
	{
		printf("%d\n", HwCheckResult());
	}
#endif
	else
		return 0;

	return 1;
}
