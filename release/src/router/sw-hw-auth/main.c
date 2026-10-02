 /*
 * Copyright 2017, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

/* header */
#include "auth_common.h"

int main(int argc, char **argv)
{
	if (argc == 2 && (!strcmp(argv[1], "productid") || !strcmp(argv[1], "odmpid")
		|| !strcmp(argv[1], "btn_rst_gpio") || !strcmp(argv[1], "btn_wps_gpio")
		|| !strcmp(argv[1], "btn_led_gpio") || !strcmp(argv[1], "btn_wltog_gpio")
		|| !strcmp(argv[1], "clm_data_ver_2g") || !strcmp(argv[1], "clm_data_ver_5g1")
		|| !strcmp(argv[1], "clm_data_ver_5g2") || !strcmp(argv[1], "hwcode"))
	) {
		DoHardwareComponent(argv[1]);
	}
	else if (argc == 2 && !strcmp(argv[1], "DoCheck")) {
		DoHardwareCheck("fk309g1sedk0353445g");
	}
	else if (argc == 2 && !strcmp(argv[1], "mastiff")) {
		DoHardwareCheck("jidf0924ij4pdfg54as");
	}
	else if (argc == 2 && !strcmp(argv[1], "wlc_nt")) {
		DoHardwareCheck("afa125g46h4yefse03t");
	}
	else if (argc == 2 && !strcmp(argv[1], "AMASH")) {
		DoHardwareCheck("g2hkhuig238789ajkhc");
	}
#if defined(RTCONFIG_SW_HW_AUTH) && defined(RTCONFIG_AMAS)
	else if (argc == 2 && !strcmp(argv[1], "getAmasMode")) {
		extern int getAmasSupportMode(void);
		printf("ret = %d\n", getAmasSupportMode());
	}
#endif
	else {
		printf("No such Command!\n");
	}

	return 1;
}
