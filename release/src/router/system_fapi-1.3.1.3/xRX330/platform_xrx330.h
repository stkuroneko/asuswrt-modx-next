
/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _PLATFORM_XRX330_H_
#define _PLATFORM_XRX330_H_

/* PPA driver module names */
static const char * xRX330PPAModules[] = { 
	"ppa_api.ko",
	"ppa_api_proc.ko",
	"swa_stack_al.ko",
	"ppa_api_sw_accel_mod.ko",
#ifdef CONFIG_DC_DATAPATH_FRAMEWORK
	"directconnect_datapath.ko"
#endif
};

static const char * xRX330PTMTCModules[] = {
	"ltqmips_vrx318_e1.ko"
};

static const char * xRX330ATMTCModules[] = {
	"ltqmips_vrx318_a1.ko"
};

static const char * xRX330ETHModules[] = {
	"ltqmips_ppe_drv.ko"
};

static const char eth_sw[MODULE_NAME_SIZE] = "lantiq_ethsw.ko";
static const char eth_phy_status[MODULE_NAME_SIZE] = "eth_phy_status.ko";

#endif /* _PLATFORM_XRX330_H_ */
