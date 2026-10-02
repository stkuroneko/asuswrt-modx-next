
/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/*Difinition of driver module names */
static const char * xRX220PPAModules[] = { 
	"ppa_api.ko",
	"ppa_api_proc.ko",
	"swa_stack_al.ko",
	"ppa_api_sw_accel_mod.ko"
};
static const char * xRX220VDSLModules[] = {
	"ppa_datapath_xrx200_e5.ko", 
	"ppa_hal_xrx200_e5.ko"
};

static const char * xRX220ADSLModules[] = {
	"ppa_datapath_xrx200_a5.ko", 
	"ppa_hal_xrx200_a5.ko"
};

static const char * xRX220ETHModules[] = {
	"ppa_datapath_xrx200_d5.ko", 
	"ppa_hal_xrx200_d5.ko"
};


static const char eth_sw[MODULE_NAME_SIZE] = "lantiq_ethsw.ko";
static const char eth_phy_status[MODULE_NAME_SIZE] = "eth_phy_status.ko";
