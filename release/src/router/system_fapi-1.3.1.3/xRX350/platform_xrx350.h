
/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/*Difinition of driver module names */
//static const char * xRX750WanModules[][1] = {
//    {"adp.ko"},{"devname=adp0"}
//};
static const char * xRX350WanModules[] = {
	"ltq_eth_drv_xrx500",
	"ltq_pae_hal",
	"ltq_tmu_hal_drv", 
	"ltq_mpe_hal_drv",
	"ltq_directpath_datapath",
#ifdef CONFIG_PACKAGE_l2tpv3tun
	"l2tp_eth",
	"l2tp_ip",
#endif
	NULL
};
static const char * xRX350WanOptionalModules[] = {
#ifdef CONFIG_DC_DATAPATH_FRAMEWORK
	"directconnect_datapath",
	"dc_mode0-xrx500"
#else
	"ltq_directconnect_datapath"
#endif
};
static const char * xRX350DSLModules[] = { 
#ifdef CONFIG_VRX518_SUPPORT
	"vrx518_tc"
#else
	"vrx318_tc"
#endif
};
static const char * xRX350PPAModules[] = { 
	"ppa_api",
	"ppa_api_proc",
	"swa_stack_al",
	"ppa_api_sw_accel_mod",
	"ltqmips_dtlk",
	"dlrx_fw"
};
static const char * xRX350SplModules[] = {
	"ppa_api_tmplbuf"
};
static const char * xRX350NetworkModules[] = {
#ifdef CONFIG_L2NAT_SUPPORT
	"l2nat",
#endif
};
