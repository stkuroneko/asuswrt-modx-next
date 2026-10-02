
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
#include "fapi_led.h"

#define ALL_INIT_DONE_SCRIPT "/opt/lantiq/etc/allinit_done.sh"

static const char * xRX750PTMTCModules[] = {
	"lantiq_vrx320_e1.ko"
};

static const char * xRX750ATMTCModules[] = {
	"lantiq_vrx320_a1.ko"
};

/* pre init modules */
static const char * pumaPreInitModules[][2] = {
	{"pdsp_drv.ko", ""},
	{"pp_drv.ko", ""},
	{"hil_drv.ko", ""},
	{NULL, NULL}
};

/* post init modules */
static const char * pumaPostInitModules[][2] = {
	{"wifi_proxy_drv.ko", ""},
	{"cppp.ko", "fwbypass=0 fwbufnum=16384 fwbuflen=2048 ucmapcfg=3"},
	{"ppa_puma_hal.ko", ""},
	{"puma_directpath_al.ko", ""},
	{"puma7_pp_init.ko", ""},
	{"ablk_helper.ko", ""},
	{"aesni-intel.ko", ""},
	{"DWC_ETH_QOS_GBE.ko", "sgmii0_2500=0 pcs0_AN=1 sgmii1_2500=1 pcs1_AN=0"},
	{"DWC_ETH_QOS.ko", "tso_enable=1"},
	{"drv_switch_api.ko", ""},
#ifdef CONFIG_PACKAGE_l2tpv3tun 
	{"l2tp_eth.ko", ""},
	{"l2tp_ip.ko", ""},
#endif
#ifdef CONFIG_VRX320_SUPPORT
	{"lantiq_vrx320_common.ko", ""},
#endif
#ifdef CONFIG_VRX320_PTM_VECTORING_SUPPORT
	{"lantiq_vrx320_vectoring.ko", ""},
#endif
#ifdef CONFIG_LTQ_PPA_API_SW_FASTPATH
	{"ppa_api_sw_accel_mod",""},
#endif
#ifdef ENABLE_LAN_PORT_LINK_EVENT
	{"eth_phy_status.ko",""},
#endif
#ifdef CONFIG_INTEL_TRAFFIC_OFFLOAD_ENGINE
	{"toe_drv.ko", ""},
#endif
#ifdef CONFIG_IPSEC_SUPPORT
	{"pp_crypto_drv.ko",""},
#endif
	{NULL, NULL}
};

/*! \def PPA_MIN_HITS
    \brief Minimum number of packets learnt before getting accelerated
 */
#define PPA_MIN_HITS 10
#define MAX_INTERFACES 6
struct InterfaceData {
	uint32_t interfaceId;
	const char* interfaceName;
	const char* vpidName;
	unsigned long long rxCounter;
	unsigned long long txCounter;
	int (*GetCounters)(struct InterfaceData *ifData);
};

struct InterfaceData* xRX750_GetInterfaceStructPtr (uint32_t interfaceId);
int32_t xRX750_ReadVpidFile(struct InterfaceData *ifData);
int32_t xRX750_ReadNetDevFile(struct InterfaceData *ifData);
int32_t xRX750_VpidAndStackBoth(struct InterfaceData *ifData);
static int xRX750_cgiGetCoremark(struct InterfaceData *ifData);
int HVP_SetInterface(IN InterfaceType interface, IN State setState);
int HVP_SetBootingUP(void);
int HVP_SetWIFIUP(void);
int HVP_SetWIFIDOWN(void);
int HVP_ConfigureLED(void);
