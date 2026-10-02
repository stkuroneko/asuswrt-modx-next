#ifndef __XRX750_CALLBACKS_H
#define __XRX750_CALLBACKS_H
#include "fapi_sys_common.h"
/* Initialize callback hanlders for xRX750 platform */
static SysFapiCB_t fapicb={
	.flag=5,
	.wanSWO = XRX750_wanSWO,
	.moduleLoad = xRX750_module_load,
	.moduleUnLoad = xRX750_module_unload,
    .ProcessorInit = xRX750_Processor_init,
	.ProcessorStat = xRX750_stats_counter,
	.SysInit = xRX750_module_init,
	.SysUnInit = xRX750_module_uninit,
	.ppa_init = PPAInit,
	.ppa_uninit = PPAUnInit,
	.sysSet = SysSet,
	.sysGet = SysGet,
	.ppaAdd = xRX750_PPAIntfAdd,
	.ppaDel = PPAIntfDel,
	.ppaHook = PPAEnHook,
	.getPortId = xRX750_PortIdGet,
	.SetLinkState = SetLinkState,
	.GetLinkState = GetLinkState,
	.VLANCfgSet = xRX750_VLANCfgSet,
	.RMONGet = xRX750_RMONGetPlatform,
	.setPortStatus = SetPortStatus,
	.getPortStatus = xRX750_GetPortStatus,
	.setMaxRate = SetMaxBitRate,
	.getMaxRate = GetMaxBitRate,
	.setDuplexMode = SetDuplexMode,
	.getDuplexMode = GetDuplexMode,
	.EnMirror = EnableMirroring,
	.disMirror = DisableMirroring,
	.SetInterfaceState = GRX750_SetInterface,
	.cfg_SwitchIOCTL = xRX750_cfg_SwitchIOCTL,
};

#endif
