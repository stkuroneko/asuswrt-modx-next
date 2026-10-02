
/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* switch ioctl macros */
/*! \def SWITCH_DEV_OPEN
    \brief  opens /dev/switch_api_0 or /dev/switch_api_1 based on file descriptor
    \passed to the macro.
    \returns UGW_FAILURE if switch_device is not opnened
    \returns UGW_SUCCESS if switch_device is opened
 */

#define SWITCH_DEV_OPEN(node, switch_fd, retval) {\
		char switch_dev[50];\
		sprintf(switch_dev, "/dev/switch_api/%d", node); \
		if ((switch_fd = open(switch_dev, O_RDONLY)) == -1) { \
			LOGF_LOG_ERROR("Unable to open switch dev : %s \n", switch_dev); \
			retval = ERR_BAD_FD; \
		 }\
	}
/*! \def SWITCH_DEV_IOCTL
    \brief  calls the switch_ioctl passed by user through linux ioctl command
    \returns UGW_FAILURE if ioctl call returns a FAILURE
    \returns UGW_SUCCESS if ioctl call is Success
 */
#define SWITCH_DEV_IOCTL(switch_fd, ioctl_cmd, params, retval) {\
		retval = ioctl(switch_fd, ioctl_cmd, params);\
		if (retval != UGW_SUCCESS) {\
			LOGF_LOG_ERROR("IOCTL failed for command 0x%08X, returned %d\n", ioctl_cmd, retval);\
			close(switch_fd);\
			switch_fd = -1;\
			retval = ERR_IOCTL_FAILED;\
		}\
	}





/*fapi_switch_funcs*/
int32_t delete_vlan_grp(int32_t vid_grp);
int32_t lan_wan_dma_sep(DMA_SEPERATION_STATUS);
int32_t init_switch_global_buff(void);
int32_t get_switch_PortCfg(lan_port_cfg_t *switchport_cfg);
/*#if !defined(CONFIG_LTQ_TARGET_GRX500) && !defined(CONFIG_TARGET_PUMA)
int32_t get_lan_vid(IFX_ETHSW_VLAN_portCfg_t *vlan_portCfg, int32_t port);
#endif
int32_t load_common_modules(int32_t platform);
int32_t remove_common_modules(int32_t platform);
int32_t load_wan_modules(sys_cfg_t *sys_cfg, int32_t platform); 		
int32_t remove_wan_modules(int32_t platform); 		
int32_t check_loaded_modules(const char *module_to_find);
*/
