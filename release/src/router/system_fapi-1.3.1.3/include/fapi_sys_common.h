/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/*! \file fapi_sys_common.h
    \brief This file contains all the API definitions, enumerations,  
    \structure definitions and macros used in ethernet SL and fapi
*/

/** \addtogroup FAPI_SYSTEM System Service
*/
/* @{ */

#ifndef __FAPI_SYS_COMMON_H
#define __FAPI_SYS_COMMON_H

#include <stdbool.h>
#include <scapi_defs.h>
#include <ugw_error.h>
#ifndef BUILD_FROM_PPA_ADAPT
#define BUILD_FROM_PPA_ADAPT
#undef CONFIG_IFX_PMCU
#include <net/ppa_api.h>
#endif
#ifdef CONFIG_LANTIQ_SWITCH
#include "ltq_switch_api/lantiq_gsw.h"
#include "ltq_switch_api/lantiq_gsw_api.h"
#endif
#include "fapi_processorstat.h"
#include "fapi_led.h"

/*!
    \Interface
    \brief Enums for all the supported Interfaces.
*/

#define FILE_NAME "/tmp/interfaces.txt"
#define FAPI_IF_MAX_FILENAME_LEN 256

int32_t Interface_setState(IN InterfaceType,IN State,IN void *);
int32_t fapi_setIfData(IN const char * pcFileName,IN const char * pcInterface,IN State eState);
char * fapi_getIfData(IN const char * pcFileName,IN char *pcInterface);
/* MACROS */

/*! \def PPA_DEVICE 
    \brief  definition of PPA device
 */
#define PPA_DEVICE      "/dev/ifx_ppa"

/*! \def SWITCH_DEVICE_ID          
    \brief  switch device id used for GSWIP_L
 */
#define SWITCH_DEVICE_ID 0

/*! \def SWITCH_DEVICE_ID_1
    \brief  switch device id used for GSWIP_R
 */
#define SWITCH_DEVICE_ID_1 1

/*! \def MAC_ADDRESS_LENGTH 
    \brief  definifition of mac address length
 */
#define MAC_ADDRESS_LENGTH 6

/*! \def IF_NAME_LEN
    \brief  Maximum size definition for Interface Name
 */
#define IF_NAME_LEN 10

/*! \def MAX_DATA_LEN
    \brief  Maximum size definition for holding commdand string
 */
#define MAX_DATA_LEN 2000

/*! \def MAX_NAME_LEN
    \brief  Maximum size definition for holding device name string
 */
#define MAX_NAME_LEN 64

/*! \def MODULE_NAME_SIZE
    \brief  Maximum size definition for holding driver module name
 */
#define MODULE_NAME_SIZE 50

/*! \def MAX_FBUF_SIZE
    \brief  Maximum size definition for file buf length
 */
#define MAX_FBUF_SIZE 256

/*! \def MAX_MODBUF_SIZE
    \brief  Maximum size definition for module buf length
 */
#define MAX_MODBUF_SIZE 1000

/*! \def MAX_SYSBUF_SIZE
    \brief  Maximum size definition for Sytemcfg buf length
 */
#define MAX_SYSBUF_SIZE 100

/*! \def MAX_MACBUF_SIZE
    \brief  Maximum size definition for MAC buf length
 */
#define MAX_MACBUF_SIZE 18

/*! \def MAC_STRING_LEN
    \brief  Maximum size definition for MAC buf length
 */
#define MAC_STRING_LEN 17

/*! \def DEFAULT_MTU_SIZE
    \brief  MTU size used to configure during PPA INIT
 */
#define DEFAULT_MTU_SIZE 1500

/*! \def MIB_BYTE_MODE
    \brief MIB MODE defined as Byte mode
 */
#define MIB_BYTE_MODE 0

/*! \def MIB_PACKET_MODE
    \brief MIB mode defined as packet mode
 */
#define MIB_PACKET_MODE 1

/*! \def PPA_MIN_HITS
    \brief Minimum number of packets learnt before getting accelerated
 */
#define PPA_MIN_HITS 10

/*! \def MAX_IFACE_SIZE
    \brief Max interface name size
 */
#define MAX_IFACE_SIZE 16

/*! \def DEVICE_STATUS_SIZE 
    \brief Max Device status
 */
#define DEVICE_STATUS_SIZE 10

/*! \def MIRROR_ENABLE
    \brief This Macro defines Mirro Enable
 */
#define MIRROR_ENABLE 1

/*! \def MIRROR_DISABLE
    \brief This Macro defines Mirro Disable
 */
#define MIRROR_DISABLE 0

#define MAX_WANMODULES 4
#define MAX_COMMONMODULES 6
#define SYSTEM_CFG_FILE "/opt/lantiq/config/syscfg.cfg"

#define MAX_MODPATHNAME_SIZE    256
#define MAX_OSRBUF_SIZE         64

#define ETH_RMON_POLLD_TIMEOUT	3540	/*59 min */
#define ETH_INTFSTATS_POLLD_TIMEOUT	3480	/*58 min */

#define FAPI_SYS_BRIDGE_ACCEL_CFG_FILE	"/opt/lantiq/etc/config_bridge_accel"
#define FAPI_SYS_LAN_PORT_SEP_CFG_FILE	"/opt/lantiq/etc/enable_lan_port_sep"
#define FAPI_SYS_SWITCH_INIT_SCRIPT		"/opt/lantiq/etc/switch_init"
#define FAPI_SYS_DISABLE_BR_ACCEL_SCRIPT "/opt/lantiq/etc/disable_bridge_acceleration.sh"
#define FAPI_SYS_WAN_VLAN_CFG_SCRIPT	"/opt/lantiq/etc/wan_vlan_config"

/* enums */

/*!
    \brief  enumerations for Port Status
*/
enum {
	eStatusDown = 0,
	eStatusUp = 1,
} ePortStatus;

/*!
    \brief  enumerations for PLATFORM NAMES
*/
enum {
	HW_PLATFORM_NONE = 0,
	HW_PLATFORM_GRX350,
	HW_PLATFORM_GRX500,
	HW_PLATFORM_GRX750,
	HW_PLATFORM_xRX330,
	HW_PLATFORM_xRX300,
	HW_PLATFORM_xRX220,
} platform_t;

/*!
    \brief  enumerations for WLAN devices used in xRX300 platforms
*/
typedef enum {
	wlan_1 = 7,
	wlan_2,
	wlan_3,
} wlan_port_t;

/*!
    \brief  enumerations for VID used in xRX300 platforms
*/
typedef enum {
	CPU_VID = 500,
	LAN_VID = 501,
	WAN_VID = 502,
} vlan_grp_t;

/*!
    \brief  enumerations for VLAN seperation in xRX300 platforms
*/
typedef enum {
	SEP_DISABLE = 0,
	SEP_ENABLE,
} DMA_SEPERATION_STATUS;

/*!
    \brief  enumerations for VLAN Operation
*/
typedef enum {
	OPER_REM = 0,
	OPER_ADD,
} Oper_t;

/* WAN Type enumeration */

/*!
    \brief  WAN type enumerations 
*/
typedef enum _wan_type {

	WAN_NONE = 0,		/* No WAN is active in system */
	ETH = 1,		/* Ethernet WAN is active in system */
	DSL_xTM = 2,		/* DSL with Auto-TC in system */
	DSL_PTM = 3,		/* DSL with PTM-TC in system */
	DSL_ATM = 4,		/*DSL with ATM-TC in system */
	CELL = 5		/* Cellular WAN in system */
} WAN_TYPE_t;

/*!
    \brief  Structure for switch port members 
*/
/* Structure Defn */
typedef struct {
	int wan_port;
	int lan_1;
	int lan_2;
	int lan_3;
	int lan_4;
} lan_port_cfg_t;

/*!
    \brief  Structure describing switch RMON parameters 
*/
typedef struct {
	uint32_t DropEvents;
	uint64_t RxBytes;
	uint64_t TxBytes;
	uint64_t RxPackets;
	uint64_t TxPackets;
	uint32_t BroadcastPackets;
	uint32_t MulticastPackets;
	uint32_t CRCErroredPackets;
	uint32_t UndersizePackets;
	uint32_t OversizePackets;
	uint32_t Packets64Bytes;
	uint32_t Packets65to127Bytes;
	uint32_t Packets128to255Bytes;
	uint32_t Packets256to511Bytes;
	uint32_t Packets512to1023Bytes;
	uint32_t Packets1024to1518Bytes;
} RMONGet_t;

/*!
    \brief  Structure describing switch port configuration parameters
*/
typedef struct {
	int32_t eLink;		/*port link status */
	int32_t eSpeed;		/*port link speed */
	int32_t DuplexForce;
	int32_t eEnable;
} PORTcfg_t;

/*!
    \brief  Structure defining system configuration during init
*/
typedef struct _sys_cfg_t {
	WAN_TYPE_t priWAN;	/* Primary WAN Type */
	WAN_TYPE_t secWAN;	/* Secondary WAN Type */
	bool secActive;		/* Secondary Active WAN - for Load balancing or Active Standby mode */
	bool qosEna;		/* QoS enabled or not */
	bool ipv6Ena;		/* IPv6 enabled or not */
	bool wanlteEna;
	int wanphy;
} sys_cfg_t;

/*!
    \brief  Structure defining interfaces added to PPA
*/
typedef struct _ifcfg_t {
	char ifName[PPA_IF_NAME_SIZE];	/* Interface Netdevice to be added or removed from acceleration */
	char baseifName[PPA_IF_NAME_SIZE];	/* base Interface Netdevice to be added or removed from acceleration */
	bool wanIf_flag;	/* When set, implies ifName - netdevice is being used as WAN  */
} ifcfg_t;

/*!
    \brief  Structure definitions used for interface and port mapping
*/
typedef struct _intf_port_map_t {
	char ifName[PPA_IF_NAME_SIZE];	/* Interface Netdevice */
	int32_t PortId;		/*Port Id read from system */
} intfPortMap_t;

typedef struct _vlanCfg_t {
	Oper_t oper;
	char ifName[PPA_IF_NAME_SIZE];	/* Interface Netdevice */
	int32_t vlanId;		/*Vlan Id assigned to interface */

} vlanCfg_t;

typedef struct _brAccelCfg_t {
	Oper_t oper;
	vlanCfg_t WanVlanCfg;
	char sBrName[MAX_IFACE_SIZE];
} brAccelCfg_t;

/*!
    \brief  Structure defining PPA Initialization configurations 
*/
typedef struct PPA_INIT_CFG {
	int32_t Min_Hits;	/*Minimum packets hitting CPU path before acceleration */
	int32_t nMax_LANNumSessions;	/*Max Lan sessions supported */
	int32_t nMax_WANNumSessions;	/*Max WAN sessions supported */
	int32_t nMax_McastNumSessions;	/*Max multicase sessions supported */
	int32_t nMax_BrNumSessions;	/*Max bridge sessions supported */
	int32_t Def_MTUSize;	/*Default MTU size */
	bool bMibMode;		/*Mib Mode, 0=bytes, 1=packets */
	bool bIP_Verify; /* ip checksum enable/disable */
} PPAInit_cfg_t;

/*
	\brief Structure defining the list of modules to load
*/
typedef struct _module_load_name {
	char **module;		/*Module name to load */
	uint32_t uNum;		/*Count number of module to load */
	const char *pcOptions;	/*additional options to insmod */
} Modules_t;

/*
	/brief Structure defining make block or character special files
*/
typedef struct MKNOD_CGF {
	char DevName[64];	/*Device Name */
	uint32_t unMajorNo;	/*Major number */
	uint32_t unMinorNo;	/*Minor number */
	uint32_t unDevNo;	/*Device number to create a nod */
} MKNODcfg_t;

/*CB struct has to be at the end of all struct definition*/
/*!
    \brief  Structure definintions for fapi callback functions
*/
/* Structure Defn */
typedef struct SysFapiCB {
	int32_t flag;
	 int32_t(*wanSWO) (sys_cfg_t *);
	 int32_t(*moduleLoad) (WAN_TYPE_t next_tc_mode);
	 int32_t(*moduleUnLoad) (WAN_TYPE_t next_tc_mode);
	 int32_t(*ProcessorStat) (ProcessorCounter * xProcessorInfo);
	 int32_t(*SysInit) (void);
	 int32_t(*SysUnInit) (void);
	 int32_t(*ProcessorInit) (void);
	 int32_t(*ProcessorUnInit) (void);
	 int32_t(*ppa_init) (PPAInit_cfg_t * ppaInit_Cfg);
	 int32_t(*ppa_uninit) (void);
	 int32_t(*sysSet) (sys_cfg_t *);
	 int32_t(*sysGet) (sys_cfg_t *);
	 int32_t(*ppaAdd) (ifcfg_t *);
	 int32_t(*ppaDel) (ifcfg_t *);
	 int32_t(*ppaHook) (PPA_CMD_ENABLE_INFO *);
	 int32_t(*SetLinkState) (int32_t, char *);
	 int32_t(*GetLinkState) (int32_t, PORTcfg_t *);
	 int32_t(*VLANCfgSet) (vlanCfg_t *);
	 int32_t(*RMONGet) (int32_t, RMONGet_t *);
	 int32_t(*getPortId) (char *);
	 int32_t(*setbrCfg) (char * , char *, char *, char *);
	 int32_t(*setPortStatus) (int32_t, int32_t);
	 int32_t(*getPortStatus) (int32_t, PORTcfg_t *);
	 int32_t(*setMaxRate) (int32_t, int32_t);
	 int32_t(*getMaxRate) (int32_t PortId, PORTcfg_t * port_get);
	 int32_t(*setDuplexMode) (int32_t, char *);
	 int32_t(*getDuplexMode) (int32_t, PORTcfg_t *);
	 int32_t(*EnMirror) (char *, char *);
	 int32_t(*disMirror) (char *, char *);
	 int32_t(*cfgbrAccel) (brAccelCfg_t * BrAccelCfg);
	 int32_t(*setInterfaceState)(InterfaceType, State, void * pAttr);
	 int32_t(*cfg_SwitchIOCTL) (int32_t, int32_t, void *);
	 int32_t(*setBridgeState) (char *);
	 int32_t(*setWanPhyGpio) (uint8_t);
} SysFapiCB_t;

/* function prototypes for common functions used across
   fapi_sys and fapi_eth
*/

/*! \brief  get_hw_platform is a helper function which reads the underlying
        \hardware and returns platform type. This is used buring system initialization
	\to load driver modules for corresponding platforms.
        \param[in] Void
        \return function retruns platform type defined in enum platform_t.
*/
int32_t get_hw_platform(void);

/*! \brief  fapi_eth_init performs system initialization based on underlying
        \hardware. This is called during system initialization by eth_sl
	\to load driver modules for underlying platforms.
        \param[in] Void
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_init(void);
/*! \brief  fapi_eth_uninit performs un initialization of ethernet driver modules
	\ based on underlying hardware
        \param[in] Void
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_uninit(void);

/*! \brief  fapi_sys_set configures the struct sys_cfg_t and fills in initialization
	\ parameters
        \param[in] struct sys_cfg_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_set(IN sys_cfg_t *);

/*! \brief  fapi_sys_get retrieves data in struct sys_cfg_t 
        \param[in] struct sys_cfg_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_get(IN sys_cfg_t *);

/*! \brief  fapi_sys_if_attach adds interface specified in struct ifcfg_t to PPA acceleration
        \param[in] struct ifcfg_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_if_attach(IN ifcfg_t *);

/*! \brief  fapi_sys_if_dettach deletes interface specified in struct ifcfg_t from PPA acceleration
        \param[in] struct ifcfg_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_if_detach(IN ifcfg_t *);

/*! \brief  fapi_sys_ppa_init performs configurations in PPA to prepare and intitialize PPA
        \param[in] Structure PPAInit_cfg_t with default initialization configuration
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_ppa_init(IN PPAInit_cfg_t * ppaInit_Cfg);

/*! \brief  fapi_sys_ppa_uninit performs configurations in PPA to unintitialize PPA
        \param[in] void
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_ppa_uninit(void);

/*! \brief  fapi_sys_ppa_enable enables or disable LAN and WAN acceleration in PPA
        \param[in] lan and wan enable info by updating PPA_CMD_ENABLE_INFO structure
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_ppa_enable(IN PPA_CMD_ENABLE_INFO * enable_info);

/*! \brief  fapi_get_mac_addr reads mac address configured on system in /proc/cmdline
	\and returns the mac address. this is used during system initialization
	\to configure mac address of LAN and WAN interfaces.
        \param[in] none
	\param[out] pointer to string containing mac address
        \return function retruns UGW_SUCCESS or UGW_FAILURE and returns mac address
*/
int32_t fapi_get_mac_addr(OUT char *mac_addr);

/*! \brief fapi_validateVLAN returns VLAN id needed for ETH Untagged Bridged WAN Connection (valid for legacy platform e.g vrx220).
	\and and rejects any other routed wan connection request on same VLAN
        \param[in] Base interface name
	\param[out] VLAN Id
        \return function retruns UGW_SUCCESS or UGW_FAILURE
*/
int fapi_validateVLAN(char *psBasIface, int *pnVLANId);

/*! \brief  fapi to find whether the linkenable is true/false.(Platform specific based on primary wan if only 1 wanmode supported)
        \param[inout] Link enable value from interface.cfg.Link enable modified if any platform dependency.
        \return void 
*/

void fapi_updateLinkEnable(INOUT char *pcLinkEnable);

/*! \brief  fapi_get_port reads the interface and returns port id of the interface
	\by reading from PPA_CMD_GET_PORTID ioctl
        \param[in] interface name to be populated in intfPortMap_t struct
	\port id is available in intfPortMap_t
        \return function retruns port number or UGW_FAILURE
*/
int32_t fapi_get_portid(IN char *ifname);

/*! \brief  fapi_set_brCfg configures switch for multi bridge in xRX220 platforms.
	\by using switch_cli commands
        \param[in] wan interface name
        \param[in] lan interface ports 
        \param[in] brname bridge name
        \param[in] Oper operation refers ADD,DEL
        \return function retruns UGW_SUCCESS or UGW_FAILURE
*/
int32_t fapi_set_brCfg(IN char *wan, IN char *lan, IN char *brname, IN char *Oper);


/*switch fapis */

/*! \brief  fapi_port_setstatus enables or disables switch port
        \param[in] switch port id and enable/disable info 
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_port_setstatus(IN int32_t PortId, IN int32_t PortEna);

/*! \brief  fapi_port_setbitrate sets port bitrate on switch port provided
        \param[in] switch port id, Max Bitrate to be configured(10,100,1000 Mbps)
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_port_setbitrate(IN int32_t PortId, IN int32_t MaxBitRate);

/*! \brief  fapi_port_setDuplexMode configures the switch port Duplex Mode provided
        \param[in] switch port id, DuplexMode; Full Duplex or Half Duplex
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/

int32_t fapi_port_setDuplexMode(IN int32_t PortId, IN char *DuplexMode);

/*! \brief  fapi_port_getDuplexMode retrieves switch port Duplex Mode
        \param[in] switch port id, 
	\param[out] Port Duplex mode filled in struct  PORTcfg_t 
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_port_getDuplexMode(IN int32_t PortId, IN PORTcfg_t *);

/*! \brief  fapi_port_getbitrate retrieves switch port bitrate
        \param[in] switch port id, 
	\param[out] Port bitrate filled in struct  PORTcfg_t 
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_port_getbitrate(IN int32_t PortId, IN PORTcfg_t *);

/*! \brief  fapi_port_getstatus retrieves switch port enable or disable status
        \param[in] switch port id, 
	\param[out] Port status filled in struct  PORTcfg_t 
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_port_getstatus(IN int32_t PortId, IN PORTcfg_t *);

/*! \brief  fapi_rmon_get retrieves switch port RMON statistics
        \param[in] switch port id, 
	\param[out] RMON stats filled in struct  RMONGet_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
//int32_t fapi_rmon_get(int port, RMONGet_t *RMONGet);
int32_t fapi_rmon_get(IN int32_t port, RMONGet_t *);

/*! \brief  fapi_EnablePortMirror configures required switch parameters to setup port mirroring on the device. Fapi accepts interface names as inputs and sets up portmirroring for the corresponding ports.
	\param[in] Downstream interface
	\param[in] Mirrored interface
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/

int32_t fapi_EnablePortMirror(IN char *DownstreamIntf, IN char *MirrorIntf);

/*! \brief  fapi_DisablePortMirror configures required switch parameters to disable port mirroring on the device. Fapi accepts interface names as inputs and disables portmirroring for the corresponding ports.
	\param[in] Downstream interface
	\param[in] Mirrored interface
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_DisablePortMirror(IN char *DownstreamIntf, IN char *MirrorIntf);

/*! \brief  fapi_switch_init performs configuration to initialize flow15 switch on xRX300 platforms
        \param[in] void
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_switch_init(void);

/*! \brief  fapi_switch_uninit performs configuration to uninitialize flow15 switch on xRX300 platforms
        \param[in] void
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_switch_uninit(void);

/*! \brief  fapi_vlan_config configures vlanid provided by user
        \param[in] vlanid provided in vlanCfg_t structure
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_vlan_config(IN vlanCfg_t *);
/*! \brief platform_FapiReg registers fapi callback functions for platform it is defined for.
        \param[in]  void
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t platform_FapiReg(void);

/*! \brief check loaded modules is a helper function which checks and returns success if module is already loaded
	returns failure if module is not already loaded/
        \param[in]  module name 
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t check_loaded_modules(const char *);

/*! \brief fapi_sys_SWO is used when wan modes are swithched. this fapi handles unloading of drivers for old wan mode
	 and loading of drivers for new wan mode and also initializes PPA
        \param[in]  new wan mode information in sys_cfg_t structure 
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_SWO(IN sys_cfg_t *);

/*! \brief fapi_sys_load is used for loading DSL driver modules during DSL tc change
        \param[in]  dirvers to be loaded for new DSL tc mode 
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_load(IN WAN_TYPE_t next_tc_mode);

/*! \brief fapi_sys_unload is used for unloading DSL driver modules during DSL tc change
        \param[in]  drivers to be unlaodedfor DSL tc mode
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_unload(IN WAN_TYPE_t next_tc_mode);

/*! \brief  api  is responsible for loading processor modules
        \param[in] Void
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
 */
int32_t fapi_processorstat_init(void);

/*! \brief  api is responsible for unloading processor modules
        \param[in] Void
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
 */
int32_t fapi_processorstat_uninit(void);

/*! \brief  api used to fetch pecostat counter of device 
        \param[in] ProcessorCounter 
        \return UGW_SUCCESS/UGW_FAILURE
 */
int32_t fapi_processorstat_get(ProcessorCounter * xProcessorInfo);

/*! \brief  fapi_sys_mknod performs character special files
        \ based on Create the special file NAME
        \param[in] MKNODcfg_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_mknod(IN MKNODcfg_t * xMknod);

/*! \brief  fapi_sys_generic_load is responsible for loading modules
        \ by calling scapi_insmod
        \param[in] Modules_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_generic_load(IN Modules_t *);

/*! \brief  fapi_sys_generic_load is responsible for unloading modules
        \ by calling scapi_rmmod
        \param[in] Modules_t
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_sys_generic_unload(IN Modules_t *);

int32_t fapi_port_setLinkState(IN int32_t PortId, IN char *LinkStatus);

int32_t fapi_port_getLinkState(IN int32_t PortId, OUT PORTcfg_t * port_get);

int32_t is_module_exists(IN const char *module_to_find);

#ifdef CONFIG_IPSEC_SUPPORT
int32_t fapi_sys_pp_crypto_support(void);
#endif

/*! \brief fapi_syslogset is used to set/pass the DEBUG LOG state in sysFAPI from sys SL
        \param[in]  log level, log_type
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_syslogset(int16_t, int16_t);

/*! \brief fapi_ethlogset is used to set/pass the DEBUG LOG state in ethFAPI from eth SL
        \param[in]  log level, log_type
	\param[out] none
        \return function retruns UGW_SUCCESS or UGW_FAILURE.
*/
int32_t fapi_ethlogset(int16_t, int16_t);

int32_t fapi_CfgBridgeAccel(INOUT brAccelCfg_t * BrAccelCfg);

int32_t Processor_init(void);
int32_t Processor_uninit(void);
int32_t stats_counter(IN ProcessorCounter *);
int32_t PPAInit(IN PPAInit_cfg_t *);
int32_t PPAUnInit(void);
int32_t SysSet(IN sys_cfg_t *);
int32_t SysGet(IN sys_cfg_t *);
int32_t PPAIntfAdd(IN ifcfg_t *);
int32_t PPAIntfDel(IN ifcfg_t *);
int32_t PPAEnHook(IN PPA_CMD_ENABLE_INFO * enable_info);
int32_t SetLinkState(IN int32_t PortId, IN char *LinkStatus);
int32_t GetLinkState(IN int32_t PortId, OUT PORTcfg_t * port_get);
int32_t RMONGet(IN int32_t port, OUT RMONGet_t * RMONGet);
int32_t SetDuplexMode(IN int32_t PortId, IN char *DuplexMode);
int32_t GetDuplexMode(IN int32_t PortId, OUT PORTcfg_t * port_get);
int32_t SetMaxBitRate(IN int32_t PortId, IN int32_t MaxBitRate);
int32_t GetMaxBitRate(IN int32_t PortId, OUT PORTcfg_t * port_get);
int32_t SetPortStatus(IN int32_t PortId, IN int32_t PortEna);
int32_t EnableMirroring(IN char *DownstreamIntf, IN char *MirrorIntf);
int32_t DisableMirroring(IN char *DownstreamIntf, IN char *MirrorIntf);
int32_t fapi_sys_setBridgeAccelState(IN char *operation);
int32_t fapi_sys_setWanPhyGpio(IN uint8_t nVal);

#ifdef PLATFORM_XRX330
int32_t xRX330_capReg(void);
int32_t XRX330_wanSWO(IN sys_cfg_t *);
int32_t xRX330_module_load(IN WAN_TYPE_t next_tc_mode);
int32_t xRX330_module_unload(IN WAN_TYPE_t next_tc_mode);
int32_t xRX330_module_init(void);
int32_t xRX330_module_uninit(void);
int32_t xRX330_load_common_modules(void);
int32_t xRX330_remove_common_modules(void);
int32_t xRX330_load_wan_modules(IN sys_cfg_t *);
int32_t xRX330_remove_wan_modules(IN sys_cfg_t *);
int32_t xRX330_PortIdGet(IN char *ifname);
int32_t xRX330_VLANCfgSet(IN vlanCfg_t * vlanCfg);
int32_t xRX330_GetPortStatus(IN int32_t PortId, OUT PORTcfg_t * port_get);
int32_t xRX330_CfgBridgeAccel(INOUT brAccelCfg_t *);
int32_t xRX330_cfg_SwitchIOCTL( __attribute__ ((unused)) IN int32_t PortId, IN int32_t ioctl_cmd, IN void *data);
int32_t xRX330_SetInterface(IN InterfaceType interface, IN State setState, IN void *data);
int32_t xRX330_SetBridgeAcclState(IN char *operation);
int32_t xRX330_SetWanPhyGpio(IN uint8_t nVal);
#endif

#ifdef PLATFORM_XRX200
int32_t xRX220_capReg(void);
int32_t XRX220_wanSWO(IN sys_cfg_t *);
int32_t xRX220_module_load(IN WAN_TYPE_t next_tc_mode);
int32_t xRX220_module_unload(IN WAN_TYPE_t next_tc_mode);
int32_t xRX220_module_init(void);
int32_t xRX220_module_uninit(void);
int32_t xRX220_load_common_modules(void);
int32_t xRX220_remove_common_modules(void);
int32_t xRX220_load_wan_modules(IN sys_cfg_t *);
int32_t xRX220_remove_wan_modules(IN sys_cfg_t *);
int32_t xRX220_PortIdGet(IN char *ifname);
int32_t xRX220_setBrCfg(IN char *Wan, IN char *lan, IN char *brname, char *Oper);
int32_t xRX220_VLANCfgSet(IN vlanCfg_t * vlanCfg);
int32_t xRX220_GetPortStatus(IN int32_t PortId, OUT PORTcfg_t * port_get);
int32_t xRX220_CfgBridgeAccel(INOUT brAccelCfg_t *);
int32_t xRX220_cfg_SwitchIOCTL( __attribute__ ((unused)) IN int32_t PortId, IN int32_t ioctl_cmd, IN void *data);
int32_t xRX220_SetInterface(IN InterfaceType interface, IN State setState, IN void *data);
int32_t xRX220_EnableMirroring(IN char *DownstreamIntf, IN char *MirrorIntf);
int32_t xRX220_DisableMirroring(IN char *DownstreamIntf, IN char *MirrorIntf);
int32_t xRX220_SetBridgeAcclState(IN char *operation);
int32_t xRX220_SetWanPhyGpio(IN uint8_t nVal);
#endif

#ifdef PLATFORM_XRX500
int32_t xRX350_capReg(void);
int32_t XRX350_wanSWO(IN sys_cfg_t *);
int32_t xRX350_module_load(IN WAN_TYPE_t next_tc_mode);
int32_t xRX350_module_unload(IN WAN_TYPE_t next_tc_mode);
int32_t xRX350_module_init(void);
int32_t xRX350_module_uninit(void);
int32_t xRX350_load_common_modules(void);
int32_t xRX350_remove_common_modules(void);
int32_t xRX350_load_wan_modules(void);
int32_t xRX350_remove_wan_modules(void);
int32_t xRX350_PortIdGet(IN char *ifname);
int32_t xRX350_VLANCfgSet(IN vlanCfg_t * vlanCfg);
int32_t xRX350_GetPortStatus(IN int32_t PortId, OUT PORTcfg_t * port_get);
int32_t xRX350_cfg_SwitchIOCTL(IN int32_t PortId, IN int32_t ioctl_cmd, IN void *data);
int32_t xRX350_SetInterface(IN InterfaceType interface, IN State setState, IN void *data);
int32_t xRX350_EnableMirroring(IN char *DownstreamIntf, IN char *MirrorIntf);
int32_t xRX350_DisableMirroring(IN char *DownstreamIntf, IN char *MirrorIntf);
int32_t xRX350_SetBridgeAcclState(IN char *operation);
int32_t xRX350_SetWanPhyGpio(IN uint8_t nVal);
#endif

#ifdef PLATFORM_XRX750
int32_t xRX750_capReg(void);
int32_t XRX750_wanSWO(IN sys_cfg_t *);
int32_t xRX750_module_load(WAN_TYPE_t next_tc_mode);
int32_t xRX750_module_unload(WAN_TYPE_t next_tc_mode);
int32_t xRX750_module_init(void);
int32_t xRX750_module_uninit(void);
int32_t xRX750_Processor_init(void);
int32_t xRX750_stats_counter(ProcessorCounter * xProcessorInfo);
int32_t xRX750_PPAIntfAdd(IN ifcfg_t * ifCfg);
int32_t xRX750_PortIdGet(IN char *ifname);
int32_t xRX750_VLANCfgSet(IN vlanCfg_t * vlanCfg);
int32_t xRX750_GetPortStatus(IN int32_t PortId, OUT PORTcfg_t * port_get);
int32_t xRX750_RMONGetPlatform(IN int32_t port, OUT RMONGet_t * RMONGet);
int32_t xRX750_SetInterface(IN InterfaceType interface, IN State setState, IN void *data);
int32_t xRX750_cfg_SwitchIOCTL(IN int32_t PortId, IN int32_t ioctl_cmd, INOUT void *data);
int32_t xRX750_SetBridgeAcclState(IN char *operation);
int32_t xRX750_SetWanPhyGpio(IN uint8_t nVal);
#endif

#endif				// #ifndef __FAPI_SYS_COMMON_H
/* @} */
