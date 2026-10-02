/*====================================================================*
 	Copyright (c) 2013,2018-2020 Qualcomm Technologies, Inc.
	All Rights Reserved.
	Confidential and Proprietary - Qualcomm Technologies, Inc.
	******************************************************************
	2013 Qualcomm Atheros, Inc. 
 *--------------------------------------------------------------------*/

#ifndef PLC_HEADER
#define PLC_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../ether/channel.h"
#include "../tools/types.h"
#include "../tools/tlv.h"
#include "../plc/chipset.h"
#include "../key/HPAVKey.h"
#include "../mme/mme.h"
#include "../nvm/nvm.h"
#include "../pib/pib.h"


/*====================================================================*
 *   these codes are returned in the MDEVICE_CLASS field of VS_SW_VER
 *   messages;
 *--------------------------------------------------------------------*/

#if 0
/*
 *   these are now defined in chipset.h and will be removed
 *   from here for cheetah release;
 */
#define CHIPSET_UNKNOWN 0x00
#define CHIPSET_INT6000A1 0x01
#define CHIPSET_INT6300A0 0x02
#define CHIPSET_INT6400A0 0x03
#define CHIPSET_AR7400A0 0x04
#define CHIPSET_AR6405A0 0x05
#define CHIPSET_PANTHER_LYNX 0x06
#define CHIPSET_QCA7450A0 0x07
#define CHIPSET_QCA7451A0 0x08
#define CHIPSET_QCA7452A0 0x09
#define CHIPSET_QCA7420A0 0x20
#define CHIPSET_QCA6410A0 0x21
#define CHIPSET_QCA6411A0 0x21
#define CHIPSET_QCA7000A0 0x22
#define CHIPSET_QCA7000I 0x22
#define CHIPSET_QCA7005A0 0x22
#define CHIPSET_QCA7500A0 0x30
#endif

/*
 * the following definitions define older constants in terms of
 * newer constants to avoid compiler errors; there is nothing
 * magic about the A0/A1 suffixes;
 */

#if 0
/*
 *   these are now defined in chipset.h and will be removed
 *   from here for cheetah release;
 */
#define CHIPSET_INT6000 CHIPSET_INT6000A1
#define CHIPSET_INT6300 CHIPSET_INT6300A0
#define CHIPSET_INT6400 CHIPSET_INT6400A0
#define CHIPSET_AR7400  CHIPSET_AR7400A0
#define CHIPSET_INT6405 CHIPSET_AR6405A0
#define CHIPSET_AR6405  CHIPSET_AR6405A0
#define CHIPSET_QCA7450 CHIPSET_QCA7450A0
#define CHIPSET_QCA7451 CHIPSET_QCA7451A0
#define CHIPSET_QCA7452 CHIPSET_QCA7452A0
#define CHIPSET_QCA7420 CHIPSET_QCA7420A0
#define CHIPSET_QCA6410 CHIPSET_QCA6410A0
#define CHIPSET_QCA6411 CHIPSET_QCA6411A0
#define CHIPSET_QCA7000 CHIPSET_QCA7000A0
#define CHIPSET_QCA7005 CHIPSET_QCA7005A0
#define CHIPSET_QCA7500 CHIPSET_QCA7500A0
#endif

#define PLC_MODULE_SOFTLOADER           0x00
#define PLC_MODULE_FIRMWARE             (1 << 0)
#define PLC_MODULE_PARAMETERS           (1 << 1)
#define PLC_MODULE_NVM_PIB              (PLC_MODULE_PARAMETERS | PLC_MODULE_FIRMWARE)
#define PLC_MODULE_OPERATION            (1 << 3)
#define PLC_MODULE_UPGRADE              (PLC_MODULE_OPERATION | PLC_MODULE_PARAMETERS | PLC_MODULE_FIRMWARE)
#define PLC_MODULE_FORCE_FLASH          (1 << 4)
#define PLC_MODULE_DO_NOT_REBOOT        (1 << 5)
#define PLC_MODULE_ALTERNATE_SECTION    (1 << 6)
#define PLC_MODULE_FORCE_SECTION        (1 << 7)

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define PLC_VERSION_STRING 0xFF
#define PLC_RECORD_SIZE 1024
#define PLC_MODULE_SIZE 1400
#define PLC_TIME_SLOTS 6    

#define LEGACY_PIBOFFSET 0x01F00000
#define INT6x00_PIBOFFSET 0x01000000
#define AR7x00_PIBOFFSET 0x00200000

#define INT_CARRIERS 1155
#define AMP_CARRIERS 2880
#define CHEETAH_CARRIERS 2690
#define CHEETAH_PRECODES 242
#define PLC_BITS_PER_TONE 9

extern byte const mod2bits [PLC_BITS_PER_TONE];
extern byte const mod2db [PLC_BITS_PER_TONE];

/*====================================================================*
 *   device manager flagword bits;
 *--------------------------------------------------------------------*/

/*
 *   We reuse flagword bits in various programs to avoid proliferating
 *   flagwords; make sure that one program does not use multiple names
 *   or refer to the same bit;
 */

#define PLC_BAILOUT           (1 << 0)
#define PLC_SILENCE           (1 << 1)
#define PLC_VERBOSE           (1 << 2)
#define PLC_ANALYSE           (1 << 3)
#define PLC_ERASE_DEVICE      PLC_ANALYSE /* ampinit, plcinit */
#define PLC_NEWLINE           PLC_ANALYSE /* ampID, plcID */
#define PLC_WAITFORRESET      (1 << 4)
#define PLC_WAITFORSTART      (1 << 5)
#define PLC_WAITFORASSOC      (1 << 6)
#define PLC_REMOTEHOSTS       PLC_WAITFORASSOC 
#define PLC_RESET_DEVICE      (1 << 7)
#define PLC_RANDOM_ADDR       PLC_RESET_DEVICE
#define PLC_TIM_GARGRAVE      PLC_RESET_DEVICE
#define PLC_BRIDGE_LIST       PLC_RESET_DEVICE /* plclist, amplist */
#define PLC_FACTORY_DEFAULTS  (1 << 8)
#define PLC_FOREVER           PLC_FACTORY_DEFAULTS /* plctest */
#define PLC_GRAPH             PLC_FACTORY_DEFAULTS /* plctone */
#define PLC_DAEMON            PLC_FACTORY_DEFAULTS /* plchost */
#define PLC_REMOTE_LIST       PLC_FACTORY_DEFAULTS /* plclist, amplist */
#define PLC_BINARY            PLC_FACTORY_DEFAULTS /* ampsnif */
#define PLC_FORCE_FLASH       PLC_FACTORY_DEFAULTS /* plchost */
#define PLC_NETWORK           (1 << 9)
#define PLC_OPEN_SESSION      PLC_NETWORK /* plcmod */
#define PLC_MONITOR           PLC_NETWORK /* ampsnif */
#define PLC_XML_FORMAT        PLC_NETWORK /* int6klog */
#define PLC_VERSION           (1 << 10)
#define PLC_WRITE_MODULE      PLC_VERSION /* plcmod */
#define PLC_MANUFACTURER      (1 << 11)
#define PLC_READ_MODULE       PLC_MANUFACTURER /* plcmod */
#define PLC_READ_MAC          (1 << 12)
#define PLC_DUMP_MODULE       PLC_READ_MAC /* int6mod */
#define PLC_DEV_TRAFFIC		  PLC_READ_MAC /* trafficgen */
#define PLC_LOCAL_TRAFFIC     PLC_READ_MAC /* int6krate, amprate, plcrate */
#define PLC_READ_PIB          (1 << 13)
#define PLC_NETWORK_TRAFFIC   PLC_READ_PIB /* plcrate */
#define PLC_READ_IDENTITY     (1 << 14)
#define PLC_UNCODED_RATES     PLC_READ_IDENTITY /* plcrate */  
#define PLC_WRITE_MAC         (1 << 15)
#define PLC_LINK_STATS        PLC_WRITE_MAC /* plcstat */
#define PLC_WRITE_PIB         (1 << 16)
#define PLC_TONE_MAP          PLC_WRITE_PIB /* plcstat */
#define PLC_FLASH_DEVICE      (1 << 17)
#define PLC_COMMIT_MODULE     PLC_FLASH_DEVICE /* plcmod */
#define PLC_QUICK_FLASH       (1 << 18)
#define PLC_SETLOCALKEY       (1 << 19)
#define PLC_RXONLY            PLC_SETLOCALKEY
#define PLC_SETREMOTEKEY      (1 << 20)
#define PLC_TXONLY            PLC_SETREMOTEKEY
#define PLC_SDRAM_INFO        (1 << 21)
#define PLC_SDRAM_CONFIG      (1 << 22)
#define PLC_CONFIGURE         PLC_SDRAM_CONFIG /* plcotst */
#define PLC_LLDP_INFO		  PLC_SDRAM_CONFIG
#define PLC_NVRAM_INFO        (1 << 23)
#define PLC_ATTRIBUTES        (1 << 24)
#define PLC_PUSH_BUTTON       (1 << 25)
#define PLC_READ_CFG          (1 << 26)
#define PLC_ERASE_SECTOR      PLC_READ_CFG
#define PLC_ROUTE_INFO		  PLC_READ_CFG
#define PLC_RD_MOD_WR_PIB     (1 << 27)
#define PLC_SNIFFER           PLC_RD_MOD_WR_PIB /* ampsnif */
#define PLC_READ_ALL          PLC_RD_MOD_WR_PIB /* ampinit */
#define PLC_WATCHDOG_REPORT   (1 << 28)
#define PLC_RESULTS           PLC_WATCHDOG_REPORT /* plcotst */
#define PLC_HOST_ACTION       (1 << 29)
#define PLC_LINK_STATUS		  (1 << 30)
#define PLC_MULTICAST_INFO    PLC_LINK_STATUS
#define PLC_RX_TONEMAPS       PLC_HOST_ACTION /* plcstat */
#define PLC_SET_PRESCALER	  PLC_NVRAM_INFO
#define PLC_GET_PRESCALER     PLC_HOST_ACTION
#define PLC_RESET_BACKOFF     PLC_ATTRIBUTES
#define PLC_COUPLING		  PLC_PUSH_BUTTON
#define PLC_TRAFFIC_UNIDI     (1 << 31) 
#define PLC_DEV_TRAFFIC_UNIDI PLC_TRAFFIC_UNIDI /* trafficgen */
#define PLC_PROXY_NW_INFO	  PLC_TRAFFIC_UNIDI

/*====================================================================*
 *   device manager flagword bits (flag2); 
 *--------------------------------------------------------------------*/

#define PLC_FLAG2_CFM_ACT           (1 << 0)
#define PLC_FLAG2_BT_SRC            (1 << 1)	

/*====================================================================*
 *   message format strings;
 *--------------------------------------------------------------------*/

#define PLC_BADVALUE "Invalid or suspect data"
#define PLC_WONTDOIT "Device refused request"
#define PLC_NODEVICE "Need a device. Try 'local' or '00:B0:52:00:00:01'."
#define PLC_BADFRAME "Unexpected response"
#define PLC_NODETECT "Device must be connected"
#define PLC_NOMEMORY "Not enough memory"
#define PLC_NOTREADY "Function not implemented"

#define PLC_ERR_OFFSET "Data offset error"
#define PLC_ERR_LENGTH "Data length error"

#define PLC_BAD_MAC "Have '%s' instead of MAC address"
#define PLC_BAD_DAK "Have '%s' instead of DAK"
#define PLC_BAD_NMK "Have '%s' instead of NMK"

/*====================================================================*
 *    program constants;
 *--------------------------------------------------------------------*/

#define PLCDEVICE "PLC"

#define HARDWAREID 0
#define SOFTWAREID 0
#define PLCSESSION 0x78563412
#define HOSTACTION 0
#define SECTORCODE 0
#define PUSHBUTTON 1
#define MODULECODE (VS_MODULE_MAC | VS_MODULE_PIB)
#define READACTION 0
#define FLASH_SIZE 0x200000
#define PLCOUPLING 0

#define PLC_STATE 0
#define PLC_TIMER 5
#define PLC_PAUSE 5
#define PLC_FLASH 30
#define PLC_SLEEP 0
#define PLC_COUNT 1
#define PLC_INDEX 0
#define PLC_FLAGS 0

#define PLC_MEMTYPE_AUTO 1
#define PLC_MEMTYPE_ITCM 2
#define PLC_MEMTYPE_DTCM 3
#define PLC_MEMTYPE_SRAM 4
#define PLC_MEMTYPE_SDRAM 5

#define PLC_ECHOTIME 3
#define PLC_LONGTIME (unsigned)(~0)
#define DEFAULT_TRAFFICGEN_RATE 0

#define PLC_EXIT(plc) ((signed) (plc->flags & PLC_BAILOUT))

/*====================================================================*
 *   common mac address names;
 *--------------------------------------------------------------------*/

#define PLCDEVICES 3

extern struct _term_ const devices [PLCDEVICES];
extern byte const broadcast [ETHER_ADDR_LEN];
extern byte const localcast [ETHER_ADDR_LEN];

/*====================================================================*
 *
 *   the plc structure holds everything needed to perform powerline
 *   device management operations including a channel structure for
 *   Ethernet interface management and a message structure for data
 *   buffer management;
 *
 *   the channel structure holds information needed to open, read,
 *   write and close a raw socket; it differs in detail depending
 *   on constants WINPCAP and LIBPCAP;
 *
 *   byte array MAC[] holds the MAC address of the target device when
 *   one is specified on the command line; this value is initialized 
 *   to 00:B0:52:00:00:01 on startup and remains unchanged unless the
 *   user specifies one or more addresses on the command line;
 *
 *   byte array RDA[] holds the MAC address of a remote device when
 *   a remote device address is required;
 *
 *   byte arrays NMK[] and DAK[] hold encryption keys used by some
 *   operations;
 *
 *   the socket _file_ structure holds the descriptor and interface
 *   name of the host NIC where the name is eth0, eth1, ... or ethn;
 *
 *   the three _file_ structures, CFG, NVM, and PIB hold descriptors
 *   and filenames for files written to the device;
 *
 *   the three _file_ structures cfg, nvm and pib hold
 *   descriptors and filenames of files read from the device;
 *
 *   integers index, count and pause control command line looping
 *   and waiting;
 *
 *   flag_t flags contains bits that define program operations and
 *   control utility program flow;
 *
 *--------------------------------------------------------------------*/

typedef struct plc 

{ 
	struct channel * channel; 
	struct channel * channel1; 
	struct message * message; 
	void * content; 
	ssize_t packetsize; 
	uint8_t MAC [ETHER_ADDR_LEN]; 
	uint8_t RDA [ETHER_ADDR_LEN]; 
	uint8_t NMK [HPAVKEY_NMK_LEN]; 
	uint8_t DAK [HPAVKEY_DAK_LEN]; 
	struct _file_ CFG; 
	struct _file_ cfg; 
	struct _file_ SFT; 
	struct _file_ sft; 
	struct _file_ NVM; 
	struct _file_ nvm; 
	struct _file_ PIB; 
	struct _file_ pib; 
	struct _file_ XML; 
	struct _file_ rpt; 
	struct _file_ socket; 
	struct _file_ socket1;
	uint32_t hardwareID; 
	uint32_t softwareID; 
	uint32_t cookie; 
	uint8_t action; 
	uint8_t sector; 
	uint8_t module; 
	uint8_t pushbutton; 
	uint8_t readaction; 
	uint8_t coupling; 
	unsigned flash_size; 
	unsigned state; 
	unsigned timer; 
	unsigned sleep; 
	unsigned count; 
	unsigned index; 
	flag_t flags; 
	flag_t flag2;
} 

PLC; 

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

signed Antiphon (struct plc * plc, uint8_t osa [], uint8_t oda []);
signed Attributes (struct plc *);
signed Attributes1 (struct plc *);
signed Attributes2 (struct plc *);
signed BootDevice (struct plc *);
signed BootDevice1 (struct plc *);
signed BootDevice2 (struct plc *);
signed BootDeviceFirmware (struct plc *);
signed BootDeviceParameters (struct plc *);
signed BootFirmware1 (struct plc *);
signed BootFirmware2 (struct plc *);
signed BootParameters1 (struct plc *);
signed BootParameters2 (struct plc *);
signed ChangeIdent (struct plc *);
signed CrossTraffic (struct plc *);
signed CrossTrafficOne (struct plc *);
signed CrossTrafficTwo (struct plc *);
signed DeviceIdent (struct plc *);
signed EmulateHost (struct plc *);
signed EmulateHost64 (struct plc *);
signed EraseFlashSector (struct plc *);
signed ExecuteApplets (struct plc *);
signed ExecuteApplets1 (struct plc *);
signed ExecuteApplets2 (struct plc *);
signed FactoryDefaults (struct plc *);
signed FactoryReset (struct plc *);
signed FlashDevice (struct plc *);
signed FlashDevice1 (struct plc *);
signed FlashDevice2 (struct plc *, uint32_t options);
signed FlashDevice3 (struct plc *);
signed FlashDevice4 (struct plc *, uint32_t options);
signed FlashFirmware (struct plc *, uint32_t options);
signed FlashNVM (struct plc *);
signed FlashNVM (struct plc *);
signed FlashPTS (struct plc *);
signed FlashParameters (struct plc *, uint32_t options);
signed FlashSoftloader (struct plc *, uint32_t options);
signed FlashUpgrade (struct plc *, uint32_t options);
signed HostActionResponse (struct plc *);
signed Identity (struct plc *);
signed Identity1 (struct plc *);
signed Identity2 (struct plc *);
signed InitDevice (struct plc *);
signed InitDevice1 (struct plc *);
signed InitDevice2 (struct plc *);
signed IsFlashExists (struct plc * plc);
signed LinkStatus (struct plc *);
signed ListLocalDevices (struct plc * plc, char const * space, char const * comma);
signed ListRemoteDevices (struct plc *, char const * space, char const * comma);
signed ListRemoteDevices1 (struct plc *, char const * space, char const * comma);
signed ListRemoteDevices2 (struct plc *, char const * space, char const * comma);
signed LldpInfo (struct plc * plc);
signed LocalTrafficSend (struct plc * plc);
signed MDUTrafficStats (struct plc *, uint8_t command, uint8_t session, uint8_t slave);
signed MDUTrafficStats (struct plc *, uint8_t command, uint8_t session, uint8_t slave);
signed MfgString (struct plc *);
signed MulticastInfo1 (struct plc *);
signed MulticastInfo2 (struct plc *);
signed NVMSelect (struct plc *, signed (struct plc *), signed (struct plc *));
signed NVRAMInfo (struct plc *);
signed NetInfo (struct plc *);
signed NetInfo1 (struct plc *);
signed NetInfo2 (struct plc *);
signed NetworkDevices (struct plc *, void * memory, size_t extent);
signed NetworkDevices1 (struct plc *, void * memory, size_t extent);
signed NetworkDevices2 (struct plc *, void * memory, size_t extent);
signed NetworkInfoStats (struct plc *);
signed NetworkInformation (struct plc *);
signed NetworkInformation1 (struct plc *);
signed NetworkInformation2 (struct plc *);
signed NetworkProbe (struct plc *);
signed NetworkTraffic (struct plc *);
signed NetworkTraffic1 (struct plc *);
signed NetworkTraffic2 (struct plc *);
signed PLCSelect (struct plc *, signed method1 (struct plc *), signed method2 (struct plc *));
signed PhyRates (struct plc *);
signed PhyRates1 (struct plc *);
signed PhyRates2 (struct plc *);
signed ProxyNetworkInfo (struct plc *);
signed PushButton (struct plc *);
signed ReadFirmware (struct plc *);
signed ReadFirmware1 (struct plc *);
signed ReadFirmware2 (struct plc *);
signed ReadFirmware3 (struct plc *);
signed RouteInfo (struct plc *);
signed RouteInfo_7500(struct plc*);
signed ReadFMI (struct plc *, uint8_t MMV, uint16_t MMTYPE);
signed ReadMFG (struct plc *, uint8_t MMV, uint16_t MMTYPE);
signed ReadMME (struct plc *, uint8_t MMV, uint16_t MMTYPE);
signed ReadMME1 (struct plc *, uint8_t MMV, uint16_t MMTYPE);
signed ReadMultiple (struct plc *, uint8_t MMV, uint16_t MMTYPE);
signed ReadParameterBlock (struct plc *, void * memory, size_t extent);
signed ReadParameters (struct plc *);
signed ReadParameters1 (struct plc *);
signed ReadParameters2 (struct plc *);
signed ReadParameters3 (struct plc *);
signed RemoteHosts (struct plc *);
signed Reset (struct plc *);
signed ResetAndWait (struct plc *);
signed ResetDevice (struct plc *);
signed RxRates2 (struct plc *);
signed SDRAMInfo (struct plc *);
signed SendMME (struct plc *);
signed SendMME1 (struct plc *);
signed SetNMK (struct plc *);
signed SlaveMembership (struct plc *);
signed StartDevice (struct plc *);
signed StartDevice1 (struct plc *);
signed StartDevice2 (struct plc *);
signed StartFirmware (struct plc *, unsigned module, void const * header);
signed StartFirmware1 (struct plc *, unsigned module, const struct lightning_nvm_header *);
signed StartFirmware2 (struct plc *, unsigned module, const struct panther_nvm_header *);
signed Topology (struct plc *);
signed Topology1 (struct plc *);
signed Topology2 (struct plc *);
signed Traffic (struct plc *);
signed Traffic1 (struct plc *);
signed Traffic2 (struct plc *);
signed Traffic3 (struct plc *, uint8_t trafficgen_rate);
signed Traffic3_unidi (struct plc *, uint8_t trafficgen_rate);
signed Transmit (struct plc *, uint8_t osa [], uint8_t oda []);
signed TxRates2 (struct plc *);
signed UpgradeDevice1 (struct plc *);
signed VersionInfo (struct plc *);
signed VersionInfo1 (struct plc *);
signed VersionInfo2 (struct plc *);
signed WaitForAssoc (struct plc *);
signed WaitForBootLoader (struct plc *);
signed WaitForReset (struct plc *);
signed WaitForRestart (struct plc *);
signed WaitForStart (struct plc *, char buffer [], size_t length);
signed WaitForStart_Destination(struct plc*);
signed WatchdogReport (struct plc *);
signed WriteCFG (struct plc *);
signed WriteExecuteApplet1 (struct plc *, unsigned module, const struct lightning_nvm_header *);
signed WriteExecuteApplet2 (struct plc *, unsigned module, const struct panther_nvm_header *);
signed WriteExecuteFirmware (struct plc *, unsigned module, void const * nvm_header);
signed WriteExecuteFirmware1 (struct plc *, unsigned module, const struct lightning_nvm_header *);
signed WriteExecuteFirmware2 (struct plc *, unsigned module, const struct panther_nvm_header *);
signed WriteExecutePIB (struct plc *, unsigned offset, struct pib_header *);
signed WriteExecuteParameters (struct plc *, unsigned module, void const * nvm_header);
signed WriteExecuteParameters1 (struct plc *, unsigned module, const struct lightning_nvm_header *);
signed WriteExecuteParameters2 (struct plc *, unsigned module, const struct panther_nvm_header *);
signed WriteFirmware (struct plc *, unsigned module, void const * nvm_header);
signed WriteFirmware1 (struct plc *, unsigned module, const struct lightning_nvm_header *);
signed WriteFirmware2 (struct plc *, unsigned module, const struct panther_nvm_header *);
signed WriteMEM (struct plc *, struct _file_ *, unsigned module, uint32_t offset, uint32_t extent);
signed WriteMOD (struct plc *, uint8_t module, void const * memory, size_t extent);
signed WriteNVM (struct plc *);
signed WritePIB (struct plc *);
signed WriteParameters (struct plc *, unsigned module, void const * nvm_header);
signed WriteParameters1 (struct plc *, unsigned module, const struct lightning_nvm_header *);
signed WriteParameters2 (struct plc *, unsigned module, const struct panther_nvm_header *);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#define PLC_FORMAT_HEX 0
#define PLC_FORMAT_DEC 1
#define PLC_FORMAT_BIN 2
#define PLC_FORMAT_ASC 3

#ifndef __GNUC__
#pragma pack (push,1)
#endif

struct __packed plcproperty

{
	uint8_t PROP_OPTION;
	uint8_t PROP_FORMAT;
	uint32_t PROP_NUMBER;
	uint32_t PROP_VERSION;
	uint32_t PROP_LENGTH;
	uint8_t PROP_BUFFER [128];
	uint8_t DATA_FORMAT;
	uint32_t DATA_LENGTH;
	uint8_t DATA_BUFFER [128];
}

plcproperty;

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

signed GetProperty (struct plc *, struct plcproperty *);
signed SetProperty (struct plc *, struct plcproperty *);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

typedef struct __packed plcstation

{
	uint8_t LOC;
	uint8_t CCO;
	uint8_t TEI;
	uint8_t MAC [ETHER_ADDR_LEN];
	uint8_t BDA [ETHER_ADDR_LEN];
	uint16_t TX;
	uint16_t RX;
	char hardware [0x10];
	char firmware [0x80];
	char identity [0x40];
}

plcstation;
typedef struct __packed plcnetwork

{
	signed ifname;
	signed plcstations;
	struct plcstation plcstation [1];
}

plcnetwork;
typedef struct __packed plctopology

{
	signed plcnetworks;
	struct plcnetwork plcnetwork [1];
}

pcltopology;

/*====================================================================*
 *   functions that use struct channel and struct message directly
 *   instead of struct plc;
 *--------------------------------------------------------------------*/

signed FlashMOD (struct channel *, uint8_t module);
signed WriteModule (struct channel *, struct message *, void const * memory, size_t extent);
signed WriteMemory (struct channel *, struct message *, struct _file_ *, uint32_t offset, uint32_t extent);
unsigned LocalDevices (struct channel const *, struct message *, void * memory, size_t extent);
signed Platform (struct channel *, const byte device []);
signed PLCReadParameterBlock (struct channel *, struct message *, void * memory, size_t extent);
signed PLCReadFirmwareImage (struct channel *, struct message *, void * memory, size_t extent);
signed PLCTopology (struct channel *, struct message *, struct plctopology *);
signed PLCTopologyPrint (struct plctopology *);

/*====================================================================*
 *   vs_module_spec message;
 *--------------------------------------------------------------------*/

#define PLC_MODULE_EXECUTE   (1 << 0)
#define PLC_MODULE_ABSOLUTE (1 << 1)
#define PLC_MODULE_RELATIVE (0 << 1)

#define PLC_MODULE_READ_TIMEOUT 5000
#define PLC_MODULE_BOOT_TIMEOUT 60000
#define PLC_MODULE_REQUEST_TIMEOUT 60000
#define PLC_MODULE_WRITE_TIMEOUT 90000

#define PLC_MOD_OP_READ_MEMORY 0x00
#define PLC_MOD_OP_READ_FLASH  0x01
#define PLC_MOD_OP_START_SESSION  0x10
#define PLC_MOD_OP_WRITE_MODULE   0x11
#define PLC_MOD_OP_CLOSE_SESSION  0x12

#define PLC_MODULEID 0x0000
#define PLC_SUBMODULEID 0x0000

#define PLC_MODULEID_MDIO_INIT  0x1000
#define PLC_MODULEID_UART_ASYNC 0x2000
#define PLC_MODULEID_ADDR_ENUM  0x3000
#define PLC_MODULEID_POWER_MGT  0x4000
#define PLC_MODULEID_TR069      0x4001
#define PLC_MODULEID_FORWARDCFG 0x7000
#define PLC_MODULEID_FIRMWARE   0x7001
#define PLC_MODULEID_PARAMETERS 0x7002
#define PLC_MODULEID_SOFTLOADER 0x7003
#define PLC_MODULEID_RESERVED1  0x7004
#define PLC_MODULEID_PIBMERGE   0x7005
#define PLC_MODULEID_RESERVED2  0x7006

typedef struct __packed vs_module_spec

{
	uint16_t MODULE_ID;
	uint16_t MODULE_SUB_ID;
	uint32_t MODULE_LENGTH;
	uint32_t MODULE_CHKSUM;
}

vs_module_spec;

#define PLC_COMMIT_FORCE   (1 << 0)
#define PLC_COMMIT_NORESET (1 << 1)
#define PLC_COMMIT_FACTPIB (1 << 31)

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

signed ModuleSpec (struct _file_ *, struct vs_module_spec *);
signed ModuleSession (struct plc *, unsigned modules, vs_module_spec *);
signed ModuleWrite (struct plc *, struct _file_ *, unsigned module, vs_module_spec *);
signed ModuleRead (struct plc *, struct _file_ *, uint16_t source, uint16_t module, uint16_t submodule);
signed ModuleDump (struct plc *, uint16_t source, uint16_t module, uint16_t submodule);
signed ModuleCommit (struct plc *, uint32_t flags);

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

#ifdef __GNUC__

__attribute__ ((format (printf, 2, 3))) 

#endif

void Request (struct plc *, char const * format, ...);

#ifdef __GNUC__

__attribute__ ((format (printf, 2, 3))) 

#endif

void Confirm (struct plc *, char const * format, ...);

#ifdef __GNUC__

__attribute__ ((format (printf, 2, 3))) 

#endif

void Display (struct plc *, char const * format, ...);

#ifdef __GNUC__

__attribute__ ((format (printf, 2, 3))) 

#endif

void Failure (struct plc *, char const * format, ...);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



