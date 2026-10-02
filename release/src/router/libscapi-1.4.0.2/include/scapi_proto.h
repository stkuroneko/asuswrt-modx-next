/********************************************************************************
 
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ****************************************************************************** 
 *         File Name    :  scapi_proto.h                                         *
 *         Description  :  prototypes for APIs defined by SCAPI.                 *  
 *  ******************************************************************************/

/*! \file scapi_proto.h
    \brief File contains the API prototypes defined for  system config API 
*/

#ifndef _SCAPI_PROTO_H
#define _SCAPI_PROTO_H

#include <ctype.h>
#include <stdbool.h>
#include <sys/msg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <sys/stat.h>

/** \addtogroup LIBSCAPI */
/* @{ */


/**
 * @brief SCAPI traceroute API
 * @details Traces intermediate hops between host and destination
 *
 * @param[in] args Command line options similar to that of traceroute utility in a single string
 * @param[in] pkt_size Size of each packet
 * @param[out] pTraceRouteResp Pointer to struct where results are stored
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 *
 * @note This API will allocate a buffer for storing route hops which is pointed by 'pxRouteHops' member of 'TraceRouteResp_D'. It is the duty of the caller to free this.
 */
int scapi_traceroute(char *args, int pkt_size, TraceRouteResp_D * pTraceRouteResp);

/**
 * @brief SCAPI killall API
 * @details Sends specified signal to all the processes with specified name
 * @param[in] pcProcessName Process name
 * @param[in] nSignal Signal number
 *
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_killAll(char *pcProcessName, int nSignal);

/**
 * @brief SCAPI ping API
 * @details Pings an address 
 * 
 * @param[in] address Address that you want to ping to
 * @param[in] timeout Time out
 * @param[in] num_ping Number of pings
 * @param[in] size Size of the packet
 * @return UGW_SUCCESS on successful / UGW_FAILURE on failure
 */
int scapi_ping(char *address, uint32 timeout, int num_ping, uint32 size);

/**
 * @brief SCAPI ping6 API
 * @details API to ping an IPv6 address
 * 
 * @param[in] address IPv6 address string
 * @param[in] timeout Time out
 * @param[in] num_ping Number of pings
 * @param[in] size Size of the packet
 * @return UGW_SUCCESS on successful / UGW_FAILURE on failure
 */
int scapi_ping6(char *address, uint32 timeout, int num_ping, uint32 size);

/**
 * @brief SCAPI rmmod API
 * @details API to remove kernel modules
 * 
 * @param[in] pcModuleName Module name that you want to remove
 * @param[in] nOptions Options flag while removing a module
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_rmmod(char *pcModuleName, int nOptions);

/**
 * @brief SCAPI insmod API
 * @details API to insert a kernel module
 * 
 * @param[in] pcModulePath Module name that you want to insert
 * @param[in] pcOptions Options string that you want to specify while inserting a module. Supports same options as that of commandline utility
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_insmod(const char *pcModulePath, const char *pcOptions);

/**
 * @brief SCAPI nslookup API
 * @details API to query name servers to retrieve resource records
 * 
 * @param[in] pxNSLookupQuery Structure which contains query information
 * @param[out] pxNSLookupResp Pointer to struct which contains response information
 * @param[out] pxResult Pointer to RESULT_D array which contains entries of retrieved information
 * @return UGW_SUCCESS on success, UGW_FAILURE on failure
 */
int scapi_nslookup(NSLOOKUP_DIAG_D * pxNSLookupQuery, NSLookupResp_D * pxNSLookupResp, RESULT_D * pxResult);

/**
 * @brief SCAPI dumpleases API
 * @details API to get DHCP leases info
 * 
 * @param[in] file File name where lease info is stored
 * @param[out] dump_lease_info Struct that contains lease info set by API
 * @param[out] no_entry Pointer to buffer which contains 'no. of lease entries' result set by the API
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_dumplease(char *file, struct dump_lease_info **lease_info, int *no_entry);

/**
 * @brief SCAPI reboot API
 * @details API that reboots the system gracefully by performing a sync before bringing the system down
 * @return Won't return
 */
int scapi_reboot(void);

/**
 * @brief SCAPI copy API
 * @details API that copies content of one file to another
 * 
 * @param[out] pcTo Destination file name (with path)
 * @param[in] pcFrom Source file name
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_copy(const char *pcTo, const char *pcFrom);

/**
 * @brief SCAPI get IP address API
 * @details API that gets IP address of an interface
 * 
 * @param[in] pcIfname Interface name
 * @param[out] pcIp Pointer to buffer which holds IP address returned by the API
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_getIfcIpaddr(char *pcIfname, char *pcIp);

/**
 * @brief SCAPI set ipaddress API
 * @details API that sets IP address of an interface
 * 
 * @param[in] pcIfname Interface name
 * @param[in] pcIp IP address string
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setIfcIpaddr(char *pcIfname, char *pcIp);

/**
 * @brief SCAPI get netmask API
 * @details API that gets netmask of an interface
 * 
 * @param[in] pcIfname Interface name
 * @param[out] pcNetmask Pointer to buffer which holds netmask address returned by the API
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_getIfcNetmask(char *pcIfname, char *pcNetmask);

/**
 * @brief SCAPI set netmask API
 * @details API that sets netmask value of an interface
 * 
 * @param[in] pcIfname Interface name
 * @param[in] pcNetmask Netmask
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setIfcNetmask(char *pcIfname, char *pcNetmask);

/**
 * @brief SCAPI Validate mac address API
 * @details API that Validates mac address format.
 * 
 * @param[in] pcMac MacAddress to be Validated
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int32_t scapi_isValidMacAddress(IN const char *pcMac);

/**
 * @brief SCAPI get mac address API
 * @details API that gets mac address of an interface
 * 
 * @param[in] pcIfname Interface name
 * @param[out] pcMac Pointer to buffer which holds mac address returned by the API
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_getIfcMacaddr(char *pcIfname, char *pcMac);

/**
 * @brief SCAPI set mac address API
 * @details API that sets mac address of an interface along with optional octet increment 
 * 
 * @param[in] pcIfname Interface name
 * @param[in] pcMac Mac address
 * @param[in] nOctetInc Octet that you want to increment on the given mac address
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setIfcMacaddr(char *pcIfname, char *pcMac, int nOctetInc);

/**
 * @brief SCAPI get transmission queue length
 * @details API that gets transmission queue length of an interface
 * 
 * @param[in] pcIfname Interface name
 * @param[out] pnTxqueuelen Pointer to queue length result
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_getIfcTxQueuelen(char *pcIfname, int *pnTxqueuelen);

/**
 * @brief SCAPI set transmission queue length API
 * @details API that sets transmission queue length of an interface
 * 
 * @param[in] pcIfname Interface name
 * @param[in] nTxqueuelen Queue length
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setIfcTxQueuelen(char *pcIfname, int nTxqueuelen);

/**
 * @brief SCAPI get interface up/down API
 * @details API to get up/down status of an interface
 * 
 * @param[in] pcIfname Interface name that you want to get status
 * @param[out] status pointer to up/down status result
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_getIfcUpdown(char *pcIfname, bool * status);

/**
 * @brief SCAPI set interface up/down API
 * @details API to bring an interface up/down
 * 
 * @param[in] pcIfname Interface name on which you want to perform up/down operation
 * @param[in] updown up/down value
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setIfcUpdown(char *pcIfname, bool updown);

/**
 * @brief SCAPI vlan add API
 * @details API to add a vlan interface
 * 
 * @param[in] pcIfName Interface name
 * @param[in] nVlan Vlan number
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_vlanAdd(char *pcIfName, int nVlan);

/**
 * @brief SCAPI vlan delete API
 * @details API to delete a vlan interface
 * 
 * @param[in] pcIfName Vlan interface name
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_vlanDel(char *pcIfName);

/**
 * @brief SCAPI set vlan name type API
 * @details API to determine how a vlan interface name will be formatted
 * 
 * @param[in] pcIfName Interface name
 * @param[in] nNameType Interface name type
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setVlanNameType(char *pcIfName, int nNameType);

/**
 * @brief SCAPI set vlan flag API
 * @details API to set a flag for a vlan interface
 * 
 * @param[in] pcIfName Vlan interface name
 * @param[in] nFlag Flag to be set
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setVlanFlag(char *pcIfName, int nFlag);

/**
 * @brief SCAPI vlan set egress ingress map API
 * @details API to set egress and ingress map of a vlan interface
 * 
 * @param[in] pcIfName Interface name
 * @param[in] nPriority Priority value
 * @param[in] nVlanQos Qos
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_setVlanEgressIngressMap(char *pcIfName, int nPriority, int nVlanQos);

/**
 * @brief SCAPI get ifconfig stats API
 * @details API to get statistics of a given interface extracted from /proc/net/dev
 * 
 * @param[in] name Interface name
 * @param[out] if_list Pointer to struct which contains stats set by API
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_ifconfigStats(char *name, INTERFACE * if_list);

/**
 * @brief SCAPI bridge add API
 * @details API to add a new bridge
 * 
 * @param[in] br Bridge name
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */

int scapi_brAdd(char *br);

/**
 * @brief SCAPI bridge delete API
 * @details API to delete a bridge
 * 
 * @param[in] br Bridge name
 * @return EXIT_SUCCESS on successful / -ve value depending on the type of error in case of failure
 */
int scapi_brDel(char *br);

/**
 * @brief SCAPI add bridge interface API
 * @details API to add a new bridge interface
 * 
 * @param[in] br Bridge name
 * @param[in] ifname Interface name
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_brAddIf(char *br, char *ifname);

/**
 * @brief SCAPI delete bridge interface API
 * @details API to delete a bridge interface
 * 
 * @param[in] br Bridge name
 * @param[in] ifname Interface name
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_brDelIf(char *br, char *ifname);

/**
 * @brief SCAPI set STP API
 * @details API to enable/disable bridge STP
 * 
 * @param[in] br Bridge name
 * @param[in] option Option to enable/disable
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */

int scapi_brSetStp(char *br, bool option);

/**
 * @brief SCAPI set bridge priority API
 * @details API to set the bridge's relative priority. The bridge with the lowest priority will be elected as the root bridge
 * 
 * @param[in] br Bridge interface name
 * @param[in] br_option Priority value option
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */

int scapi_brSetPrio(char *br, unsigned int br_option);

/**
 * @brief SCAPI set hello API
 * @details API to send hello packets every 'time' secs which are used to communicate information about the topology throughout the entire Bridged Local Area Network
 * 
 * @param[in] br Bridge interface name
 * @param[in] time Time in seconds
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_brSetHello(char *br, char *time);

/**
 * @brief SCAPI bridge age set API
 * @details The aging time is the number of seconds a MAC-address will be kept in the forwarding database, after having received a packet from this MAC address.
 * 
 * @param[in] br Bridge interface name
 * @param[in] time Time in seconds
 * 
 * @return EXIT_SUCCESS on successful / -EXIT_FAILURE on failure
 */
int scapi_brSetAge(char *br, char *time);

/**
 * @brief SCAPI set bridge farward delay time
 * @details API to set time spent in each of the Listening and Learning states before the Forwarding state is entered
 * 
 * @param br Bridge interface name
 * @param time Time in seconds
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_brFwdDelay(char *br, char *time);

/**
 * @brief SCAPI set bridge max age API
 * @details API to set the maximum message age. If the last seen (received) hello packet is more than this number of seconds old, the bridge in question will start the takeover procedure in attempt to become the Root Bridge itself
 * 
 * @param br bridge interface name
 * @param time Time
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_brSetMaxAge(char *br, char *time);

/**
 * @brief SCAPI gets next MAC address API
 * @details API that generates a MAC address for an interface by properly incrementing the base MAC address without any conflicts (with MAC addresses of other interfaces)
 * @param[in] pcIfname Interface name for which a MAC address should be generated
 * @param[in] pcMac Pointer to a buffer where generated MAC address will be stored
 * 
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_getNextMacaddr(char *pcIfname, char *pcMac);

/**
 * @brief SCAPI remove next MAC address API
 * @details API that removes the entry of generated MAC address for an interface from the config file
 * 
 * @param[in] pcIfname Interface name of the entry to deleted
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_removeNextMacaddr(char *pcIfname);

/**
 * @brief SCAPI spawn API
 * @details API to fork a new shell and carry out a given operation and collect exit status of the child process (of the shell)
 * 
 * @param[in] pcBuf Command to be executed by the shell
 * @param[in] nBlockingFlag Flag that determines if the command is blocking or non blocking
 * @param[out] pnChildExitStatus Exit status of the child process (of the shell)
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 * 
 * @note 1. Spawn daemons in non-blocking mode.
 * @note 2. Spawn utilities in blocking mode. For every utility which is executed in non-blocking,
 *       it is assumed that parent handles the SIGCHLD signal and does wait() or waitpid() in that
 *       signal handler. If not, then the child will stay as a zombie until parent exits
 * @note 3. If int pointed by pnChildExitStatus is greater than 128, then it possibly means that
 *       the executed process (from shell) exited due to an unhandled signal. It is expected that the user programs
 *       spawned by this API doesn't do exit() with a value greater than or equal to 128
 */
int scapi_spawn(char *pcBuf, int nBlockingFlag, int *pnChildExitStatus);

/**
 * @brief SCAPI route add API
 * @details API to add an entry into kernel's routing table
 * 
 * @param[in] pcDest Address of destination network or host
 * @param[in] pcGateway Gateway address
 * @param[in] pcGenmask Netmask address
 * @param[in] pcDev Interface name
 * @param[in] nMetric Metric associated with a route. Distance to the target (counted in hops)
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_routeAdd(char *pcDest, char *pcGateway, char *pcGenmask, char *pcDev, int nMetric);

/**
 * @brief SCAPI route delete API
 * @details API to delete an entry from kernel's routing table
 * 
 * @param[in] pcDest Address of destination network or host
 * @param[in] pcGateway Address of gateway
 * @param[in] pcGenmask Address of netmask
 * @param[in] pcDev Interface name
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
int scapi_routeDel(char *pcDest, char *pcGateway, char *pcGenmask, char *pcDev);

/**
 * @brief SCAPI get process name API
 * @details API to get process name when PID is provided
 * 
 * @param[in] process_num PID
 * @return EXIT_SUCCESS on successful / -ve value (depending on the type of error) on failure
 */
char *scapi_get_process_name(pid_t process_num);

/*! \brief API for command line utility of controld 
*/
int32_t ControlDCtl(eControlDOption_t eControlDOption, ControlDArgs_t * pxControlDArgs);

/**
 * @brief SCAPI procd spawn API
 * @details API to spawn a process through procd
 * 
 * @param[in] pcAction Action to be done on the process. Start/Stop
 * @param[in] pxProcdObj Pointer to ProcdObj, which is used to construct the Ubus message
 * 
 * @return UGW_SUCCESS on successful / UGW_FAILURE on failure
 */
int32_t scapi_procdSpawn(char *pcAction, ProcdObj * pxProcdObj);

/**
 * @brief SCAPI get memory information API
 * @details API to get memory information from proc entries
 * 
 * @param[out] xInfo pointer to struct that contains memory info set by API
 * @return EXIT_SUCCESS on successful / -EXIT_FAILURE on failure
 */
int scapi_getMeminfo(MemInfo * pxInfo);

/**
 * @brief SCAPI get CPU information API
 * @details API to get CPU information from proc entries
 * 
 * @param[out] xInfo pointer to struct that contains memory info set by API
 * @return EXIT_SUCCESS on successful / -EXIT_FAILURE on failure
 */
int scapi_getCPUInfo(CPUInfo *xInfo);

/**
 * @brief  SCAPI get Hardware Version API
 * @details API to get Hardware Version information from proc entries
 * @param[out] char pointer which contains Hardware Version set by API
 * @return EXIT_SUCCESS in case of success, -EXIT_FAILURE in case of failure
 */
int32_t scapi_getHardwareVersion(char *pcHwVer);

/**
 * @brief  SCAPI get Model Name API
 * @details API to get Model Name information from config.sh entries
 * @param[out] char pointer which contains Model Name set by API
 * @return EXIT_SUCCESS in case of success, -EXIT_FAILURE in case of failure
 */
int32_t scapi_getModelName(char *pcModelName);

/**
 * @brief SCAPI get arp table API
 * @details SCAPI to get ARP table API
 * 
 * @param[out] pxArpTable Pointer to struct that contains ARP entries set by API
 * @return UGW_SUCCESS on successful / UGW_FAILURE on failure
 */
int scapi_getArpTable(arpTable_t * pxArpTable);

/**
 * @brief SCAPI get MAC table API
 * @details API to fetch MAC table of an interface
 * 
 * @param[out] macTable Pointer to struct which contains MAC entries set by API
 * @param[in] pIntFace Interface name
 * 
 * @return UGW_SUCCESS on successful / UGW_FAILURE on failure
 */
int scapi_getMacTable(macTable_t * pxMacTable, char *pIntFace);

/**
 * @brief SCAPI encrypt file
 * @details SCAPI to encrypt the file with given password
 * 
 * @param[IN] pcInFile file to encrypt  
 * @param[IN] pcPassWd password key
 * @param[OUT] pcOutFile output file name to encrypt to

 * @return UGW_SUCCESS on successful / UGW_FAILURE on failure
 */
int scapi_encryption(IN char *pcInFile, IN char *pcPassWd, OUT char *pcOutFile);

/**
 * @brief SCAPI decrypt file
 * @details SCAPI to decrypt the file with given password
 * 
 * @param[IN] pcInFile file to decrypt  
 * @param[IN] pcPassWd password key
 * @param[OUT] pcOutFile output file name to decrypt in.

 * @return UGW_SUCCESS on successful / UGW_FAILURE on failure
 */
int scapi_decryption(IN char *pcInFile, IN char *pcPassWd, OUT char *pcOutFile);

/*!  \brief  This function is used to create procd param list
  \param[IN] pxParamList Pointer to the Procd param list structure used to construct ubus command
  \param[IN] pcParamName Name of the parameter to be added 
  \param[IN] pcParamValue Value of the parameter to be added 
  \return Pointer to the new paramlist on success / NULL on failure
 */
ProcdParamList *scapi_setProcdParamList(IN ProcdParamList * pxParamList, IN const char *pcParamName, IN const char *pcParamValue);

/*!  \brief  This function used to initialize the Procd obj to default
  \param[IN] pxProcdObj Pointer to the ProcdObj structure for the initialization
  \return EXIT_SUCCESS
 */
int scapi_initializeProcdObj(IN ProcdObj * pxProcdObj);

/*!
    \brief function to allocate memory for Procd param list
    \return Parameter list ptr 
*/
void *scapi_createProcdParam(void);

/*!  \brief Wrapper function to start crond daemon
  \return  EXIT_SUCCESS or the error code.
  */
int32_t scapi_startCrond(void);

/*!  \brief Wrapper function to stop crond daemon
  \return  EXIT_SUCCESS or the error code.
  */
int32_t scapi_stopCrond(void);

/*!  \brief Wrapper function to Restart crond daemon
  \return  EXIT_SUCCESS or the error code.
  */
int32_t scapi_restartCrond(void);

/*!  \brief Write to the configuration file with given inputs
  \param[in] pcMin Pointer to minutes.
  \param[in] pcHour Pointer to hour.
  \param[in] pcDayOfMon Pointer to Day of month.
  \param[in] pcMonth Pointer to month.
  \param[in] pcDayOfWeek Pointer to Day of week.
  \param[in] pcCommand Pointer to command to be executed.
  \param[in] nAction Action to be performed. addition or deletion from a file
  \return  UGW_SUCCESS or the error code.
  */
int32_t scapi_setCronjob(IN char *pcMin, IN char *pcHour, IN char *pcDayOfMon, IN char *pcMonth, IN char *pcDayOfWeek, IN char *pcCommand, IN int32_t nAction);

/*!  \brief function to get mac address
  \param[in] pcMac mac address holder.
  \return  mac address on UGW_SUCCESS or the error code.
  */
int32_t  scapi_getBaseMac(char* pcMac);


/* @} */
#endif				// _SCAPI_PROTO_H
