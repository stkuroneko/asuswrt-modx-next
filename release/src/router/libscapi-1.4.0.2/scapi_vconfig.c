/******************************************************************************** 

  Copyright (c) 2014 

  Lantiq Beteiligungs-GmbH & Co. KG 

  Lilienthalstrasse 15, 85579 Neubiberg, Germany  

  For licensing information, see the file 'LICENSE' in the root folder of 

  this software module. 

 ********************************************************************************/ 



/*========================Includes============================*/ 

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <stdarg.h>
#include <string.h>
#include <ltq_api_include.h>
#include <sys/ioctl.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <ltq_api_include.h>



/*====================Implementation==========================*/ 


/*
 ** =============================================================================
 **   Function Name    :scapi_vlanAdd
 **
 **   Description      :Add a vlan interface
 **
 **   Parameters       :pcIfName(IN) -> interface name, nVlan(IN) -> vlan number
 **
 **   Return Value     :Success -> EXIT_SUCCESS, Failure -> Different -ve values
 **
 **   Notes            :Adding same vlan with different interface name type will lead to ioctl failure 
 **
 ** ============================================================================
 */

int scapi_vlanAdd(char* pcIfName, int nVlan)
{
	struct vlan_ioctl_args xIfr = {0};

	int nSkfd = -1;
	int nRet = -EXIT_FAILURE;

	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	xIfr.cmd = ADD_VLAN_CMD;
	strncpy(xIfr.device1, pcIfName, IFNAMSIZ-1);

	xIfr.u.VID = nVlan;

	if(ioctl(nSkfd, SIOCSIFVLAN, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/*
 ** =============================================================================
 **   Function Name    :scapi_vlanDel
 **
 **   Description      :Removes a vlan interface
 **
 **   Parameters       :pcIfName -> interface name with vlan. E.g eth0.512 
 **
 **   Return Value     :Success -> EXIT_SUCCESS, Failure -> Different -ve values
 **
 **   Notes            :Interface should be a vlan interface
 **
 ** ============================================================================
 */

int scapi_vlanDel(char* pcIfName)
{
	struct vlan_ioctl_args xIfr = {0};
	int nSkfd = -1;
	int nRet = -EXIT_FAILURE;

	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	xIfr.cmd = DEL_VLAN_CMD;
	strncpy(xIfr.device1, pcIfName, IFNAMSIZ-1);

	if(ioctl(nSkfd, SIOCSIFVLAN, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}       


/*
 ** =============================================================================
 **   Function Name    :scapi_setVlanNameType
 **
 **   Description      :Sets the way in which vlan interface appears
 **
 **   Parameters       :pcIfName(IN) -> interface name, nNameType(IN)
 **
 **   Return Value     :Success -> EXIT_SUCCESS, Failure -> Different -ve values
 **
 **   Notes            :This will effect the subsequent vlan add API calls
 **
 ** ============================================================================
 */
int scapi_setVlanNameType(char* pcIfName, int nNameType)
{
	pcIfName = pcIfName; /* to avoid unused parameter warning */
	struct vlan_ioctl_args xIfr = {0};

	int nSkfd = -1;
	int nRet = -EXIT_FAILURE;

	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	xIfr.cmd = SET_VLAN_NAME_TYPE_CMD;
	xIfr.u.name_type = nNameType;

	if(ioctl(nSkfd, SIOCSIFVLAN, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/*
 ** =============================================================================
 **   Function Name    :scapi_setVlanFlag
 **
 **   Description      :Turn on or off ethernet header reorders
 **
 **   Parameters       :pcIfName(IN) -> vlan interface name, nFlag(IN) -> 0 or 1
 **
 **   Return Value     :Success -> EXIT_SUCCESS, Failure -> Different -ve values
 **
 **   Notes            : 
 **
 ** ============================================================================
 */      
int scapi_setVlanFlag(char* pcIfName, int nFlag)
{
	struct vlan_ioctl_args xIfr = {0};

	int nSkfd = -1;
	int nRet = -EXIT_FAILURE;

	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	strncpy(xIfr.device1, pcIfName, IFNAMSIZ-1);
	xIfr.cmd = SET_VLAN_FLAG_CMD;
	xIfr.u.flag = nFlag; //can be only 0 or 1. or else ioctl fails

	if(ioctl(nSkfd, SIOCSIFVLAN, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}


/*
 ** =============================================================================
 **   Function Name    :scapi_setVlanEgressIngressMap
 **
 **   Description      :To tag or queue packets with particulat skb priority
 **			 For Ingress Packets having VLAN Priority (range 0-7) nVlanQos, the API sets the skb_priority. While egress the same packet will have VLAN Priority set  **                      as nVlanQos (based on skb_priority set during ingress
 **
 **   Parameters       :pcIfName(IN) -> vlan interface name, nPriority(IN) 
 **
 **   Return Value     :Success -> EXIT_SUCCESS, Failure -> Different -ve values
 **
 **   Notes            :Calling the API multiple times with same priority and qos
 **                      will result in ioctl failure
 **
 ** ============================================================================
 */
int scapi_setVlanEgressIngressMap(char* pcIfName, int nPriority, int nVlanQos)
{
	struct vlan_ioctl_args xIfr = {0};

	int nSkfd = -1;
	int nRet = -EXIT_FAILURE;

	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	strncpy(xIfr.device1, pcIfName, IFNAMSIZ-1);
	xIfr.u.skb_priority = nPriority;
	xIfr.vlan_qos = nVlanQos; //range [0,7]

	if(ioctl(nSkfd, SIOCSIFVLAN, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}


