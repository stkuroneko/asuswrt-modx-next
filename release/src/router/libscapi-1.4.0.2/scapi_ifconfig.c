/*****************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/***************************************************************************** *
 *     File Name  : scapi_ifconfig.c                                           *
 *     Project    : UGW                                                        *
 *     Description: cal - ifconfig set and get APIs                            *
 *                                                                             *
 ******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <ltq_api_include.h>

#ifndef LOG_LEVEL
uint16_t LOGLEVEL = SYS_LOG_DEBUG + 1;
#else
uint16_t LOGLEVEL = LOG_LEVEL + 1;
#endif

#ifndef LOG_TYPE
uint16_t LOGTYPE = SYS_LOG_TYPE_FILE;
#else
uint16_t LOGTYPE = LOG_TYPE;
#endif

/* 
 ** =============================================================================
 **   Function Name    :scapi_getIfcIpaddr
 **
 **   Description      :Gets ipv4 address of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **			pcIp(OUT) -> resultant ip address. 
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **			Failure -> Different -ve values 
 ** 
 **   Notes            :Its duty of the top layer to allocate for ip address and pass the pointer  
 **
 ** ============================================================================
 */

int scapi_getIfcIpaddr(char* pcIfname, char* pcIp)
{
	int nSkfd = -1, nRet = -EXIT_FAILURE;
	struct ifreq xIfr ={.ifr_ifru={0}};  //gcc bug w.r.t structs when '-Werror=missing-field-initializers' is enabled

	nSkfd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(nSkfd < 0) 
	{ 
		nRet = -errno; 
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler; 
	} 
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);	


	if(pcIfname == NULL || pcIp == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet)); 
		goto returnHandler;
	}
	/* Preparing ioctl to get ipv4 address */
	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);
	if(ioctl(nSkfd, SIOCGIFADDR, &xIfr) < 0)
	{
		/*  might create problem in multithreaded environmet. What's the
		 *  solution ??*/
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	/* Top layer should provide a NULL terminated array of size INET_ADDRSTRLEN */
	strncpy(pcIp, inet_ntoa(((struct sockaddr_in *)&xIfr.ifr_addr)->sin_addr), INET_ADDRSTRLEN-1);
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_setIfcIpaddr
 **
 **   Description      :Sets ipv4 address of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     pcIp(IN) -> ip address to be set. 
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            : 
 **
 ** ============================================================================
 */

int scapi_setIfcIpaddr(char* pcIfname, char* pcIp)
{

	struct ifreq xIfr = {.ifr_ifru={0}};

	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	if(pcIfname == NULL || pcIp == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);

	inet_pton(AF_INET, pcIp, &(((struct sockaddr_in *)&xIfr.ifr_addr)->sin_addr));

	if(ioctl(nSkfd, SIOCSIFADDR, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_getIfcNetmask
 **
 **   Description      :Gets netmask of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     pcNetmask(OUT) -> resultant netmask. 
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :Its duty of the top layer to allocate for netmask address and pass the pointer  
 **
 ** ============================================================================
 */

int scapi_getIfcNetmask(char* pcIfname, char* pcNetmask)
{

	struct ifreq xIfr ={.ifr_ifru={0}};
	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	if(pcIfname == NULL || pcNetmask == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	/* Preparing ioctl to get ipv4 address */
	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);
	if(ioctl(nSkfd, SIOCGIFNETMASK, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	/* Top layer should provide a NULL terminated array of size INET_ADDRSTRLEN */
	strncpy(pcNetmask, inet_ntoa(((struct sockaddr_in *)&xIfr.ifr_addr)->sin_addr), INET_ADDRSTRLEN-1);
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_setIfcNetmask
 **
 **   Description      :Sets netmask of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     pcNetmask(IN) -> resultant netmask. 
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            : 
 **
 ** ============================================================================
 */


int scapi_setIfcNetmask(char* pcIfname, char* pcNetmask)
{

	struct ifreq xIfr = {.ifr_ifru={0}};

	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	if(pcIfname == NULL || pcNetmask == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);

	inet_pton(AF_INET, pcNetmask, &(((struct sockaddr_in *)&xIfr.ifr_addr)->sin_addr));

	if(ioctl(nSkfd, SIOCSIFNETMASK, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_getIfcMacaddr
 **
 **   Description      :Gets mac address of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                      pcMac(OUT) -> resultant mac address. 
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                      Failure -> Different -ve values 
 ** 
 **   Notes            :Top layer should allocate a NULL terminated array of size SCAPI_MAC_LEN  
 **
 ** ============================================================================
 */

int scapi_getIfcMacaddr(char* pcIfname, char* pcMac)
{

	struct ifreq xIfr = {.ifr_ifru={0}};

	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);

	if(pcIfname == NULL || pcMac == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	//xIfr.ifr_addr.sa_family = AF_INET;
	xIfr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);
	if(ioctl(nSkfd, SIOCGIFHWADDR, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	/* Top layer should provide a NULL terminated array of size SCAPI_MAC_LEN */
	/* get result */
	sprintf(pcMac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			(unsigned char)xIfr.ifr_hwaddr.sa_data[0],
			(unsigned char)xIfr.ifr_hwaddr.sa_data[1],
			(unsigned char)xIfr.ifr_hwaddr.sa_data[2],
			(unsigned char)xIfr.ifr_hwaddr.sa_data[3],
			(unsigned char)xIfr.ifr_hwaddr.sa_data[4],
			(unsigned char)xIfr.ifr_hwaddr.sa_data[5]);
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_setIfcMacaddr
 **
 **   Description      :Sets mac address of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     pcMacaddr(IN) -> mac address to be set. 
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :Setting the same mac address as current one is causing the
 **			IOCTL to fail. This behaviour is not observed for ip & netmask or txqueue length
 **
 ** ============================================================================
 */

int scapi_setIfcMacaddr(char* pcIfname, char* pcMac, int nOctetInc)
{

	struct ifreq xIfr = {.ifr_ifru={0}};

	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);
	if(pcIfname == NULL || pcMac == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	xIfr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);	

	sscanf(pcMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
			&(xIfr.ifr_hwaddr.sa_data[0]), 
			&(xIfr.ifr_hwaddr.sa_data[1]), 
			&(xIfr.ifr_hwaddr.sa_data[2]),
			&(xIfr.ifr_hwaddr.sa_data[3]),
			&(xIfr.ifr_hwaddr.sa_data[4]),
			&(xIfr.ifr_hwaddr.sa_data[5]));

	if(nOctetInc == 4  || nOctetInc == 5){
		int nCurrentIndex = nOctetInc, nParentIndex = nOctetInc-1;

		xIfr.ifr_hwaddr.sa_data[nCurrentIndex] += 1;
		
		/* If incremented value is 00, that means old octet is
		 * FF. You need to increment the parent index octet in
		 * this case
		 */
		for(;xIfr.ifr_hwaddr.sa_data[nCurrentIndex] == 0;){
			xIfr.ifr_hwaddr.sa_data[nParentIndex] += 1;
			nCurrentIndex = nParentIndex;
			nParentIndex = nParentIndex -1;

			/* only last 3 octets are allowed to change */

			/* Extreme case: 
			 * XX:XX:XX:FF:FF:FF ---> XX:XX:XX:00:00:00
			 */
			if(nParentIndex < 3)
				break;
		}
	}
	/* If provided octed is >=0 but not 4 or 5 */
	else if(nOctetInc >= 0){
		nRet = -EINVAL;
		LOGF_LOG_DEBUG("DEBUG = You cannot change any octets other than 4 or 5");
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	if(ioctl(nSkfd, SIOCSIFHWADDR, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_getIfcTxQueuelen
 **
 **   Description      :Gets tx queue length of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     pnTxqueuelen(OUT) -> queue len 
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :
 **
 ** ============================================================================
 */

int scapi_getIfcTxQueuelen(char *pcIfname, int* pnTxqueuelen)
{

	struct ifreq xIfr = {.ifr_ifru={0}};

	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);
	if(pcIfname == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);

	if(ioctl(nSkfd, SIOCGIFTXQLEN, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	*pnTxqueuelen = xIfr.ifr_qlen;
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_setIfcTxQueuelen
 **
 **   Description      :Sets tx queue length of an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     nTxqueuelen(IN) -> queue len to be set
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :
 **
 ** ============================================================================
 */

int scapi_setIfcTxQueuelen(char* pcIfname, int nTxqueuelen)
{

	struct ifreq xIfr = {.ifr_ifru={0}};

	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);
	if(pcIfname == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);
	xIfr.ifr_qlen = nTxqueuelen;

	if(ioctl(nSkfd, SIOCSIFTXQLEN, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}	

/* 
 ** =============================================================================
 **   Function Name    :scapi_getIfcUpdown
 **
 **   Description      :Gets the interface status whether it is up or down
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     status(OUT) -> up/down status. 0(down), 1(up)
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :
 **
 ** ============================================================================
 */

int scapi_getIfcUpdown(char *pcIfname, bool* status)
{

	struct ifreq xIfr = {.ifr_ifru={0}};
	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);
	if(pcIfname == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);
	if(ioctl(nSkfd, SIOCGIFFLAGS, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}	

	/* returning status */
	xIfr.ifr_flags & IFF_UP ? (*status = true):(*status = false);
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_setIfcUpdown
 **
 **   Description      :Brings up/down an interface
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                     updown(IN) -> 0(DOWN), 1(UP)
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :
 **
 ** ============================================================================
 */
int scapi_setIfcUpdown(char* pcIfname, bool updown)
{

	struct ifreq xIfr = {.ifr_ifru={0}}; 
	int nSkfd = -1, nRet = -EXIT_FAILURE;
	nSkfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(nSkfd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fcntl(nSkfd, F_SETFD, fcntl(nSkfd, F_GETFD) | FD_CLOEXEC);
	if(pcIfname == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	xIfr.ifr_addr.sa_family = AF_INET;
	strncpy(xIfr.ifr_name, pcIfname, IFNAMSIZ-1);

	/* Makin sure that setting interface updown flags doesn't reset other flags */
	if(ioctl(nSkfd, SIOCGIFFLAGS, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	if(1 == updown) 
		xIfr.ifr_flags |= IFF_UP;
	else if(0 == updown)
		xIfr.ifr_flags &= (~IFF_UP);

	if(ioctl(nSkfd, SIOCSIFFLAGS, &xIfr) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	close(nSkfd);
	return nRet;
}
