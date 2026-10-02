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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <net/route.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <ltq_api_include.h>

/* 
 ** =============================================================================
 **   Function Name    :scapi_routeAdd
 **
 **   Description      :Adds a kernel route entry
 **
 **   Parameters       :pcDest(IN) -> Destination n/w or host
 **                     pcGateway(IN) -> Gateway
 **                     pcGenmask(IN) -> mask for destination
 **                     pcDev(IN) -> Interface name
 **						nMetric(IN) -> Metric
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :No options are setby default. E.g Just Providing
 **						pcGateway option with pcDest and pcGenmask as NULL wouldn't create
 **						default pcGateway entry. pcDest and pcGenmask should be explicitly
 **						given as '0.0.0.0'
 **                     eg. route add default pcGateway x.x.x.x --> scapi_routeAdd("0.0.0.0", "x.x.x.x", "0.0.0.0", NULL);
 **
 ** ============================================================================
 */

int scapi_routeAdd(char *pcDest, char *pcGateway, char *pcGenmask, char *pcDev, int nMetric)
{
	struct rtentry xRoute = {0};
	struct sockaddr_in *pxAddr = NULL;

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

	if(pcDest == NULL || pcGateway == NULL || pcGenmask == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d\n", nRet);
		goto returnHandler;
	}
	/* settin pcGateway */
	pxAddr = (struct sockaddr_in*) &xRoute.rt_gateway;
	pxAddr->sin_family = AF_INET;
	pxAddr->sin_addr.s_addr = inet_addr(pcGateway);
	/* setting destination */
	pxAddr = (struct sockaddr_in*) &xRoute.rt_dst;
	pxAddr->sin_family = AF_INET;
	pxAddr->sin_addr.s_addr = inet_addr(pcDest);
	/* setting mask */
	pxAddr = (struct sockaddr_in*) &xRoute.rt_genmask;
	pxAddr->sin_family = AF_INET;
	pxAddr->sin_addr.s_addr = inet_addr(pcGenmask);
	/*default gateway. UG Flag */
	if(!strcmp(pcDest, "0.0.0.0") && !strcmp(pcGenmask, "0.0.0.0"))
		xRoute.rt_flags = RTF_UP | RTF_GATEWAY;
	/*host type destination. UH Flag*/
	if(!strcmp(pcGenmask, "255.255.255.255"))
		xRoute.rt_flags = RTF_UP | RTF_HOST;
	if(nMetric > 0)
		xRoute.rt_metric = nMetric;
	else
		xRoute.rt_metric = 0;

	if(pcDev != NULL)
		xRoute.rt_dev = pcDev;

	if(ioctl(nSkfd, SIOCADDRT, &xRoute) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	if(nSkfd != -1)
		close(nSkfd);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_routeDel
 **
 **   Description      :Deletes a kernel route entry
 **
 **   Parameters       :pcDest(IN) -> Destination n/w or host
 **                     pcGateway(IN) -> Gateway
 **						pcGenmask(IN) -> mask for destination
 **						pcDev(IN) -> Interface name
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values 
 ** 
 **   Notes            :
 **
 ** ============================================================================
 */

int scapi_routeDel(char* pcDest, char* pcGateway, char* pcGenmask, char* pcDev)
{
	struct rtentry xRoute = {0};
	struct sockaddr_in *pxAddr = NULL;

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

	if(pcDest == NULL || pcGateway == NULL || pcGenmask == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d\n", nRet);
		goto returnHandler;
	}
	/* gateway */
	pxAddr = (struct sockaddr_in*) &xRoute.rt_gateway;
	pxAddr->sin_family = AF_INET;
	pxAddr->sin_addr.s_addr = inet_addr(pcGateway);
	/* destination */
	pxAddr = (struct sockaddr_in*) &xRoute.rt_dst;
	pxAddr->sin_family = AF_INET;
	pxAddr->sin_addr.s_addr = inet_addr(pcDest);
	/* mask */
	pxAddr = (struct sockaddr_in*) &xRoute.rt_genmask;
	pxAddr->sin_family = AF_INET;
	pxAddr->sin_addr.s_addr = inet_addr(pcGenmask);
	/* default Gateway. UG Flag */
	if(!strcmp(pcDest, "0.0.0.0") && !strcmp(pcGenmask, "0.0.0.0"))
		xRoute.rt_flags = RTF_UP | RTF_GATEWAY;
	/* dest is host. UH Flag */
	if(!strcmp(pcGenmask, "255.255.255.255"))
		xRoute.rt_flags = RTF_UP | RTF_HOST;

	//xRoute.rt_metric = 0;

	if(pcDev != NULL)
		xRoute.rt_dev = pcDev;
	if(ioctl(nSkfd, SIOCDELRT, &xRoute) < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	nRet = EXIT_SUCCESS;
returnHandler:
	if(nSkfd != -1)
		close(nSkfd);
	return nRet;
}
