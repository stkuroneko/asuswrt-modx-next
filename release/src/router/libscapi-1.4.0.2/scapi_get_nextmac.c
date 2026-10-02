/*****************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/***************************************************************************** *
 *     File Name  : scapi_get_nextmac.c                                        *
 *     Project    : UGW                                                        *
 *     Description: API to get next mac address by validating mac address
 *                  other interfaces                                           *
 *                                                                             *
 ******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
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
#include <glob.h>
#include <ltq_api_include.h>
#include <regex.h>


#define NEXT_MAC_CONF "/opt/lantiq/etc/nextmac.conf"
#define BOOT_CHK "/tmp/.bootchk"
#define GLOB_INTERFACES "/sys/class/net/*/address"
#define MAC_IN_USE 422

/* 
 ** =============================================================================
 **   Function Name    :scapi_incrementMacaddr
 **
 **   Description      :Increments mac address properly till last 3 octets
 **
 **   Parameters       :pxIfr(IN) -> Pointer to ifreq type struct which is holding mac
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values
 **   
 **   NOTES            :If incremented mac has reached the maximum condition of XX:XX:XX:FF:FF:FF,
 **			API will fail
 ** ============================================================================
 */
static int scapi_incrementMacaddr(struct ifreq *pxIfr){
	int nRet = -EXIT_FAILURE;
	int nCurrentIndex = 5, nParentIndex = 4;

	pxIfr->ifr_hwaddr.sa_data[nCurrentIndex] += 1;

	/* If incremented value is 00, that means old octet is
	 * FF. You need to increment the parent index octet in
	 * this case
	 */
	for(;pxIfr->ifr_hwaddr.sa_data[nCurrentIndex] == 0;){
		/* only last 3 octets are allowed to change */

		/* Extreme case: 
		 * XX:XX:XX:FF:FF:FF ---> XX:XX:XX:00:00:00
		 *                                   */
		if(nParentIndex < 3){
			nRet = -EINVAL;
			goto returnHandler;
		}

		pxIfr->ifr_hwaddr.sa_data[nParentIndex] += 1;
		nCurrentIndex = nParentIndex;
		nParentIndex = nParentIndex -1;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_getMacFromFile
 **
 **   Description      :gets mac address of an interface from config file(NEXT_MAC_CONFIG)
 **
 **   Parameters       :pcMac(OUT) -> Pointer to a buffer which will hold the mac
 **                                     address returned by this API
 **			pcIfname(IN) -> Interface name
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                      Failure -> Different -ve values 
 ** ============================================================================
 */
static int scapi_getMacFromFile(char* pcIfname,char* pcMac){
	FILE *fp = fopen(NEXT_MAC_CONF, "ab+");
	char line[64] = {0};

	char* saveptr = NULL;
	char* token = NULL;
	bool got_mac = false;

	char interfaceName[32] = {0};

	int nRet = -EXIT_FAILURE;

	if(fp == NULL){
		nRet = -2;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	/* or else 'eth0' will match with eth0_1 during strstr */
	sprintf(interfaceName, "%s>", pcIfname);
	while (fgets(line, sizeof(line), fp)) {
		char *pos;
		if ((pos=strchr(line, '\n')) != NULL)
			*pos = '\0';

		char* pcFind = strstr(line, interfaceName);
		/* Interface found */
		if( pcFind != NULL){
			/* strtok is used so that we don't have to trim
			 * extra white spaces. We have to do it manually
			 * with strchr*/
			token = strtok_r(pcFind, "> ", &saveptr);
			/* This is our mac address */
			token = strtok_r(NULL, "> ", &saveptr);
			if (token == NULL){
				nRet = -EINVAL;
				LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
				goto returnHandler;
			}
			else{
				got_mac = true;
				sprintf(pcMac, "%s", token);
			}
			break;
		}

	}

	/* We parsed whole file but could not retreive mac address of
	 * the interface */
	if(got_mac != true){
		nRet = -EXIT_FAILURE;
		LOGF_LOG_DEBUG("Error = Couldn't get mac for the interface\n");
		goto returnHandler;
	}

	nRet = EXIT_SUCCESS;
	LOGF_LOG_DEBUG("GOT NEXMAC FROM CONFIG FILE\n");
returnHandler:
	if(fp != NULL)
		fclose(fp);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_validateMacaddr
 **
 **   Description      :Validates a given mac address (incremented) with the mac
 **			addresses of other interfaces in the system as well as
 **			with the interfaces (which might be not added to the system yet)
 **			in the config file
 **
 **   Parameters       :pcMac(IN) -> Mac address to be validated
 **                     pcIfName(IN) -> Interface name
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                      Failure -> Different -ve values
 **
 **   NOTES            :Doesn't validate with mac of pcIfname because it might be garbage
 **			When the interface is just up 
 ** ============================================================================
 */
static int scapi_validateMacaddr(char* pcIfname, char* pcMac){
	int nRet = -EXIT_FAILURE;
	FILE *fp = fopen(NEXT_MAC_CONF, "r");
	char ifcStr[64] = {0};
	glob_t results = {0};
	char line[128] = {0};


	if(fp == NULL){
		nRet = -EXIT_FAILURE;
		LOGF_LOG_ERROR("Couldn't get interfaces\n");
		goto returnHandler;
	}

	nRet = glob(GLOB_INTERFACES, 0, NULL, &results);

	if(nRet != 0){
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	unsigned int i = 0;
	/* Validate the mac with interfaces in the system */
	/* Loop through all interfaces interfaces in the system and
	 * validate*/
	for (i = 0; i < results.gl_pathc; i++){
		sprintf(ifcStr, "%s", results.gl_pathv[i]);
		char* pcCurrentIfName = strrchr(ifcStr, '/');
		if(pcCurrentIfName == NULL){
			nRet = -EXIT_FAILURE;
			LOGF_LOG_ERROR("Couldn't get interface name\n");
			goto returnHandler;
		}
		*pcCurrentIfName = '\0';
		pcCurrentIfName = strrchr(ifcStr, '/');
		pcCurrentIfName++;
		/* Validate against all other interfaces except pcIfname*/
		if(strcmp(pcIfname, pcCurrentIfName) != 0){
			char pcMacIfc[SCAPI_MAC_LEN] = {0};
			nRet = scapi_getIfcMacaddr(pcCurrentIfName, pcMacIfc);
			if( nRet < 0){
				nRet = -EXIT_FAILURE;
				LOGF_LOG_ERROR("Couldn't get interfaces\n");
				goto returnHandler;
			}
			//printf("Interface = %s, IfcMac = %s, MacTest = %s\n", pcCurrentIfName, pcMacIfc, pcMac);
			/* If a match is found. Current mac is invalid*/
			if( strcmp(pcMac, pcMacIfc) == 0){
				nRet = -MAC_IN_USE;
				LOGF_LOG_DEBUG("Next mac validation failed. Mac should be incremented further\n");
				goto returnHandler;
			}
		}
	}

	/* Validate with interfaces in config file now. Some interfaces
	   might be added to the config but not to the system */
	while (fgets(line, sizeof(line), fp)) {
		char *pos;
		if ((pos=strchr(line, '\n')) != NULL)
			*pos = '\0';
		//printf("Line = %s, MacTest = %s\n", line, pcMac);
		char* pcFind = strstr(line, pcMac);
		/* This mac is already in use for some other interface*/
		if( pcFind != NULL){
			nRet = -MAC_IN_USE;
			LOGF_LOG_ERROR("ERROR = %d. Mac in use by other interface\n", nRet);
			LOGF_LOG_DEBUG("%s is in use by some other interface. Increment further\n", pcMac);
			goto returnHandler;
		}

	}
	nRet = EXIT_SUCCESS;
returnHandler:
	globfree(&results);
	if(fp != NULL)
		fclose(fp);
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_getBaseMac
 **
 **   Description      :Gets base mac from /proc/cmdline.
 **
 **   Parameters       :pcMac(OUT) -> Pointer to a buffer which will hold the mac
 **					address returned by this API
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                      Failure -> Different -ve values 
 ** ============================================================================
 */

int scapi_getBaseMac(char* pcMac){
	FILE* fpProc = NULL;
	char fbuf[512] = {0};
	//char proc_mac_addr[32] = {0};
	int nRet = -EXIT_FAILURE, check = 0;
	struct stat st;

	check = stat("/nvram/appcpu.cfg", &st);
	if(!check) {
		fpProc = popen("/usr/sbin/nvram_env.sh get ethaddr", "r");
	} else {
		fpProc = fopen("/proc/cmdline", "r");
	}
	if (fpProc == NULL)
	{
		if (!check) {
			LOGF_LOG_DEBUG("popen(/usr/sbin/nvram_env.sh) failed due to '%m'\n");
		} else {
			LOGF_LOG_DEBUG("/proc/cmdline not found!!\n");
		}
		nRet = -EXIT_FAILURE;
		goto returnHandler;
	}
	else
	{
		char *p = fgets(fbuf, sizeof(fbuf), fpProc);
		if (p == NULL) {
			LOGF_LOG_DEBUG("fgets failed due to '%m'\n");
			nRet = -EXIT_FAILURE;
			goto returnHandler;
		}
		if (!check) {
			p = fbuf;
		} else {
			p = strstr(fbuf, "ethaddr"); /* Searching for 'ethaddr=MAC' (or may be 'ethaddr MAC') from /proc/cmdline */
			p = ((p) ? (p + 8) : NULL);
		}
		if(p != NULL)
		{
			int i = 0;
			for(i=0;i<17;i++)
			{
				pcMac[i] = *(p + i);
			}

		}
		else{
			LOGF_LOG_DEBUG("MAC Address not read from /proc/cmdline\n");
			nRet = -EXIT_FAILURE;
			goto returnHandler;
		}
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	if (fpProc != NULL) {
		if (!check) {
			pclose(fpProc);
		} else {
			fclose(fpProc);
		}
	}
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_validateWithBase
 **
 **   Description      :Validates a given mac with base mac from /proc/cmdline.
 **			validation is done by comparing first 3 octets of the mac
 **
 **   Parameters       :pcMac(IN) -> Mac address to validate
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                      Failure -> Different -ve values 
 ** 
 **
 ** ============================================================================
 */

static int scapi_validateWithBase(char* pcMac){
	char proc_mac_addr[32] = {0};
	int nRet = -EXIT_FAILURE;

	if (scapi_getBaseMac(proc_mac_addr) != EXIT_SUCCESS) {
		goto returnHandler;
	}

	//printf("Mac = %s, Proc Mac = %s\n", pcMac, proc_mac_addr);
	/* Check if first 3 octets are matching or else fail */
	if(strncasecmp(pcMac, proc_mac_addr, 9) != 0){
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	nRet = EXIT_SUCCESS;

returnHandler:
	return nRet;
}

/* 
 ** =============================================================================
 **   Function Name    :scapi_getNextMacaddr
 **
 **   Description      :Gets next mac address of an interface and saves it in config file
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

int scapi_getNextMacaddr(char* pcIfname, char* pcMac)
{
	struct ifreq xIfr = {.ifr_ifru={0}};
	int nSkfd = -1;
	int nRet = -EXIT_FAILURE;
	FILE* fp = NULL;

	if(pcIfname == NULL || pcMac == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}


	if(access (BOOT_CHK, F_OK) != -1)
	{
		nRet = scapi_getMacFromFile(pcIfname, pcMac);
		/* We successfully got mac address from the config file */
		if(nRet == EXIT_SUCCESS){
			/* Validate first 3 octets */
			nRet = scapi_validateWithBase(pcMac);
			if(nRet == EXIT_SUCCESS)
				goto returnHandler;
			else{
				nRet = remove(NEXT_MAC_CONF);
				if( nRet != 0){
					nRet = -EXIT_FAILURE;
					LOGF_LOG_ERROR("Couldn't remove the configuration file\n");
					goto returnHandler;
				}
			}
		}
	}
	else
	{
		int nFd=0;
		char sBaseMac[32]={0},sMacBuf[32]={0};

		if((nFd = open(BOOT_CHK, O_RDWR|O_CREAT,0666)) == -1) perror("open");
		if(nFd > 0) 
			close(nFd);

		/* get base mac */
		nRet = scapi_getBaseMac(sBaseMac);
		
		if(nRet != EXIT_SUCCESS)
		{
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
		}
	
		/* get cuurent mac */
		if (access (NEXT_MAC_CONF, F_OK) != -1)
		{
	
			nRet = scapi_getMacFromFile(pcIfname,sMacBuf);
		
			if(nRet != EXIT_SUCCESS)
			{
			LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
			goto returnHandler;
			}
		}
		else
		{
			snprintf(pcMac, 32, "%s",sBaseMac);
			goto finish;
		}

		/*checking for full length as first interface bought up with base mac.*/
		/* if needed change to fixed lenght. */
		if(strcasecmp(sBaseMac, sMacBuf) == 0)
		{
			snprintf(pcMac, 32, "%s",sMacBuf);
			goto returnHandler;
		}
		else
		{
			nRet = remove(NEXT_MAC_CONF);
			snprintf(pcMac, 32, "%s",sBaseMac);
			goto finish;
		}
	}

	/* This interface is not present in the config file. Get base
	 * mac address, validate it and save it in the config file*/
	char macTemp[32] = {0};
	nRet = scapi_getBaseMac(macTemp);
	if(nRet != EXIT_SUCCESS){
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	//printf("Base Mac address = %s\n", macTemp);
	sscanf(macTemp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&(xIfr.ifr_hwaddr.sa_data[0]),
			&(xIfr.ifr_hwaddr.sa_data[1]),
			&(xIfr.ifr_hwaddr.sa_data[2]),
			&(xIfr.ifr_hwaddr.sa_data[3]),
			&(xIfr.ifr_hwaddr.sa_data[4]),
			&(xIfr.ifr_hwaddr.sa_data[5]));

#if 1
	while(1){
		struct stat st;
		memset(&st, 0, sizeof(st));

		if (stat(NEXT_MAC_CONF, &st) == 0 && st.st_size != 0) {
			nRet = scapi_incrementMacaddr(&xIfr);

			if(nRet != EXIT_SUCCESS){
				LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
				goto returnHandler;
			}
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


		nRet  = scapi_validateMacaddr(pcIfname, pcMac);

		/* Validation successful */
		if( nRet == 0){
			break;
		}
		/* Mac already in use. Increment further */
		else if( nRet == -MAC_IN_USE)
		{
			continue;
		}
		else{
			nRet = -EXIT_FAILURE;
			LOGF_LOG_ERROR("Unable to validate the mac with interfaces\n");
			goto returnHandler;
		}
		//printf("Validation failed. Further incrementing the mac\n");
	}
finish:
	/* This file is already created by scapi_getNextMacFromFile() API */
	fp = fopen(NEXT_MAC_CONF, "a+");
	if(fp == NULL){
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	fprintf(fp, "%s> %s\n", pcIfname, pcMac);
#endif
	nRet = EXIT_SUCCESS;
returnHandler:
	if(nSkfd != -1)
		close(nSkfd);
	if(fp != NULL)
		fclose(fp);
	return nRet;
}
/* 
 ** =============================================================================
 **   Function Name    :scapi_isValidMacAddress
 **
 **   Description      :API to validate a Mac aaddress.
 **
 **   Parameters       :pcMac(IN) -> Mac Adsress 
 **
 **   Return Value     :Success -> EXIT_SUCCESS in case of validation success
 **                      Failure -> EXIT_FAILURE in case of validation fails 
 ** 
 ** ============================================================================
 */
int32_t scapi_isValidMacAddress(IN const char *pcMac)
{
	int32_t nRet = UGW_SUCCESS;
	regex_t xRegex;
	int32_t nRegRet;
	char sExp[] = "^[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]$";
	char msgbuf[100];

	if (strlen(pcMac) > 0) {
		/* Compile regular expression */
		if (regcomp(&xRegex, sExp, REG_ICASE)) {
			LOGF_LOG_ERROR("Could not compile xRegex\n");
			nRet = UGW_FAILURE;
			goto end;
		}
		/* Execute regular expression */
		nRegRet = regexec(&xRegex, pcMac, 0, NULL, 0);
		if (!nRegRet) {
			nRet = UGW_SUCCESS;
		} else if (nRegRet == REG_NOMATCH) {
			nRet = ERR_VALIDATION_FAILED;
		} else {
			regerror(nRegRet, &xRegex, msgbuf, sizeof(msgbuf));
			LOGF_LOG_ERROR("Regex match failed: %s\n", msgbuf);
			nRet = ERR_VALIDATION_FAILED;
		}
		/* Free compiled regular expression */
		regfree(&xRegex);
	}
 end:
	return nRet;
}    

