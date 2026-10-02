/********************************************************************************

        Copyright (c) 2015
        LANTIQ DEUTSCHLAND GMBH
        Lilienthalstrasse 15, 85579 Neubiberg, Germany
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.

********************************************************************************/

/*  *****************************************************************************
 *         File Name    : fapi_interfaces.c                                       *
 *         Description  : This FAPI file provide framework for storing            *
 *                        status of all the interfaces                            *
 *                                                                                *
 *  *****************************************************************************/

/*! \file fapi_interfaces.c
 \brief This File contains the Generic API's and common utility API's
for all the SLs to set the status of the interfaces.
*/

/** \defgroup NONE
*/
/* @{ */
#include <ulogging.h>
#ifdef PLATFORM_XRX200
#include "xRX220_callback.h"
#endif
#ifdef PLATFORM_XRX500
#include "xRX350_callback.h"
#endif
#ifdef PLATFORM_XRX750
#include "xRX750_callback.h"
#endif
#ifdef PLATFORM_XRX330
#include "xRX330_callback.h"
#endif
#include <string.h>

char *caIfName[MAX_INTERFACE] = {
        "BOOTING",
        "LAN",
        "ETHWAN",
        "DSLWAN",
        "GPONWAN",
        "WIFI2",
        "WIFI5",
        "WIFI5G2",
        "FXS1",
        "FXS2",
        "SFP",
        "LTE",
        "VDSL1",
        "VDSL2",
        "POWER",
        "INITDONE",
        "INTERNET",
	"DECT",
	"VOIP0",
	"VOIP1",
	"WPS",
	"SHDAP"
};

/*!  \brief  This is the LED FAPI exposed to all the SL to set concerned Interface state.
  \param[in] InterfaceType enum specifying the InterfaceType type for which sl needs to set the state.
  \param[in] State enum specifying the state type for the concerned Interface.
  \param[in] pAttr Pointer to the  attributes parameters needed for concerned interface.
  \param[out] NONE
  \return
*/
int32_t FAPI_InterfaceSetState(IN InterfaceType eInterface ,IN State eSetState ,IN void * pAttr)
{
	int32_t nRetval = UGW_FAILURE;
	if((eInterface < 0) || (eInterface >= MAX_INTERFACE)) {
                LOGF_LOG_INFO("Invalid interface %d\n",eInterface);
		return UGW_FAILURE;
	}
	if((eSetState < 0) || (eSetState >= INVALID_STATE)) {
                LOGF_LOG_INFO("Invalid State %d\n",eSetState);
		return UGW_FAILURE;
	}
	nRetval = Interface_setState(eInterface,eSetState,pAttr);
	return nRetval;
}

int32_t Interface_setState(IN InterfaceType eInterface,IN State eSetState,IN void * pAttr)
{
        int32_t nRetval = UGW_FAILURE;

        nRetval = fapi_setIfData(FILE_NAME, caIfName[eInterface], eSetState);
        if(nRetval != UGW_SUCCESS) {
                LOGF_LOG_INFO("fapi_setIfData Returned error\n");
        }
        if(fapicb.setInterfaceState != NULL) {
                nRetval= fapicb.setInterfaceState(eInterface,eSetState,pAttr);
        }
        return nRetval;
}

/*!  \brief  This is the API for retrieving the State of the Interface.
  \param[in] pcFileName pointer to the file name .
  \param[in] pcInterface pointer specifying the oncerned Interface.
  \param[out] NONE
  \return
*/
char * fapi_getIfData(IN const char * pcFileName,IN char *pcInterface)
{
   char *pcStatus = NULL;
   FILE *fdIn=NULL;
   int nFound = 0;
   static char caInLine[FAPI_IF_MAX_FILENAME_LEN];

   fdIn = fopen (pcFileName, "r");
   if(fdIn == NULL) {
      LOGF_LOG_ERROR("file : %s open failed\n", pcFileName);
	  return NULL;
   }
   /* get a single line */
   while (fgets (caInLine, sizeof (caInLine), fdIn)){
          if (strncmp (caInLine,pcInterface, strlen(pcInterface)) == 0){
                nFound = 1;
                break;
          }
   }
  fclose (fdIn);
  if(nFound) {
   	pcStatus = strtok(caInLine,"=");
   	pcStatus = strtok(NULL,"=");
   	return pcStatus;
   }
   else {
         return NULL;
   }
}


/**
   Deletes old data from file and saves new configuration.

   \param pcFileName      File Name to open.
   \param pcInterface  pointer to the interface.
   \param eState enum specifying the State of the interface.

   \return UGW_SUCCESS on success, otherwise UGW_FAILURE
**/
int32_t fapi_setIfData(IN const char * pcFileName,IN const char * pcInterface,IN State eState)
{
   FILE *fdIn = NULL;
   FILE	*fdOut = NULL;
   char caInLine[FAPI_IF_MAX_FILENAME_LEN];
   char caTempName[FAPI_IF_MAX_FILENAME_LEN];
   int nLineLen = 0;
   int nInterfacefound = 0;

   memset(caInLine, 0, sizeof(caInLine));
   memset(caTempName, 0, sizeof(caTempName));

   if ((fdIn = fopen (pcFileName, "r+t")) == NULL) {
        fdIn = fopen (pcFileName, "w+");
        if (fdIn == NULL) {
		LOGF_LOG_ERROR("file open failed\n");
                return UGW_FAILURE;
        }
   }

   snprintf (caTempName,sizeof(caTempName),"%s.tmp", pcFileName);
   /* open output file */
   if ((fdOut = fopen (caTempName, "w+")) == NULL) {
      fclose (fdIn);
      return UGW_FAILURE;
   }
   /* get a single line */
   while (fgets (caInLine, sizeof (caInLine), fdIn)) {
      /* get read string length */
      nLineLen = strlen (caInLine);
      /* check string length */
      if (0 == nLineLen){
         /* empty line */
         continue;
      }
      if(caInLine[nLineLen-1] == '\n') {
                caInLine[nLineLen-1] = '\0';
      }
      if (strncmp (caInLine,pcInterface, strlen(pcInterface)) == 0) {
                nInterfacefound = 1;
                snprintf(caInLine,sizeof(caInLine),"%s=%d",pcInterface,eState);
      }
       fprintf (fdOut, "%s\n", caInLine);

   } /* while (fgets (acaInLine, sizeof (acaInLine), fdIn)) */
   if(nInterfacefound == 0) {
        snprintf(caInLine,sizeof(caInLine),"%s=%d",pcInterface,eState);
        fprintf (fdOut, "%s\n", caInLine);
   }

   /* close files */
   fclose (fdIn);
   fclose (fdOut);

   /* remove old file */
   if (remove (pcFileName) == 0) {
      /* rename output file */
      if (0 != rename (caTempName, pcFileName)) {
         return UGW_FAILURE;
      }
   }
   else {
      return UGW_FAILURE;
   }

   return UGW_SUCCESS;
}
/* @} */
