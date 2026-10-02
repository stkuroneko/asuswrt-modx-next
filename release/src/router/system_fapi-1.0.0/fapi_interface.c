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
#include <string.h>
#ifdef PLATFORM_XRX750
#define HVP_BOARD_ID	"BoardID=0xE6"
#define CGP_BOARD_ID	"BoardID=0xE9"
#define EASY750_BOARD_ID	"BoardID=0xE5"
#endif


int FAPI_InterfaceSetState(IN InterfaceType interface ,IN State setState)
{
	int32_t nRetval = UGW_FAILURE;
	nRetval = Interface_setState(interface,setState);
	return nRetval;
}



int   Interface_setState(IN InterfaceType interface,IN State setState)
{
        int32_t nRetval = UGW_FAILURE;
        switch(interface){
                case BOOTING :
                        {
				nRetval = SetFAPIIfData(FILE_NAME,"BOOTING",setState);
                                break;
                        }
                case LAN :
                        {
				nRetval = SetFAPIIfData(FILE_NAME,"LAN", setState);
                                break;
                        }
                case ETHWAN :
                        {
				nRetval = SetFAPIIfData(FILE_NAME,"ETHWAN", setState);
                                break;
                        }
                case WIFI2:
                        {
				nRetval = SetFAPIIfData(FILE_NAME,"WIFI2", setState);
                                break;
                        }
                case WIFI5:
                        {
				nRetval = SetFAPIIfData(FILE_NAME,"WIFI5", setState);
                                break;
			}
		case INITDONE:
			{
				nRetval = SetFAPIIfData(FILE_NAME,"INITDONE",setState);
				break;
			}
                default:
                        break;
        }

	if(nRetval != UGW_SUCCESS) {
		LOGF_LOG_INFO("SetFAPIIfData Returned error\n");
		return nRetval;
	}
	if(fapicb.SetInterfaceState != NULL) {
		nRetval= fapicb.SetInterfaceState(interface,setState);
		return nRetval;
	}

		return nRetval;
}

char * GetFAPIIfData(const char * pcFileName,char *interface)
{
   char *status = NULL;
   FILE *fdIn=NULL;
   int found = 0;

   static char acInLine[FAPI_IF_MAX_FILENAME_LEN];

   memset(acInLine,0,sizeof(acInLine));

   if ((fdIn = fopen (pcFileName, "r")) == NULL) {
      LOGF_LOG_ERROR("file open failed\n");
      fclose (fdIn);
	  return NULL;
   }
   /* get a single line */
   while (fgets (acInLine, sizeof (acInLine), fdIn)){
          if (strncmp (acInLine,interface, strlen(interface)) == 0){
                found = 1;
                break;
          }
   }
  fclose (fdIn);
  if(found) {
   	status = strtok(acInLine,"=");
   	status = strtok(NULL,"=");
   	return status;
   }
   else {
         return NULL;
   }
}


/**
   Deletes old data from file and saves new configuration.

   \param pcFileName      File Name to open.
   \param pInterface           Data tag.
   \param iDataCount      Number of pcData strings.
   \param pcData          Data content for setting. First of argument list.

   \return UGW_SUCCESS on success, otherwise UGW_FAILURE
**/
int SetFAPIIfData (const char * pcFileName,const char * pInterface,int state)
{
   FILE *fdIn, *fdOut;
   char acInLine[FAPI_IF_MAX_FILENAME_LEN];
   char acTempName[FAPI_IF_MAX_FILENAME_LEN];
   int nLineLen = 0;
   int interface_found = 0;
   if ((fdIn = fopen (pcFileName, "r+t")) == NULL) {
        fdIn = fopen (pcFileName, "w+");
        if (fdIn == NULL) {
		LOGF_LOG_ERROR("file open failed\n");
                return UGW_FAILURE;
        }
   }

   snprintf (acTempName,sizeof(acTempName),"%s.tmp", pcFileName);
   /* open output file */
   if ((fdOut = fopen (acTempName, "w+")) == NULL) {
      fclose (fdIn);
      return UGW_FAILURE;
   }
   /* get a single line */
   while (fgets (acInLine, sizeof (acInLine), fdIn)) {
      /* get read string length */
      nLineLen = strlen (acInLine);
      /* check string length */
      if (0 == nLineLen){
         /* empty line */
         continue;
      }
      if(acInLine[nLineLen-1] == '\n') {
                acInLine[nLineLen-1] = '\0';
      }
      if (strncmp (acInLine,pInterface, strlen(pInterface)) == 0) {
                interface_found = 1;
                snprintf(acInLine,sizeof(acInLine),"%s=%d",pInterface,state);
      }
       fprintf (fdOut, "%s\n", acInLine);

   } /* while (fgets (acInLine, sizeof (acInLine), fdIn)) */
   if(interface_found == 0) {
        snprintf(acInLine,sizeof(acInLine),"%s=%d",pInterface,state);
        fprintf (fdOut, "%s\n", acInLine);
   }

   /* close files */
   fclose (fdIn);
   fclose (fdOut);

   /* remove old file */
   if (remove (pcFileName) == 0) {
      /* rename output file */
      if (0 != rename (acTempName, pcFileName)) {
         return UGW_FAILURE;
      }
   }
   else {
      return UGW_FAILURE;
   }

   return UGW_SUCCESS;
}
/* @} */
