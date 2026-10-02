/********************************************************************************
 
        Copyright (c) 2015
        LANTIQ DEUTSCHLAND GMBH
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    : fapi_led_main.c                                       *
 *         Description  : This FAPI main file provide framework for LED         *
 *                        controls for concerned SLs                            *
 *                                                                              *
 *  *****************************************************************************/

/*! \file fapi_led_main.c
 \brief This File contains the Generic API's and common utility API's 
for all the SLs to SET/RESET the concerned LED Attributes.
*/

/** \defgroup NONE
*/
/* @{ */
#include <ulogging.h>
#include "fapi_led.h"
#ifdef PLATFORM_XRX750
#define HVP_BOARD_ID	"BoardID=0xE6"
#define CGP_BOARD_ID	"BoardID=0xE9"
#define EASY750_BOARD_ID	"BoardID=0xE5"

static char* xRX750_check_boardID(void);

char *caLedPath[MAX_LED_TYPE][MAX_PLATFORM_TYPE] = {
	/*GRX_350 LEDs, XRX330 LEDs, XRX200 LEDs , EASY750 LEDs, HVP LEDs*/
	{FAPI_LEDNAME_BROADBANDLED, FAPI_LEDNAME_BROADBANDLED, FAPI_LEDNAME_BROADBANDLED, NULL, NULL},
	{FAPI_LEDNAME_BROADBANDLED1, FAPI_LEDNAME_BROADBANDLED1, NULL, NULL, NULL},
	{FAPI_LEDNAME_VOIP0LED, FAPI_LEDNAME_VOIP0LED, NULL, NULL, NULL},
	{FAPI_LEDNAME_VOIP1LED, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LTELED, FAPI_LEDNAME_LTELED, NULL, FAPI_GRX750_LEDNAME_LTELED, NULL},
	{FAPI_LEDNAME_INTERNETLED, FAPI_LEDNAME_INTERNETLED, FAPI_LEDNAME_INTERNETLED, NULL, NULL},
	{FAPI_LEDNAME_WIFI2GLED, FAPI_LEDNAME_WIFI2GLED, NULL, FAPI_GRX750_LEDNAME_WIFI24GLED, NULL},
	{FAPI_LEDNAME_WIFI5GLED, FAPI_LEDNAME_WIFI5GLED, NULL, FAPI_GRX750_LEDNAME_WIFI5G1LED, NULL},
	{FAPI_LEDNAME_DECTLED, NULL, NULL, NULL, NULL},
	{NULL, NULL, FAPI_LEDNAME_WPSLED, NULL, NULL},
	{FAPI_LEDNAME_G2LED0, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_G3LED0, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_G4LED0, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_G5LED0, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_G6FLED0, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED16, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED17, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED18, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED19, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED20, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED21, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED22, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED23, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED24, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED25, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED26, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED27, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED28, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED29, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED30, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED31, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED32, NULL, NULL, NULL, NULL},
	{FAPI_LEDNAME_LED33, NULL, NULL, NULL, NULL},
	{NULL, NULL, NULL, FAPI_GRX750_LEDNAME_FXS1LED, NULL},
	{NULL, NULL, NULL, FAPI_GRX750_LEDNAME_FXS2LED, NULL},
	{NULL, NULL, NULL, FAPI_GRX750_LEDNAME_SFPLED, NULL},
	{NULL, NULL, NULL, FAPI_GRX750_LEDNAME_VDSL1LED, NULL},
	{NULL, NULL, NULL, FAPI_GRX750_LEDNAME_VDSL2LED, NULL},
	{NULL, NULL, NULL, FAPI_GRX750_LEDNAME_WIFI5G2LED, NULL},
	{NULL, NULL, NULL, FAPI_GRX750_LEDNAME_POWERLED, NULL},
	{NULL, NULL, NULL, NULL, FAPI_HVP_LEDNAME_RED},
	{NULL, NULL, NULL, NULL, FAPI_HVP_LEDNAME_BLUE},
	{NULL, NULL, NULL, NULL, FAPI_HVP_LEDNAME_GREEN},
};
#else
char *caLedPath[MAX_LED_TYPE][MAX_PLATFORM_TYPE] = {
	/*GRX_350 LEDs, XRX330 LEDs, XRX200 LEDs */
	{FAPI_LEDNAME_BROADBANDLED, FAPI_LEDNAME_BROADBANDLED, FAPI_LEDNAME_BROADBANDLED},
	{FAPI_LEDNAME_BROADBANDLED1, FAPI_LEDNAME_BROADBANDLED1, NULL},
	{FAPI_LEDNAME_VOIP0LED, FAPI_LEDNAME_VOIP0LED, NULL},
	{FAPI_LEDNAME_VOIP1LED, NULL, NULL},
	{FAPI_LEDNAME_LTELED, FAPI_LEDNAME_LTELED, NULL},
	{FAPI_LEDNAME_INTERNETLED, FAPI_LEDNAME_INTERNETLED, FAPI_LEDNAME_INTERNETLED},
	{FAPI_LEDNAME_WIFI2GLED, FAPI_LEDNAME_WIFI2GLED, NULL},
	{FAPI_LEDNAME_WIFI5GLED, FAPI_LEDNAME_WIFI5GLED, NULL},
	{FAPI_LEDNAME_DECTLED, NULL, NULL},
	{NULL, NULL, FAPI_LEDNAME_WPSLED},
	{FAPI_LEDNAME_G2LED0, NULL, NULL},
	{FAPI_LEDNAME_G3LED0, NULL, NULL},
	{FAPI_LEDNAME_G4LED0, NULL, NULL},
	{FAPI_LEDNAME_G5LED0, NULL, NULL},
	{FAPI_LEDNAME_G6FLED0, NULL, NULL},
	{FAPI_LEDNAME_LED16, NULL, NULL},
	{FAPI_LEDNAME_LED17, NULL, NULL},
	{FAPI_LEDNAME_LED18, NULL, NULL},
	{FAPI_LEDNAME_LED19, NULL, NULL},
	{FAPI_LEDNAME_LED20, NULL, NULL},
	{FAPI_LEDNAME_LED21, NULL, NULL},
	{FAPI_LEDNAME_LED22, NULL, NULL},
	{FAPI_LEDNAME_LED23, NULL, NULL},
	{FAPI_LEDNAME_LED24, NULL, NULL},
	{FAPI_LEDNAME_LED25, NULL, NULL},
	{FAPI_LEDNAME_LED26, NULL, NULL},
	{FAPI_LEDNAME_LED27, NULL, NULL},
	{FAPI_LEDNAME_LED28, NULL, NULL},
	{FAPI_LEDNAME_LED29, NULL, NULL},
	{FAPI_LEDNAME_LED30, NULL, NULL},
	{FAPI_LEDNAME_LED31, NULL, NULL},
	{FAPI_LEDNAME_LED32, NULL, NULL},
	{FAPI_LEDNAME_LED33, NULL, NULL},
};
#endif
/*!  \brief  This is the LED FAPI exposed to all the SL to set concerned LEDs attributes. 
  \param[in] LedType enum specifying the LED type for which sl needs to set the attributes.
  \param[in] trigger enum specifying the trigger type for the concerned LED.
  \param[in] pLedAttr Pointer to the LED attributes parameters needed to be set for concerned LED.
  \param[out] NONE
  \return  
*/
int FAPI_LEDSetAttribute(IN LEDType led, IN TriggerType trigger, IN void *pLedAttr)
{
	uint32_t unTriggerIndex = TRIGGER_MAX;
	unTriggerIndex = trigger;
	int32_t nRetval = UGW_FAILURE;
	char *pTriggerPath = NULL;
	LOGF_LOG_DEBUG(" Enter to Set LED Attribute \n");

	switch (unTriggerIndex) {
	case TRIGGER_TIMER:
		{
			nRetval = LED_TriggerTimer(led, pLedAttr);
			if (nRetval == UGW_FAILURE) {
				LOGF_LOG_ERROR(" Failed to set LED attributes for trigger type Timer \n");
			}
			break;
		}

	case TRIGGER_NETDEV:
		{
			nRetval = LED_TriggerNetDev(led, pLedAttr);
			if (nRetval == UGW_FAILURE) {
				LOGF_LOG_ERROR(" Failed to set LED attributes for trigger type NetDev \n");
			}
			break;
		}
	case TRIGGER_NONE:
		{
			pTriggerPath = TRIGGER_TYPE_NONE;
			nRetval = LED_TriggerGeneric(led, pTriggerPath, pLedAttr);
			if (nRetval == UGW_FAILURE) {
				LOGF_LOG_ERROR(" Failed to set LED attributes for trigger type None \n");
			}
			break;

		}
	case TRIGGER_NANDDISK:
		{
			pTriggerPath = TRIGGER_TYPE_NANDDISK;
			nRetval = LED_TriggerGeneric(led, pTriggerPath, pLedAttr);
			if (nRetval == UGW_FAILURE) {
				LOGF_LOG_ERROR(" Failed to set LED attributes for trigger type NANDDisk \n");
			}
			break;

		}
	case TRIGGER_HEARTBEAT:
		{
			pTriggerPath = TRIGGER_TYPE_HEARTBEAT;
			nRetval = LED_TriggerGeneric(led, pTriggerPath, pLedAttr);
			if (nRetval == UGW_FAILURE) {
				LOGF_LOG_ERROR(" Failed to set LED attributes for trigger type Heartbeat \n");
			}
			break;

		}
	case TRIGGER_DEFAULT:
		{
			pTriggerPath = TRIGGER_TYPE_DEFAULT;
			nRetval = LED_TriggerGeneric(led, pTriggerPath, pLedAttr);
			if (nRetval == UGW_FAILURE) {
				LOGF_LOG_ERROR(" Failed to set LED attributes for trigger type Default \n");
			}
			break;
		}
	default:
		{
			LOGF_LOG_ERROR("Invalid Trigger Type\n");
			nRetval = UGW_FAILURE;
		}
	}
	return nRetval;
}

/*!  \brief  This is the LED FAPI utility API used to set concerned LEDs attributes for trigger type "Timer". 
  \param[in] LedName enum specifying the LED type for which, sl needs to set the attributes.
  \param[in] LedAttr Pointer to the LED attributes parameters needed to be set for concerned LED.
  \param[out] NONE
  \return  
*/
int LED_TriggerTimer(IN LEDType led, IN void *pLedAttr)
{
	sTimerAttr *pAttr = (sTimerAttr *) pLedAttr;
	int32_t nRetval = UGW_FAILURE;
	char sPath[MAX_PATH_LEN] = { 0 };
	char sAttribute[MAX_ATTR_LEN] = { 0 };
	char LEDName[MAX_PATH_LEN] = { 0 };
	int nPlatformType = MAX_PLATFORM_TYPE;
	nRetval = LED_GetInfo(led, LEDName, &nPlatformType);
	if (nRetval == UGW_FAILURE) {
		LOGF_LOG_ERROR(" LED_GetInfo failed \n");
		goto End;
	}

	/* Setting trigger Type */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/trigger");
	LOGF_LOG_DEBUG(" LED path = %s\n", sPath);
	snprintf(sAttribute, MAX_ATTR_LEN, "%s", "timer");
	nRetval = LED_SetAttribute(sPath, sAttribute);
	if (nRetval == UGW_SUCCESS) {
		LOGF_LOG_DEBUG(" Setting Trigger type as timer for LED: %s \n", LEDName);
	} else {
		goto End;
	}

	memset(sPath, '\0', MAX_PATH_LEN);
	/* Setting Brightness of the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/brightness");
	if (pAttr->nBrightness >= INVALID_BRIGHTNESS_ATTRIBUTE && pAttr->nBrightness <= MAX_LED_BRIGHTNESS) {
		if (pAttr->nBrightness != INVALID_BRIGHTNESS_ATTRIBUTE) {
			snprintf(sAttribute, MAX_ATTR_LEN, "%d", pAttr->nBrightness);
			nRetval = LED_SetAttribute(sPath, sAttribute);
			if (nRetval != UGW_SUCCESS) {
				LOGF_LOG_ERROR(" Setting Brightness value failed for LED: %s to %d \n", LEDName, pAttr->nBrightness);
				nRetval = UGW_FAILURE;
				goto End;
			}
			LOGF_LOG_DEBUG(" Setting Brightness value for LED: %s to %d \n", LEDName, pAttr->nBrightness);
		}
	} else {
		LOGF_LOG_ERROR("Brightness = %d is not valid.\n", pAttr->nBrightness);
		nRetval = UGW_FAILURE;
		goto End;
	}
	memset(sPath, '\0', MAX_PATH_LEN);
	/* Setting delay_on of the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/delay_on");
	LOGF_LOG_DEBUG("LED path = %s\n", sPath);
	if (pAttr->nDelayOn > INVALID_DELAYON_ATTRIBUTE) {
		snprintf(sAttribute, MAX_ATTR_LEN, "%d", pAttr->nDelayOn);
		nRetval = LED_SetAttribute(sPath, sAttribute);
		if (nRetval != UGW_SUCCESS) {
			LOGF_LOG_ERROR("Setting delay_on value for LED: %s to %d failed.\n", LEDName, pAttr->nDelayOn);
			nRetval = UGW_FAILURE;
			goto End;
		}
		LOGF_LOG_DEBUG("Setting delay_on value for LED: %s to %d .\n", LEDName, pAttr->nDelayOn);
	}
	memset(sPath, '\0', MAX_PATH_LEN);
	/* Setting delay_off of the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/delay_off");
	LOGF_LOG_DEBUG("LED path = %s\n", sPath);
	if (pAttr->nDelayOff > INVALID_DELAYOFF_ATTRIBUTE) {
		snprintf(sAttribute, MAX_ATTR_LEN, "%d", pAttr->nDelayOff);
		nRetval = LED_SetAttribute(sPath, sAttribute);
		if (nRetval != UGW_SUCCESS) {
			LOGF_LOG_ERROR("Setting Delay_Off value for LED: %s to %d failed..\n", LEDName, pAttr->nDelayOff);
			nRetval = UGW_FAILURE;
			goto End;
		}
		LOGF_LOG_DEBUG("Setting Delay_Off value for LED: %s to %d .\n", LEDName, pAttr->nDelayOff);
	}
 End:
	return nRetval;
}

/*!  \brief  This is the LED FAPI utility API used to set concerned LEDs attributes for trigger type "Netdev". 
  \param[in] LedName enum specifying the LED type for which, sl needs to set the attributes.
  \param[in] pLedAttr Pointer to the LED attributes parameters needed to be set for concerned LED.
  \param[out] NONE
  \return  
*/
int LED_TriggerNetDev(IN LEDType led, IN void *pLedAttr)
{
	sNetDevAttr *pAttr = (sNetDevAttr *) pLedAttr;
	uint16_t unBytes_written = 0;
	int32_t nRetval = UGW_FAILURE;
	char sPath[MAX_PATH_LEN] = { 0 };
	char sAttribute[MAX_ATTR_LEN] = { 0 };
	char LEDName[MAX_PATH_LEN] = { 0 };
	int nPlatformType = MAX_PLATFORM_TYPE;
	nRetval = LED_GetInfo(led, LEDName, &nPlatformType);
	if (nRetval == UGW_FAILURE) {
		LOGF_LOG_ERROR(" LED_GetInfo failed \n");
		goto End;
	}

	/* Setting trigger Type */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/trigger");
	LOGF_LOG_DEBUG(" LED path = %s\n", sPath);
	snprintf(sAttribute, MAX_ATTR_LEN, "%s", "netdev");
	nRetval = LED_SetAttribute(sPath, sAttribute);
	if (nRetval != UGW_SUCCESS) {
		LOGF_LOG_ERROR(" Setting Trigger type as netdev failed for LED: %s \n", LEDName);
		goto End;
	}
	LOGF_LOG_DEBUG(" Setting Trigger type as netdev for LED: %s \n", LEDName);

	memset(sPath, '\0', MAX_PATH_LEN);
	/* Setting mode of the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/mode");
	LOGF_LOG_DEBUG(" LED path = %s\n", sPath);
	if (pAttr->unMode == LED_INVALID_TRIGGER_MODE) {
		LOGF_LOG_ERROR("Trigger Mode = %d is not valid.\n", pAttr->unMode);
		nRetval = UGW_FAILURE;
		goto End;
	}
	if (pAttr->unMode & LED_TRIGGER_MODE_LINK) {
		unBytes_written += snprintf(sAttribute + unBytes_written, MAX_ATTR_LEN, "%s", "link ");
	}
	if (pAttr->unMode & LED_TRIGGER_MODE_RX) {
		unBytes_written += snprintf(sAttribute + unBytes_written, MAX_ATTR_LEN, "%s", "rx ");
	}
	if (pAttr->unMode & LED_TRIGGER_MODE_TX) {
		unBytes_written += snprintf(sAttribute + unBytes_written, MAX_ATTR_LEN, "%s", "tx ");
	}
	nRetval = LED_SetAttribute(sPath, sAttribute);
	if (nRetval != UGW_SUCCESS) {
		LOGF_LOG_ERROR(" Setting mode failed for the LED: %s to %d \n", LEDName, pAttr->unMode);
		nRetval = UGW_FAILURE;
		goto End;
	}
	LOGF_LOG_DEBUG(" Setting mode for the LED: %s to %d \n", LEDName, pAttr->unMode);
	memset(sPath, '\0', MAX_PATH_LEN);

	/* Setting Brightness of the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/brightness");
	LOGF_LOG_DEBUG(" LED path = %s\n", sPath);
	if (pAttr->nBrightness >= INVALID_BRIGHTNESS_ATTRIBUTE || pAttr->nBrightness <= MAX_LED_BRIGHTNESS) {
		if (pAttr->nBrightness != INVALID_BRIGHTNESS_ATTRIBUTE) {
			snprintf(sAttribute, MAX_ATTR_LEN, "%d", pAttr->nBrightness);
			nRetval = LED_SetAttribute(sPath, sAttribute);
			if (nRetval != UGW_SUCCESS) {
				LOGF_LOG_ERROR(" Setting Brightness value failed for LED: %s to %d \n", LEDName, pAttr->nBrightness);
				nRetval = UGW_FAILURE;
				goto End;
			}
			LOGF_LOG_DEBUG(" Setting Brightness value for LED: %s to %d \n", LEDName, pAttr->nBrightness);
		}
	} else {
		LOGF_LOG_ERROR("Brightness = %d is not valid.\n", pAttr->nBrightness);
		nRetval = UGW_FAILURE;
		goto End;
	}
	memset(sPath, '\0', MAX_PATH_LEN);
	/* Setting Interval for the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/interval");
	LOGF_LOG_DEBUG(" LED path = %s\n", sPath);
	if (pAttr->nInterval == INVALID_INTERVAL_ATTRIBUTE) {
		LOGF_LOG_ERROR("Interval = %d is not valid.\n", pAttr->nInterval);
		nRetval = UGW_FAILURE;
		goto End;
	}
	snprintf(sAttribute, MAX_ATTR_LEN, "%d", pAttr->nInterval);
	nRetval = LED_SetAttribute(sPath, sAttribute);
	if (nRetval != UGW_SUCCESS) {
		LOGF_LOG_ERROR(" Setting Interval value failed for LED: %s to %d \n", LEDName, pAttr->nInterval);
		nRetval = UGW_FAILURE;
		goto End;
	}
	LOGF_LOG_DEBUG(" Setting Interval value for LED: %s to %d \n", LEDName, pAttr->nInterval);
	memset(sPath, '\0', MAX_PATH_LEN);

	/* Setting Device_name for the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/device_name");
	LOGF_LOG_DEBUG(" LED path = %s\n", sPath);
	snprintf(sAttribute, MAX_ATTR_LEN, "%s", pAttr->DevName);
	nRetval = LED_SetAttribute(sPath, sAttribute);
	if (nRetval != UGW_SUCCESS) {
		LOGF_LOG_ERROR(" Setting device name failed for LED: %s to %s \n", LEDName, pAttr->DevName);
		nRetval = UGW_FAILURE;
		goto End;
	}
	LOGF_LOG_DEBUG(" Setting device name for LED: %s to %s \n", LEDName, pAttr->DevName);
 End:
	return nRetval;
}

/*!  \brief  This is the LED FAPI utility API used to set concerned LEDs attributes for trigger type "Default". 
  \param[in] LedName enum specifying the LED type for which, sl needs to set the attributes.
  \param[in] pTrigger pointer specifying the trigger type for which, sl needs to set the attributes.
  \param[in] pLedAttr Pointer to the LED attributes parameters needed to be set for concerned LED.
  \param[out] NONE
  \return  
*/
int LED_TriggerGeneric(IN LEDType led, IN char *pTrigger, IN void *pLedAttr)
{
	sDefaultAttr *pAttr = (sDefaultAttr *) pLedAttr;
	int32_t nRetval = UGW_FAILURE;
	char sPath[MAX_PATH_LEN] = { 0 };
	char sAttribute[MAX_ATTR_LEN] = { 0 };
	char LEDName[MAX_PATH_LEN] = { 0 };
	int nPlatformType = MAX_PLATFORM_TYPE;
	nRetval = LED_GetInfo(led, LEDName, &nPlatformType);
	if (nRetval == UGW_FAILURE) {
		LOGF_LOG_ERROR(" LED_GetInfo failed \n");
		goto End;
	}

	/* Setting trigger Type */
	snprintf(sPath, MAX_PATH_LEN, "%s", LEDName);
	strncat(sPath, "/trigger", strlen("/trigger"));
	snprintf(sAttribute, MAX_ATTR_LEN, "%s", pTrigger);
	nRetval = LED_SetAttribute(sPath, sAttribute);
	if (nRetval != UGW_SUCCESS) {
		LOGF_LOG_ERROR(" Setting Trigger type as %s failed for LED: %s \n", pTrigger, LEDName);
		goto End;
	}
	LOGF_LOG_DEBUG(" Setting Trigger type as %s for LED: %s \n", pTrigger, LEDName);
	memset(sPath, '\0', MAX_PATH_LEN);

	/* Setting Brightness of the LED */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/brightness");
	LOGF_LOG_DEBUG(" LED path = %s\n", sPath);
	if (pAttr->nBrightness >= INVALID_BRIGHTNESS_ATTRIBUTE || pAttr->nBrightness <= MAX_LED_BRIGHTNESS) {
		if (pAttr->nBrightness != INVALID_BRIGHTNESS_ATTRIBUTE) {
			snprintf(sAttribute, MAX_ATTR_LEN, "%d", pAttr->nBrightness);
			nRetval = LED_SetAttribute(sPath, sAttribute);
			if (nRetval != UGW_SUCCESS) {
				LOGF_LOG_ERROR(" Setting Brightness value failed for LED: %s to %d \n", LEDName, pAttr->nBrightness);
				nRetval = UGW_FAILURE;
				goto End;
			}
			LOGF_LOG_DEBUG(" Setting Brightness value for LED: %s to %d \n", LEDName, pAttr->nBrightness);
		}
	} else {
		LOGF_LOG_ERROR("Brightness = %d is not valid.\n", pAttr->nBrightness);
		nRetval = UGW_FAILURE;
		goto End;
	}

 End:
	return nRetval;
}

/*!  \brief  This is the LED FAPI utility API used to set concerned LEDs attributes. 
  \param[in] pFilePath string specifying the LED path in sysfs directory for which, sl needs to set the attributes.
  \param[in] pLedAttr Pointer to the LED attributes parameters needed to be set for concerned LED.
  \param[out] NONE
  \return  
*/
int LED_SetAttribute(char *pFilepath, char *pattr)
{
	int32_t nRetval = UGW_FAILURE;
	FILE *pFile = NULL;
	pFile = fopen(pFilepath, "wb");
	if (!pFile) {
		LOGF_LOG_ERROR(" Error while opening file :%s \n", pFilepath);
		nRetval = UGW_FAILURE;
		goto End;
	}
	nRetval = fwrite(pattr, sizeof(char), strlen(pattr), pFile);
	if (!nRetval) {
		LOGF_LOG_ERROR(" Error while writing into file :%s \n", pFilepath);
		nRetval = UGW_FAILURE;
		fclose(pFile);
		goto End;
	} else {
		nRetval = UGW_SUCCESS;
	}
	fclose(pFile);
 End:
	return nRetval;

}

/*!  \brief  This is the LED FAPI utility API used to get LED name as present in sys/class/leds direcory from LED type. 
  \param[in] LEDType enum specifying LED Type .
  \param[out] LEDName LED pName.
  \return  
*/
int LED_GetInfo(IN LEDType led, OUT char *pName, OUT int *pPlatformType)
{
	int32_t nRetval = UGW_FAILURE;
	char ModelName[MAX_PATH_LEN] = { 0 };
#ifdef PLATFORM_XRX750
        FILE *fp = NULL;
        char fbuf[256];
#endif
	LED_GetPlatformInfo(ModelName);
	if (!strncmp(ModelName, "XRX330", strlen("XRX330")))
		*pPlatformType = XRX330;
	else if (!strncmp(ModelName, "GRX350", strlen("GRX350")))
		*pPlatformType = GRX350;
	else if (!strncmp(ModelName, "GRX500", strlen("GRX500")))
		*pPlatformType = GRX350;
	else if (!strncmp(ModelName, "xRX200", strlen("xRX200")))
		*pPlatformType = XRX200;
	else {
#ifdef PLATFORM_XRX750
		fp = fopen("/proc/cpuinfo", "r");
		if (fp) {
			fgets(fbuf, sizeof(fbuf), fp);
			do {
				if (strstr(fbuf, "Atom")){
					if (strstr(xRX750_check_boardID(), HVP_BOARD_ID) != NULL) {
						*pPlatformType = HVP;
					} else if (strstr(xRX750_check_boardID(), EASY750_BOARD_ID) != NULL) {
						*pPlatformType = GRX750;
					} else {
						*pPlatformType = GRX750;
					}
					break;
				}
			} while (fgets(fbuf, sizeof(fbuf), fp) != NULL);

			fclose(fp);

			if(*pPlatformType != GRX750 &&  *pPlatformType != HVP) {
				LOGF_LOG_ERROR("Model %s Not Supported \n", ModelName);
				return UGW_FAILURE;
			}
		} else {
			LOGF_LOG_ERROR("ERROR: File open failed\n");
			return UGW_FAILURE;
		}
#else
		LOGF_LOG_ERROR("Model %s Not Supported \n", ModelName);
		return UGW_FAILURE;
#endif
	}
	switch (*pPlatformType) {
	case XRX330:
		{
			if (caLedPath[led][XRX330] == NULL) {
				LOGF_LOG_ERROR("LED %d not available on %d platform \n", led, *pPlatformType);
				return UGW_FAILURE;
			}
			snprintf(pName, MAX_PATH_LEN, "%s%s", LED_DEFAULT_PATH, caLedPath[led][XRX330]);
			LOGF_LOG_DEBUG("led path %s \n", pName);
			nRetval = UGW_SUCCESS;
			break;
		}
	case GRX350:
		{
			if (caLedPath[led][GRX350] == NULL) {
				LOGF_LOG_ERROR("LED %d not available on %d platform \n", led, *pPlatformType);
				return UGW_FAILURE;
			}
			snprintf(pName, MAX_PATH_LEN, "%s%s", LED_DEFAULT_PATH, caLedPath[led][GRX350]);
			LOGF_LOG_DEBUG("led path %s \n", pName);
			nRetval = UGW_SUCCESS;
			break;
		}
	case XRX200:
		{
			if (caLedPath[led][XRX200] == NULL) {
				LOGF_LOG_ERROR("LED %d not available on %d platform \n", led, *pPlatformType);
				return UGW_FAILURE;
			}
			snprintf(pName, MAX_PATH_LEN, "%s%s", LED_DEFAULT_PATH, caLedPath[led][XRX200]);
			LOGF_LOG_DEBUG("led path %s \n", pName);
			nRetval = UGW_SUCCESS;
			break;
		}
#ifdef PLATFORM_XRX750
	case GRX750:
		{
		        if (caLedPath[led][GRX750] == NULL) {
                                LOGF_LOG_ERROR("LED %d not available on %d platform \n", led, *pPlatformType);
                                return UGW_FAILURE;
                        }
                        snprintf(pName, MAX_PATH_LEN, "%s%s", LED_DEFAULT_PATH, caLedPath[led][GRX750]);
                        LOGF_LOG_DEBUG("led path %s \n", pName);
                        nRetval = UGW_SUCCESS;
                        break;
		}
	case HVP:
		{
		        if (caLedPath[led][HVP] == NULL) {
                                LOGF_LOG_ERROR("LED %d not available on %d platform \n", led, *pPlatformType);

                                return UGW_FAILURE;
                        }
                        snprintf(pName, MAX_PATH_LEN, "%s%s", LED_DEFAULT_PATH, caLedPath[led][HVP]);
                        LOGF_LOG_DEBUG("led path %s \n", pName);
                        nRetval = UGW_SUCCESS;
                        break;
		}

#endif

	default:
		{
			LOGF_LOG_ERROR("Unsupported Platform \n");
			nRetval = UGW_FAILURE;
		}
	}
	return nRetval;
}
#ifdef PLATFORM_XRX750
/* =============================================================================
* Function Name : xRX750_check_boardID                                       *
* Description   : This function checks and set current board type              *
* Input     : None                                                             *
* OutPut    : None                                                             *
* Returns   : Board type string                                                *
============================================================================== */

static char* xRX750_check_boardID(void)
{
	FILE* fp = NULL;
	char fbuf[1024] = {0};
	static char *board_type = NULL;

	if (board_type != NULL){
		LOGF_LOG_DEBUG("board ID already exist = %s\n", board_type);
		return board_type;
	}

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL)
	{
		LOGF_LOG_ERROR("/proc/cmdline not found!!\n");
		goto run_default;
	}

	if (fgets(fbuf, sizeof(fbuf), fp) == NULL){
		LOGF_LOG_ERROR("Failed to read string from file!\n");
		goto run_default;
	}

	if (strstr(fbuf, HVP_BOARD_ID) != NULL) {
		LOGF_LOG_DEBUG("Haven Park board detected\n");
		board_type = HVP_BOARD_ID;
		fclose(fp);
		return board_type;
	} else if (strstr(fbuf, EASY750_BOARD_ID) != NULL) {
		LOGF_LOG_DEBUG("EASY750 board detected\n");
		board_type = EASY750_BOARD_ID;
		fclose(fp);
		return board_type;
	}


run_default:
	LOGF_LOG_DEBUG("Set board type to CGP (default)\n");
	board_type = CGP_BOARD_ID;
	fclose(fp);
	return board_type;
}
#endif

/*!  \brief  This is the utility API used to get Platform Model Number. 
  \param[in] NONE.
  \param[out] pName Model Name.
  \return  
*/
int LED_GetPlatformInfo(OUT char *pName)
{
        FILE *fp = NULL;
        fp = fopen("/proc/cpuinfo", "r");
        if (fp == NULL) {
                LOGF_LOG_ERROR("ERROR: File open failed\n");
                return UGW_FAILURE;
        }
        fscanf(fp, "system type : %s\n", pName);
        LOGF_LOG_DEBUG("\n system type: %s\n", pName);
        fclose(fp);
        return UGW_SUCCESS;
}

/* @} */
