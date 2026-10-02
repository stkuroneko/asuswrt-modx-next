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

#if defined(PLATFORM_XRX750)
char *caLedPath[MAX_LED_TYPE] = {
	FAPI_GRX750_LEDNAME_LTELED,
	FAPI_GRX750_LEDNAME_WIFI24GLED,
	FAPI_GRX750_LEDNAME_WIFI5G1LED,
	FAPI_GRX750_LEDNAME_FXS1LED,
	FAPI_GRX750_LEDNAME_FXS2LED,
	FAPI_GRX750_LEDNAME_SFPLED,
	FAPI_GRX750_LEDNAME_VDSL1LED,
	FAPI_GRX750_LEDNAME_VDSL2LED,
	FAPI_GRX750_LEDNAME_WIFI5G2LED,
	FAPI_GRX750_LEDNAME_POWERLED,
	FAPI_HVP_LEDNAME_RED,
	FAPI_HVP_LEDNAME_BLUE,
	FAPI_HVP_LEDNAME_GREEN,
};
#elif defined(PLATFORM_XRX500)
char *caLedPath[MAX_LED_TYPE] = {
	FAPI_LEDNAME_BROADBANDLED,
	FAPI_LEDNAME_BROADBANDLED1,
	FAPI_LEDNAME_VOIP0LED,
	FAPI_LEDNAME_VOIP1LED,
	FAPI_LEDNAME_LTELED,
	FAPI_LEDNAME_INTERNETLED,
	FAPI_LEDNAME_WIFI2GLED,
	FAPI_LEDNAME_WIFI5GLED,
	FAPI_LEDNAME_DECTLED,
	FAPI_LEDNAME_G2LED0,
	FAPI_LEDNAME_G3LED0,
	FAPI_LEDNAME_G4LED0,
	FAPI_LEDNAME_G5LED0,
	FAPI_LEDNAME_G6FLED0,
	FAPI_LEDNAME_LED16,
	FAPI_LEDNAME_LED17,
	FAPI_LEDNAME_LED18,
	FAPI_LEDNAME_LED19,
	FAPI_LEDNAME_LED20,
	FAPI_LEDNAME_LED21,
	FAPI_LEDNAME_LED22,
	FAPI_LEDNAME_LED23,
	FAPI_LEDNAME_LED24,
	FAPI_LEDNAME_LED25,
	FAPI_LEDNAME_LED26,
	FAPI_LEDNAME_LED27,
	FAPI_LEDNAME_LED28,
	FAPI_LEDNAME_LED29,
	FAPI_LEDNAME_LED30,
	FAPI_LEDNAME_LED31,
	FAPI_LEDNAME_LED32,
	FAPI_LEDNAME_LED33,
};
#elif defined(PLATFORM_XRX200)
char *caLedPath[MAX_LED_TYPE] = {
        FAPI_LEDNAME_BROADBANDLED,
        FAPI_LEDNAME_INTERNETLED,
        FAPI_LEDNAME_WPSLED,
};
#elif defined(PLATFORM_XRX330)
char *caLedPath[MAX_LED_TYPE] = {
	FAPI_LEDNAME_BROADBANDLED,
	FAPI_LEDNAME_BROADBANDLED1,
	FAPI_LEDNAME_VOIP0LED,
	FAPI_LEDNAME_LTELED,
	FAPI_LEDNAME_INTERNETLED,
	FAPI_LEDNAME_WIFI2GLED,
	FAPI_LEDNAME_WIFI5GLED,
};
#else
char *caLedPath[MAX_LED_TYPE] = {
	FAPI_LEDNAME_BROADBANDLED,
	FAPI_LEDNAME_BROADBANDLED1,
	FAPI_LEDNAME_VOIP0LED,
	FAPI_LEDNAME_VOIP1LED,
	FAPI_LEDNAME_LTELED,
	FAPI_LEDNAME_INTERNETLED,
	FAPI_LEDNAME_WIFI2GLED,
	FAPI_LEDNAME_WIFI5GLED,
	FAPI_LEDNAME_DECTLED,
        FAPI_LEDNAME_WPSLED,
	FAPI_LEDNAME_G2LED0,
	FAPI_LEDNAME_G3LED0,
	FAPI_LEDNAME_G4LED0,
	FAPI_LEDNAME_G5LED0,
	FAPI_LEDNAME_G6FLED0,
	FAPI_LEDNAME_LED16,
	FAPI_LEDNAME_LED17,
	FAPI_LEDNAME_LED18,
	FAPI_LEDNAME_LED19,
	FAPI_LEDNAME_LED20,
	FAPI_LEDNAME_LED21,
	FAPI_LEDNAME_LED22,
	FAPI_LEDNAME_LED23,
	FAPI_LEDNAME_LED24,
	FAPI_LEDNAME_LED25,
	FAPI_LEDNAME_LED26,
	FAPI_LEDNAME_LED27,
	FAPI_LEDNAME_LED28,
	FAPI_LEDNAME_LED29,
	FAPI_LEDNAME_LED30,
	FAPI_LEDNAME_LED31,
	FAPI_LEDNAME_LED32,
	FAPI_LEDNAME_LED33,
	FAPI_GRX750_LEDNAME_FXS1LED,
	FAPI_GRX750_LEDNAME_FXS2LED,
	FAPI_GRX750_LEDNAME_SFPLED,
	FAPI_GRX750_LEDNAME_VDSL1LED,
	FAPI_GRX750_LEDNAME_VDSL2LED,
	FAPI_GRX750_LEDNAME_WIFI5G2LED,
	FAPI_GRX750_LEDNAME_POWERLED,
	FAPI_HVP_LEDNAME_RED,
	FAPI_HVP_LEDNAME_BLUE,
	FAPI_HVP_LEDNAME_GREEN,
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
	nRetval = LED_GetInfo(led, LEDName);
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
	nRetval = LED_GetInfo(led, LEDName);
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
	nRetval = LED_GetInfo(led, LEDName);
	if (nRetval == UGW_FAILURE) {
		LOGF_LOG_ERROR(" LED_GetInfo failed \n");
		goto End;
	}

	/* Setting trigger Type */
	snprintf(sPath, MAX_PATH_LEN, "%s%s", LEDName, "/trigger");
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
int LED_GetInfo(IN LEDType led, OUT char *pName)
{
	int32_t nRetval = UGW_SUCCESS;

	if((led < 0) || (led >= MAX_LED_TYPE)){
		nRetval = UGW_FAILURE;
	}

	snprintf(pName, MAX_PATH_LEN, "%s%s", LED_DEFAULT_PATH, caLedPath[led]);
	LOGF_LOG_DEBUG("led path %s \n", pName);
	return nRetval;
}

/* @} */
