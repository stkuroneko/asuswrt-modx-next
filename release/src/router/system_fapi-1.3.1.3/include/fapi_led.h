/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/*! \file fapi_led.h
 \brief This File contains the Generic API's and common utility API's 
for all the SLs to SET/RESET the concerned LED Attributes.
*/

/** \addtogroup FAPI_SYSTEM
*/
/* @{ */

#ifndef __FAPI_LED_H_
#define __FAPI_LED_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ugw_error.h>
#include <ltq_api_include.h>


/* Name of all the Led Types present on the  board   *
 * This name will be used to create corresponding LED path *
 * for FAPI APIs. For e.g broadband_led1 will have an entry*
 * in /sys/class/leds/broadband_led1.					   *
 */ 
#if defined(PLATFORM_XRX750)
#define FAPI_GRX750_LEDNAME_FXS1LED	"FXS_1_LED"
#define FAPI_GRX750_LEDNAME_FXS2LED	"FXS_2_LED"
#define FAPI_GRX750_LEDNAME_SFPLED	"SFP_LED"
#define FAPI_GRX750_LEDNAME_VDSL1LED	"VDSL_1_LED"
#define FAPI_GRX750_LEDNAME_VDSL2LED	"VDSL_2_LED"
#define FAPI_GRX750_LEDNAME_WIFI24GLED	"WIFI_24G_LED"
#define FAPI_GRX750_LEDNAME_WIFI5G1LED	"WIFI_5G_1_LED"
#define FAPI_GRX750_LEDNAME_LTELED	"LTE_LED"
#define FAPI_GRX750_LEDNAME_POWERLED	"POWER_LED"
#define FAPI_GRX750_LEDNAME_WIFI5G2LED	"WIFI_5G_2_LED"
#define FAPI_HVP_LEDNAME_RED		"havenPark_red"
#define FAPI_HVP_LEDNAME_BLUE		"havenPark_blue"
#define FAPI_HVP_LEDNAME_GREEN		"havenPark_green"

#elif defined(PLATFORM_XRX500)
#define FAPI_LEDNAME_G6FLED0        "g6fled0"
#define FAPI_LEDNAME_G2LED0         "g2led0"
#define FAPI_LEDNAME_G3LED0         "g3led0"
#define FAPI_LEDNAME_G4LED0         "g4led0"
#define FAPI_LEDNAME_G5LED0         "g5led0"
#define FAPI_LEDNAME_DECTLED        "dect_led"
#define FAPI_LEDNAME_WIFI5GLED      "wifi5g_led"
#define FAPI_LEDNAME_VOIP1LED       "voip1_led"
#define FAPI_LEDNAME_VOIP0LED       "voip0_led"
#define FAPI_LEDNAME_LTELED         "lte_led"
#define FAPI_LEDNAME_WIFI2GLED      "wifi2g_led"
#define FAPI_LEDNAME_INTERNETLED    "internet_led"
#define FAPI_LEDNAME_BROADBANDLED1  "broadband_led1"
#define FAPI_LEDNAME_BROADBANDLED   "broadband_led"
#define FAPI_LEDNAME_LED16          "led16"
#define FAPI_LEDNAME_LED17          "led17"
#define FAPI_LEDNAME_LED18          "led18"
#define FAPI_LEDNAME_LED19          "led19"
#define FAPI_LEDNAME_LED20          "led20"
#define FAPI_LEDNAME_LED21          "led21"
#define FAPI_LEDNAME_LED22          "led22"
#define FAPI_LEDNAME_LED23          "led23"
#define FAPI_LEDNAME_LED24          "led24"
#define FAPI_LEDNAME_LED25          "led25"
#define FAPI_LEDNAME_LED26          "led26"
#define FAPI_LEDNAME_LED27          "led27"
#define FAPI_LEDNAME_LED28          "led28"
#define FAPI_LEDNAME_LED29          "led29"
#define FAPI_LEDNAME_LED30          "led30"
#define FAPI_LEDNAME_LED31          "led31"
#define FAPI_LEDNAME_LED32          "led32"
#define FAPI_LEDNAME_LED33          "led33"

#elif defined(PLATFORM_XRX200)
#define FAPI_LEDNAME_BROADBANDLED   "broadband_led"
#define FAPI_LEDNAME_INTERNETLED    "internet_led"
#define FAPI_LEDNAME_WPSLED         "wps_led"

#elif defined(PLATFORM_XRX330)
#define FAPI_LEDNAME_BROADBANDLED1  "broadband_led1"
#define FAPI_LEDNAME_BROADBANDLED   "broadband_led"
#define FAPI_LEDNAME_VOIP0LED       "voip0_led"
#define FAPI_LEDNAME_LTELED         "lte_led"
#define FAPI_LEDNAME_INTERNETLED    "internet_led"
#define FAPI_LEDNAME_WIFI2GLED      "wifi2g_led"
#define FAPI_LEDNAME_WIFI5GLED      "wifi5g_led"

#else
#define FAPI_LEDNAME_G6FLED0        "g6fled0"
#define FAPI_LEDNAME_G2LED0         "g2led0"
#define FAPI_LEDNAME_G3LED0         "g3led0"
#define FAPI_LEDNAME_G4LED0         "g4led0"
#define FAPI_LEDNAME_G5LED0         "g5led0"
#define FAPI_LEDNAME_DECTLED        "dect_led"
#define FAPI_LEDNAME_WIFI5GLED      "wifi5g_led"
#define FAPI_LEDNAME_VOIP1LED       "voip1_led"
#define FAPI_LEDNAME_VOIP0LED       "voip0_led"
#define FAPI_LEDNAME_LTELED         "lte_led"
#define FAPI_LEDNAME_WIFI2GLED      "wifi2g_led"
#define FAPI_LEDNAME_INTERNETLED    "internet_led"
#define FAPI_LEDNAME_BROADBANDLED1  "broadband_led1"
#define FAPI_LEDNAME_BROADBANDLED   "broadband_led"
#define FAPI_LEDNAME_LED16          "led16"
#define FAPI_LEDNAME_LED17          "led17"
#define FAPI_LEDNAME_LED18          "led18"
#define FAPI_LEDNAME_LED19          "led19"
#define FAPI_LEDNAME_LED20          "led20"
#define FAPI_LEDNAME_LED21          "led21"
#define FAPI_LEDNAME_LED22          "led22"
#define FAPI_LEDNAME_LED23          "led23"
#define FAPI_LEDNAME_LED24          "led24"
#define FAPI_LEDNAME_LED25          "led25"
#define FAPI_LEDNAME_LED26          "led26"
#define FAPI_LEDNAME_LED27          "led27"
#define FAPI_LEDNAME_LED28          "led28"
#define FAPI_LEDNAME_LED29          "led29"
#define FAPI_LEDNAME_LED30          "led30"
#define FAPI_LEDNAME_LED31          "led31"
#define FAPI_LEDNAME_LED32          "led32"
#define FAPI_LEDNAME_LED33          "led33"
#define FAPI_LEDNAME_WPSLED         "wps_led"
#define FAPI_GRX750_LEDNAME_FXS1LED	"FXS_1_LED"
#define FAPI_GRX750_LEDNAME_FXS2LED	"FXS_2_LED"
#define FAPI_GRX750_LEDNAME_SFPLED	"SFP_LED"
#define FAPI_GRX750_LEDNAME_VDSL1LED	"VDSL_1_LED"
#define FAPI_GRX750_LEDNAME_VDSL2LED	"VDSL_2_LED"
#define FAPI_GRX750_LEDNAME_WIFI24GLED	"WIFI_24G_LED"
#define FAPI_GRX750_LEDNAME_WIFI5G1LED	"WIFI_5G_1_LED"
#define FAPI_GRX750_LEDNAME_LTELED	"LTE_LED"
#define FAPI_GRX750_LEDNAME_POWERLED	"POWER_LED"
#define FAPI_GRX750_LEDNAME_WIFI5G2LED	"WIFI_5G_2_LED"
#define FAPI_HVP_LEDNAME_RED		"havenPark_red"
#define FAPI_HVP_LEDNAME_BLUE		"havenPark_blue"
#define FAPI_HVP_LEDNAME_GREEN		"havenPark_green"
#endif
/*!
    \LedType
    \brief Enums for all the supported LEDs.
*/
#ifdef PLATFORM_XRX750
typedef enum {
	LTELED,
        WIFI2GLED,
        WIFI5GLED,
        FXS1LED,
        FXS2LED,
        SFPLED,
        VDSLLED,
        VDSL1LED,
        WIFI5G2LED,
        POWERLED,
        HVPRED,
        HVPBLUE,
        HVPGREEN,
        MAX_LED_TYPE
} LEDType;
#elif defined(PLATFORM_XRX500)
typedef enum {
	BROADBANDLED,
	BROADBANDLED1,
	VOIP0LED,
	VOIP1LED,
	LTELED,
	INTERNETLED,
	WIFI2GLED,
	WIFI5GLED,
	DECTLED,
	G2LED0,
	G3LED0,
	G4LED0,
	G5LED0,
	G6FLED0,
	LED16,
	LED17,
	LED18,
	LED19,
	LED20,
	LED21,
	LED22,
	LED23,
	LED24,
	LED25,
	LED26,
	LED27,
	LED28,
	LED29,
	LED30,
	LED31,
	LED32,
	LED33,
	MAX_LED_TYPE
} LEDType;
#elif defined(PLATFORM_XRX200)
typedef enum {
        BROADBANDLED,
        INTERNETLED,
        WPSLED,
        MAX_LED_TYPE
} LEDType;
#elif defined(PLATFORM_XRX330)
typedef enum {
        BROADBANDLED,
        BROADBANDLED1,
        VOIP0LED,
        LTELED,
        INTERNETLED,
        WIFI2GLED,
        WIFI5GLED,
        MAX_LED_TYPE
} LEDType;
#else
typedef enum {
	BROADBANDLED, 
	BROADBANDLED1, 
	VOIP0LED, 
	VOIP1LED, 
	LTELED, 
	INTERNETLED, 
	WIFI2GLED, 
	WIFI5GLED, 
	DECTLED, 
	WPSLED,
	G2LED0, 
	G3LED0, 
	G4LED0, 
	G5LED0, 
	G6FLED0, 
	LED16,
	LED17, 
	LED18, 
	LED19, 
	LED20, 
	LED21, 
	LED22, 
	LED23, 
	LED24, 
	LED25, 
	LED26, 
	LED27, 
	LED28, 
	LED29, 
	LED30, 
	LED31, 
	LED32, 
	LED33,
	FXS1LED,
        FXS2LED,
        SFPLED,
        VDSL1LED,
        VDSL2LED,
        WIFI5G2LED,
        POWERLED,
	HVPRED,
	HVPBLUE,
	HVPGREEN,
	MAX_LED_TYPE, 
} LEDType;
#endif

/* All supported trigger types for the LEDs */ 
#define TRIGGER_TYPE_NONE       "NONE"
#define TRIGGER_TYPE_TIMER      "timer"
#define TRIGGER_TYPE_NETDEV     "netdev"
#define TRIGGER_TYPE_NANDDISK   "nand-disk"
#define TRIGGER_TYPE_DEFAULT    "default-on"
#define TRIGGER_TYPE_HEARTBEAT  "heartbeat"
#define MAX_ATTR_LEN 128
#define MAX_PATH_LEN 256
#define LED_DEFAULT_PATH        "/sys/class/leds/"
#define INVALID_DELAYON_ATTRIBUTE         -1
#define INVALID_DELAYOFF_ATTRIBUTE        -1
#define INVALID_BRIGHTNESS_ATTRIBUTE      -1
#define INVALID_LED_BLINK_ATTRIBUTE       -1
#define INVALID_INTERVAL_ATTRIBUTE        -1
#define INVALID_LED_SOURCE_ATTRIBUTE      NULL
#define INVALID_DEV_NAME_ATTRIBUTE        NULL
#define MAX_LED_BRIGHTNESS                255
#define MAX_LED_BLINK_ATTRIBUTE           1

/*!
    \State
    \brief Enums for all the Interfaces.
*/
typedef enum{
        BOOTING,
        LAN,
        ETHWAN,
        DSLWAN,
        GPONWAN,
        WIFI2G,
        WIFI5G,
        WIFI5G2,
        FXS1,
        FXS2,
        SFP,
        LTEIF,
        VDSL,
        VDSL1,
        POWER,
        INITDONE,
        INTERNET,
        DECT,
        VOIP0,
        VOIP1,
	WPS,
	SHDAP,
        MAX_INTERFACE
}InterfaceType;

/*!
    \State
    \brief Enums for all the possible states of the  Interfaces.
*/
typedef enum {
	DOWN,
	UP,
	READY,
	TRAINING,
	ERROR,
	HEART_BEAT,
	INVALID_STATE
} State;


/*!
    \TriggerType
    \brief Enums for all supported enum types.
*/ 
typedef enum { 
	TRIGGER_NONE, /* trigger type NONE            */ 
	TRIGGER_TIMER, /* Trigger type timer           */ 
	TRIGGER_NETDEV, /* Trigger Type netdev          */ 
	TRIGGER_NANDDISK, /* Trigger type nand-disk       */ 
	TRIGGER_HEARTBEAT, /* Trigger type heartbeat       */ 
	TRIGGER_DEFAULT, /* Trigger Type default-on      */ 
	TRIGGER_MAX, /* Trigger Type UNKNOWN         */ 
} TriggerType;
 
/*!
    \TriggerMode
    \brief Enums for possible mode types when trigger type is set to netdev.
*/ 
typedef enum { 
	LED_TRIGGER_MODE_LINK = 0x01, 
	LED_TRIGGER_MODE_RX = 0x02, 
	LED_TRIGGER_MODE_TX = 0x04,
	LED_INVALID_TRIGGER_MODE = 0x08
} TriggerMode;
 
/*!
    \sNetDevAttr
    \brief Structure containing the LED attributes for netdev trigger type.
*/ 

typedef struct {
	uint16_t unMode;	/* When trigger type is set o netdev, we need to specify this. This means LED is supposed to be set ON/OFF on link/rx/tx activity */
	int16_t nBrightness;	/* To set LED OFF and ON */
	int32_t nInterval;
	char DevName[MAX_ATTR_LEN];
} sNetDevAttr;
 
/*!
    \sTimerAttr
    \brief Structure containing the LED attributes for timer trigger type.
*/ 
typedef struct {
	int16_t nBrightness;	/* To set LED OFF and ON */
	int32_t nDelayOn;	/* How long (in milliseconds) the LED should be on */
	int32_t nDelayOff;	/* How long (in milliseconds) the LED should be off */
} sTimerAttr;
 
/*!
    \sDefaultAttr
    \brief Structure containing the LED attributes for timer trigger type.
*/ 
typedef struct {
	int16_t nBrightness;	/* To set LED OFF and ON */
} sDefaultAttr;
 
/*!  \brief  This is the LED FAPI exposed to all the SL to set concerned LEDs attributes. 
  \param[in] LedType enum specifying the LED type for which sl needs to set the attributes.
  \param[in] triggerType enum specifying the trigger type for the concerned LED.
  \param[in] LedAttr Pointer to the LED attributes parameters needed to be set for concerned LED.
  \param[out] NONE
  \return  
*/ 
int FAPI_LEDSetAttribute(IN LEDType led, IN TriggerType trigger, IN void *LedAttr);
int LED_TriggerNone(IN LEDType led, IN void *LedAttr);
int LED_TriggerTimer(IN LEDType led, IN void *LedAttr);
int LED_TriggerNetDev(IN LEDType led, IN void *LedAttr);
int LED_TriggerGeneric(IN LEDType led, IN char *pTrigger, IN void *LedAttr);
int LED_SetAttribute(char *pFilepath, char *pattr);
int LED_GetName(IN LEDType led, OUT char *LEDName);
int LED_GetInfo(IN LEDType led, OUT char *Name);
/*!  \brief  This is the LED FAPI exposed to all the SL to set concerned Interface state.
  \param[in] Interface enum specifying the Interface type for which sl needs to set the state.
  \param[in] State  enum specifying the State type for the concerned Interface.
  \param[in] void pointer specifying the attributes sl needs to set for the  concerned Interface. 	
  \param[out] NONE
  \return
*/
int FAPI_InterfaceSetState(IN InterfaceType, IN State, IN void *);

#endif
/* @} */
