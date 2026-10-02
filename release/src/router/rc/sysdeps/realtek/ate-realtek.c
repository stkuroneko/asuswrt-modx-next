/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */
#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include <net/if_arp.h>
#include <shutils.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <errno.h>
#include <etioctl.h>
#include <rc.h>
typedef u_int64_t __u64;
typedef u_int32_t __u32;
typedef u_int16_t __u16;
typedef u_int8_t __u8;
#include <linux/sockios.h>
#include <linux/ethtool.h>
#if defined(RTCONFIG_REALTEK)
#if defined(RTCONFIG_RTL8198D)
#include "flash_mtd.h"
#endif
#include "realtek.h"

//TODO
#if defined(RPAC92)
#include "../../../src-rtk-sdk4.3.1/linux/realtek/rtl819x/linux-4.4.x/drivers/net/wireless/realtek/rtl8192cd/ieee802_mib.h"
#include "../../../src-rtk-sdk4.3.1/linux/realtek/rtl819x/linux-4.4.x/include/generated/autoconf.h"
#else
#include "../../../../../realtek/rtl819x/linux-3.10/drivers/net/wireless/rtl8192cd/ieee802_mib.h"
#include "../../../../../realtek/rtl819x/linux-3.10/include/generated/autoconf.h"
#endif
#include "mib_adapter/rtk_wifi_drvmib.h"
#else
#include <ctype.h>
#endif
#include <wlutils.h>
#include <shared.h>

extern void set_led(int wl0_stage, int wl1_stage);

static char *ATE_REALTEK_FACTORY_MODE_STR()
{
	char atemode[8];

	snprintf(atemode, sizeof(atemode), "%s%s%s%s%s%s%s%s", "A", "T", "E", "M", "O", "D", "E", "\0");
	return strdup(atemode);
}

int IS_ATE_FACTORY_MODE(void)
{
	char *mode_str = ATE_REALTEK_FACTORY_MODE_STR();
	int ret = strcmp(nvram_safe_get(mode_str), "1");

	free(mode_str);

	return (ret == 0);
}

void platform_start_ate_mode(void)
{
}

void ate_commit_bootlog(char *err_code)
{
	nvram_set("Ate_power_on_off_enable", err_code);
	nvram_commit();
}

#if defined(RTCONFIG_CONCURRENTREPEATER)
#if defined(RPAC53) || defined(RPAC55) || defined(RPAC92)
int set_off_led(led_state_t *led)
{
#if  defined(RPAC53)
	switch (led->id) {
	case LED_POWER:
		led_control(LED_POWER_RED, LED_OFF);
		led_control(LED_POWER, LED_OFF);
		break;
	case LED_2G:
		led_control(LED_2G_ORANGE, LED_OFF);
		led_control(LED_2G_GREEN, LED_OFF);
		led_control(LED_2G_RED, LED_OFF);
		break;
	case LED_5G:
		led_control(LED_5G_ORANGE, LED_OFF);
		led_control(LED_5G_GREEN, LED_OFF);
		led_control(LED_5G_RED, LED_OFF);
		break;
	case LED_LAN:
		led_control(LED_LAN, LED_OFF);
		break;
	default:
		dbG("Not support the LED ID:%d\n", led->id);
	}
#elif defined(RPAC55)
	switch (led->id) {
	case LED_POWER:
		led_control(LED_POWER, LED_OFF);
		led_control(LED_POWER_RED, LED_OFF);
		break;
	case LED_WIFI:
		led_control(LED_WIFI, LED_OFF);
		break;
	case LED_SIG1:
		led_control(LED_SIG1, LED_OFF);
		break;
	case LED_SIG2:
		led_control(LED_SIG2, LED_OFF);
		break;
	default:
		dbG("Not support the LED ID:%d\n", led->id);
	}
#elif defined(RPAC92)
	switch (led->id) {
	case LED_POWER:
		led_control(LED_POWER, LED_OFF);
		led_control(LED_POWER_RED, LED_OFF);
		break;
	case LED_WIFI:
		led_control(LED_WIFI, LED_OFF);
		break;
	case LED_SIG1:
		led_control(LED_SIG1, LED_OFF);
		break;
	case LED_SIG2:
		led_control(LED_SIG2, LED_OFF);
		break;
	case LED_PURPLE:
		led_control(LED_PURPLE, LED_OFF);
		break;
	default:
		dbG("Not support the LED ID:%d\n", led->id);
	}
#endif
	led->state = LED_OFF;
	return 0;
}

int set_on_led(led_state_t *led)
{
#if defined(RPAC53)
	switch (led->id) {
	case LED_POWER:
		if (led->color == LED_GREEN)
			led_control(LED_POWER, LED_ON);
		else if (led->color == LED_RED)
			led_control(LED_POWER_RED, LED_ON);
		break;
	case LED_2G:
		if (led->color == LED_RED)
			led_control(LED_2G_RED, LED_ON);
		else if (led->color == LED_GREEN)
			led_control(LED_2G_GREEN, LED_ON);
		else if (led->color == LED_ORANGE)
			led_control(LED_2G_ORANGE, LED_ON);
		break;
	case LED_5G:
		if (led->color == LED_RED)
			led_control(LED_5G_RED, LED_ON);
		else if (led->color == LED_GREEN)
			led_control(LED_5G_GREEN, LED_ON);
		else if (led->color == LED_ORANGE)
			led_control(LED_5G_ORANGE, LED_ON);
		break;
	case LED_LAN:
		led_control(LED_LAN, LED_ON);
		break;
	default:
		dbG("Not support the LED ID:%d\n", led->id);
	}
#elif defined(RPAC55)
	switch (led->id) {
	case LED_POWER:
		if (led->color == LED_BLUE)
			led_control(LED_POWER, LED_ON);
		else if (led->color == LED_RED)
			led_control(LED_POWER_RED, LED_ON);
		break;
	case LED_WIFI:
		led_control(LED_WIFI, LED_ON);
		break;
	case LED_SIG1:
		led_control(LED_SIG1, LED_ON);
		break;
	case LED_SIG2:
		led_control(LED_SIG2, LED_ON);
		break;
	default:
		dbG("Not support the LED ID:%d\n", led->id);
	}
#elif defined(RPAC92)
	switch (led->id) {
	case LED_POWER:
		if (led->color == LED_BLUE)
			led_control(LED_POWER, LED_ON);
		else if (led->color == LED_RED)
			led_control(LED_POWER_RED, LED_ON);
		break;
	case LED_WIFI:
		led_control(LED_WIFI, LED_ON);
		break;
	case LED_SIG1:
		led_control(LED_SIG1, LED_ON);
		break;
	case LED_SIG2:
		led_control(LED_SIG2, LED_ON);
		break;
	case LED_PURPLE:
		led_control(LED_PURPLE, LED_ON);
		break;
	default:
		dbG("Not support the LED ID:%d\n", led->id);
	}
#endif
	led->state = LED_ON;
	return 0;
}
void update_gpiomode(int gpio, int mode)
{
	char path[PATH_MAX], val_str[64];
 
	sprintf(val_str, "gpiomode %d %d", gpio, mode);
	sprintf(path, "/proc/asus_ate");
	f_write_string(path, val_str, 0, 0);
}
#endif
#endif

int setAllLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);
#if defined(RPAC68U)
	set_led(LED_ON_ALL, LED_ON_ALL);
#elif defined(RPAC53)
	led_control(LED_POWER, LED_ON);
	led_control(LED_WAN, LED_ON);
	led_control(LED_LAN, LED_ON);
	led_control(LED_USB, LED_ON);

	update_gpiomode(14, 1);
	led_control(LED_POWER_RED, LED_ON);
	led_control(LED_2G_ORANGE, LED_ON);
	led_control(LED_2G_GREEN, LED_ON);
	led_control(LED_2G_RED, LED_ON);
	led_control(LED_5G_ORANGE, LED_ON);
	led_control(LED_5G_GREEN, LED_ON);
	led_control(LED_5G_RED, LED_ON);
#elif defined(RPAC55)
	led_control(LED_POWER, LED_ON);
	led_control(LED_POWER_RED, LED_ON);
	led_control(LED_WIFI, LED_ON);
	led_control(LED_SIG1, LED_ON);
	led_control(LED_SIG2, LED_ON);
#elif defined(RPAC92)
	led_control(LED_POWER, LED_ON);
	led_control(LED_POWER_RED, LED_ON);
	led_control(LED_SIG1, LED_ON);
	led_control(LED_SIG2, LED_ON);
	led_control(LED_PURPLE, LED_ON);
	led_control(LED_WIFI, LED_ON);
#endif
	puts("1");
	return 0;
}

int setAllLedOff(void)
{
	rtklog("%s\n",__FUNCTION__);
#if defined(RPAC68U)
	set_led(LED_OFF_ALL, LED_OFF_ALL);
#elif defined(RPAC53)
	led_control(LED_POWER, LED_OFF);
	led_control(LED_WAN, LED_OFF);
	led_control(LED_LAN, LED_OFF);
	led_control(LED_USB, LED_OFF);

	update_gpiomode(14, 1);
	led_control(LED_POWER_RED, LED_OFF);
	led_control(LED_2G_ORANGE, LED_OFF);
	led_control(LED_2G_GREEN, LED_OFF);
	led_control(LED_2G_RED, LED_OFF);
	led_control(LED_5G_ORANGE, LED_OFF);
	led_control(LED_5G_GREEN, LED_OFF);
	led_control(LED_5G_RED, LED_OFF);
#elif defined(RPAC55)
	led_control(LED_POWER, LED_OFF);
	led_control(LED_POWER_RED, LED_OFF);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
#elif defined(RPAC92)
	led_control(LED_POWER, LED_OFF);
	led_control(LED_POWER_RED, LED_OFF);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
	led_control(LED_PURPLE, LED_OFF);
#endif
	puts("1");
	return 0;
}

#if defined(RTCONFIG_WPS_ALLLED_BTN) || defined(RTCONFIG_SW_CTRL_ALLLED)
void setAllLedNormal(void)
{
	led_control(LED_POWER, LED_ON);

#ifdef RTCONFIG_LAN4WAN_LED
	LanWanLedCtrl();
#endif

	/* check LED_WAN status */
	kill_pidfile_s("/var/run/wanduck.pid", SIGUSR2);
}
#endif

#ifdef RTCONFIG_SW_CTRL_ALLLED
void setAllLedBrightness(void)
{
}
#endif

#ifdef RPAC53
int setAllGreenLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	led_control(LED_POWER, LED_ON);
	led_control(LED_LAN, LED_ON);
	update_gpiomode(14, 1);

	led_control(LED_2G_GREEN, LED_ON);
	led_control(LED_5G_GREEN, LED_ON);
	
	puts("1");
	return 0;
}

int setAllOrangeLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	led_control(LED_2G_ORANGE, LED_ON);
	led_control(LED_5G_ORANGE, LED_ON);

	puts("1");
	return 0;
}
#endif

#ifdef RPAC92
int setAllGreenLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	led_control(LED_POWER_RED, LED_OFF);
	led_control(LED_POWER, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
	led_control(LED_PURPLE, LED_OFF);
	led_control(LED_WIFI, LED_ON);
	puts("1");
	return 0;
}

int setAllYellowLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	led_control(LED_POWER_RED, LED_OFF);

	led_control(LED_POWER, LED_OFF);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_ON);
	led_control(LED_PURPLE, LED_OFF);

	puts("1");
	return 0;
}
int setAllWhiteLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	led_control(LED_POWER_RED, LED_OFF);

	led_control(LED_POWER, LED_OFF);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_ON);
	led_control(LED_SIG2, LED_OFF);
	led_control(LED_PURPLE, LED_OFF);

	puts("1");
	return 0;
}

int setAllPurpleLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	led_control(LED_POWER_RED, LED_OFF);

	led_control(LED_POWER, LED_OFF);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
	led_control(LED_PURPLE, LED_ON);

	puts("1");
	return 0;
}

int setAllBlueLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	/* Turn off other lights.*/
	led_control(LED_POWER_RED, LED_OFF);

	led_control(LED_POWER, LED_ON);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
	led_control(LED_PURPLE, LED_OFF);

	puts("1");
	return 0;
}

#endif

#if defined(RPAC53) || defined(RPAC55)  || defined(RPAC92)
int setAllRedLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	/* Turn off other lights.*/
#if defined(RPAC55)
	led_control(LED_POWER, LED_OFF);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
#endif

#if defined(RPAC92)
	led_control(LED_POWER, LED_OFF);
	led_control(LED_WIFI, LED_OFF);
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
	led_control(LED_PURPLE, LED_OFF);
#endif

	led_control(LED_POWER_RED, LED_ON);
#if defined(RPAC53)
	led_control(LED_2G_RED, LED_ON);
	led_control(LED_5G_RED, LED_ON);
#endif

	puts("1");
	return 0;
}
#endif
#if defined(RPAC55)
int setAllBlueLedOn(void)
{	
	rtklog("%s\n",__FUNCTION__);

	/* Turn off other lights.*/
	led_control(LED_POWER_RED, LED_OFF);

	led_control(LED_POWER, LED_ON);
	led_control(LED_WIFI, LED_ON);
	led_control(LED_SIG1, LED_ON);
	led_control(LED_SIG2, LED_ON);

	puts("1");
	return 0;
}
#endif

#ifdef RPAC92
int getMAC_5G_2(void)
{
	unsigned char buffer[6];
	char macaddr[18];
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	if (FRead(buffer, OFFSET_MAC_ADDR_5G_2, 6) < 0)
		printf("READ MAC address: Out of scope\n");
	else {
		ether_etoa(buffer, macaddr);
		puts(macaddr);
	}
	return 0;
}
#endif

int setMAC_2G(const char *mac)
{
	unsigned char ea[ETHER_ADDR_LEN];

	if (mac==NULL || !isValidMacAddr(mac))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
		return 0;

#ifdef RTCONFIG_RTL8198D
	if (ether_atoe(mac, ea)) {
		FWrite(ea, OFFSET_MAC_ADDR_2G, 6);
		getMAC_2G();
	}
#else
	int offset = HW_SETTING_OFFSET;
	int offset_nic0 = HW_SETTING_OFFSET;

	if (ether_atoe(mac, ea))
	{
		offset += sizeof(PARAM_HEADER_T);
		offset += (int)(&((struct hw_setting *)0)->wlan);
		offset += sizeof(struct hw_wlan_setting);
		offset += (int)(&((struct hw_wlan_setting *)0)->macAddr);
		rtk_flash_write(ea,offset,6);

		/* Set NIC0 MAC address */
		offset_nic0 += sizeof(PARAM_HEADER_T);
		offset_nic0 += (int)(&((struct hw_setting *)0)->nic0Addr);
		rtk_flash_write(ea, offset_nic0, 6);

		/* Set Guest Network MAC address */
		offset += 6; // 1st Guest Network MAC address
		ea[5] += 1;
		rtk_flash_write(ea, offset, 6);
		offset += 6; // 2nd Guest Network MAC address
		ea[5] += 1;
		rtk_flash_write(ea, offset, 6);
		offset += 6; // 3rd Guest Network MAC address
		ea[5] += 1;
		rtk_flash_write(ea, offset, 6);

		getMAC_2G();
	}
#endif
	return 1;
}

int setMAC_5G(const char *mac)
{
	char ea[ETHER_ADDR_LEN];

	if (mac==NULL || !isValidMacAddr(mac))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
		return 0;

#ifdef RTCONFIG_RTL8198D
	if (ether_atoe(mac, ea)) {
		FWrite(ea, OFFSET_MAC_ADDR_5G, 6);
		getMAC_5G();
	}
#else
	int offset = HW_SETTING_OFFSET;
	int offset_nic1 = HW_SETTING_OFFSET;

	if (ether_atoe(mac, ea))
	{
		offset += sizeof(PARAM_HEADER_T);
		offset += (int)(&((struct hw_setting *)0)->wlan);
		offset += (int)(&((struct hw_wlan_setting *)0)->macAddr);
		rtk_flash_write(ea,offset,6);

		/* Set NIC1 MAC address */
		offset_nic1 += sizeof(PARAM_HEADER_T);
		offset_nic1 += (int)(&((struct hw_setting *)0)->nic1Addr);
		rtk_flash_write(ea, offset_nic1, 6);

		/* Set Guest Network MAC address */
		offset += 6; // 1st Guest Network MAC address
		ea[5] += 1;
		rtk_flash_write(ea, offset, 6);
		offset += 6; // 2nd Guest Network MAC address
		ea[5] += 1;
		rtk_flash_write(ea, offset, 6);
		offset += 6; // 3rd Guest Network MAC address
		ea[5] += 1;
		rtk_flash_write(ea, offset, 6);

		getMAC_5G();
	}
#endif
	return 1;
}
#ifdef RPAC92
int setMAC_5G_2(const char *mac)
{
	char ea[ETHER_ADDR_LEN];

	if (mac==NULL || !isValidMacAddr(mac))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
		return 0;

	if (ether_atoe(mac, ea)) {
		FWrite(ea, OFFSET_MAC_ADDR_5G_2, 6);
		getMAC_5G_2();
	}
	return 1;
}
#endif

#ifdef RPAC55
int setMAC_BT(const char *mac)
{
	rtklog("%s\n",__FUNCTION__);
	char ea[ETHER_ADDR_LEN];
	int offset = BLUETOOTH_HW_SETTING_OFFSET;
	if (mac==NULL || !isValidMacAddr(mac))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
		return 0;

	if (ether_atoe(mac, ea))
	{
		offset += sizeof(PARAM_HEADER_T);
		offset += (int)(&(((BLUETOOTH_HW_SETTING_T *)0)->btAddr));
		rtk_flash_write(ea,offset,6);

		getMAC_BT();
	}
	return 1;
}
int getMAC_BT(const char *mac)
{
	rtklog("%s\n",__FUNCTION__);
	unsigned char buffer[6];
	char macaddr[18];
	int offset = BLUETOOTH_HW_SETTING_OFFSET;
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	offset += sizeof(PARAM_HEADER_T);
	offset += (int)(&(((BLUETOOTH_HW_SETTING_T *)0)->btAddr));
	rtk_flash_read(buffer,offset,6);

	ether_etoa(buffer, macaddr);
	puts(macaddr);
}
#endif

int setCountryCode_2G(const char *cc)
{
	if (cc==NULL || !isValidCountryCode(cc))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
		return 0;

#ifdef RTCONFIG_RTL8198D
	char CC[3];

	memset(&CC[0], toupper(cc[0]), 1);
	memset(&CC[1], toupper(cc[1]), 1);
	memset(&CC[2], 0, 1);

	FWrite(CC, OFFSET_COUNTRY_CODE, 2);
	puts(CC);
#else
	int rd_offset_2g = HW_SETTING_OFFSET;
	int rd_offset_5g = HW_SETTING_OFFSET;
	int cc_offset = HW_SETTING_OFFSET;
	int i = 0, num = sizeof(reg_domain)/sizeof(reg_domain_t);
	unsigned char code_2g = 0;
	unsigned char code_5g = 0;

	while (i < num) {
		if (strcmp(cc, reg_domain[i].name) == 0) {
			code_2g = reg_domain[i].band_2G;
			code_5g = reg_domain[i].band_5G;
			break;
		}
		i++;
	}

	if ((code_2g < DOMAIN_FCC || code_2g >= DOMAIN_MAX) || (code_5g < DOMAIN_FCC || code_5g >= DOMAIN_MAX))
		return 0;

	/* write country code */
	cc_offset += sizeof(PARAM_HEADER_T);
	cc_offset += (int)(&((struct hw_setting *)0)->countryCode);	
	rtk_flash_write(cc, cc_offset, 2);

	/* write regDomain for 2G */
	rd_offset_2g += sizeof(PARAM_HEADER_T);
	rd_offset_2g += (int)(&((struct hw_setting *)0)->wlan);
	rd_offset_2g += sizeof(struct hw_wlan_setting);
	rd_offset_2g += (int)(&((struct hw_wlan_setting *)0)->regDomain);	
	rtk_flash_write(&code_2g, rd_offset_2g, 1);
	nvram_set("wl0_country_code", cc);
	
	/* write regDomain for 5G */
	rd_offset_5g += sizeof(PARAM_HEADER_T);
	rd_offset_5g += (int)(&((struct hw_setting *)0)->wlan);
	rd_offset_5g += (int)(&((struct hw_wlan_setting *)0)->regDomain);
	rtk_flash_write(&code_5g, rd_offset_5g, 1);
	nvram_set("wl1_country_code", cc);
	puts(cc);
#endif

	return 1;
}

int setCountryCode_5G(const char *cc)
{
	return 1;
}

int setTerritoryCode(const char *tcode)
{
	unsigned char tc_buf[5];
	memset(tc_buf, 0, sizeof(tc_buf));
#ifndef RTCONFIG_RTL8198D
	int tc_offset = HW_SETTING_OFFSET;
	tc_offset += sizeof(PARAM_HEADER_T);
	tc_offset += (int)(&((struct hw_setting *)0)->territoryCode);
#endif
	/* special case
	 * if tcode == "FFFFF", Write FF, FF, FF, FF, FF to OFFSET_TERRITORY_CODE
	 */
	if (!strcmp(tcode, "FFFFF")) {
		memset(tc_buf, 0xFF, sizeof(tc_buf));
#ifdef RTCONFIG_RTL8198D
		FWrite(tc_buf, OFFSET_TERRITORY_CODE, 5);
#else
		rtk_flash_write(tc_buf, tc_offset, 5);
#endif
		nvram_unset("territory_code");

		return 0;
	}

	/* [A-Z][0-9 A-Z]/[0-9][0-9] */
	if (tcode[2] != '/' ||
		!isupper(tcode[0]) || (!isupper(tcode[1]) && !isdigit(tcode[1])) ||
		!isdigit(tcode[3]) || !isdigit(tcode[4]))
	{
		return -1; //only check 5 bytes??
	}

	if (!IS_ATE_FACTORY_MODE())
		return -1;
#ifdef RTCONFIG_RTL8198D
	FWrite(tcode, OFFSET_TERRITORY_CODE, 5);
#else
	rtk_flash_write(tcode, tc_offset, 5);
#endif
	nvram_set("territory_code", tcode);

	return 0;
}

int getTerritoryCode()
{
	unsigned char tc_buf[6];
	memset(tc_buf, 0, sizeof(tc_buf));
#ifdef RTCONFIG_RTL8198D
	if(FRead(tc_buf, OFFSET_TERRITORY_CODE, 5)<0) {
		printf("READ TERRITORY_CODE: Fail\n");
		return 0;
	}
#else
	int tc_offset = HW_SETTING_OFFSET;
	tc_offset += sizeof(PARAM_HEADER_T);
	tc_offset += (int)(&((struct hw_setting *)0)->territoryCode);

	rtk_flash_read(tc_buf, tc_offset, 5);
#endif
	if (tc_buf[0] != 0xFF)
		puts(tc_buf);

	return 0;
}

#ifdef RTCONFIG_RTL8198D
int getPSK(void)
{
	char buffer[15]={0};
	int i;
	memset(buffer,0,sizeof(buffer));
	FRead(buffer, OFFSET_PSK, 14);
	if (buffer[0] == (char)0xFF)
		puts("NONE");
	else{
		for(i = 0; i < 14 && buffer[i] != '\0'; i++) {
			if ((unsigned char)buffer[i] == 0xff)
			{
				buffer[i] = '\0';
				break;
			}
		}
		puts(buffer);
	}
	return 0;
}

int setPSK(const char *psk)
{
	int i;
	char buffer[15];

	if (strcmp(psk, "NONE")) {
		if (psk == NULL || strlen(psk) < 8 ||strlen(psk) > 32)
			return -1;

		for (i = 0; i < strlen(psk) ; i++) {
			if (psk[i] == '0' || psk[i] == '1' || psk[i] == '8')
				return -1;
		else if (psk[i] != '_' && !isalnum(psk[i]))
			return -1;
		}
		if (!IS_ATE_FACTORY_MODE())
			return -1;

		memset(buffer,0,sizeof(buffer));
		memcpy(buffer,psk,14);
		FWrite(buffer, OFFSET_PSK, 15);
	}
	else
	{
		/* reset to 0xFF to clean */
		memset(buffer,0xFF,sizeof(buffer));
		FWrite(buffer, OFFSET_PSK, 15);		
	}
	return 0;
}
#else
int getPSK(void)
{

	return 0;
}

int setPSK(const char *psk)
{

	return 0;
}
#endif
int setUsb3p0Enable()
{
	usb3_enable(1);
	nvram_set("usb_usb3", "1");
	puts("1");
	return 0;
}

int setUsb3p0Disable()
{
	usb3_enable(0);
	nvram_set("usb_usb3", "0");
	puts("1");
	return 0;
}

int setSN(const char *SN)
{
	return 0;
}

int getEISN(void)
{
	return 1;
}

int setEISN(const char *EISN)
{
	return 1;
}

int setMN(const char *MN)
{
	char modelname[16];
#ifndef RTCONFIG_RTL8198D
	int mn_offset = HW_SETTING_OFFSET;

	mn_offset += sizeof(PARAM_HEADER_T);
	mn_offset += (int)(&((struct hw_setting *)0)->modelName);
#endif
	if(MN==NULL || !is_valid_hostname(MN))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
		return 0;

	memset(modelname, 0, sizeof(modelname));
	strncpy(modelname, MN, sizeof(modelname) -1);
#ifdef RTCONFIG_RTL8198D
	FWrite(modelname, OFFSET_ODMPID, sizeof(modelname));
#else
	rtk_flash_write(modelname, mn_offset, sizeof(modelname));
#endif
	nvram_set("odmpid", modelname);
	puts(nvram_safe_get("odmpid"));

	return 1;
}

int setPIN(const char *pin)
{
	if (!IS_ATE_FACTORY_MODE())
		return 0;
#ifndef RTCONFIG_RTL8198D
	int offset = HW_SETTING_OFFSET;
	offset += sizeof(PARAM_HEADER_T);
	offset += (int)(&((struct hw_setting *)0)->wlan);
	offset += (int)(&((struct hw_wlan_setting *)0)->wscPin);
#endif
	if (pincheck(pin))
	{
#ifdef RTCONFIG_RTL8198D
		FWrite(pin, OFFSET_PIN_CODE, 8);
#else
		rtk_flash_write(pin,offset,8);
		offset += sizeof(struct hw_wlan_setting);
		rtk_flash_write(pin,offset,8);
#endif
		char PIN[9];
		memset(PIN, 0, 9);
		memcpy(PIN, pin, 8);
		puts(PIN);
		return 1;
	}
	return 0;	
}

int getBootVer()
{
	char buf[32], out[64];
	memset(buf, 0, sizeof(buf));
#ifdef RTCONFIG_RTL8198D
	FRead(buf, OFFSET_BOOT_VER, 4);
	snprintf(out, sizeof(out), "%s-%c.%c.%c.%c", \
			 nvram_safe_get("productid"), \
			 buf[0], buf[1], buf[2], buf[3]);
#else
	FILE *fp;
	system("echo 'bootver 1' > /proc/asus_ate");
	fp = popen("cat /proc/asus_ate", "r");
	if (fp) {
		fgets(buf, sizeof(buf),fp);
		pclose(fp);
	}
	sprintf(out, "%s-%s", nvram_safe_get("productid"), buf);
#endif
	puts(out);
	return 0;
}

int getMAC_2G()
{
	unsigned char buffer[6];
	char macaddr[18];
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

#ifdef RTCONFIG_RTL8198D
	if (FRead(buffer, OFFSET_MAC_ADDR_2G, 6) < 0) {
		printf("READ MAC address 2G: Out of scope\n");
		return 0;
	}
#else
	int offset = HW_SETTING_OFFSET;
	offset += sizeof(PARAM_HEADER_T);
	offset += (int)(&((struct hw_setting *)0)->wlan);
	offset += sizeof(struct hw_wlan_setting);
	offset += (int)(&((struct hw_wlan_setting *)0)->macAddr);
	rtk_flash_read(buffer,offset,6);
#endif

	ether_etoa(buffer, macaddr);
	puts(macaddr);

	return 0;
}

int getMAC_5G()
{
	unsigned char buffer[6];
	char macaddr[18];

	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));
#ifdef RTCONFIG_RTL8198D
	if(FRead(buffer, OFFSET_MAC_ADDR_5G, 6) < 0) {
		printf("READ MAC address: Out of scope\n");
		return 0;
	}
#else
	int offset = HW_SETTING_OFFSET;
	offset += sizeof(PARAM_HEADER_T);
	offset += (int)(&((struct hw_setting *)0)->wlan);
	offset += (int)(&((struct hw_wlan_setting *)0)->macAddr);
	rtk_flash_read(buffer,offset,6);
#endif

	ether_etoa(buffer, macaddr);
	puts(macaddr);

	return 0;
}

int getCountryCode_2G()
{
	char country_code[3];
	memset(country_code, 0, sizeof(country_code));
#ifdef RTCONFIG_RTL8198D
	FRead(country_code, OFFSET_COUNTRY_CODE, 2);
#else
	int cc_offset = HW_SETTING_OFFSET;


	cc_offset += sizeof(PARAM_HEADER_T);
	cc_offset += (int)(&((struct hw_setting *)0)->countryCode);

	rtk_flash_read(country_code, cc_offset, 2);
#endif
	if (country_code[0] == 0x0 && country_code[0] == 0xff)	// 0x0 is default
		;
	else
		puts(country_code);

	return 0;
}

int getCountryCode_5G()
{
	return 0;
}

int getSN(void)
{
	return 0;
}

int getMN(void)
{
	puts(nvram_safe_get("odmpid"));
	return 0;
}

/** @brief Get device model name form flash.
 *
 *  @param modelname IN/OUT. Return model name to caller. 
 *
 *  @param length IN. Param modelname is length. Prevent to overflow.
 *
 *  @return 0 is normal. Others is error.
 */
int getflashMN(char *modelname, int length)
{
#ifndef RTCONFIG_RTL8198D
	int mn_offset = HW_SETTING_OFFSET;
 
	mn_offset += sizeof(PARAM_HEADER_T);
	mn_offset += (int)(&((struct hw_setting *)0)->modelName);
#endif
	memset(modelname, 0, length);

	if (length > 16)
		length = 16; /* hw-setting modelname size is 16. */
#ifdef RTCONFIG_RTL8198D
	FRead(modelname, OFFSET_ODMPID, length);
#else
	rtk_flash_read(modelname, mn_offset, length);
#endif
	modelname[length - 1] = '\0';

	return 0;
}

int getPIN()
{

	unsigned char PIN[9];
	memset(PIN, 0, sizeof(PIN));
#ifdef RTCONFIG_RTL8198D
	FRead(PIN, OFFSET_PIN_CODE, 8);
#else
	int offset = HW_SETTING_OFFSET;
	offset += sizeof(PARAM_HEADER_T);
	offset += (int)(&((struct hw_setting *)0)->wlan);
	offset += (int)(&((struct hw_wlan_setting *)0)->wscPin);
	rtk_flash_read(PIN,offset,8);
#endif
	if (PIN[0] != 0xff)
		puts(PIN);

	return 0;
}

int GetPhyStatus(int verbose, phy_info_list *list)
{
	FILE *fp;
	char out[64], output[64] = "";
	char *b;
	char phystatus[5][4];
	int i;

	system("echo 'physt 1' > /proc/asus_ate");
	fp = popen("cat /proc/asus_ate", "r");
	if (fp) {
		fgets(out, sizeof(out),fp);
		pclose(fp);
	}

	for (i = 0, b = strtok(out, ";"); b != NULL; b = strtok(NULL, ";"), i++)
		snprintf(phystatus[i], sizeof(phystatus[i])/sizeof(char) - 1, "%s", index(b, '=')+1);
	
#if defined(RPAC53)
	sprintf(output, "L1=%s;", phystatus[4]);
#elif defined(RPAC55)
	sprintf(output, "L1=%s;", phystatus[0]);
#elif defined(RPAC92)
	sprintf(output, "L1=%s;", phystatus[1]);
#else
	sprintf(output, "L1=%s;L2=%s;L3=%s;L4=%s;L5=%s;", 
			phystatus[0], phystatus[1], phystatus[2], phystatus[3], phystatus[4]);
#endif

	puts(output);

	return 1;
}


unsigned int get_channel_list(int band, char *chList, char *countryCode)
{
	int i = 0, num = sizeof(reg_domain)/sizeof(reg_domain_t);
	unsigned char code = 0;
	struct channel_list *ch = NULL;
	char tmp[8];

	//ch = ((band == WLAN_2G)?reg_channel_2_4g:reg_channel_5g_full_band);
	if(band == WLAN_2G)
	{
		ch = reg_channel_2_4g;
	}
	else if(band == WLAN_5G)
	{
		ch = reg_channel_5g_full_band;
	}
#ifdef RPAC92
	else if(band == WLAN_5G_2)
	{
		ch = reg_channel_5g_full_band_2;
	}
#endif

	while (i < num) {
		if (strcmp(countryCode, reg_domain[i].name) == 0) {
			code = ((band == WLAN_2G)?reg_domain[i].band_2G:reg_domain[i].band_5G);
			break;
		}
		i++;
	}

	if (code) {
		for(i=0; i<ch[code-1].len; i++) {
			memset(tmp,0,sizeof(tmp));
			sprintf(tmp,"%d",ch[code-1].channel[i]);
			strcat(chList,tmp);
			if(i != ch[code-1].len - 1)
				strcat(chList,",");
		}
		//puts(chList);
	}

	return code;
}


int Get_ChannelList_2G(void)
{
	rtklog("%s\n",__FUNCTION__);
	unsigned char countryCode[3];
	char chList[256]={0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	int unit = 0;
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	memset(countryCode, 0, sizeof(countryCode));
	strncpy(countryCode, nvram_safe_get(strcat_r(prefix, "country_code", tmp)), 2);
	rtklog("countryCode:%s\n",countryCode);

#if 1
	get_channel_list(WLAN_2G, chList, countryCode);
	puts(chList);

/*
	printf("\n\n======================================\n");
	printf("chList[%s]\n", chList);
	printf("======================================\n\n\n");
*/
#elif 0
{
	int i = 0, num = sizeof(reg_domain)/sizeof(reg_domain_t);
	unsigned char code = 0;

	while (i < num) {
		if (strcmp(countryCode, reg_domain[i].name) == 0) {
			code = reg_domain[i].band_2G;
			break;
		}
		i++;
	}

	if (code) {
		for(i=0; i<reg_channel_2_4g[code-1].len; i++) {
			memset(tmp,0,sizeof(tmp));
			sprintf(tmp,"%d",reg_channel_2_4g[code-1].channel[i]);
			strcat(chList,tmp);
			if(i != reg_channel_2_4g[code-1].len - 1)
				strcat(chList,",");
		}
		puts(chList);
	}
}
#else
	if(rtk_get_channel_list_via_country(countryCode,chList,WLAN_2G)==0)
	{
		puts(chList);
	}
#endif

	return 1;
}

int Get_ChannelList_5G(void)
{
	rtklog("%s\n",__FUNCTION__);
	unsigned char countryCode[3];
	char chList[256]={0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	int unit = 1;
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	memset(countryCode, 0, sizeof(countryCode));
	strncpy(countryCode, nvram_safe_get(strcat_r(prefix, "country_code", tmp)), 2);
	rtklog("countryCode:%s\n",countryCode);

#if 1
	get_channel_list(WLAN_5G, chList, countryCode);
	puts(chList);
#elif 0
{
	int i = 0, num = sizeof(reg_domain)/sizeof(reg_domain_t);
	unsigned char code = 0;
	//struct channel_list *ch = reg_channel_5g_full_band;

	while (i < num) {
		if (strcmp(countryCode, reg_domain[i].name) == 0) {
			code = reg_domain[i].band_2G;
			break;
		}
		i++;
	}

	if (code) {
		for(i=0; i<reg_channel_5g_full_band[code-1].len; i++) {
			memset(tmp,0,sizeof(tmp));
			sprintf(tmp,"%d",reg_channel_5g_full_band[code-1].channel[i]);
			strcat(chList,tmp);
			if(i != reg_channel_5g_full_band[code-1].len - 1)
				strcat(chList,",");
		}
		puts(chList);
	}
}
#else
	if(rtk_get_channel_list_via_country(countryCode,chList,WLAN_5G)==0)
	{
		puts(chList);
	}
#endif
	return 1;
}

#ifdef RPAC92
int Get_ChannelList_5G_2(void)
{
	rtklog("%s\n",__FUNCTION__);
	unsigned char countryCode[3];
	char chList[256]={0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	int unit = 1;
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	memset(countryCode, 0, sizeof(countryCode));
	strncpy(countryCode, nvram_safe_get(strcat_r(prefix, "country_code", tmp)), 2);
	rtklog("countryCode:%s\n",countryCode);

#if 1
	get_channel_list(WLAN_5G_2, chList, countryCode);
	puts(chList);
#elif 0
{
	int i = 0, num = sizeof(reg_domain)/sizeof(reg_domain_t);
	unsigned char code = 0;
	//struct channel_list *ch = reg_channel_5g_full_band;

	while (i < num) {
		if (strcmp(countryCode, reg_domain[i].name) == 0) {
			code = reg_domain[i].band_2G;
			break;
		}
		i++;
	}

	if (code) {
		for(i=0; i<reg_channel_5g_full_band[code-1].len; i++) {
			memset(tmp,0,sizeof(tmp));
			sprintf(tmp,"%d",reg_channel_5g_full_band[code-1].channel[i]);
			strcat(chList,tmp);
			if(i != reg_channel_5g_full_band[code-1].len - 1)
				strcat(chList,",");
		}
		puts(chList);
	}
}
#else
	if(rtk_get_channel_list_via_country(countryCode,chList,WLAN_5G_2)==0)
	{
		puts(chList);
	}
#endif
	return 1;
}
#endif

void Get_fail_ret(void)
{
#if 0	/* don't need the below now */
	unsigned char ate_ret_buf[2];
	int ate_ret_offset = HW_SETTING_OFFSET;

	/* using the last byte of territoryCode to save ate ret */
	memset(ate_ret_buf, 0, sizeof(ate_ret_buf));
	ate_ret_offset += sizeof(PARAM_HEADER_T);
	ate_ret_offset += (int)(&((struct hw_setting *)0)->modelName);
	ate_ret_offset -= 1;

	rtk_flash_read(ate_ret_buf, ate_ret_offset, 1);
	puts(ate_ret_buf);
#endif
}

void Get_fail_reboot_log(void)
{
}

void Get_fail_dev_log(void)
{
}

void set_factory_mode()
{
	char *mode_str;
	char magic_str[] = {'a', 't', 'e', 'C', 'o', 'm', 'm', 'a', 'n', 'd', '_', 'f', 'l', 'a', 'g', '\0'};

	if(!nvram_match(magic_str, "1"))
		return;

	mode_str = ATE_REALTEK_FACTORY_MODE_STR();
	nvram_set(mode_str,"1");
	nvram_commit();
	free(mode_str);
}

#if defined(RTCONFIG_OPENPLUS_TFAT) || defined(RTCONFIG_OPENPLUSPARAGON_NTFS) || defined(RTCONFIG_OPENPLUSTUXERA_NTFS) || defined(RTCONFIG_OPENPLUSPARAGON_HFS) || defined(RTCONFIG_OPENPLUSTUXERA_HFS)
void set_fs_coexist(){
	nvram_set("COFS", "1");
	nvram_commit();
}
#endif

void set_IpAddr_Lan(const char *value){
	puts("ATE_ERROR_INCORRECT_PARAMETER\n");
}

void get_IpAddr_Lan(){
	char *buf = nvram_safe_get("IpAddr_Lan");

	if(buf == NULL || strlen(buf) <= 0 || !strcmp(buf, "NONE"))
		puts("NONE");
	else
		puts(buf);
}

void set_MRFLAG(const char *value){
	puts("ATE_ERROR_INCORRECT_PARAMETER\n");
}

void get_MRFLAG(){
	char *buf = nvram_safe_get("MRFLAG");

	if(buf == NULL || strlen(buf) <= 0 || !strcmp(buf, "NONE"))
		puts("NONE");
	else
		puts(buf);
}

#ifdef RTCONFIG_AMAS
int get_amas_bdl(void)
{
    unsigned char bdl = 0x0;
    int offset = HW_SETTING_OFFSET;

    offset += sizeof(PARAM_HEADER_T);
    offset += (int)(&((struct hw_setting *)0)->amas_bdl);

    rtk_flash_read(&bdl, offset, 1);

    printf("%d\n", bdl);

    return 0;
}
int set_amas_bdl(int flag)
{
    unsigned char bdl = (unsigned char)flag;
    int offset = HW_SETTING_OFFSET;

    offset += sizeof(PARAM_HEADER_T);
    offset += (int)(&((struct hw_setting *)0)->amas_bdl);

    if (!IS_ATE_FACTORY_MODE())
        return 0;

    rtk_flash_write(&bdl, offset, sizeof(bdl));
    return get_amas_bdl();
}

int unset_amas_bdl(void)
{
    unsigned char bdl=0x0;
    int offset = HW_SETTING_OFFSET;

    offset += sizeof(PARAM_HEADER_T);
    offset += (int)(&((struct hw_setting *)0)->amas_bdl);

    if (!IS_ATE_FACTORY_MODE())
        return 0;

    rtk_flash_write(&bdl, offset, sizeof(bdl));

    return get_amas_bdl();
}

int get_amas_bdlkey(void)
{
	return 0;
}

int set_amas_bdlkey(const char *str)
{
	return 0;
}

int unset_amas_bdlkey(void)
{
	return 0;
}
#endif


#if defined(RPAC92)
int set_HwId(const char *HwId)
{
	if (!IS_ATE_FACTORY_MODE() || HwId == NULL)
		return -1;

	FWrite(HwId, OFFSET_HWID, 4);
	puts(HwId);

}

int set_HwVersion(const char *HwVer)
{
	if (!IS_ATE_FACTORY_MODE() || HwVer == NULL)
		return -1;

	FWrite(HwVer, OFFSET_HW_VERSION, 8);
	puts(HwVer);

	return 0;
}

int set_HwBom(const char *HwBom)
{
	if (!IS_ATE_FACTORY_MODE() || HwBom == NULL)
		return -1;

	FWrite(HwBom, OFFSET_HW_BOM, 32);
	puts(HwBom);

	return 0;
}

int set_DateCode(const char *DateCode)
{
	int i;

	if (DateCode == NULL || strlen(DateCode) != 8)
		return -1;

	/* YYYYMMDD */
	for ( i = 0; i < 8; i++) {
		if(!isdigit(DateCode[i]))
			return -1;
	}

	if (!IS_ATE_FACTORY_MODE())
		return -1;

	FWrite(DateCode, OFFSET_HW_DATE_CODE, 8);
	puts(DateCode);

	return 0;
}

int get_HwId(void)
{
	char buffer[4+1]={0};

	FRead((unsigned char*)buffer, OFFSET_HWID, 4);
	puts(buffer);

	return 0;
}

int get_HwVersion(void)
{
	char buffer[8+1]={0};

	FRead((unsigned char*)buffer, OFFSET_HW_VERSION, 8);
	puts(buffer);

	return 0;
}

int get_HwBom(void)
{
	char buffer[32+1]={0};

	FRead((unsigned char*)buffer, OFFSET_HW_BOM, 32);
	puts(buffer);

	return 0;
}

int get_DateCode(void)
{
	char buffer[8+1]={0};

	FRead((unsigned char*)buffer, OFFSET_HW_DATE_CODE, 8);
	puts(buffer);

	return 0;
}
#endif
