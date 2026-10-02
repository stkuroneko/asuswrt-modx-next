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

#include <rc.h>
#include <stdio.h>
#include <fcntl.h>		//	for restore175C() from Ralink src
#include <ralink.h>
#include <bcmnvram.h>
//#include <linux/ethtool.h>
#if !defined(__GLIBC__) && !defined(__UCLIBC__) /* musl */
#else
#include <linux/sockios.h>
#endif
#include <net/if_arp.h>
#include <shutils.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#if defined(RTCONFIG_ASUSCTRL)
#include <rtstate.h>
#include <stdlib.h>
#endif
//#include <linux/if.h>
#include <iwlib.h>
#include <wps.h>
#include <stapriv.h>
#include <shared.h>
#include "flash_mtd.h"
#include "ate.h"

#if defined(RTACRH18)
#include "swlib.h"
#endif

#if defined(RTACRH18)
#define RTKSWITCH_DEV  "switch0"
#else
#define RTKSWITCH_DEV  "/dev/rtkswitch"
#endif

#define LED_CONTROL(led, flag) ralink_gpio_write_bit(led, flag)

#if defined(RT4GAC86U)
/*
*4G-AC86U LED MAP:
* Power 2.4G  5G  WAN  LAN  USB2.0  2G_LED_YELLOW  3G_LED_BLUE 4G_LED_WHITE 4G_WEAK_SIGNAL 4G_NORMAL_SIGNAL 4G_GOOD_SIGNAL
*   22   98    2   62   86    99         3                4          20             95             96            97 
*/
	int led_map[]={22,98,2,62,86,3,4,20,95,96,97,99};
#endif
static char *ATE_RALINK_FACTORY_MODE_STR()
{
	char atemode[8];

	snprintf(atemode, sizeof(atemode), "%s%s%s%s%s%s%s%s", "A", "T", "E", "M", "O", "D", "E", "\0");
	return strdup(atemode);
}

int IS_ATE_FACTORY_MODE(void)
{
	char *mode_str = ATE_RALINK_FACTORY_MODE_STR();
	int ret = strcmp(nvram_safe_get(mode_str), "1");

	free(mode_str);

	return (ret == 0);
}

//Supports both RTL8367M and RTL8367R Realtek switch
/*
 * This function is used by factory only and always
 * think the LAN port next to WAN port as LAN1
 * even WebUI/case define another LAN port as LAN1.
 */
int
GetPhyStatus(int verbose, phy_info_list *list)
{
#if defined(RTN14U) || defined(RTAC52U) || defined(RTAC51U) || defined(RTN11P) || defined(RTN300) || defined(RTN54U) || defined(RTAC1200HP) || defined(RTAC54U)
	ATE_mt7620_esw_port_status();
	return 1;
#elif defined(RTN56UB1) || defined(RTN56UB2) || defined(RTAC1200GA1) || defined(RTAC1200GU) || defined(RTCONFIG_RALINK_MT7621) || defined(RTAC85U) || defined(RTAC85P) || defined(RTN800HP) || defined(RTACRH26) || defined(TUFAC1750)
	ATE_mt7621_esw_port_status();
	return 1;
#elif defined(RTAC1200) || defined(RTAC1200V2) || defined(RTN11P_B1)
	ATE_mt7628_esw_port_status();
	return 1;
#elif defined(RT4GAC86U)
extern	void ATE_mt7622_rtl8367s_esw_port_status(void);
	ATE_mt7622_rtl8367s_esw_port_status();
	return 1;
#elif defined(RTCONFIG_SWITCH_MT7986_MT7531)
	ATE_port_status();
	return 1;
#elif defined(RTACRH18)
#define NR_LAN_PORT 4
    int i;
    phyState pS;
    char buf[32];
    struct switch_dev *dev;
    struct switch_attr *attr;
    struct switch_val val;
    struct switch_port_link *link;
    unsigned int wan_link = 0, wan_speed = 0;

    memset(&pS, 0, sizeof(phyState));
    dev = swlib_connect(RTKSWITCH_DEV);
    if (!dev) {
        _dprintf("Failed to connect to the switch.\n");
        goto out;
    }

    swlib_scan(dev);
    attr = swlib_lookup_attr(dev, SWLIB_ATTR_GROUP_PORT, "link");
    if (!attr) {
        _dprintf("Unknown attribute \"key\"\n");
        goto out;
    }

    for (i=0; i<NR_LAN_PORT; i++) {
        memset(&val, 0, sizeof(struct switch_val));
        val.port_vlan = i;
        if (swlib_get_attr(dev, attr, &val) < 0) {
            _dprintf("Failed to get attribute.\n");
            goto out;
        }

        link = val.value.link;
        if (link->link) {
            pS.link[i] = 1;
            if (link->speed == 10)
                pS.speed[i] = 0;
            else if (link->speed == 100)
                pS.speed[i] = 1;
            else if (link->speed == 1000)
                pS.speed[i] = 2;
            else 
                pS.speed[i] = 0;
        }
    }

    if (get_ralink_wan_status(&wan_link, &wan_speed) != 0) {
        _dprintf("Failed to get WAN status.\n");
        goto out;
    }

    pS.link[4] = wan_link;
    pS.speed[4] = wan_speed;

    snprintf(buf, sizeof(buf), "W0=%C;L1=%C;L2=%C;L3=%C;L4=%C;",
        (pS.link[4] == 1) ? (pS.speed[4] == 2) ? 'G' : 'M': 'X',
        (pS.link[3] == 1) ? (pS.speed[3] == 2) ? 'G' : 'M': 'X',
        (pS.link[2] == 1) ? (pS.speed[2] == 2) ? 'G' : 'M': 'X',
        (pS.link[1] == 1) ? (pS.speed[1] == 2) ? 'G' : 'M': 'X',
        (pS.link[0] == 1) ? (pS.speed[0] == 2) ? 'G' : 'M': 'X');
    
    puts(buf);
    swlib_free_all(dev);
    return 1;
out:
    if (dev)
        swlib_free_all(dev);
    return 0;
#else
	int fd;
	char buf[32];
#if defined(RTAC53) || defined(RTAC51UP)
	int porder[5] = {0,1,2,3,4};
#else
	int porder[5] = {4,3,2,1,0};
#endif
	int *o = porder;

#ifdef RTCONFIG_DSL
	int porder_dsl[5] = {0,1,2,3,4};

	o = porder_dsl;
#endif

	fd = open(RTKSWITCH_DEV, O_RDONLY);
	if (fd < 0) {
		perror(RTKSWITCH_DEV);
		return 0;
	}

	phyState pS;

	pS.link[0] = pS.link[1] = pS.link[2] = pS.link[3] = pS.link[4] = 0;
	pS.speed[0] = pS.speed[1] = pS.speed[2] = pS.speed[3] = pS.speed[4] = 0;

	if (ioctl(fd, 18, &pS) < 0)
	{
		sprintf(buf, "ioctl: %s", RTKSWITCH_DEV);
		perror(buf);
		close(fd);
		return 0;
	}

	close(fd);

#if defined(RTAC53)
	sprintf(buf, "W0=%C;L1=%C;L2=%C;",
		(pS.link[o[0]] == 1) ? (pS.speed[o[0]] == 2) ? 'G' : 'M': 'X',
		(pS.link[o[3]] == 1) ? (pS.speed[o[3]] == 2) ? 'G' : 'M': 'X',
		(pS.link[o[4]] == 1) ? (pS.speed[o[4]] == 2) ? 'G' : 'M': 'X');
#else
	sprintf(buf, "W0=%C;L1=%C;L2=%C;L3=%C;L4=%C;",
		(pS.link[o[0]] == 1) ? (pS.speed[o[0]] == 2) ? 'G' : 'M': 'X',
		(pS.link[o[1]] == 1) ? (pS.speed[o[1]] == 2) ? 'G' : 'M': 'X',
		(pS.link[o[2]] == 1) ? (pS.speed[o[2]] == 2) ? 'G' : 'M': 'X',
		(pS.link[o[3]] == 1) ? (pS.speed[o[3]] == 2) ? 'G' : 'M': 'X',
		(pS.link[o[4]] == 1) ? (pS.speed[o[4]] == 2) ? 'G' : 'M': 'X');
#endif

	puts(buf);
	return 1;
#endif
}


int
getBootVer()
{
	unsigned char btv[5];
	char output_buf[32];
	memset(btv, 0, sizeof(btv));
	memset(output_buf, 0, sizeof(output_buf));
	FRead(btv, OFFSET_BOOT_VER, 4);
	sprintf(output_buf, "%s-%c.%c.%c.%c", nvram_safe_get("productid"), btv[0], btv[1], btv[2], btv[3]);
	puts(output_buf);

	return 0;
}

void
ate_commit_bootlog(char *err_code)
{
	unsigned char fail_buffer[ OFFSET_SERIAL_NUMBER - OFFSET_FAIL_RET ];

	nvram_set("Ate_power_on_off_enable", err_code);
	nvram_commit();

	memset(fail_buffer, 0, sizeof(fail_buffer));
	strncpy(fail_buffer, err_code, OFFSET_FAIL_BOOT_LOG - OFFSET_FAIL_RET -1);
	Gen_fail_log(nvram_get("Ate_reboot_log"), nvram_get_int("Ate_boot_check"), (struct FAIL_LOG *) &fail_buffer[ OFFSET_FAIL_BOOT_LOG - OFFSET_FAIL_RET ]);
	Gen_fail_log(nvram_get("Ate_dev_log"), nvram_get_int("Ate_boot_check"), (struct FAIL_LOG *) &fail_buffer[ OFFSET_FAIL_DEV_LOG  - OFFSET_FAIL_RET ]);

	FWrite(fail_buffer, OFFSET_FAIL_RET, sizeof(fail_buffer));
}

#if defined(RTN65U)
void
ate_run_in(void)
{
	unsigned char ateTxFreqOffset;
	char tmpbuf[32];
	char *wl_ifnames;
	int rai0 = 0;
	int ra0  = 0;

	wl_ifnames = nvram_safe_get("wl_ifnames");
	if(strstr(wl_ifnames, "rai0") != NULL)
		rai0 = 1;
	if(strstr(wl_ifnames, "ra0" ) != NULL)
		ra0  = 1;

	if(rai0)
	{
		eval("iwpriv", "rai0", "set", "ATE=ATESTART");
		eval("iwpriv", "rai0", "set", "ATECHANNEL=6");
		eval("iwpriv", "rai0", "set", "ATETXANT=0");
		eval("iwpriv", "rai0", "set", "ATETXMODE=1");
		eval("iwpriv", "rai0", "set", "ATETXMCS=7");
		eval("iwpriv", "rai0", "set", "ATETXBW=0");
		eval("iwpriv", "rai0", "set", "ATETXGI=0");
		eval("iwpriv", "rai0", "set", "ATETXLEN=1024");
		FRead(&ateTxFreqOffset, 0x4803A, 1);
		sprintf(tmpbuf, "ATETXFREQOFFSET=%u", (unsigned char) ateTxFreqOffset);
		eval("iwpriv", "rai0", "set", tmpbuf);
		eval("iwpriv", "rai0", "set", "ATETXPOW0=0");
		eval("iwpriv", "rai0", "set", "ATETXPOW1=0");
		eval("iwpriv", "rai0", "set", "ATEAUTOALC=1");
		eval("iwpriv", "rai0", "set", "ATEIPG=200");
		eval("iwpriv", "rai0", "set", "ATETXCNT=1000000000000000");
		eval("iwpriv", "rai0", "set", "ATE=TXFRAME");
	}

	if(ra0)
	{
		eval("iwpriv", "ra0", "set", "ATE=ATESTART");
		eval("iwpriv", "ra0", "set", "ATECHANNEL=48");
		eval("iwpriv", "ra0", "set", "ATETXANT=0");
		eval("iwpriv", "ra0", "set", "ATETXMODE=1");
		eval("iwpriv", "ra0", "set", "ATETXMCS=7");
		eval("iwpriv", "ra0", "set", "ATETXBW=0");
		eval("iwpriv", "ra0", "set", "ATETXGI=0");
		eval("iwpriv", "ra0", "set", "ATETXLEN=1024");
		FRead(&ateTxFreqOffset, 0x40044, 1);
		sprintf(tmpbuf, "ATETXFREQOFFSET=%u", (unsigned char) ateTxFreqOffset);
		eval("iwpriv", "ra0", "set", tmpbuf);
		eval("iwpriv", "ra0", "set", "ATETXPOW0=0");
		eval("iwpriv", "ra0", "set", "ATETXPOW1=0");
		eval("iwpriv", "ra0", "set", "ATETXPOW2=0");
		eval("iwpriv", "ra0", "set", "ATEAUTOALC=1");
		eval("iwpriv", "ra0", "set", "ATEIPG=200");
		eval("iwpriv", "ra0", "set", "ATETXCNT=1000000000000000");
		eval("iwpriv", "ra0", "set", "ATE=TXFRAME");
		eval("iwpriv", "ra0", "mac", "102C=40000000");	//set LED on
	}

	if(ra0 && rai0)
	{ //stop and restart 2.4G after setting 5G
		eval("iwpriv", "rai0", "set", "ATE=ATESTART");
		eval("iwpriv", "rai0", "set", "ATE=TXFRAME");
	}
}
#endif // RTN65U


int
getMAC_5G()
{
#if defined(RTCONFIG_MT798X)
	puts("not support!\n");
	return 0;
#else
	unsigned char buffer[6];
	char macaddr[18];
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	if (FRead(buffer, OFFSET_MAC_ADDR, 6)<0)
		dbg("READ MAC address: Out of scope\n");
	else
	{
		ether_etoa(buffer, macaddr);
		puts(macaddr);
	}
	return 0;
#endif
}

int
getMAC_2G()
{
	unsigned char buffer[6];
	char macaddr[18];
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	if (FRead(buffer, OFFSET_MAC_ADDR_2G, 6)<0)
		dbg("READ MAC address 2G: Out of scope\n");
	else
	{
		ether_etoa(buffer, macaddr);
		puts(macaddr);
	}
	return 0;
}

int
setMAC_5G(const char *mac)
{
#if defined(RTCONFIG_MT798X)
	return 0;
#else
	char ea[ETHER_ADDR_LEN];

	if (mac==NULL || !isValidMacAddr(mac))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (ether_atoe(mac, ea))
	{
		FWrite(ea, OFFSET_MAC_ADDR, 6);
		FWrite(ea, OFFSET_MAC_GMAC0, 6);
		{
			char *mac5 = mac;
			void set_et0macaddr(char *macaddr2, char *macaddr);
			set_et0macaddr(NULL, mac5);
		}
		getMAC_5G();
	}
	return 1;
#endif
}


int
setMAC_2G(const char *mac)
{
	char ea[ETHER_ADDR_LEN];

	if (mac==NULL || !isValidMacAddr(mac))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (ether_atoe(mac, ea))
	{
		FWrite(ea, OFFSET_MAC_ADDR_2G, 6);
#if defined(RTCONFIG_MT798X)
		FWrite(ea, OFFSET_MAC_GMAC0, 6);
		FWrite(ea, OFFSET_MAC_GMAC1, 6);
#else
		FWrite(ea, OFFSET_MAC_GMAC2, 6);
#endif
		{
			char *mac5 = NULL;
#if defined(RTAC1200V2) || defined(RTACRH18) || defined(RT4GAC86U) || defined(RTAX53U) || defined(RT4GAX56) || defined(RTAX54) || defined(XD4S) || defined(RTCONFIG_MT798X)
	/* set et1macaddr the same as et0macaddr for spec. */
			char macaddr[18];
			strlcpy(macaddr, mac, sizeof(macaddr));
			mac5 = macaddr;
#endif
			void set_et0macaddr(char *macaddr2, char *macaddr);
			set_et0macaddr(mac, mac5);
		}
		getMAC_2G();
	}
	return 1;
}

#if defined(RTN14U)
int
eeprom_upgrade(const char *path, int is_bk)
{
#define FLASH_OFFSET	0x40000
	FILE *fp=NULL;
	char buf_org[512], buf_new[512];
	int ret=0;
	int len, offset;

	fp=fopen(path, "r");
	if (!fp) goto quit_out;
	len=fread(buf_new, 1, 512, fp);
	if (len!=512) goto quit_out;
	if (is_bk)
	{
		FRead(buf_org, FLASH_OFFSET, 512);
		offset=OFFSET_BOOT_VER-FLASH_OFFSET;
		memcpy(buf_new+offset,buf_org+offset,4);
		offset=OFFSET_COUNTRY_CODE-FLASH_OFFSET;
		memcpy(buf_new+offset,buf_org+offset,2);
		offset=OFFSET_MAC_ADDR-FLASH_OFFSET;
		memcpy(buf_new+offset,buf_org+offset,6);
		offset=OFFSET_PIN_CODE-FLASH_OFFSET;
		memcpy(buf_new+offset,buf_org+offset,8);
		offset=OFFSET_TXBF_PARA-FLASH_OFFSET;
		memcpy(buf_new+offset,buf_org+offset,33);
	}
	FWrite(buf_new, FLASH_OFFSET, 512);
	ret=1;
quit_out:
	if (fp) fclose(fp);
	if (ret)
		fprintf(stderr,"success!\n");
	else
		fprintf(stderr,"fail!\n");
	return ret;
}
#endif

#if defined(RTCONFIG_NEW_REGULATION_DOMAIN)
int getRegSpec(void)
{
	char value_str[MAX_REGSPEC_LEN+1];
	int i;

	memset(value_str, 0, sizeof(value_str));
	FRead(value_str, REGSPEC_ADDR, MAX_REGSPEC_LEN);
	for(i = 0; i < MAX_REGSPEC_LEN && value_str[i] != '\0'; i++) {
		if ((unsigned char)value_str[i] == 0xff)
		{
			value_str[i] = '\0';
			break;
		}
	}
	puts(value_str);
	return 0;
}

int getRegDomain_2G(void)
{
	char value_str[MAX_REGDOMAIN_LEN+1];
	int i;

	memset(value_str, 0, sizeof(value_str));
	FRead(value_str, REG2G_EEPROM_ADDR, MAX_REGDOMAIN_LEN);

	for(i=0; i<MAX_REGDOMAIN_LEN; ++i) {
		if ((value_str[i]==(char)0xFF) || (value_str[i]=='\0'))
			break;
		printf("%c", value_str[i]);
	}
	printf("\n");
	return 0;
}

int getRegDomain_5G(void)
{
	char value_str[MAX_REGDOMAIN_LEN+1];
	int i;

	memset(value_str, 0, sizeof(value_str));
	FRead(value_str, REG5G_EEPROM_ADDR, MAX_REGDOMAIN_LEN);

	for(i=0; i<MAX_REGDOMAIN_LEN; ++i) {
		if ((value_str[i]==(char)0xFF) || (value_str[i]=='\0'))
			break;
		printf("%c", value_str[i]);
	}
	printf("\n");
	return 0;
}

#endif

#if defined(RTCONFIG_CONCURRENTREPEATER)
int set_off_led(led_state_t *led)
{
	int model = get_model();
	if (model ==  MODEL_RPAC87) {
		switch(led->id) {
			case LED_POWER:
				if (led->color == LED_GREEN)
					led_control(LED_POWER, LED_OFF);
				break;
			case LED_2G:
				if (led->color == LED_GREEN)
					led_control(LED_2G_GREEN1, LED_OFF);			
				else if (led->color == LED_GREEN2)
					led_control(LED_2G_GREEN2, LED_OFF);
				else if (led->color == LED_GREEN3)
					led_control(LED_2G_GREEN3, LED_OFF);
				else if (led->color == LED_GREEN4)
					led_control(LED_2G_GREEN4, LED_OFF);
				else if (led->color == ALL_LED){
					led_control(LED_2G_GREEN1, LED_OFF);
					led_control(LED_2G_GREEN2, LED_OFF);
					led_control(LED_2G_GREEN3, LED_OFF);
					led_control(LED_2G_GREEN4, LED_OFF);
				}
				else if (led->color == LED_NONE) {
					led_control(LED_2G_GREEN1, LED_OFF);
					led_control(LED_2G_GREEN2, LED_OFF);
					led_control(LED_2G_GREEN3, LED_OFF);
					led_control(LED_2G_GREEN4, LED_OFF);
				}						
				break;
			case LED_5G:
				if (led->color == LED_GREEN)
					led_control(LED_5G_GREEN1, LED_OFF);
				else if (led->color == LED_GREEN2)
					led_control(LED_5G_GREEN2, LED_OFF);
				else if (led->color == LED_GREEN3)
					led_control(LED_5G_GREEN3, LED_OFF);
				else if (led->color == LED_GREEN4) 
					led_control(LED_5G_GREEN4, LED_OFF);
				else if (led->color == ALL_LED) {
					led_control(LED_5G_GREEN1, LED_OFF);
					led_control(LED_5G_GREEN2, LED_OFF);
					led_control(LED_5G_GREEN3, LED_OFF);
					led_control(LED_5G_GREEN4, LED_OFF);						
				}
				else if (led->color == LED_NONE) {
					led_control(LED_5G_GREEN1, LED_OFF);
					led_control(LED_5G_GREEN2, LED_OFF);
					led_control(LED_5G_GREEN3, LED_OFF);
					led_control(LED_5G_GREEN4, LED_OFF);
				}				
				break;			
			default:
				dbG("Not support the LED ID:%d\n", led->id);
		}
	}
	led->state = LED_OFF;

	return 0;
}
int set_on_led(led_state_t *led)
{
	int model = get_model();
	if (model ==  MODEL_RPAC87) {
		switch(led->id) {
			case LED_POWER:
				if (led->color == LED_GREEN)
					led_control(LED_POWER, LED_ON);
				break;
			case LED_2G:
				if (led->color == LED_GREEN)
					led_control(LED_2G_GREEN1, LED_ON);			
				else if (led->color == LED_GREEN2)
					led_control(LED_2G_GREEN2, LED_ON);
				else if (led->color == LED_GREEN3)
					led_control(LED_2G_GREEN3, LED_ON);
				else if (led->color == LED_GREEN4)
					led_control(LED_2G_GREEN4, LED_ON);
				else if (led->color == ALL_LED){
					led_control(LED_2G_GREEN1, LED_ON);
					led_control(LED_2G_GREEN2, LED_ON);
					led_control(LED_2G_GREEN3, LED_ON);
					led_control(LED_2G_GREEN4, LED_ON);
				}
				else if (led->color == LED_NONE) {
					led_control(LED_2G_GREEN1, LED_OFF);
					led_control(LED_2G_GREEN2, LED_OFF);
					led_control(LED_2G_GREEN3, LED_OFF);
					led_control(LED_2G_GREEN4, LED_OFF);
				}
				else if (led->color == LED_SL4) {
					led_control(LED_2G_GREEN1, LED_ON);
					led_control(LED_2G_GREEN2, LED_ON);
					led_control(LED_2G_GREEN3, LED_ON);
					led_control(LED_2G_GREEN4, LED_ON);
				}
				else if (led->color == LED_SL3) {
					led_control(LED_2G_GREEN1, LED_ON);
					led_control(LED_2G_GREEN2, LED_ON);
					led_control(LED_2G_GREEN3, LED_ON);
					led_control(LED_2G_GREEN4, LED_OFF);
				}
				else if (led->color == LED_SL2) {
					led_control(LED_2G_GREEN1, LED_ON);
					led_control(LED_2G_GREEN2, LED_ON);
					led_control(LED_2G_GREEN3, LED_OFF);
					led_control(LED_2G_GREEN4, LED_OFF);
				}
				else if (led->color == LED_SL1) {
					led_control(LED_2G_GREEN1, LED_ON);
					led_control(LED_2G_GREEN2, LED_OFF);
					led_control(LED_2G_GREEN3, LED_OFF);
					led_control(LED_2G_GREEN4, LED_OFF);
				}
				break;
			case LED_5G:
				if (led->color == LED_GREEN)
					led_control(LED_5G_GREEN1, LED_ON);
				else if (led->color == LED_GREEN2)
					led_control(LED_5G_GREEN2, LED_ON);
				else if (led->color == LED_GREEN3)
					led_control(LED_5G_GREEN3, LED_ON);
				else if (led->color == LED_GREEN4) 
					led_control(LED_5G_GREEN4, LED_ON);
				else if (led->color == ALL_LED) {
					led_control(LED_5G_GREEN1, LED_ON);
					led_control(LED_5G_GREEN2, LED_ON);
					led_control(LED_5G_GREEN3, LED_ON);
					led_control(LED_5G_GREEN4, LED_ON);
				}
				else if (led->color == LED_NONE){
					led_control(LED_5G_GREEN1, LED_OFF);
					led_control(LED_5G_GREEN2, LED_OFF);
					led_control(LED_5G_GREEN3, LED_OFF);
					led_control(LED_5G_GREEN4, LED_OFF);
				}
				else if (led->color == LED_SL4) {
					led_control(LED_5G_GREEN1, LED_ON);
					led_control(LED_5G_GREEN2, LED_ON);
					led_control(LED_5G_GREEN3, LED_ON);
					led_control(LED_5G_GREEN4, LED_ON);
				}
				else if (led->color == LED_SL3) {
					led_control(LED_5G_GREEN1, LED_ON);
					led_control(LED_5G_GREEN2, LED_ON);
					led_control(LED_5G_GREEN3, LED_ON);
					led_control(LED_5G_GREEN4, LED_OFF);
				}
				else if (led->color == LED_SL2) {
					led_control(LED_5G_GREEN1, LED_ON);
					led_control(LED_5G_GREEN2, LED_ON);
					led_control(LED_5G_GREEN3, LED_OFF);
					led_control(LED_5G_GREEN4, LED_OFF);
				}
				else if (led->color == LED_SL1) {
					led_control(LED_5G_GREEN1, LED_ON);
					led_control(LED_5G_GREEN2, LED_OFF);
					led_control(LED_5G_GREEN3, LED_OFF);
					led_control(LED_5G_GREEN4, LED_OFF);
				}
				break;
			default:
				dbG("Not support the LED ID:%d\n", led->id);
		}
	}
	led->state = LED_ON;

	return 0;
}
#endif  /* RTCONFIG_CONCURRENTREPEATER */

int
setAllLedOn(void)
{
#if defined(RT4GAC86U)

	led_control(LED_POWER,LED_ON);
	led_control(LED_LAN,LED_ON);
	led_control(LED_WAN,LED_ON);
	led_control(LED_2G,LED_ON);
	led_control(LED_5G,LED_ON);
	led_control(LED_USB,LED_ON);

	led_control(LED_NOMOBILE,LED_ON);
	led_control(LED_2G_YELLOW,LED_ON);
	led_control(LED_3G_BLUE,LED_ON);
	led_control(LED_4G_WHITE,LED_ON);

	led_control(LED_SIG1,LED_ON);
	led_control(LED_SIG2,LED_ON);
	led_control(LED_SIG3,LED_ON);
	
#elif defined(RTAX53U)
	led_control(LED_POWER  , LED_ON);
	led_control(LED_USB,LED_ON);
	eval("mii_mgr", "-s", "-p", "0", "-r", "13", "-v", "0x1f");
	eval("mii_mgr", "-s", "-p", "0", "-r", "14", "-v", "0x24");
	eval("mii_mgr", "-s", "-p", "0", "-r", "13", "-v", "0x401f");
	eval("mii_mgr", "-s", "-p", "0", "-r", "14", "-v", "0x0");
	eval("iwpriv", "ra0", "set", "led_setting=00-00-00-00-02-00-00-00");
	eval("iwpriv", "rai0", "set", "led_setting=01-00-00-00-02-00-00-00");
#elif defined(RTAX54)
	led_control(LED_POWER  , LED_ON);
	led_control(LED_USB,LED_ON);
	eval("iwpriv", "ra0", "set", "led_setting=00-00-00-00-02-00-00-00");
	eval("iwpriv", "rai0", "set", "led_setting=01-00-00-00-02-00-00-00");
	eval("switch", "reg", "w", "7d00", "11111"); //LED_EN: 1=enable 0=disable
	eval("switch", "reg", "w", "7d04", "66666"); //LED_IO_MODE: 0=GPIO 1=PHY mode
	eval("switch", "reg", "w", "7d10", "11111"); //GPIOMODE:1=output 0=input
	eval("switch", "reg", "w", "7d14", "11111"); //GPIO_OE:1=output enable  0=output disable
	eval("switch", "reg", "w", "7d18", "11100"); //WAN LED on, LAN LED on
#elif defined(XD4S)
#if defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED)	
   	led_control(LED_BLUE, LED_ON);
	led_control(LED_GREEN, LED_ON);
	led_control(LED_RED, LED_ON);
#endif	
#elif defined(RT4GAX56)
	led_control(LED_POWER  , LED_ON);
	led_control(LED_2G	, LED_ON);
	led_control(LED_5G	, LED_ON);
	led_control(LED_WAN  , LED_ON);
	led_control(LED_WAN_RED  , LED_ON);
#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_NOMOBILE,LED_ON);
	led_control(LED_2G_YELLOW,LED_ON);
	led_control(LED_3G_BLUE,LED_ON);
	led_control(LED_4G_WHITE,LED_ON);

	led_control(LED_SIG1,LED_ON);
	led_control(LED_SIG2,LED_ON);
	led_control(LED_SIG3,LED_ON);
#endif
#elif defined(TUFAX4200) || defined(TUFAX6000)
	led_control(LED_POWER, LED_ON);
	force_gpy211_led_onoff(5, 1);	/* 2.5G LAN LED */
	force_gpy211_led_onoff(6, 1);	/* 2.5G WAN LED, active-low */
	force_mt7531_led_onoff(1);	/* LAN1~LAN4 LED */
	wan_red_led_control(LED_ON);
	led_control(LED_2G, LED_ON);
	led_control(LED_5G, LED_ON);
#if defined(TUFAX4200)
	if (nvram_match("HwId", "B")) {
		/* HwId B: 2.5G x 2, WiFi LED x 1
		 * Don't turn on WiFi LED by WF2G_LED, it can't be output high or input.
		 */
		gpio_dir(1, GPIO_DIR_OUT_LOW);
	}
#endif
#else
#ifdef RTCONFIG_DSL
  	LED_CONTROL(RA_LED_POWER, RA_LED_ON);
  	LED_CONTROL(RA_LED_WAN, RA_LED_ON);
#else
	led_control(LED_POWER, LED_ON);
	led_control(LED_WPS  , LED_ON);
#if defined(RTAC51UP) || defined(RTAC53)
	eval("rtkswitch", "100", "0x20003");
#else
	led_control(LED_WAN  , LED_ON);
	led_control(LED_LAN  , LED_ON);
#endif
	led_control(LED_USB  , LED_ON);
	if (have_usb3_led(get_model()))
		led_control(LED_USB3, LED_ON);
#if defined(RTN14U) || defined(RTN800HP)
	led_control(LED_2G  , LED_ON);
#endif
#if defined(RTAC1200HP) || defined(RTN56UB1) || defined(RTN56UB2) || defined(RTAC1200GA1) || defined(RTAC1200GU) || defined(RTAC85U) || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750)
	led_control(LED_2G  , LED_ON);
	led_control(LED_5G  , LED_ON);
#endif
#if defined(RTN11P_B1)	
	//Set WLED_N(GPIO44) to GPIO Mode, and turn on.
	system("reg s 0xB0000000; reg w 0x64 0x30015015");	
	system("reg s 0xB0000600; reg w 0x04 0x1C20; reg w 0x24 0x69CB");	
	led_control(LED_POWER  , LED_ON);
	led_control(LED_WAN  , LED_ON);	
	led_control(LED_LAN  , LED_ON);
	led_control(LED_2G  , LED_ON);		
#endif
#if defined(RPAC87)
	led_control(LED_2G_GREEN1  , LED_ON);
	led_control(LED_2G_GREEN2  , LED_ON);
	led_control(LED_2G_GREEN3  , LED_ON);
	led_control(LED_2G_GREEN4  , LED_ON);

	led_control(LED_5G_GREEN1  , LED_ON);
	led_control(LED_5G_GREEN2  , LED_ON);
	led_control(LED_5G_GREEN3  , LED_ON);
	led_control(LED_5G_GREEN4  , LED_ON);
#endif
#if defined(RTN800HP)  || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750)
	//Set Lan Led to gpio mode, and turn on
	system("switch reg w 7d00 11111; switch reg w 7d04 66666; "
		   "switch reg w 7d10 11111; switch reg w 7d14 11111; "
		   "switch reg w 7d18 01000");
#endif
#if defined(RTAC1200V2)
	system("regs w 0x10110168 0xE0011F"); //LED_WAN, LED_LAN
	system("regs w 0x10000624 0x205F");	//LED_POWER/LED_2G
	system("iwpriv rai0 set led_setting=01-00-00-00-00-00-00-00"); //LED_5G	
	led_control(LED_POWER  , LED_ON);
	led_control(LED_2G	, LED_ON);
	led_control(LED_5G	, LED_ON);
	led_control(LED_WAN  , LED_ON); 
	led_control(LED_LAN  , LED_ON);
#endif

#if defined(RTACRH18)
	system("switch reg w 7c10 11011111; switch reg w 7c14 10110000; "
		   "switch reg w 7c18 110; switch reg w 7c00 1462000; "
		   "switch reg w 7c04 0");	

    led_control(LED_2G  , LED_ON);
    led_control(LED_5G  , LED_ON);
	led_control(LED_POWER  , LED_ON);
    system("mii_mgr_cl45 -s -p 0 -d 0x1f -r 24 -v 0007"); // WLAN LED ON
	//system("regs w 0x10110168 0xE0011F"); //LED_WAN, LED_LAN
	//system("regs w 0x10000624 0x205F");	//LED_POWER/LED_2G
	//system("iwpriv rai0 set led_setting=01-00-00-00-00-00-00-00"); //LED_5G	
	//led_control(LED_POWER  , LED_ON);
	//led_control(LED_2G	, LED_ON);
	//led_control(LED_5G	, LED_ON);
	//led_control(LED_WAN  , LED_ON); 
	//led_control(LED_LAN  , LED_ON);
#endif
	__wps_led_control(LED_ON);
	wan_red_led_control(LED_ON);
#ifdef RTCONFIG_LED_ALL
	led_control(LED_ALL  , LED_ON);
#endif
#endif
#endif //RT4GAC86U
	puts("1");
	return 0;
}

int
setAllLedOff(void)
{
#if defined(RT4GAC86U)

	led_control(LED_POWER,LED_OFF);
	led_control(LED_LAN,LED_OFF);
	led_control(LED_WAN,LED_OFF);
	led_control(LED_2G,LED_OFF);
	led_control(LED_5G,LED_OFF);
	led_control(LED_USB,LED_OFF);

	led_control(LED_NOMOBILE,LED_OFF);
	led_control(LED_2G_YELLOW,LED_OFF);
	led_control(LED_3G_BLUE,LED_OFF);
	led_control(LED_4G_WHITE,LED_OFF);

	led_control(LED_SIG1,LED_OFF);
	led_control(LED_SIG2,LED_OFF);
	led_control(LED_SIG3,LED_OFF);
#elif defined(RTAX53U)
	led_control(LED_POWER, LED_OFF);
	led_control(LED_USB, LED_OFF);
	eval("mii_mgr", "-s", "-p", "0", "-r", "13", "-v", "0x1f");
	eval("mii_mgr", "-s", "-p", "0", "-r", "14", "-v", "0x24");
	eval("mii_mgr", "-s", "-p", "0", "-r", "13", "-v", "0x401f");
	eval("mii_mgr", "-s", "-p", "0", "-r", "14", "-v", "0x4000");
	eval("iwpriv", "ra0", "set", "led_setting=00-00-00-00-02-00-00-01");
	eval("iwpriv", "rai0", "set", "led_setting=01-00-00-00-02-00-00-01");
#elif defined(RTAX54)
	led_control(LED_POWER, LED_OFF);
	eval("iwpriv", "ra0", "set", "led_setting=00-00-00-00-02-00-00-01");
	eval("iwpriv", "rai0", "set", "led_setting=01-00-00-00-02-00-00-01");
	eval("switch", "reg", "w", "7d00", "11111"); //LED_EN: 1=enable 0=disable
	eval("switch", "reg", "w", "7d04", "66666"); //LED_IO_MODE: 0=GPIO 1=PHY mode
	eval("switch", "reg", "w", "7d10", "11111"); //GPIOMODE:1=output 0=input
	eval("switch", "reg", "w", "7d14", "11111"); //GPIO_OE:1=output enable  0=output disable
	eval("switch", "reg", "w", "7d18", "11111"); //WAN LED off, LAN LED off
#elif defined(XD4S)
#if defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED)	
   	led_control(LED_BLUE, LED_OFF);
	led_control(LED_GREEN, LED_OFF);
	led_control(LED_RED, LED_OFF);
#endif	
#elif defined(RT4GAX56)
	led_control(LED_POWER  , LED_OFF);
	led_control(LED_2G	, LED_OFF);
	led_control(LED_5G	, LED_OFF);
	led_control(LED_WAN  , LED_OFF);
	led_control(LED_WAN_RED  , LED_OFF);
#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_NOMOBILE,LED_OFF);
	led_control(LED_2G_YELLOW,LED_OFF);
	led_control(LED_3G_BLUE,LED_OFF);
	led_control(LED_4G_WHITE,LED_OFF);

	led_control(LED_SIG1,LED_OFF);
	led_control(LED_SIG2,LED_OFF);
	led_control(LED_SIG3,LED_OFF);
#endif
#elif defined(TUFAX4200) || defined(TUFAX6000)
	led_control(LED_POWER, LED_OFF);
	force_gpy211_led_onoff(5, 0);	/* 2.5G LAN LED */
	force_gpy211_led_onoff(6, 0);	/* 2.5G WAN LED, active-low */
	force_mt7531_led_onoff(0);	/* LAN1~LAN4 LED */
	wan_red_led_control(LED_OFF);
	led_control(LED_2G, LED_OFF);
	led_control(LED_5G, LED_OFF);
#if defined(TUFAX4200)
	if (nvram_match("HwId", "B")) {
		/* WiFi LED x 1, 2G LED is not defined in nvram. */
		gpio_dir(1, GPIO_DIR_OUT_LOW);
	}
#endif
#else
#ifdef RTCONFIG_DSL
	LED_CONTROL(RA_LED_POWER, RA_LED_OFF);
	LED_CONTROL(RA_LED_WAN, RA_LED_OFF);
#else
	led_control(LED_POWER, LED_OFF);
	led_control(LED_WPS  , LED_OFF);
#if defined(RTAC51UP) || defined(RTAC53)
	eval("rtkswitch", "100", "0x20002");
#else
	led_control(LED_WAN  , LED_OFF);
	led_control(LED_LAN  , LED_OFF);
#endif
	led_control(LED_USB  , LED_OFF);
	if (have_usb3_led(get_model()))
		led_control(LED_USB3, LED_OFF);
#if defined(RTN14U) || defined(RTN800HP)
	led_control(LED_2G  , LED_OFF);
#endif
#if defined(RTAC1200HP) || defined(RTN56UB1) || defined(RTN56UB2) || defined(RTAC1200GA1) || defined(RTAC1200GU) || defined(RTAC85U)  || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750)
	led_control(LED_2G  , LED_OFF);
	led_control(LED_5G  , LED_OFF);
#endif
#if defined(RTN11P_B1)
	//Set WLED_N(GPIO44) to GPIO Mode, and turn off.
	system("reg s 0xB0000000; reg w 0x64 0x30015015");	   //set WLED_N to gpio mode.
	system("reg s 0xB0000600; reg w 0x04 0x1C20; reg w 0x24 0x79CB"); //set direction(0x01) & data (0x01)
	led_control(LED_POWER  , LED_OFF);
	led_control(LED_WAN  , LED_OFF);	
	led_control(LED_LAN  , LED_OFF);
	led_control(LED_2G  , LED_OFF);		
#endif
#if defined(RPAC87)
	led_control(LED_2G_GREEN1  , LED_OFF);
	led_control(LED_2G_GREEN2  , LED_OFF);
	led_control(LED_2G_GREEN3  , LED_OFF);
	led_control(LED_2G_GREEN4  , LED_OFF);

	led_control(LED_5G_GREEN1  , LED_OFF);
	led_control(LED_5G_GREEN2  , LED_OFF);
	led_control(LED_5G_GREEN3  , LED_OFF);
	led_control(LED_5G_GREEN4  , LED_OFF);
#endif
#if defined(RTN800HP)  || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750)
	//Set Lan Led to gpio mode, and turn off
	system("switch reg w 7d00 11111; switch reg w 7d04 66666; "
		   "switch reg w 7d10 11111; switch reg w 7d14 11111; "
		   "switch reg w 7d18 10111");
#endif
	__wps_led_control(LED_OFF);
	wan_red_led_control(LED_OFF);

#if defined(RTACRH18)
	system("switch reg w 7c10 11011111; switch reg w 7c14 10110000; "
		   "switch reg w 7c18 110; switch reg w 7c00 1462000; "
		   "switch reg w 7c04 1462000");
    system("mii_mgr_cl45 -s -p 0 -d 0x1f -r 24 -v 4007");   // WAN LED OFF
    led_control(LED_2G  , LED_OFF);
    led_control(LED_5G  , LED_OFF);
#endif	


#ifdef RTCONFIG_LED_ALL
	led_control(LED_ALL  , LED_OFF);
#endif
#endif
#endif //RT4GAC86U
	puts("1");
	return 0;
}	
#if defined(RTCONFIG_WANRED_LED)
int setAllRedLedOn(void){
	led_control(LED_POWER,LED_OFF);
	led_control(LED_LAN,LED_OFF);
	led_control(LED_WAN,LED_OFF);
	led_control(LED_2G,LED_OFF);
	led_control(LED_5G,LED_OFF);
	led_control(LED_WAN_RED,LED_OFF);
#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_2G_YELLOW,LED_OFF);
	led_control(LED_3G_BLUE,LED_OFF);
	led_control(LED_4G_WHITE,LED_OFF);

	led_control(LED_SIG1,LED_OFF);
	led_control(LED_SIG2,LED_OFF);
	led_control(LED_SIG3,LED_OFF);
#endif
	//red led on
#if defined(RTCONFIG_WANRED_LED)
	led_control(LED_WAN_RED,LED_ON);
#endif
#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_NOMOBILE,LED_ON);
#endif
	puts("1");
	return 0;

}
#endif

#if defined(RT4GAC86U) || defined(RT4GAX56)
int setAllBlueLedOn(void){
	led_control(LED_POWER,LED_OFF);
	led_control(LED_LAN,LED_OFF);
	led_control(LED_WAN,LED_OFF);
	led_control(LED_2G,LED_OFF);
	led_control(LED_5G,LED_OFF);
#if defined(RTCONFIG_WANRED_LED)
	led_control(LED_WAN_RED,LED_OFF);
#endif
#if !defined(RT4GAX56)
	led_control(LED_USB,LED_OFF);
#endif

#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_NOMOBILE,LED_OFF);
	led_control(LED_2G_YELLOW,LED_OFF);
	led_control(LED_3G_BLUE,LED_OFF);
	led_control(LED_4G_WHITE,LED_OFF);

	led_control(LED_SIG1,LED_OFF);
	led_control(LED_SIG2,LED_OFF);
	led_control(LED_SIG3,LED_OFF);

	//blue led on
	led_control(LED_3G_BLUE,LED_ON);
#endif
	puts("1");
	return 0;
}

int setAllYellowLedOn(void){

	led_control(LED_POWER,LED_OFF);
	led_control(LED_LAN,LED_OFF);
	led_control(LED_WAN,LED_OFF);
	led_control(LED_2G,LED_OFF);
	led_control(LED_5G,LED_OFF);
#if defined(RTCONFIG_WANRED_LED)
	led_control(LED_WAN_RED,LED_OFF);
#else
	led_control(LED_USB,LED_OFF);
#endif

#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_NOMOBILE,LED_OFF);
	led_control(LED_2G_YELLOW,LED_OFF);
	led_control(LED_3G_BLUE,LED_OFF);
	led_control(LED_4G_WHITE,LED_OFF);

	led_control(LED_SIG1,LED_OFF);
	led_control(LED_SIG2,LED_OFF);
	led_control(LED_SIG3,LED_OFF);

	// yellow led on
	led_control(LED_2G_YELLOW,LED_ON);
#endif
	puts("1");
	return 0;
}

int setAllWhiteLedOn(void){

	led_control(LED_POWER,LED_ON);
	led_control(LED_LAN,LED_ON);
	led_control(LED_WAN,LED_ON);
	led_control(LED_2G,LED_ON);
	led_control(LED_5G,LED_ON);
#if !defined(RT4GAX56)
	led_control(LED_USB,LED_ON);
#endif

#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_NOMOBILE,LED_ON);
	led_control(LED_2G_YELLOW,LED_ON);
	led_control(LED_3G_BLUE,LED_ON);
	led_control(LED_4G_WHITE,LED_ON);

	led_control(LED_SIG1,LED_ON);
	led_control(LED_SIG2,LED_ON);
	led_control(LED_SIG3,LED_ON);
#endif

#if defined(RTCONFIG_WANRED_LED)
	led_control(LED_WAN_RED,LED_OFF);
#endif
#ifdef RTCONFIG_INTERNAL_GOBI
	led_control(LED_NOMOBILE,LED_OFF);
	led_control(LED_2G_YELLOW,LED_OFF);
	led_control(LED_3G_BLUE,LED_OFF);
#endif
	puts("1");
	return 0;
}
#endif
#if defined(RTCONFIG_WPS_ALLLED_BTN) || defined(RTCONFIG_SW_CTRL_ALLLED)
void setAllLedNormal(void)
{
	led_control(LED_POWER, LED_ON);

#if defined(RTAC65U) || defined(RTAC85U) || defined(RTAC85P) || defined(RTN800HP) || defined(RTACRH26) || defined(TUFAC1750) || defined(RT4GAX56)
	if (nvram_match("wl0_radio", "1"))
		led_control(LED_2G, LED_ON);
#ifdef RTCONFIG_HAS_5G
	if (nvram_match("wl1_radio", "1"))
		led_control(LED_5G, LED_ON);
#endif
#elif defined(RTAC51UP) || defined(RTAC53)
	eval("rtkswitch", "100", "0x20000"); //lan/wan ethernet/giga led
	led_table_ctrl(LED_ON);
#elif defined(RTACRH18)
	if (nvram_match("wl0_radio", "1"))
		led_control(LED_2G, LED_ON);
	 if (nvram_match("wl1_radio", "1"))
		led_control(LED_5G, LED_ON);
	eval("switch", "reg", "w", "7C10", "11111111");
	eval("switch", "reg", "w", "7C14", "11110110");
	eval("switch", "reg", "w", "7C18", "111");
	eval("mii_mgr_cl45", "-s", "-p", "0", "-d", "0x1f", "-r", "24", "-v", "C007");
#elif defined(RT4GAC86U)
	if (nvram_match("wl0_radio", "1"))
		led_control(LED_2G, LED_ON);
	 if (nvram_match("wl1_radio", "1"))
		led_control(LED_5G, LED_ON);
	 if (nvram_match("link_internet", "2"))
		led_control(LED_WAN, LED_ON);
#elif defined(RTAX53U)
	if (nvram_match("wl0_radio", "1"))
		eval("iwpriv", "ra0", "set", "led_setting=00-00-00-00-02-00-00-00");
	if (nvram_match("wl1_radio", "1"))
		eval("iwpriv", "rai0", "set", "led_setting=01-00-00-00-02-00-00-00");
	eval("mii_mgr", "-s", "-p", "0", "-r", "13", "-v", "0x1f");
	eval("mii_mgr", "-s", "-p", "0", "-r", "14", "-v", "0x24");
	eval("mii_mgr", "-s", "-p", "0", "-r", "13", "-v", "0x401f");
	eval("mii_mgr", "-s", "-p", "0", "-r", "14", "-v", "0xC007");
#elif defined(RTAX54)
	int val=0, wan_status=0, lan_status=0;
	char tmpbuf[8]={0};
	if (nvram_match("wl0_radio", "1"))
		eval("iwpriv", "ra0", "set", "led_setting=00-00-00-00-02-00-00-00");
	if (nvram_match("wl1_radio", "1"))
		eval("iwpriv", "rai0", "set", "led_setting=01-00-00-00-02-00-00-00");
	eval("switch", "reg", "w", "7d00", "11111"); //LED_EN: 1=enable 0=disable
	eval("switch", "reg", "w", "7d04", "66666"); //LED_IO_MODE: 0=GPIO 1=PHY mode
	eval("switch", "reg", "w", "7d10", "11111"); //GPIOMODE:1=output 0=input
	eval("switch", "reg", "w", "7d14", "11111"); //GPIO_OE:1=output enable  0=output disable
	wan_status = rtkswitch_wanPort_phyStatus(-1);
	lan_status = rtkswitch_lanPorts_phyStatus() << 4;
	val = wan_status | lan_status;
	val = ~val & 0x11;
	snprintf(tmpbuf, sizeof(tmpbuf),"0x%x", val);
	eval("switch", "reg", "w", "7d18", tmpbuf);
#elif defined(XD4S)
#if defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED)	
   	led_control(LED_BLUE, LED_ON);
	led_control(LED_GREEN, LED_ON);
	led_control(LED_RED, LED_ON);
#endif	
#endif

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

#if defined(RTCONFIG_NEW_REGULATION_DOMAIN)

#if defined(RTCONFIG_MT798X)
static int valid_regspec(char *spec)
{
	if ((strcmp(spec, "FCC") == 0)
	 || (strcmp(spec, "CE") == 0)
	 || (strcmp(spec, "CN") == 0)
	 || (strcmp(spec, "IC") == 0)
	 || (strcmp(spec, "AU") == 0)
	 || (strcmp(spec, "NCC") == 0)
	 || (strcmp(spec, "NCC2") == 0)
	 || (strcmp(spec, "JP") == 0)
	 || (strcmp(spec, "EAC") == 0))
		return 1;
	return 0;
}
#endif

int setRegSpec(const char *regSpec, int do_write)
{
	char REGSPEC[MAX_REGSPEC_LEN+1];
#if !defined(RTCONFIG_MT798X)
	char file[64];
#endif
	int i;
#ifdef RTAC52U
	unsigned char dst[16];
	int v2 = 0;
#endif

	if (regSpec == NULL || regSpec[0] == '\0' || strlen(regSpec) > MAX_REGSPEC_LEN)
		return -1;

	if (do_write == 1 && !IS_ATE_FACTORY_MODE())
                return -1;

	memset(REGSPEC, 0, sizeof(REGSPEC));
	for (i=0; regSpec[i]!='\0' ;i++)
		REGSPEC[i]=(char)toupper(regSpec[i]);

#ifdef RTAC53
	if (strcmp(regSpec, "NONE")) {
#endif
#if defined(RTCONFIG_MT798X)
	if (!valid_regspec(REGSPEC))
		return -1;
#else
	// may be CE, FCC, AU, SG, NCC, NCC2, JP, IC. It is based on files in /ra_SKU/
	snprintf(file, sizeof(file), "/ra_SKU/SingleSKU_%s.dat", REGSPEC);
	if (!f_exists(file))
		return -1;
#endif
#ifdef RTAC52U
	if (!(FRead(dst, OFFSET_EEPROM_VER, 2) < 0) && dst[0] == 0x00 && dst[1] == 0x02) {
		v2 = 1;
		snprintf(file, sizeof(file), "/ra_SKU/SingleSKU_%s_0002.dat", REGSPEC);
		if (!f_exists(file))
			return -1;
	}
#endif

#ifdef RTCONFIG_HAS_5G
#if !defined(RTCONFIG_MT798X)
	snprintf(file, sizeof(file), "/ra_SKU/SingleSKU_5G_%s.dat", REGSPEC);
	if (!f_exists(file))
		return -1;
#endif
#ifdef RTAC52U
	if(v2) {
		snprintf(file, sizeof(file), "/ra_SKU/SingleSKU_5G_%s_0002.dat", REGSPEC);
		if (!f_exists(file))
			return -1;
	}
#endif	/* RTAC52U */
#endif	/* RTCONFIG_HAS_5G */

	if(do_write)
		FWrite(REGSPEC, REGSPEC_ADDR, MAX_REGSPEC_LEN);
#ifdef RTAC53
	}
	else {
		/* reset to 0xFF to clean */
		memset(REGSPEC,0xFF,sizeof(REGSPEC));
		FWrite(REGSPEC, REGSPEC_ADDR, MAX_REGSPEC_LEN);
	}
#endif
	return 0;
}

int setRegDomain_2G(const char *cc)
{
	char CC[MAX_REGDOMAIN_LEN+1];
	int i;

	if (!IS_ATE_FACTORY_MODE())
                return -1;

	if (!strcasecmp(cc, "2G_CH11")) ;
	else if (!strcasecmp(cc, "2G_CH13")) ;
	else if (!strcasecmp(cc, "2G_CH14")) ;
	else
		return -1;

	memset(CC, 0x0, sizeof(CC));
	strcpy(CC, cc);
	for (i=0;CC[i]!='\0';i++)
		CC[i]=(char)toupper(CC[i]);
	FWrite(CC, REG2G_EEPROM_ADDR, MAX_REGDOMAIN_LEN);
	return 0;
}

int setRegDomain_5G(const char *cc)
{
	char CC[MAX_REGDOMAIN_LEN+1];
	int i;

	if (!IS_ATE_FACTORY_MODE())
                return -1;
	if (!strcasecmp(cc, "5G_ALL")) ;
	else if (!strcasecmp(cc, "5G_BAND12")) ;
	else if (!strcasecmp(cc, "5G_BAND14")) ;
	else if (!strcasecmp(cc, "5G_BAND24")) ;
	else if (!strcasecmp(cc, "5G_BAND1")) ;
	else if (!strcasecmp(cc, "5G_BAND3")) ;
	else if (!strcasecmp(cc, "5G_BAND4")) ;
	else if (!strcasecmp(cc, "5G_BAND123")) ;
	else if (!strcasecmp(cc, "5G_BAND124")) ;
	else
		return -1;

	memset(CC, 0x0, sizeof(CC));
	strcpy(CC, cc);
	for (i=0;CC[i]!='\0';i++)
		CC[i]=(char)toupper(CC[i]);
	FWrite(CC, REG5G_EEPROM_ADDR, MAX_REGDOMAIN_LEN);
	return 0;
}


#else	/* ! RTCONFIG_NEW_REGULATION_DOMAIN */

int
getCountryCode_2G()
{
	unsigned char CC[3];

	memset(CC, 0, sizeof(CC));
	FRead(CC, OFFSET_COUNTRY_CODE, 2);
	if (CC[0] == 0xff && CC[1] == 0xff)	// 0xffff is default
		;
	else
		puts(CC);
	return 1;
}


#if defined(RTN65U)
int
isWifiPower1(const char *cc)
{
	if ((strcmp(cc, "US") == 0)
	 || (strcmp(cc, "TW") == 0))
		return 1;
	return 0;
}

int
isWifiPower2(const char *cc)
{
	if ((strcmp(cc, "CN") == 0)
	 || (strcmp(cc, "GB") == 0))
		return 1;
	return 0;
}

//for specific power
int
isWifiPower3(const char *cc)
{
	if ((strcmp(cc, "DB") == 0)
	 || (strcmp(cc, "Z1") == 0)
	 || (strcmp(cc, "Z2") == 0)
	 || (strcmp(cc, "Z3") == 0)
	 || (strcmp(cc, "Z4") == 0))
		return 1;
	return 0;
}

void
modify_ralink_power_2g(const char *old_CC, const char *CC, unsigned char *flash_buf)
{
	const unsigned char power1Value[] = {0x66,0x66,0x66,0x66,0x66,0x66,0x77,0x66,0x55,0x33,0x77,0x66,0x55,0x11,0x77,0x66,0x55,0x33};
	const unsigned char power2Value[] = {0x33,0x33,0x33,0x33,0x33,0x33,0x44,0x44,0x33,0x33,0x44,0x44,0x33,0x11,0x44,0x44,0x33,0x33};
	const unsigned char power3Value[] = {0x77,0x77,0x77,0x77,0x77,0x66,0x77,0x66,0x55,0x33,0x77,0x66,0x55,0x11,0x77,0x66,0x55,0x33};
	const unsigned char *powerValue = NULL;
	int len;

	if(!isValidCountryCode(CC))
	{
	}
	else if(isWifiPower1(CC))
	{
		powerValue = power1Value;
		len = sizeof(power1Value);
	}
	else if(isWifiPower2(CC))
	{
		powerValue = power2Value;
		len = sizeof(power2Value);
	}
	//for specific power
	else if(isWifiPower3(CC))
	{
		printf("use power3\n");
		powerValue = power3Value;
		len = sizeof(power3Value);
	}
	memcpy(flash_buf + (OFFSET_POWER_2G - OFFSET_MTD_FACTORY), powerValue, len);
}

void
modify_ralink_power_5g(const char *old_CC, const char *CC, unsigned char *flash_buf)
{
	signed char modify;
	signed char oldP = 0, newP = 0;

	
	if(!isValidCountryCode(old_CC))
		oldP = 0;
	else if(isWifiPower1(old_CC))
		oldP = -7;
	else if(isWifiPower2(old_CC))
		oldP = 0;
	else if(isWifiPower3(old_CC))
	   	oldP = 0;

	if(!isValidCountryCode(CC))
		newP = 0;
	else if(isWifiPower1(CC))
		newP = -7;
	else if(isWifiPower2(CC))
		newP = 0;
	else if(isWifiPower3(CC))
	   	newP = 0;

	modify = newP - oldP;

	_dprintf("old(%s, %d) new(%s, %d) modify(%d)\n", old_CC, oldP, CC, newP, modify);
	if(modify != 0)
	{
		struct ralink_eeprom {unsigned int offset; int number;};
		const struct ralink_eeprom pa[] = {
			{OFFSET_POWER_5G_TX0_36_x6, 6},
			{OFFSET_POWER_5G_TX1_36_x6, 6},
			{OFFSET_POWER_5G_TX2_36_x6, 6},
		};
		int i,cnt;
		unsigned char *pPower;

		for(i =0; i < ARRAY_SIZE(pa); i++)
		{
			pPower = flash_buf + (pa[i].offset - OFFSET_MTD_FACTORY);
			for(cnt = 0; cnt < pa[i].number; cnt++)
			{
				pPower[cnt] += modify;
			}
		}
	}
}
#endif

int
setCountryCode_2G(const char *cc)
{
	char CC[3];

	if (cc==NULL || !isValidCountryCode(cc))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	/* Please refer to ISO3166 code list for other countries and can be found at
	 * http://www.iso.org/iso/en/prods-services/iso3166ma/02iso-3166-code-lists/list-en1.html#sz
	 */
	else if (!strcasecmp(cc, "AE")) ;
	else if (!strcasecmp(cc, "AL")) ;
	else if (!strcasecmp(cc, "AM")) ;
	else if (!strcasecmp(cc, "AR")) ;
	else if (!strcasecmp(cc, "AT")) ;
	else if (!strcasecmp(cc, "AU")) ;
	else if (!strcasecmp(cc, "AZ")) ;
	else if (!strcasecmp(cc, "BE")) ;
	else if (!strcasecmp(cc, "BG")) ;
	else if (!strcasecmp(cc, "BH")) ;
	else if (!strcasecmp(cc, "BN")) ;
	else if (!strcasecmp(cc, "BO")) ;
	else if (!strcasecmp(cc, "BR")) ;
	else if (!strcasecmp(cc, "BY")) ;
	else if (!strcasecmp(cc, "BZ")) ;
	else if (!strcasecmp(cc, "CA")) ;
	else if (!strcasecmp(cc, "CH")) ;
	else if (!strcasecmp(cc, "CL")) ;
	else if (!strcasecmp(cc, "CN")) ;
	else if (!strcasecmp(cc, "CO")) ;
	else if (!strcasecmp(cc, "CR")) ;
	else if (!strcasecmp(cc, "CY")) ;
	else if (!strcasecmp(cc, "CZ")) ;
	else if (!strcasecmp(cc, "DB")) ;
	else if (!strcasecmp(cc, "DE")) ;
	else if (!strcasecmp(cc, "DK")) ;
	else if (!strcasecmp(cc, "DO")) ;
	else if (!strcasecmp(cc, "DZ")) ;
	else if (!strcasecmp(cc, "EC")) ;
	else if (!strcasecmp(cc, "EE")) ;
	else if (!strcasecmp(cc, "EG")) ;
	else if (!strcasecmp(cc, "ES")) ;
	else if (!strcasecmp(cc, "FI")) ;
	else if (!strcasecmp(cc, "FR")) ;
	else if (!strcasecmp(cc, "GB")) ;
	else if (!strcasecmp(cc, "GE")) ;
#if defined(RTN14U) || defined(RTAC52U) || defined(RTAC51U) || defined(RTN11P) || defined(RTN300) || defined(RTN54U) || defined(RTAC1200HP) || defined(RTN56UB1) || defined(RTAC54U) || defined(RTN56UB2) || defined(RTAC1200GA1) || defined(RTCONFIG_MTK_REP) && !defined(RTAC1200GU) || defined(RTAC51UP) || defined(RTAC53) || defined(RTN11P_B1)
	else if (!strcasecmp(cc, "EU")) ;
#endif
	else if (!strcasecmp(cc, "GR")) ;
	else if (!strcasecmp(cc, "GT")) ;
	else if (!strcasecmp(cc, "HK")) ;
	else if (!strcasecmp(cc, "HN")) ;
	else if (!strcasecmp(cc, "HR")) ;
	else if (!strcasecmp(cc, "HU")) ;
	else if (!strcasecmp(cc, "ID")) ;
	else if (!strcasecmp(cc, "IE")) ;
	else if (!strcasecmp(cc, "IL")) ;
	else if (!strcasecmp(cc, "IN")) ;
	else if (!strcasecmp(cc, "IR")) ;
	else if (!strcasecmp(cc, "IS")) ;
	else if (!strcasecmp(cc, "IT")) ;
	else if (!strcasecmp(cc, "JO")) ;
	else if (!strcasecmp(cc, "JP")) ;
	else if (!strcasecmp(cc, "KP")) ;
	else if (!strcasecmp(cc, "KR")) ;
	else if (!strcasecmp(cc, "KW")) ;
	else if (!strcasecmp(cc, "KZ")) ;
	else if (!strcasecmp(cc, "LB")) ;
	else if (!strcasecmp(cc, "LI")) ;
	else if (!strcasecmp(cc, "LT")) ;
	else if (!strcasecmp(cc, "LU")) ;
	else if (!strcasecmp(cc, "LV")) ;
	else if (!strcasecmp(cc, "MA")) ;
	else if (!strcasecmp(cc, "MC")) ;
	else if (!strcasecmp(cc, "MK")) ;
	else if (!strcasecmp(cc, "MO")) ;
	else if (!strcasecmp(cc, "MX")) ;
	else if (!strcasecmp(cc, "MY")) ;
	else if (!strcasecmp(cc, "NL")) ;
	else if (!strcasecmp(cc, "NO")) ;
	else if (!strcasecmp(cc, "NZ")) ;
	else if (!strcasecmp(cc, "OM")) ;
	else if (!strcasecmp(cc, "PA")) ;
	else if (!strcasecmp(cc, "PE")) ;
	else if (!strcasecmp(cc, "PH")) ;
	else if (!strcasecmp(cc, "PK")) ;
	else if (!strcasecmp(cc, "PL")) ;
	else if (!strcasecmp(cc, "PR")) ;
	else if (!strcasecmp(cc, "PT")) ;
	else if (!strcasecmp(cc, "QA")) ;
	else if (!strcasecmp(cc, "RO")) ;
	else if (!strcasecmp(cc, "RU")) ;
	else if (!strcasecmp(cc, "SA")) ;
	else if (!strcasecmp(cc, "SE")) ;
	else if (!strcasecmp(cc, "SG")) ;
	else if (!strcasecmp(cc, "SI")) ;
	else if (!strcasecmp(cc, "SK")) ;
	else if (!strcasecmp(cc, "SV")) ;
	else if (!strcasecmp(cc, "SY")) ;
	else if (!strcasecmp(cc, "TH")) ;
	else if (!strcasecmp(cc, "TN")) ;
	else if (!strcasecmp(cc, "TR")) ;
	else if (!strcasecmp(cc, "TT")) ;
	else if (!strcasecmp(cc, "TW")) ;
	else if (!strcasecmp(cc, "UA")) ;
	else if (!strcasecmp(cc, "US")) ;
	else if (!strcasecmp(cc, "UY")) ;
	else if (!strcasecmp(cc, "UZ")) ;
	else if (!strcasecmp(cc, "VE")) ;
	else if (!strcasecmp(cc, "VN")) ;
	else if (!strcasecmp(cc, "YE")) ;
	else if (!strcasecmp(cc, "ZA")) ;
	else if (!strcasecmp(cc, "ZW")) ;
#if defined(RTN65U)
	//for specific power
	else if (!strcasecmp(cc, "Z1")) ; //US
	else if (!strcasecmp(cc, "Z2")) ; //GB
	else if (!strcasecmp(cc, "Z3")) ; //TW
	else if (!strcasecmp(cc, "Z4")) ; //CN
#endif
	else
	{
		return 0;
	}

	memset(&CC[0], toupper(cc[0]), 1);
	memset(&CC[1], toupper(cc[1]), 1);
	memset(&CC[2], 0, 1);

#if defined(RTN14U) || defined(RTN11P) || defined(RTN300)
	FWrite(CC, OFFSET_COUNTRY_CODE, 2);
#else
#define MTD_SIZE_FACTORY 0x10000
    {
	unsigned char *flash_buf;
	if((flash_buf = malloc(MTD_SIZE_FACTORY)) == NULL)
	{
		return 0;
	}
	FRead(flash_buf, OFFSET_MTD_FACTORY, MTD_SIZE_FACTORY);

#if defined(RTN65U) // adjust power for different regulation domain
	if(get_model() == MODEL_RTN65U)
	{
		char old_CC[3];
		FRead(old_CC, OFFSET_COUNTRY_CODE, 2);
		old_CC[2] = '\0';
		modify_ralink_power_2g(old_CC, CC, flash_buf);
		modify_ralink_power_5g(old_CC, CC, flash_buf);
	}
#endif // RTN65U
	memcpy(flash_buf + (OFFSET_COUNTRY_CODE - OFFSET_MTD_FACTORY), CC, 2);
	FWrite(flash_buf, OFFSET_MTD_FACTORY, MTD_SIZE_FACTORY);
	free(flash_buf);
    }
#endif

	puts(CC);
	return 1;
}
#endif	/* ! RTCONFIG_NEW_REGULATION_DOMAIN */

int getSN(void)
{
	char buf[SERIAL_NUMBER_LENGTH32 + 1];

	memset(buf, 0, sizeof(buf));
	if (FRead(buf, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH32) < 0)
		dbg("READ Serial Number: Out of scope\n");
	else {
		buf[lenFRead(buf, sizeof(buf))] = '\0';
		if (!strlen(buf)) {
			nvram_unset("serial_no");
			puts("NONE");
		}
		else {
			nvram_set("serial_no", buf);
			puts(buf);
		}
	}

	return 1;
}

int setSN(const char *SN)
{
	char buf[SERIAL_NUMBER_LENGTH32 + 1];

	if (!IS_ATE_FACTORY_MODE())
		return 0;

	memset(buf, 0xff, sizeof(buf));
	if (SN && isResetFactory(SN))
		;
	else if (SN == NULL || !isValidSN(SN))
		return 0;
	else
		sprintf(buf, "%s", SN);

	if (FWrite(buf, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH32) < 0)
		return 0;
	getSN();

	return 1;
}	

int getEISN(void)
{
	char buf[SERIAL_NUMBER_LENGTH32 + 1];

	memset(buf, 0, sizeof(buf));
	if (FRead(buf, OFFSET_EISN, SERIAL_NUMBER_LENGTH32) < 0)
		dbg("READ EISN: Out of scope\n");
	else {
		buf[lenFRead(buf, sizeof(buf))] = '\0';
		if (!strlen(buf))
			puts("NONE");
		else
			puts(buf);
	}

	return 1;
}

int setEISN(const char *EISN)
{
	char buf[SERIAL_NUMBER_LENGTH32 + 1];

	if (!IS_ATE_FACTORY_MODE())
		return 0;

	memset(buf, 0xff, sizeof(buf));
	if (EISN && isResetFactory(EISN))
		;
	else if (EISN == NULL || !isValidEISN(EISN))
		return 0;
	else
		sprintf(buf, "%s", EISN);

	if (FWrite(buf, OFFSET_EISN, SERIAL_NUMBER_LENGTH32) < 0)
		return 0;
	getEISN();

	return 1;
}

#ifdef RTCONFIG_ODMPID
int setMN(const char *MN)
{
#ifdef RTCONFIG_32BYTES_ODMPID
        char modelname[32];
#else
	char modelname[16];
#endif
	if(MN==NULL || !is_valid_hostname(MN))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	memset(modelname, 0, sizeof(modelname));
	strncpy(modelname, MN, sizeof(modelname) -1);
#ifdef RTCONFIG_32BYTES_ODMPID
 	FWrite(modelname, OFFSET_32BYTES_ODMPID, sizeof(modelname));
#else
	FWrite(modelname, OFFSET_ODMPID, sizeof(modelname));
#endif
	nvram_set("odmpid", modelname);
	puts(nvram_safe_get("odmpid"));
	return 1;
}

int getMN(void)
{
	puts(nvram_safe_get("odmpid"));
	return 1;
}	
#endif

int getSSID_2G(void)
{
	puts(nvram_safe_get("wl0_ssid"));
	return 1;
}

int getSSID_5G(void)
{
	puts(nvram_safe_get("wl1_ssid"));
	return 1;
}

int
getPIN()
{
	unsigned char PIN[9];
	memset(PIN, 0, sizeof(PIN));
	FRead(PIN, OFFSET_PIN_CODE, 8);
	if (PIN[0]!=0xff)
		puts(PIN);
	return 0;
}

int
setPIN(const char *pin)
{

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (pincheck(pin))
	{
		FWrite(pin, OFFSET_PIN_CODE, 8);
		char PIN[9];
		memset(PIN, 0, 9);
		memcpy(PIN, pin, 8);
		puts(PIN);
		return 1;
	}
	return 0;	
}

int Get_channel_list(int unit)
{
	unsigned char countryCode[3];
	char chList[256];

#ifdef RTCONFIG_NEW_REGULATION_DOMAIN
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	memset(countryCode, 0, sizeof(countryCode));
	strncpy(countryCode, nvram_safe_get(strcat_r(prefix, "country_code", tmp)), 2);
#else
	memset(countryCode, 0, sizeof(countryCode));
	FRead(countryCode, OFFSET_COUNTRY_CODE, 2);
#endif
	if(get_channel_list_via_driver(unit, chList, sizeof(chList)) > 0)
	{
		puts(chList);
	}
	else if (countryCode[0] != 0xff && countryCode[1] != 0xff)	// 0xffff is default
	{
		if(get_channel_list_via_country(unit, countryCode, chList, sizeof(chList)) > 0)
		{
			puts(chList);
		}
	}
	return 1;
}

int Get_ChannelList_2G(void)
{
	return Get_channel_list(0);
}

int Get_ChannelList_5G(void)
{
	return Get_channel_list(1);
}

void
Get_fail_ret(void)
{
	unsigned char str[ OFFSET_FAIL_BOOT_LOG - OFFSET_FAIL_RET ];
	FRead(str, OFFSET_FAIL_RET, sizeof(str));
	if(str[0] == 0 || str[0] == 0xff)
		return;
	str[sizeof(str) -1] = '\0';
	puts(str);
}

void
Get_fail_reboot_log(void)
{
	char str[512];
	Get_fail_log(str, sizeof(str), OFFSET_FAIL_BOOT_LOG);
	puts(str);
}

void
Get_fail_dev_log(void)
{
	char str[512];
	Get_fail_log(str, sizeof(str), OFFSET_FAIL_DEV_LOG);
	puts(str);
}

#if !defined(RTN14U) && !defined(RTAC52U) && !defined(RTAC51U) && !defined(RTN11P) && !defined(RTN300) && !defined(RTN54U) && !defined(RTAC1200HP) && !defined(RTN56UB1) && !defined(RTAC54U) && !defined(RTN56UB2) && !defined(RTAC1200GA1) && !defined(RTAC1200GU) && !defined(RTN11P_B1) && !defined(RTN10P_V3) && !defined(RTCONFIG_MTK_REP) && !defined(RTAC85U) && !defined(RTAC85P) && !defined(RTAC65U) && !defined(RTN800HP) && !defined(RTACRH26) && !defined(TUFAC1750)
int Set_SwitchPort_LEDs(const char *group, const char *action)
{
	int groupNo;
	int actionNo;

	if((groupNo = strtol(group, NULL, 0)) < 0 || groupNo > 2)
		return -1;

	if (strcmp(action, "normal") == 0)
		actionNo = 0;
	else if (strcmp(action, "blink") == 0)
		actionNo = 1;
	else if (strcmp(action, "off") == 0)
		actionNo = 2;
	else if (strcmp(action, "on") == 0)
		actionNo = 3;
	else
		return -1;

	return rtkswitch_ioctl(100, (groupNo << 16) | (actionNo));
}
#endif

#if defined(RTAC1200HP)
int set_wantolan(void)
{

	if (!IS_ATE_FACTORY_MODE())
                return -1;

	eval("rtkswitch","8","100");
	doSystem("brctl addif br0 vlan2");
	nvram_set("Ate_wan_to_lan", "1");
	nvram_commit();
	puts("1");
	return 0;
}
#else
int set_wantolan(void)
{
	return 0;
}   
#endif


int
set40M_Channel_2G(char *channel)
{
	char chl_buf[12];
	if (channel==NULL || !isValidChannel(1, channel))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
                return 0;
	sprintf(chl_buf,"Channel=%s", channel);
	eval("iwpriv", (char *)WIF_2G, "set", chl_buf);
	eval("iwpriv", (char *)WIF_2G, "set", "HtBw=1");
	puts("1");
	return 1;
}

#if defined(RTCONFIG_HAS_5G)
int
set40M_Channel_5G(char *channel)
{
	char chl_buf[12];
	if (channel==NULL || !isValidChannel(0, channel))
		return 0;

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	sprintf(chl_buf,"Channel=%s", channel);
	eval("iwpriv", (char *)WIF_5G, "set", chl_buf);
	eval("iwpriv", (char *)WIF_5G, "set", "HtBw=1");
	puts("1");
	return 1;
}
#endif	/* RTCONFIG_HAS_5G */

#if defined(RTCONFIG_INTERNAL_GOBI)
#if defined(RT4GAC86U)
int setgobi_imei(const char *imei){
	char buffer[15];
	int i;
	if(imei == NULL)
		return -1;

	if (!IS_ATE_FACTORY_MODE())
		return -1;

	if(strncmp(imei,"NONE",4)!=0){
	for ( i = 0; i < 15; i++) {
		if(!isdigit(imei[i]))
			return -1;
		}

		FWrite(imei, OFFSET_GOBIIMEI, 15);

	}else{
		/* reset to 0xFF to clean */
		memset(buffer,0xFF,sizeof(buffer));
		FWrite(buffer, OFFSET_GOBIIMEI, 15);	
	}
	return 0;
} 
#endif
#endif

#if defined(RTCONFIG_TCODE)
int getTerritoryCode(void)
{
	char buf[6];

	memset(buf, 0, sizeof(buf));
	FRead((unsigned char *)buf, OFFSET_TERRITORY_CODE, 5);
	if ((unsigned char)buf[0] != 0xFF)
		puts(buf);

	return 0;
}

int setTerritoryCode(const char *tcode)
{
	unsigned char buf[5];

	/* special case
	 * if tcode == "FFFFF", Write FF, FF, FF, FF, FF to OFFSET_TERRITORY_CODE
	 */
	if (!strcmp(tcode, "FFFFF")) {
		memset(buf, 0xFF, sizeof(buf));
		FWrite(buf, OFFSET_TERRITORY_CODE, 5);
		nvram_unset("territory_code");

		return 0;
	}

	/* [A-Z][0-9 A-Z]/[0-9][0-9] */
	if (tcode[2] != '/' ||
	    !isupper(tcode[0]) || (!isupper(tcode[1]) && !isdigit(tcode[1])) ||
	    !isdigit(tcode[3]) || !isdigit(tcode[4]))
	{
		return -1;
	}

	if (!IS_ATE_FACTORY_MODE())
                return -1;

	FWrite(tcode, OFFSET_TERRITORY_CODE, 5);
	nvram_set("territory_code", tcode);

	return 0;
}

#define MAX_PSK_LEN (14)
int checkPSK(const char *psk)
{
	char buffer[MAX_PSK_LEN + 1];
	int i;

	if (psk == NULL)
		return -1;

	memset(buffer,0,sizeof(buffer));
	if (FRead(buffer, OFFSET_PSK, MAX_PSK_LEN) < 0) {
		return -1;
	}
	for (i = 0; i < sizeof(buffer) || buffer[i] == '\0'; i++) {
		if( (unsigned char)buffer[i] == 0xff ) {
			buffer[i] = '\0';
			break;
		}
	}

	if(!strcmp(buffer, psk))
		;
	else if (!strcmp(psk, "NONE") && buffer[0] == '\0')
		;
	else
		return -1;

        return 0;
}

int getPSK(void)
{
	char buffer[MAX_PSK_LEN + 1]={0};
	int i;
	memset(buffer,0,sizeof(buffer));
	FRead(buffer, OFFSET_PSK, MAX_PSK_LEN);
	if (buffer[0] == (char)0xFF)
		puts("NONE");
	else{
		for(i = 0; i < MAX_PSK_LEN && buffer[i] != '\0'; i++) {
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
	char buffer[MAX_PSK_LEN + 1];

	if (psk == NULL)
		return -1;

	if (!IS_ATE_FACTORY_MODE())
		return -1;

	if (strcmp(psk, "NONE")) {
		int len = strlen(psk);
		if (len < 8 || len > MAX_PSK_LEN)
			return -1;

		for (i = 0; i < len; i++) {
			if (!isprint(psk[i]) || psk[i] == ' ' || psk[i] == '"' || psk[i] == '\'')
				return -1;
		}

		memset(buffer,0,sizeof(buffer));
		memcpy(buffer,psk,len);
		FWrite(buffer, OFFSET_PSK, MAX_PSK_LEN);
	}
	else
	{
		/* reset to 0xFF to clean */
		memset(buffer,0xFF,sizeof(buffer));
		FWrite(buffer, OFFSET_PSK, MAX_PSK_LEN);
	}
	return 0;
}
#endif

#if defined (RTCONFIG_WLMODULE_RT3352_INIC_MII)
void getRSSI(const char *start, char **end, char *rssi)
{
	char *pS, *pV, *pN;

	if(start == NULL || rssi == NULL)
		return;

	rssi[0] = '\0';
	if((pS = strstr(start, "RSSI")) == NULL)
		return;

	if((pN = strchr(pS, '\n')) == NULL)
		return;

	if(end)
		*end = pN;

	if((pV = strchr(pS, '=')) == NULL || pV > pN)
		return;

	pV++;
	while(pV[0] == ' ' || pV[0] == '\t')
		pV++;

	while(pN > pV && isspace(pN[-1]))
		pN--;

	if(pN-pV > 0)
	{
		memcpy(rssi, pV, pN-pV);
		rssi[pN-pV] = '\0';
	}
}
#endif	/* RTCONFIG_WLMODULE_RT3352_INIC_MII */

int
getrssi(int band)
{
#if defined (RTCONFIG_WLMODULE_RT3352_INIC_MII)
#define RTPRIV_IOCTL_STATISTICS		(SIOCIWFIRSTPRIV + 0x09)
	char data[1024];
	struct iwreq wrq;

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = 0;

	if(wl_ioctl(get_wifname(band), RTPRIV_IOCTL_STATISTICS, &wrq) < 0)
	{
		dbg("errors in getting STATISTICS result\n");
		return 0;
	}

	if(wrq.u.data.length > 0)
	{
		char *start;
		char rssi1[8], rssi2[8], rssi3[8];
		start = wrq.u.data.pointer;
		getRSSI(start, &start, rssi1);
		getRSSI(start, &start, rssi2);
		getRSSI(start, &start, rssi3);
		printf("%s,%s,%s\n", rssi1, rssi2, rssi3);
	}

	return 0;
#else	/* !RTCONFIG_WLMODULE_RT3352_INIC_MII */
	char data[32];
	struct iwreq wrq;

	memset(data, 0x00, 32);
	wrq.u.data.length = 32;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_GRSSI;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting RSSI result\n");
		return 0;
	}

	if(wrq.u.data.length > 0)
	{
		puts(wrq.u.data.pointer);
	}

	return 0;
#endif	/* RTCONFIG_WLMODULE_RT3352_INIC_MII */
}

int 
ResetDefault(void)
{
	int ret;

	ret = eval("mtd-erase", "-d", "nvram");

#if defined(RTAC1200V2)
    // "dd if=/dev/mtdblock2 of=/lib/firmware/e2p bs=65535 skip=0 count=1";
	//doSystem("dd if=/dev/mtdblock2 of=/lib/firmware/e2p bs=65535 skip=0 count=1");
#endif	

	if(ret == 1)
		puts("Timeout");	//timeout
	else if(ret == 0)
		puts("1");		//success
	else
		puts("0");		//erase fail

	return ret;
}

#define DEV_FLAGS_MAGIC "FL"
struct device_flags
{
	char magic[2];
	union {
		__u16 value;
		__u16 reserve:15,
		      has_thermal_pad:1;
	} u;
};

int Get_Device_Flags(void)
{
	struct device_flags dev_flags;
	int ret = -1;
	if( FRead((char *)&dev_flags, OFFSET_DEV_FLAGS, 4) < 0)
		dbg("READ DEV Flags: Out of scope\n");
	else if (memcmp(&dev_flags.magic, DEV_FLAGS_MAGIC, sizeof(dev_flags.magic)) != 0)
		dbg("READ DEV Flags: no contents !\n");
	else
	{
		char buf[128];
		char *p = buf;
		if(dev_flags.u.has_thermal_pad)
			p += sprintf(p, " Has Thermal Pad.");
		printf("Flags: 0x%04x\n%s\n", (__u16)dev_flags.u.value, buf);
		ret = 0;
	}
	return ret;
}

int Set_Device_Flags(const char *flags_str)
{
	struct device_flags dev_flags;

	if(flags_str == NULL || strlen(flags_str) != 6 || strncmp(flags_str, "0x", 2) != 0)
		return -1;

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	memset(&dev_flags, 0, sizeof(dev_flags));
	memcpy(&dev_flags.magic, DEV_FLAGS_MAGIC, sizeof(dev_flags.magic));
	dev_flags.u.value = strtoul(flags_str, NULL, 16);
	FWrite((const char *)&dev_flags, OFFSET_DEV_FLAGS, 4);
	return Get_Device_Flags();
}

void set_factory_mode(void)
{
	char *mode_str;
	char magic_str[] = {'a', 't', 'e', 'C', 'o', 'm', 'm', 'a', 'n', 'd', '_', 'f', 'l', 'a', 'g', '\0'};

	if(!nvram_match(magic_str, "1"))
		return;

	mode_str = ATE_RALINK_FACTORY_MODE_STR();
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

int _dump_powertable(void)
{
	int n = 0;
	char wif[8], *next;
#if defined(RTCONFIG_WLMODULE_MT7915D_AP)
	char data[1024*41];
#elif defined(RTCONFIG_MT798X)
	char data[42000]; // according driver's definition
#else
	char data[1024*24];
#endif

	struct iwreq wrq;

	foreach (wif, nvram_safe_get("wl_ifnames"), next) {

		memset(data, 0, sizeof(data));

		wrq.u.data.pointer = data;
		wrq.u.data.length = sizeof(data);
		wrq.u.data.flags = ASUS_SUBCMD_GETSKUTABLE;

		if (wl_ioctl(wif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
			fprintf(stderr, "wl_ioctl error!!!\n");
			return 0;
		}

		printf("%dg power table:\n%s", n==0?2:5,data);
		n++;
		sleep(1);
	}

	return 0;
}

int _dump_txbftable(void)
{
	int n = 0;
	char wif[8], *next;
#if defined(RTCONFIG_WLMODULE_MT7915D_AP)
	char data[1024*41];
#elif defined(RTCONFIG_MT798X)
	char data[42000]; // according driver's definition
#else
	char data[1024*24];
#endif

	struct iwreq wrq;

	foreach (wif, nvram_safe_get("wl_ifnames"), next) {

		memset(data, 0, sizeof(data));

		wrq.u.data.pointer = data;
		wrq.u.data.length = sizeof(data);
		wrq.u.data.flags = ASUS_SUBCMD_GETSKUTABLE_TXBF;

		if (wl_ioctl(wif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
#if !defined(RTAC1200V2) /* RT-AC1200_V2 only support 5G TXBF */
			fprintf(stderr, "wl_ioctl error!!!\n");
			return 0;
#endif
		}

		printf("%dg power table:\n%s", n==0?2:5,data);
		n++;
		sleep(1);
	}

	return 0;
}

#ifdef RTCONFIG_ATEUSB3_FORCE
int getForceU3(void)
{
	char value='0';

	FRead(&value, OFFSET_FORCE_USB3, 1);
	puts(value=='1'?"1":"0");

	return 0;
}

int setForceU3(const char *val)
{
	if (val[0]!='0' && val[0]!='1')
		return -1;
	if (!IS_ATE_FACTORY_MODE())
                return -1;

	FWrite(val, OFFSET_FORCE_USB3, 1);

	if (val[0] == '0')
		nvram_unset("usb_usb3");
	else
		nvram_set("usb_usb3", "1");
	nvram_commit();

	return 0;
}
#endif

void set_IpAddr_Lan(const char *value){
// offset OFFSET_IPADDR_LAN
	if (!IS_ATE_FACTORY_MODE()) {
		puts("ATE_ERROR_INCORRECT_PARAMETER");
		return;
	}

	char ipaddr_lan[16];
	
	if(!strcmp(value, "NONE")){
		memset(ipaddr_lan, 0xFF, sizeof(ipaddr_lan));
		nvram_unset("IpAddr_Lan");
	} else {
		memset(ipaddr_lan, 0, sizeof(ipaddr_lan));
		strncpy(ipaddr_lan, value, sizeof(ipaddr_lan)-1);
		nvram_set("IpAddr_Lan", ipaddr_lan);
	}

	FWrite(ipaddr_lan, OFFSET_IPADDR_LAN, sizeof(ipaddr_lan));
	nvram_commit();
	puts(nvram_safe_get("IpAddr_Lan"));
}

void get_IpAddr_Lan(){
	char *buf = nvram_safe_get("IpAddr_Lan");

	if(buf == NULL || strlen(buf) <= 0 || !strcmp(buf, "NONE"))
		puts("NONE");
	else
		puts(buf);
}

void set_MRFLAG(const char *value){
// offset OFFSET_IPADDR_LAN
	if (!IS_ATE_FACTORY_MODE()) {
		puts("ATE_ERROR_INCORRECT_PARAMETER");
		return;
	}

	char ipaddr_lan[16];

	if(!strcmp(value, "NONE")){
		memset(ipaddr_lan, 0xFF, sizeof(ipaddr_lan));
		nvram_unset("MRFLAG");
	} else {
		memset(ipaddr_lan, 0, sizeof(ipaddr_lan));
		strncpy(ipaddr_lan, value, sizeof(ipaddr_lan)-1);
		nvram_set("MRFLAG", ipaddr_lan);
	}

	FWrite(ipaddr_lan, OFFSET_IPADDR_LAN, sizeof(ipaddr_lan));
	nvram_commit();
	puts(nvram_safe_get("MRFLAG"));
}

void get_MRFLAG(){
	char *buf = nvram_safe_get("MRFLAG");

	if(buf == NULL || strlen(buf) <= 0 || !strcmp(buf, "NONE"))
		puts("NONE");
	else
		puts(buf);
}

int set_HwId(const char *HwId)
{
	unsigned char buf[4 + 1] = { 0 };

	if (!IS_ATE_FACTORY_MODE() || !HwId)
                return -1;

	strlcpy(buf, HwId, sizeof(buf));
	if (FWrite(buf, OFFSET_HWID, 4))
		return -1;

	nvram_set("HwId", HwId);
	puts(nvram_safe_get("HwId"));

	return 0;
}

int set_HwVersion(const char *HwVer)
{
	unsigned char buf[8 + 1] = { 0 };

	if (!IS_ATE_FACTORY_MODE() || !HwVer)
                return -1;

	strlcpy(buf, HwVer, sizeof(buf));
	if (FWrite(buf, OFFSET_HW_VERSION, 8))
		return -1;

	nvram_set("HwVer", HwVer);
	puts(nvram_safe_get("HwVer"));

	return 0;
}

int set_HwBom(const char *HwBom)
{
	unsigned char buf[32 + 1] = { 0 };

	if (!IS_ATE_FACTORY_MODE() || !HwBom)
                return -1;

	strlcpy(buf, HwBom, sizeof(buf));
	if (FWrite(buf, OFFSET_HW_BOM, 32))
		return -1;

	nvram_set("HwBom", HwBom);
	puts(nvram_safe_get("HwBom"));

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
	char *p, hwid[4 + 1] = { 0 };

	if (FRead((unsigned char*) hwid, OFFSET_HWID, 4))
		return -1;
	if ((p = strchr(hwid, 0xff)) != NULL)
		*p = '\0';
	puts(hwid);
	return 0;
}

int get_HwVersion(void)
{
	char *p, hwver[8 + 1] = { 0 };

	if (FRead((unsigned char*) hwver, OFFSET_HW_VERSION, 8))
		return -1;
	if ((p = strchr(hwver, 0xff)) != NULL)
		*p = '\0';
	puts(hwver);
	return 0;
}

int get_HwBom(void)
{
	char *p, hwbom[32 + 1] = { 0 };

	if (FRead((unsigned char*) hwbom, OFFSET_HW_BOM, 32))
		return -1;
	if ((p = strchr(hwbom, 0xff)) != NULL)
		*p = '\0';
	puts(hwbom);
	return 0;
}

int get_DateCode(void)
{
	char buffer[8+1]={0};

	FRead((unsigned char*)buffer, OFFSET_HW_DATE_CODE, 8);
	puts(buffer);

	return 0;
}

#ifdef RTCONFIG_AMAS
int set_amas_bdl(int flag)
{
	unsigned char value = (unsigned char)flag;

	if (!IS_ATE_FACTORY_MODE())
		return 0;

	if (FWrite(&value, OFFSET_AMAS_BUNDLE_FLAG, 1) < 0)
		puts("0");
	else
		printf("%d\n",flag);

	return 1;
}

int unset_amas_bdl(void)
{
	char value = 0xff;

	if (!IS_ATE_FACTORY_MODE())
		return 0;

	if (FWrite(&value, OFFSET_AMAS_BUNDLE_FLAG, 1) < 0)
		puts("0");
	else
		puts("");

	return 1;
}

int get_amas_bdl(void)
{
	unsigned char value;
	char buf[6];

	FRead(&value, OFFSET_AMAS_BUNDLE_FLAG, 1);
	if (value == 0xff)
	{	
		value = 0; // empty
		puts("");
	}
	else
	{	
		snprintf(buf, sizeof(buf)-1, "%u", value);
		puts(buf);
	}	

	return 1;
}

int get_amas_bdlkey(void)
{
	unsigned char buffer[CFGSYNC_GROUPID_LEN+1];

	if (FRead(buffer, OFFSET_AMAS_BUNDLE_KEY, CFGSYNC_GROUPID_LEN) < 0) {
		dbg("READ Group ID: Out of scope\n");
		return 0;
	}
	else {
		buffer[CFGSYNC_GROUPID_LEN]='\0';
		if (is_valid_group_id(buffer))
			puts(buffer);
		else {
			puts("");
			return 0;
		}
	}
	return 1;
}

int set_amas_bdlkey(const char *str)
{
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	FWrite(str, OFFSET_AMAS_BUNDLE_KEY, CFGSYNC_GROUPID_LEN);
	return get_amas_bdlkey();
}

int unset_amas_bdlkey(void)
{
	unsigned char buffer1[CFGSYNC_GROUPID_LEN];
	unsigned char buffer2[CFGSYNC_GROUPID_LEN];

	if (!IS_ATE_FACTORY_MODE())
                return 0;

	memset(buffer1, 0xFF, CFGSYNC_GROUPID_LEN);
	FWrite(buffer1, OFFSET_AMAS_BUNDLE_KEY, CFGSYNC_GROUPID_LEN);
	FRead(buffer2, OFFSET_AMAS_BUNDLE_KEY, CFGSYNC_GROUPID_LEN);
	if (memcmp(buffer1, buffer2, CFGSYNC_GROUPID_LEN)) {
		dbg("FWrite fail!!\n"); /* should not happen */
		return 0;
	}
	else
		puts("");
	return 1;
}
#endif

#if defined(RTCONFIG_ASUSCTRL)
/**
 * Description:
 * 	Obtain asusctrl_flags from the factory and set it to asusctrl_flags of nvram.
 * 	Always remove "0x" from OFFSET_ASUSCTRL_FLAGS.
 * 	Always prefix "0x" to asusctrl_flags nvram variable, except it's zero.
 * @return: 
 * 	-1  : Failed to read value from factory.
 * 	 0  : Sccess.
 */
int asus_ctrl_get(void)
{
	unsigned char asusctrl_flags[ASUSCTRL_FLAGS_LENGTH + 1] = { 0 };

	if (FRead(asusctrl_flags, OFFSET_ASUSCTRL_FLAGS, ASUSCTRL_FLAGS_LENGTH))
		return -1;
	else
		asusctrl_flags[ASUSCTRL_FLAGS_LENGTH] = '\0';

	if (asusctrl_flags[0] != 0xff) {
		char val[sizeof("0xXXX") + sizeof(asusctrl_flags)] = { 0 };

		snprintf(val, sizeof(val), "0x%lx", strtoul(asusctrl_flags, NULL, 16));
		nvram_set("asusctrl_flags", val);
		puts(asusctrl_flags);
	}

	return 0;

}

/**
 * Description:
 *	Store the asusctrl_flags value in the factory(addr is OFFSET_ASUSCTRL_FLAGS).
 * 	Always remove "0x" from OFFSET_ASUSCTRL_FLAGS.
 * 	Always prefix "0x" to asusctrl_flags nvram variable, except it's zero.
 * @return: 
 * 	-1  : Failed to write value to factory.
 * 	 0  : Success.
 */
int asus_ctrl_write(const char *asusctrl_value)
{
	unsigned char buf[ASUSCTRL_FLAGS_LENGTH + 1] = { 0 };

	if (isResetFactory(asusctrl_value)) {		// reset asusctrl
		memset(buf, 0xFF, sizeof(buf));
		FWrite(buf, OFFSET_ASUSCTRL_FLAGS, ASUSCTRL_FLAGS_LENGTH);
		nvram_set("asusctrl_flags", "0");
		_dprintf("asusctrl_value : clean-up-asusctrl-value.\n");
		return 0;
	}
	else {
		char val[sizeof("0xXXX") + sizeof(buf)] = { 0 };

		/* set nvram by asusctrl_value, reset default will be cleaned */
		asus_ctrl_nv((char *)asusctrl_value);

		snprintf(val, sizeof(val), "0x%lx", strtoul(asusctrl_value, NULL, 16));
		if (nvram_match("asusctrl_flags", val)) {
			_dprintf("asusctrl_flags : all-up-to-date.\n");
			return 0;
		}

		strlcpy(buf, val + strlen("0x"), sizeof(buf));
		if (FWrite(buf, OFFSET_ASUSCTRL_FLAGS, ASUSCTRL_FLAGS_LENGTH))
			return -1;

		asus_ctrl_get();
	}

	return 0;
}

/**
 * Description:
 * 	Obtain asusctrl_sku from the factory and set it to asusctrl_chg_sku of nvram.
 * @return: 
 * 	-1  : Failed to read value from factory.
 * 	 0  : Sccess.
 */
int asus_ctrl_sku_get()
{
	unsigned char asusctrl_sku[ASUSCTRL_CHG_SKU_LENGTH + 1] = { 0 };

	if (FRead(asusctrl_sku, OFFSET_ASUSCTRL_CHG_SKU, ASUSCTRL_CHG_SKU_LENGTH))
		return -1;
	else
		asusctrl_sku[ASUSCTRL_CHG_SKU_LENGTH] = '\0';

	if (asusctrl_sku[0] != 0xff) {
		nvram_set("asusctrl_chg_sku", asusctrl_sku);
		puts(asusctrl_sku);
	}
	return 0;
}

/**
 * Description:
 * 	1. Check whether the ctrl_sku value is correct.
 *	2. If ctrl_sku and tcode match, do nothing.
 *	3. Store the ctrl_sku value in the factory(addr is OFFSET_ASUSCTRL_CHG_SKU).
 * @return: 
 * 	-1  : Invalid param.
 * 	-2  : Failed to read value from factory.
 * 	-3  : Failed to write value to factory.
 * 	 0  : Success.
 */
int asus_ctrl_sku_write(const char *asusctrl_value)
{
	char tcode[6] = { 0 };
	unsigned char buf[ASUSCTRL_CHG_SKU_LENGTH + 1] = { 0 };

	if (!strcmp(asusctrl_value, "FF")) {
		memset(buf, 0xFF, sizeof(buf));
		FWrite(buf, OFFSET_ASUSCTRL_CHG_SKU, ASUSCTRL_CHG_SKU_LENGTH);
		nvram_unset("asusctrl_chg_sku");

		return 0;
	}

	/* [A-Z][0-9A-Z] */
	if ( (strlen(asusctrl_value) != ASUSCTRL_CHG_SKU_LENGTH) ||
	    !isupper(asusctrl_value[0]) || (!isupper(asusctrl_value[1]) && !isdigit(asusctrl_value[1])) 
	   )
	{
		return -1;
	}

	if (FRead((unsigned char*)&tcode, OFFSET_TERRITORY_CODE, 5))
		return -2;
	else
		tcode[5] = '\0';

	if (strncmp(tcode, asusctrl_value, 2)) {
		nvram_set("webs_chg_sku", "1");

		if (nvram_match("asusctrl_chg_sku", (char *)asusctrl_value)) {
			_dprintf("asusctrl_chg_sku : all-up-to-date.\n");
			return 0;
		}

		strlcpy(buf, asusctrl_value, sizeof(buf));
		if (FWrite(buf, OFFSET_ASUSCTRL_CHG_SKU, ASUSCTRL_CHG_SKU_LENGTH))
			return -3;

		asus_ctrl_sku_get();
	}

	return 0;
}

/**
 * Description:
 * 	asusctrl function initialization.
 * @return: 
 * 	None.
 */
void init_asusctrl()
{
	switch ( get_model() ) {
	/*case MODEL_RTAX53U:*/
	default:
		asus_ctrl_get();
		break;
	}
}

#define IsValid_REGDOMAIN_2G(CC) ( !strcasecmp(CC,"2G_CH11") || !strcasecmp(CC,"2G_CH13") || !strcasecmp(CC,"2G_CH14") )
#define IsValid_REGDOMAIN_5G(CC) ( !strcasecmp(CC,"5G_ALL") || !strcasecmp(CC,"5G_BAND12") || !strcasecmp(CC,"5G_BAND14") || !strcasecmp(CC,"5G_BAND24") || !strcasecmp(CC,"5G_BAND1") || !strcasecmp(CC,"5G_BAND4") || !strcasecmp(CC,"5G_BAND123") || !strcasecmp(CC,"5G_BAND124") )
#define IsValid_SKU(P) ( (P!=NULL && P->tcode!=NULL && P->regspec!=NULL && P->regdomain_2g!=NULL && P->regdomain_5g!=NULL) )
struct ctrl_sku_tbl_t {
    char *tcode;
    char *regspec;
    char *regdomain_2g;
    char *regdomain_5g;
};

static const struct ctrl_sku_tbl_t ctrl_sku_tbl[] = {
#if defined(RTACRH18)
	{ 	"US", "FCC", "2G_CH11", "5G_BAND14" 	},
	{ 	"CA", "IC", "2G_CH11", "5G_BAND14" 	},
	{ 	"EU", "CE", "2G_CH13", "5G_BAND123" 	},
	{	"UK", "CE", "2G_CH13", "5G_BAND123"	},
	{	"BZ", "FCC", "2G_CH11", "5G_BAND14"	},
#endif	// RTACRH18

#if defined(RT4GAX56)
	{ 	"AA", "CE", "2G_CH13", "5G_ALL" 	},
	{ 	"EU", "CE", "2G_CH13", "5G_BAND123" 	},
	{ 	"TW", "NCC", "2G_CH11", "5G_BAND14" 	},
#endif	// RT4GAX56

#if defined(RT4GAC86U)
	{ 	"EU", "CE", "2G_CH13", "5G_BAND123" 	},
	{ 	"US", "FCC", "2G_CH11", "5G_BAND14" 	},
#endif 	// RT4GAC86U

#if defined(RTAX53U)
	{ 	"UK", "CE", "2G_CH13", "5G_BAND123" 	},
	{ 	"EU", "CE", "2G_CH13", "5G_BAND123" 	},
	{ 	"AA", "FCC", "2G_CH11", "5G_BAND14" 	},
	{ 	"TW", "NCC", "2G_CH11", "5G_BAND14" 	},
#endif	// RTAX53U

#if defined(RTAX54)
	{ 	"US", "FCC", "2G_CH11", "5G_BAND14" 	},
	{ 	"TW", "NCC", "2G_CH11", "5G_BAND14" 	},
	{ 	"CA", "IC", "2G_CH11", "5G_BAND14" 	},
#endif	// RTAX54

#if defined(XD4S)
	{ 	"UK", "CE", "2G_CH13", "5G_BAND123" 	},
	{ 	"EU", "CE", "2G_CH13", "5G_BAND123" 	},
	{ 	"AA", "FCC", "2G_CH11", "5G_BAND14" 	},
	{ 	"TW", "NCC", "2G_CH11", "5G_BAND14" 	},
#endif	// XD4S

#if defined(TUFAX4200) || defined(TUFAX6000)
	{ "EU", "CE",	"2G_CH13", "5G_BAND123" },
	{ "UK", "CE",	"2G_CH13", "5G_BAND123" },
	{ "AA", "FCC",	"2G_CH11", "5G_ALL" },
	{ "JP", "JP",	"2G_CH13", "5G_BAND123" },
	{ "TW", "FCC",	"2G_CH11", "5G_ALL" },
	{ "CN", "CN",	"2G_CH13", "5G_BAND124" },
	{ "US", "FCC",	"2G_CH11", "5G_ALL" },
#endif
	{0, 0, 0, 0},
};

/**
 * Description:
 * 	When chg_sku is not equal to tcode, update tcode to the value of chg_sku.
 * @return:
 * 	None.
 */
void asus_ctrl_sku_check()
{
	const struct ctrl_sku_tbl_t *p_sku_tbl = NULL, *p = NULL;
	char tcode[6] = {0}, chg_sku[6] = {0};

	asus_ctrl_get();
	if (!asus_ctrl_en(ASUSCTRL_CHG_SKU))
		return;

	asus_ctrl_sku_get();
	strlcpy(chg_sku, nvram_safe_get("asusctrl_chg_sku"), sizeof(chg_sku));
	strlcpy(tcode, nvram_safe_get("territory_code"), sizeof(tcode));

	dbg("%s: initial chg_sku [%s] tcode [%s]\n", __func__, chg_sku, tcode);
	if (strlen(chg_sku) != 2) {
		/* If chg_sku is empty or other value, provide the tcode value for it. */
		strlcpy(chg_sku, tcode, ASUSCTRL_CHG_SKU_LENGTH + 1);
		dbg("reset chg_sku [%s] as same value of tcode [%s]\n", chg_sku, tcode);
	}
	dbg("%s: chg_sku [%s] tcode [%s]\n", __func__, chg_sku, tcode);
	if (!strncmp(tcode, chg_sku, 2))
		return;

	for (p = NULL, p_sku_tbl = &ctrl_sku_tbl[0]; IsValid_SKU(p_sku_tbl); p_sku_tbl++) {
		if (strncmp(chg_sku, p_sku_tbl->tcode, 2) == 0) {
			p = p_sku_tbl;
			break;
		}
	}

	if (p == NULL)
		return;

	/* Fix-up territory_code at run-time, based on chg_sku. */
	if (strncmp(tcode, chg_sku, 2) != 0) {
		memcpy(tcode, chg_sku, 2);
		nvram_set("territory_code", tcode);
	}

	nvram_set("ctl_reg_spec", p->regspec);
	nvram_set("ctl_wl_reg_2g", p->regdomain_2g);
	nvram_set("ctl_wl_reg_5g", p->regdomain_5g);
	dbg("chg_sku [%s]: new regspec [%s] regdom [%s/%s] asusctrl_flags [%s] asusctrl_chg_sku [%s]\n",
		chg_sku, p->regspec, p->regdomain_2g, p->regdomain_5g,
		nvram_get("asusctrl_flags")? : "NULL",
		nvram_get("asusctrl_chg_sku")? : "NULL");
	return;
}

/**
 * Description:
 * 	When chg_sku is not equal to tcode and the asusctrl flag is set, then reboot.
 * @return: 
 * 	None.
 */
void asus_ctrl_sku_update()
{
	char tcode[6], chg_sku[6];
	unsigned int act;

	asus_ctrl_get();
	asus_ctrl_sku_get();

	act = strtoul(nvram_safe_get("asusctrl_flags"), NULL, 16);
	strlcpy(chg_sku, nvram_safe_get("asusctrl_chg_sku"), sizeof(chg_sku));
	strlcpy(tcode, nvram_safe_get("territory_code"), sizeof(tcode));

	if (strlen(chg_sku) != 0 && strncmp(tcode, chg_sku, 2) != 0 && (act & (1 << ASUSCTRL_CHG_SKU))) {
		_dprintf("\n%s: Reboot\n", __func__);
		kill(1, SIGTERM);
	}
}

/* Execute this function BEFORE init_syspara() updates territory_code to nvram.
 * If location_code is set as default country of old sku, e.g., reset to default
 * and then configured via normal process in old firmware, load setting file with
 * old location_code setting, etc. Reset location_code if territory_code in nvram
 * same as territory_code in factory, location_code same as first two characters
 * of territory_code in factory, and first two character territory_code in factory
 * is differ from new sku which is specified in chg_sku.
 */
void fix_location_code(void)
{
	int asusctrl_flags = 0;
	char f_tcode[6] = { 0 };
	char flags_str[ASUSCTRL_FLAGS_LENGTH + 1] = { 0 };
	char chg_sku[ASUSCTRL_CHG_SKU_LENGTH + 1] = { 0 };

	if (!nvram_get("location_code") || nvram_match("location_code", "")
	 || !nvram_get("territory_code") || nvram_match("territory_code", ""))
		return;

	if (FRead(flags_str, OFFSET_ASUSCTRL_FLAGS, ASUSCTRL_FLAGS_LENGTH) < 0
	 || *(unsigned char*)flags_str == 0xFF)
		return;

	asusctrl_flags = strtoul(flags_str, NULL, 16);
	if (!(asusctrl_flags & (1U << ASUSCTRL_CHG_SKU)))
		return;

	if (FRead(f_tcode, OFFSET_TERRITORY_CODE, 5) < 0)
		return;

	if (FRead(chg_sku, OFFSET_ASUSCTRL_CHG_SKU, ASUSCTRL_CHG_SKU_LENGTH) < 0
	 || strlen(chg_sku) != 2)
		return;

	dbg("lcode [%s] n/f_tcode [%s]/[%s] chg_sku [%s]\n",
		nvram_get("location_code")? : "NULL", nvram_get("territory_code")? : "NULL", f_tcode, chg_sku);
	if (!strncmp(nvram_safe_get("location_code"), f_tcode, 2)
	 && nvram_match("territory_code", f_tcode)
	 && strncmp(f_tcode, chg_sku, ASUSCTRL_CHG_SKU_LENGTH)) {
		nvram_set("location_code", "");
		dbg("clear stale location_code.\n");
	}
}
#endif //RTCONFIG_ASUSCTRL

#if defined(RTCONFIG_COBRAND)
int get_cb(void)
{
	puts(nvram_safe_get("CoBrand"));
        return 1;
}

int set_cb(int n)
{
	unsigned char val;
	if (!IS_ATE_FACTORY_MODE())
                return -1;
	val=(unsigned char)n;
	FWrite(&val, OFFSET_HW_COBRAND, 1);
	nvram_set_int("CoBrand",n);
	nvram_commit();
	return get_cb();
}

int unset_cb(void)
{
	unsigned char val=0xff;
	if (!IS_ATE_FACTORY_MODE())
                return -1;
	FWrite(&val, OFFSET_HW_COBRAND, 1);
	nvram_unset("CoBrand");
	nvram_commit();
        return get_cb();
}
#endif

#if defined(TUFAX4200) || defined(TUFAX6000) // EEPROM runtime fix
#define PA_EEPROM_SIZE		4096
#define PA_EEPROM_OFFSET	0
void eeprom_check(void)
{
#if defined(TUFAX4200)
	unsigned int offset_val[] = { \
		0x19c, 0x05,
		0x3f7, 0x03,
		0x3fa, 0x02,
		0x3fb, 0x02,
		0x3fc, 0x04,
		0x3fd, 0x02,
		0x3fe, 0x02,
		0x3ff, 0x02,
		0x400, 0x02,
		0x401, 0x02,
		0x402, 0x02,
		0x421, 0x0c,
		0x423, 0x07,
		0x425, 0x0b,
		0x429, 0x0a,
		0x42d, 0x0a,
		0x81e, 0xc7,
		0x81f, 0xc6,
		0x823, 0xc7,
		0x825, 0xc7,
		0x83e, 0xc7,
		0x83f, 0xc7,
		0xd08, 0x54,
		0xd09, 0x0c,
		0xd0a, 0x54,
		0xd0b, 0x0c,
		0xd0c, 0x54,
		0xd0d, 0x0e,
		0xd0e, 0x56,
		0xd0f, 0x0c,
		0xd10, 0x56,
		0xd11, 0x0f,
		0xd12, 0x54,
		0xd13, 0x0a,
		0xd14, 0x54,
		0xd15, 0x0a,
		0xd16, 0x54,
		0xd17, 0x0c,
		0xd18, 0x56,
		0xd19, 0x0a,
		0xd1a, 0x56,
		0xd1b, 0x0c,
		0xd1c, 0x54,
		0xd1d, 0x0a,
		0xd1e, 0x54,
		0xd1f, 0x0a,
		0xd20, 0x54,
		0xd21, 0x0c,
		0xd22, 0x56,
		0xd23, 0x0a,
		0xd24, 0x56,
		0xd25, 0x0c,
		0xdbe, 0xd3 };
#elif defined(TUFAX6000)
	unsigned int offset_val[] = { \
		0xdbd, 0x00,
		0x81e, 0xc8,
		0x81f, 0xc6,
		0x820, 0xc4,
		0x821, 0xc2,
		0x822, 0x00,
		0x823, 0xca,
		0x824, 0xca,
		0x825, 0xc8,
		0x826, 0xc6,
		0x827, 0xc4,
		0x828, 0xc2,
		0x829, 0x00,
		0x82a, 0x81,
		0x82b, 0x82,
		0x82c, 0xca,
		0x82d, 0xc8,
		0x82e, 0xc6,
		0x82f, 0xc4,
		0x830, 0xc2,
		0x831, 0x00,
		0x832, 0x81,
		0x833, 0x82,
		0x834, 0x00,
		0x835, 0xca,
		0x836, 0xc8,
		0x837, 0xc6,
		0x838, 0xc4,
		0x839, 0xc2,
		0x83a, 0x00,
		0x83b, 0x81,
		0x83c, 0x82,
		0x83d, 0x00,
		0x83e, 0xcb,
		0x83f, 0xc8,
		0x840, 0xc6,
		0x841, 0xc4,
		0x842, 0xc2,
		0x843, 0x00,
		0x844, 0x81,
		0x845, 0x82,
		0x846, 0x84,
		0x847, 0x84,
		0x848, 0xca,
		0x849, 0xc8,
		0x84a, 0xc6,
		0x84b, 0xc4,
		0x84c, 0xc2,
		0x84d, 0x00,
		0x84e, 0x81,
		0x84f, 0x82,
		0x850, 0x84,
		0x851, 0x84,
		0x852, 0xca,
		0x853, 0xc8,
		0x854, 0xc6,
		0x855, 0xc4,
		0x856, 0xc2,
		0x857, 0x00,
		0x858, 0x81,
		0x859, 0x82,
		0x85a, 0x84,
		0x85b, 0x85,
		0x85c, 0xc8,
		0x85d, 0xc6,
		0x85e, 0xc4,
		0x85f, 0xc2,
		0x860, 0x00,
		0x861, 0x82,
		0x862, 0x83,
		0x863, 0x84,
		0x864, 0x86,
		0x865, 0x87,
		0x866, 0xca,
		0x867, 0xc8,
		0x868, 0xc6,
		0x869, 0xc4,
		0x86a, 0xc2,
		0x86b, 0x00,
		0x86c, 0x81,
		0x86d, 0x82,
		0x86e, 0x84,
		0x86f, 0x84,
		0x870, 0xca,
		0x871, 0xc8,
		0x872, 0xc6,
		0x873, 0xc4,
		0x874, 0xc2,
		0x875, 0x00,
		0x876, 0x81,
		0x877, 0x82,
		0x878, 0x84,
		0x879, 0x84,
		0x87a, 0xca,
		0x87b, 0xc8,
		0x87c, 0xc6,
		0x87d, 0xc4,
		0x87e, 0xc2,
		0x87f, 0x00,
		0x880, 0x81,
		0x881, 0x82,
		0x882, 0x84,
		0x883, 0x84,
		0x421, 0x0b,
		0x429, 0x0c,
		0x42d, 0x0a,
		0x3f6, 0x02,
		0x3f8, 0x02,
		0x3f9, 0x06,
		0x3fc, 0x00,
		0x402, 0x00,
		0x600, 0xf0,
		0x601, 0xe0,
		0x7d3, 0xca,
		0x7d4, 0xc8,
		0x7d5, 0xc8,
		0x7d6, 0xc6,
		0x7d7, 0xc4,
		0x7d8, 0xc2,
		0x7d9, 0x00,
		0x7da, 0xc8,
		0x7db, 0xc8,
		0x7dc, 0xc8,
		0x7dd, 0xc6,
		0x7de, 0xc4,
		0x7df, 0xc2,
		0x7e0, 0x00,
		0x7e1, 0x81,
		0x7e2, 0x82,
		0x7e3, 0xc8,
		0x7e4, 0xc8,
		0x7e5, 0xc6,
		0x7e6, 0xc4,
		0x7e7, 0xc2,
		0x7e8, 0x00,
		0x7e9, 0x81,
		0x7ea, 0x82,
		0x7eb, 0x00,
		0x7ec, 0xc7,
		0x7ed, 0xc8,
		0x7ee, 0xc6,
		0x7ef, 0xc4,
		0x7f0, 0xc2,
		0x7f1, 0x00,
		0x7f2, 0x81,
		0x7f3, 0x82,
		0x7f4, 0x84,
		0x7f5, 0x84,
		0x7f6, 0xc8,
		0x7f7, 0xc8,
		0x7f8, 0xc6,
		0x7f9, 0xc4,
		0x7fa, 0xc2,
		0x7fb, 0x00,
		0x7fc, 0x81,
		0x7fd, 0x82,
		0x7fe, 0x84,
		0x7ff, 0x83,
		0x800, 0xc8,
		0x801, 0xc8,
		0x802, 0xc6,
		0x803, 0xc4,
		0x804, 0xc2,
		0x805, 0x00,
		0x806, 0x81,
		0x807, 0x82,
		0x808, 0x84,
		0x809, 0x84,
		0x80a, 0xc8,
		0x80b, 0xc8,
		0x80c, 0xc6,
		0x80d, 0xc4,
		0x80e, 0xc2,
		0x80f, 0x00,
		0x810, 0x81,
		0x811, 0x82,
		0x812, 0x84,
		0x813, 0x84,
		0x814, 0xc8,
		0x815, 0xc8,
		0x816, 0xc6,
		0x817, 0xc4,
		0x818, 0xc2,
		0x819, 0x00,
		0x81a, 0x81,
		0x81b, 0x82,
		0x81c, 0x84,
		0x81d, 0x84 };
#else
#error "Check Your Model definition!"
#endif
	int i, array_size, mdy_cnt;
	unsigned char buf[PA_EEPROM_SIZE];
	FRead(buf, OFFSET_MTD_FACTORY+PA_EEPROM_OFFSET, PA_EEPROM_SIZE);
	array_size = ARRAY_SIZE(offset_val);
	if (array_size && (array_size & 1) == 0 && buf[0] == 0x86 && buf[1] == 0x79) {
		for(i = 0, mdy_cnt = 0; i < array_size; i += 2) {
			unsigned char orgval = buf[offset_val[i]];
			if (offset_val[i] >= PA_EEPROM_SIZE) {
				_dprintf("XXXX Error, eeprom offset:0x%x over the limit:0x%x!!\n", offset_val[i], PA_EEPROM_SIZE);
				continue;
			}
			if (orgval != offset_val[i+1]) {
				_dprintf("XXXX update eeprom offset:0x%x from [0x%x] to [0x%x]!!\n", offset_val[i], orgval, offset_val[i+1]);
				buf[offset_val[i]] = (unsigned char) offset_val[i+1];
				mdy_cnt++;
			}
		}
		if (mdy_cnt)
			FWrite(buf, OFFSET_MTD_FACTORY+PA_EEPROM_OFFSET, PA_EEPROM_SIZE);
	}
}
#endif

int checkPASS(const char *pass)
{
	char buffer[PASS_LEN +1];
	int i;
#if defined(RTCONFIG_NVRAM_ENCRYPT) && defined(RTCONFIG_PASS_V2)
	char dec_passwd[256] = {0};
#endif

	if (pass == NULL)
		return -1;

	memset(buffer,0,sizeof(buffer));
	if (FRead(buffer, PASS_OFFSET, PASS_LEN) < 0) {
		_dprintf("checkPASS FRead(%08x, %02x): Out of scope\n", PASS_OFFSET, PASS_LEN);
		return -1;
	}
	for (i = 0; i < sizeof(buffer) || buffer[i] == '\0'; i++) {
		if( (unsigned char)buffer[i] == 0xff ) {
			buffer[i] = '\0';
			break;
		}
	}

#if defined(RTCONFIG_NVRAM_ENCRYPT) && defined(RTCONFIG_PASS_V2)
	pw_dec(buffer, dec_passwd, sizeof(dec_passwd), 0);
	strlcpy(buffer, dec_passwd, sizeof(buffer));
#endif
	if(!strcmp(buffer, pass))
		;
	else if (!strcmp(pass, "NONE") && buffer[0] == '\0')
		;
	else
		return -1;

        return 0;
}

int getPASS(void)
{
	char buffer[PASS_LEN + 1];
	int i;

	memset(buffer,0,sizeof(buffer));
	FRead(buffer, OFFSET_PASS, MAX_PASS_LEN);
	if (buffer[0] == (char)0xFF)
		puts("NONE");
	else{
		for(i = 0; i < MAX_PASS_LEN && buffer[i] != '\0'; i++) {
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

int setPASS(const char *pass)
{
	int i;
	int len;
	char buffer[PASS_LEN +1];

	if (pass == NULL)
		return -1;

	if (!IS_ATE_FACTORY_MODE())
		return -1;

	if (pass[0] == '\0' || strcmp(pass, "NONE") == 0) {
		/* reset to 0xFF to clean */
		memset(buffer,0xFF,sizeof(buffer));
		nvram_set("forget_it", "");
	}
	else {
		len = strlen(pass);
		if (len < 1 || len > PASS_LEN)
			return -1;

		for (i = 0; i < len; i++) {
			if (!isprint(pass[i]) || pass[i] == ' ' || pass[i] == '"' || pass[i] == '\'')
				return -1;
		}

		memset(buffer,0,sizeof(buffer));
#if defined(RTCONFIG_NVRAM_ENCRYPT) && defined(RTCONFIG_PASS_V2)
		pw_enc(pass, buffer, 0);
#else
		strlcpy(buffer,pass,PASS_LEN);
#endif
		nvram_set("forget_it", buffer);
	}

	FWrite(buffer, PASS_OFFSET, PASS_LEN);
	return 0;
}

