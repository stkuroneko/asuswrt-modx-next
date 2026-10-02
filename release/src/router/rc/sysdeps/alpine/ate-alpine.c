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
#include <fcntl.h>		//      for restore175C() from Ralink src
#include <alpine.h>
#include <asm/byteorder.h>
#include <bcmnvram.h>
//#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <shutils.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <uapi/linux/mii.h>
//#include <linux/if.h>
#include <iwlib.h>
//#include <wps.h>
//#include <stapriv.h>
#include <shared.h>
#include "flash_mtd.h"
#include "ate.h"

#define RTKSWITCH_DEV  "/dev/rtkswitch"

static struct country_to_code_tbl_s {
	char *country;
	int code_2g, code_5g;
} country_to_code_tbl[] = {
	{ "US",	841, -1 },
	{ "CA",	124, -1 },
	{ "TW",	158, -1 },
	{ "CN",	156, -1 },
	{ "GB",	826, -1 },
	{ "DE",	276, -1 },
	{ "SG",	702, -1 },
	{ "HU",	348, -1 },
	{ "AU",	37, -1 },
	{ "DB", 392, 100 },	/* MUST HAVE, 2G ch1~14, 5G_ALL */

	{ NULL, -1, -1 }
};

/**
 * Convert RegulationDomain to QCA WiFi driver's CountryID
 * @band
 * 	2:	2G
 *  otherwise:	5G
 * @return
 *     -1:	invalid parameter
 *     <0:	country id not found
 *    >=0:	country id
 */
int country_to_code(char *ctry, int band)
{
	int code = -2;
	struct country_to_code_tbl_s *p;

	if (!ctry)
		return -1;
	for (p = &country_to_code_tbl[0]; p->country != NULL && p->code_2g >= 0; ++p) {
		if (strcmp(p->country, ctry))
			continue;

		code = p->code_2g;
		if (band != 2 && p->code_5g >= 0)
			code = p->code_5g;
	}

	return code;
}

static char *ATE_QCA_FACTORY_MODE_STR()
{
	char atemode[8];

	snprintf(atemode, sizeof(atemode), "%s%s%s%s%s%s%s%s", "A", "T", "E", "M", "O", "D", "E", "\0");
	return strdup(atemode);
}

int IS_ATE_FACTORY_MODE(void)
{
	char *mode_str = ATE_QCA_FACTORY_MODE_STR();
	int ret = strcmp(nvram_safe_get(mode_str), "1");

	free(mode_str);

	return (ret == 0);
}

void hexdump(unsigned char *pt, unsigned short len)
{
	unsigned short i;
	for (i=0;i<len;i++) {
		if (i%32==0) printf("%s%04x: ",i?"\n":"",i);
		printf("%02x ",pt[i]);
	}
	printf("\n");
}

int getMAC_5G(void)
{
	unsigned char buffer[6];
	char macaddr[18];
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	if (FRead(buffer, OFFSET_MAC_ADDR, 6) < 0)
		dbg("READ MAC address: Out of scope\n");
	else {
		ether_etoa(buffer, macaddr);
		puts(macaddr);
	}
	return 0;
}

int getMAC_2G(void)
{
	unsigned char buffer[6];
	char macaddr[18];
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	if (FRead(buffer, OFFSET_MAC_ADDR_2G, 6) < 0)
		dbg("READ MAC address 2G: Out of scope\n");
	else {
		ether_etoa(buffer, macaddr);
		puts(macaddr);
	}
	return 0;
}

int getEEPROM(unsigned char *outbuf, unsigned short *lenpt, char *area)
{
	unsigned long offset;
	int ret;
	if (strstr(area,"5G")) {
		if (*lenpt>QC98XX_EEPROM_SIZE_LARGEST)
			*lenpt=QC98XX_EEPROM_SIZE_LARGEST;
		offset=OFFSET_MAC_ADDR-QC98XX_EEPROM_MAC_OFFSET;
	} else if (strstr(area,"2G")) {
		if (*lenpt>QCA9557_EEPROM_SIZE)
			*lenpt=QCA9557_EEPROM_SIZE;
		offset=OFFSET_MAC_ADDR_2G-QCA9557_EEPROM_MAC_OFFSET;
	} else
		return -1;

	if (strstr(area,"CAL"))
		ret=CalRead(outbuf, offset-MTD_FACTORY_BASE_ADDRESS, *lenpt);
	else
		ret=FRead(outbuf, offset, *lenpt);
	if (ret < 0)
		return -1;
	return 0;
}

int setMAC_5G(const char *mac)
{
	char ea[ETHER_ADDR_LEN];
	char qcsapi_cmd[255] = {0};

	if (mac == NULL || !isValidMacAddr(mac))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"qcsapi_pcie set_mac_addr wifi0_0 %s", mac);
	system(qcsapi_cmd);
	if (ether_atoe(mac, ea)) {
		FWrite(ea, OFFSET_MAC_ADDR, 6);
		getMAC_5G();
	}
	return 1;
}

int setMAC_2G(const char *mac)
{
	char ea[ETHER_ADDR_LEN];
	char qcsapi_cmd[255] = {0};
#if 0
	char system_cmd[255] = {0};
#endif

	if (mac == NULL || !isValidMacAddr(mac))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (ether_atoe(mac, ea)) {
		FWrite(ea, OFFSET_MAC_ADDR_2G, 6);

	system("cp /sbin/fw_env.config /etc/");
	system("cp /sbin/fw_print /tmp/fw_printenv");
	system("cp /sbin/fw_print /tmp/fw_setenv");
	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"/tmp/fw_setenv ethaddr %s", mac);
	system(qcsapi_cmd);
	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"/tmp/fw_setenv eth1addr %s", mac);
	system(qcsapi_cmd);
	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"/tmp/fw_setenv eth2addr %s", mac);
	system(qcsapi_cmd);
	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"/tmp/fw_setenv eth3addr %s", mac);
	system(qcsapi_cmd);
	system("rm -f /etc/fw_env.config");
	system("rm -f /tmp/fw_printenv");
	system("rm -f /tmp/fw_setenv");

	inc_mac(mac, 1);

	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"qcsapi_pcie update_bootcfg_param pciemac %s", mac);
	system(qcsapi_cmd);
	system("qcsapi_pcie commit_bootcfg");
	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"qcsapi_pcie set_mac_addr pcie0 %s", mac);
	system(qcsapi_cmd);
	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd),
			"qcsapi_pcie set_mac_addr wifi2_0 %s", mac);
	system(qcsapi_cmd);
#if 0
		memset(system_cmd, 0, sizeof(system_cmd));
		snprintf(system_cmd, sizeof(system_cmd),
		"cp /sbin/fw_env.config /etc/fw_env.config; cp -f /sbin/fw_print /tmp/fw_setenv");
		system(system_cmd);

		memset(system_cmd, 0, sizeof(system_cmd));
		snprintf(system_cmd, sizeof(system_cmd),
		"/tmp/fw_setenv eth1addr %s", mac);
		system(system_cmd);

		memset(system_cmd, 0, sizeof(system_cmd));
		snprintf(system_cmd, sizeof(system_cmd),
		"/tmp/fw_setenv eth2addr %s", mac);
		system(system_cmd);

		memset(system_cmd, 0, sizeof(system_cmd));
		snprintf(system_cmd, sizeof(system_cmd),
		"/tmp/fw_setenv eth3addr %s", mac);
		system(system_cmd);

		memset(system_cmd, 0, sizeof(system_cmd));
		snprintf(system_cmd, sizeof(system_cmd),
		"rm -f /etc/fw_env.config; rm -f /tmp/fw_setenv");
		system(system_cmd);
#endif

		getMAC_2G();
	}
	return 1;
}

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

int
getCountryCode_5G()
{
	unsigned char CC[3];

	memset(CC, 0, sizeof(CC));
	FRead(CC, OFFSET_COUNTRY_CODE_5G, 2);
	if (CC[0] == 0xff && CC[1] == 0xff)	// 0xffff is default
		;
	else
		puts(CC);
	return 1;
}


void ctl_update(char *, int);
int
setCountryCode_2G(const char *cc)
{
	char CC[3];
	char qcsapi_cmd[255] = {0};

	if (cc==NULL || !isValidCountryCode(cc))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;
	/* Please refer to ISO3166 code list for other countries and can be found at
	 * http://www.iso.org/iso/en/prods-services/iso3166ma/02iso-3166-code-lists/list-en1.html#sz
	 */
	if (country_to_code((char*) cc, 2) < 0)
		return 0;

	memset(&CC[0], toupper(cc[0]), 1);
	memset(&CC[1], toupper(cc[1]), 1);
	memset(&CC[2], 0, 1);

	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd), 
			"qcsapi_pcie update_config_param global region %s", cc);
	system(qcsapi_cmd);
	FWrite(CC, OFFSET_COUNTRY_CODE, 2);
	puts(CC);
	return 1;
}

int
setCountryCode_5G(const char *cc)
{
	char CC[3];
	char qcsapi_cmd[255] = {0};

	if (cc==NULL || !isValidCountryCode(cc))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;
	/* Please refer to ISO3166 code list for other countries and can be found at
	 * http://www.iso.org/iso/en/prods-services/iso3166ma/02iso-3166-code-lists/list-en1.html#sz
	 */
	if (country_to_code((char*) cc, 2) < 0)
		return 0;

	memset(&CC[0], toupper(cc[0]), 1);
	memset(&CC[1], toupper(cc[1]), 1);
	memset(&CC[2], 0, 1);

	snprintf(qcsapi_cmd, sizeof(qcsapi_cmd), 
			"qcsapi_pcie update_config_param global region %s", cc);
	system(qcsapi_cmd);
	FWrite(CC, OFFSET_COUNTRY_CODE_5G, 2);
	puts(CC);
	return 1;
}

int getSN(void)
{
	char sn[SERIAL_NUMBER_LENGTH + 1];

	if (FRead(sn, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH) < 0)
		dbg("READ Serial Number: Out of scope\n");
	else {
		sn[SERIAL_NUMBER_LENGTH] = '\0';
		puts(sn);
	}
	return 1;
}

int setSN(const char *SN)
{
	if (SN == NULL || !isValidSN(SN))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (FWrite(SN, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH) < 0)
		return 0;

	getSN();
	return 1;
}

int getEISN(void)
{
	return 1;
}

int setEISN(const char *EISN)
{
	return 1;
}

#ifdef RTCONFIG_ODMPID
int setMN(const char *MN)
{
	char modelname[16];

	if (MN == NULL || !is_valid_hostname(MN))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	memset(modelname, 0, sizeof(modelname));
	strncpy(modelname, MN, sizeof(modelname) - 1);
	FWrite(modelname, OFFSET_ODMPID, sizeof(modelname));

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


int setPIN(const char *pin)
{	
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (pincheck(pin)) {
		FWrite(pin, OFFSET_PIN_CODE, 8);
		char PIN[9];
		memset(PIN, 0, 9);
		memcpy(PIN, pin, 8);
		puts(PIN);
		return 1;
	}
	return 0;
}

int getPIN(void)
{
	unsigned char PIN[9];
	memset(PIN, 0, sizeof(PIN));
	FRead(PIN, OFFSET_PIN_CODE, 8);
	if (PIN[0] != 0xff)
		puts(PIN);
	return 0;
}


int getBootVer(void)
{
	puts(nvram_safe_get("bl_version"));

	return 0;
}

#if defined(RTCONFIG_EXT_RTL8370MB)
/**
 * @link:
 * 	0:	no-link
 * 	1:	link-up
 * @speed:
 * 	0,10:	10Mbps
 * 	1,100:	100Mbps
 * 	2,1000:	1000Mbps
 * 	3,10000:	10000Mbps
 */
static char conv_speed(unsigned int link, unsigned int speed)
{
	char ret = 'X';

	if (link != 1)
		return ret;

	if (speed == 2 || speed == 1000)
		ret = 'G';
	else if (speed == 3 || speed == 10000)
		ret = 'S';
	else
		ret = 'M';

	return ret;
}
#endif

//Supports both RTL8367M and RTL8367R Realtek switch
/*
 * This function is used by factory only and always
 * think the LAN port next to WAN port as LAN1
 * even WebUI/case define another LAN port as LAN1.
 */
int GetPhyStatus(int verbose, phy_info_list *list)
{
	int fd;
	char buf[64];
	unsigned int wan_link[2], wan_speed[2];
	unsigned int sfp_link[0], sfp_speed[0];
	phyState pS;
	//char *wan_ifname[2] = { "eth1", "eth0" };	/* AR8035, AQR107 */

	fd = open(RTKSWITCH_DEV, O_RDONLY);
	if (fd < 0) {
		perror(RTKSWITCH_DEV);
		return 0;
	}

	memset(&pS, 0, sizeof(pS));
	if (ioctl(fd, 18, &pS) < 0) {
		snprintf(buf, sizeof(buf), "ioctl: %s", RTKSWITCH_DEV);
		perror(buf);
		close(fd);
		return 0;
	}
	close(fd);

	f_read_string("/sys/class/net/eth1/operstate", buf, sizeof(buf));
	if(strncmp(buf, "up", 2)==0) wan_link[0] = 1;
	else wan_link[0] = 0;
	f_read_string("/sys/class/net/eth1/speed", buf, sizeof(buf));
	wan_speed[0] = atoi(buf);

	f_read_string("/sys/class/net/eth0/operstate", buf, sizeof(buf));
	if(strncmp(buf, "up", 2)==0) wan_link[1] = 1;
	else wan_link[1] = 0;
	f_read_string("/sys/class/net/eth0/speed", buf, sizeof(buf));
	wan_speed[1] = atoi(buf);

	f_read_string("/sys/class/net/eth2/operstate", buf, sizeof(buf));
	if(strncmp(buf, "up", 2)==0) sfp_link[0] = 1;
	else sfp_link[0] = 0;
	f_read_string("/sys/class/net/eth2/speed", buf, sizeof(buf));
	sfp_speed[0] = atoi(buf);

	snprintf(buf, sizeof(buf), "W0=%C;W1=%C;L1=%C;L2=%C;L3=%C;L4=%C;L5=%C;L6=%C;L7=%C;L8=%C;L9=%C;",
		conv_speed(wan_link[0], wan_speed[0]),
		conv_speed(wan_link[1], wan_speed[1]),
		conv_speed(pS.link[0], pS.speed[0]),
		conv_speed(pS.link[1], pS.speed[1]),
		conv_speed(pS.link[2], pS.speed[2]),
		conv_speed(pS.link[3], pS.speed[3]),
		conv_speed(pS.link[4], pS.speed[4]),
		conv_speed(pS.link[5], pS.speed[5]),
		conv_speed(pS.link[6], pS.speed[6]),
		conv_speed(pS.link[7], pS.speed[7]),
		conv_speed(sfp_link[0], sfp_speed[0]));

	puts(buf);
	return 1;
}

/* Turn on ALL LED except WAN RED LED which should be turn on by setAllLedOn2(). */
int setAllLedOn(void)
{
	set_gpio(0, 1);
	set_gpio(1, 1);
	set_gpio(4, 1);
	set_gpio(2, 1);
	set_gpio(29, 1);
	set_gpio(44, 1);
	set_gpio(46, 1);
#ifdef RTCONFIG_QSR10G
	system("qcsapi_pcie set_LED 1 1");
	system("qcsapi_pcie set_LED 13 1");
#endif

	puts("1");
	return 0;
}

int setAllLedOff(void)
{
	set_gpio(0, 0);
	set_gpio(1, 0);
	set_gpio(4, 0);
	set_gpio(2, 0);
	set_gpio(29, 0);
	set_gpio(44, 0);
	set_gpio(46, 0);
#ifdef RTCONFIG_QSR10G
	system("qcsapi_pcie set_LED 1 0");
	system("qcsapi_pcie set_LED 13 0");
#endif

	puts("1");
	return 0;
}

int fanCtrl(int speed)
{
	//default: revolution: 0x1e=0x83 0x1f-0x06 -> 100% duty cycle = 3600PRM
	system("i2cset -y 0 0x2e 0x1e 0x83 i");
	system("i2cset -y 0 0x2e 0x1f 0x06 i");
	//set configure
	system("i2cset -y 0 0x2e 0x00 0x9d i");
	system("i2cset -y 0 0x2e 0x01 0x3f i");

	if(speed == 0){
		system("i2cset -y 0 0x2e 0x22 0x00 i");
	}else if(speed == 1){
		system("i2cset -y 0 0x2e 0x22 0x55 i");
	}else if(speed == 2){
		system("i2cset -y 0 0x2e 0x22 0x80 i");
	}else if(speed == 3){
		system("i2cset -y 0 0x2e 0x22 0xb3 i");
	}else if(speed == 4){
		system("i2cset -y 0 0x2e 0x22 0xff i");
	}else if(speed == 5){
		int data = 0, i, n;
		int INIT_RPM = 6000000;
		int CUR_RPM = 0;
		char *buffer, *tmp;

		system("i2cget -y 0 0x2e 0x08 w > /tmp/fanReadoutput.txt");
		buffer = read_whole_file("/tmp/fanReadoutput.txt");
	
		if(buffer)
		{
			tmp = buffer;
			tmp += 2;
			for(i = 0; i < 4; ++i)
			{
				n = *tmp;
				n = toupper(n);
				if(n >= 'A')
					n = n - 'A' + 10;
				else
					n -= '0';
				data *= 16;
				data += n;
				++tmp;
			}
			free(buffer);
		}
		unlink("/tmp/fanReadoutput.txt");
		if(data)
		{
			CUR_RPM = INIT_RPM / data;
			_dprintf("%d\n", CUR_RPM);
			return CUR_RPM;
		}else
			puts("Read Error");
	}
	sleep(1);	
	return 1;
}

int ResetDefault(void)
{
	system("mtd-erase -d nvram");
	puts("1");
	return 0;
}


int set40M_Channel_2G(char *channel)
{
	puts("0");
	return 1;
}

int set40M_Channel_5G(char *channel)
{
	puts("0");
	return 1;
}

int Get_channel_list(int unit)
{
	unsigned char countryCode[3];
	char chList[256];

	char tmp[128], prefix[] = "wlXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	memset(countryCode, 0, sizeof(countryCode));
	strncpy(countryCode,
		nvram_safe_get(strcat_r(prefix, "country_code", tmp)), 2);

	if (get_channel_list_via_driver(unit, chList, sizeof(chList)) > 0) {
		puts(chList);
	} else if (countryCode[0] != 0xff && countryCode[1] != 0xff)	// 0xffff is default
	{
		if (get_channel_list_via_country
		    (unit, countryCode, chList, sizeof(chList)) > 0) {
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

//End of new ATE Command

void Gen_fail_log(const char *logStr, int max, struct FAIL_LOG *log)
{
	const char *p = logStr;
	char *next;
	int num;
	int x, y;

	memset(log, 0, sizeof(struct FAIL_LOG));
	if (max > FAIL_LOG_MAX)
		log->num = FAIL_LOG_MAX;
	else
		log->num = max;

	if (logStr == NULL)
		return;

	while (*p != '\0') {
		while (*p != '\0' && !isdigit(*p))
			p++;
		if (*p == '\0')
			break;
		num = strtoul(p, &next, 0);
		if (num > FAIL_LOG_MAX)
			break;
		x = num >> 3;
		y = num & 0x7;
		log->bits[x] |= (1 << y);
		p = next;
	}
}

void Get_fail_ret(void)
{
	unsigned char str[OFFSET_FAIL_BOOT_LOG - OFFSET_FAIL_RET];
	FRead(str, OFFSET_FAIL_RET, sizeof(str));
	if (str[0] == 0 || str[0] == 0xff)
		return;
	str[sizeof(str) - 1] = '\0';
	puts(str);
}

void Get_fail_reboot_log(void)
{
	char str[512];
	Get_fail_log(str, sizeof(str), OFFSET_FAIL_BOOT_LOG);
	puts(str);
}

void Get_fail_dev_log(void)
{
	char str[512];
	Get_fail_log(str, sizeof(str), OFFSET_FAIL_DEV_LOG);
	puts(str);
}


#define DEV_FLAGS_MAGIC "FL"
struct device_flags {
	char magic[2];
	union {
		__u16 value;
		__u16 reserve:15, has_thermal_pad:1;
	} u;
};

int Get_Device_Flags(void)
{
	struct device_flags dev_flags;
	int ret = -1;
	if (FRead((char *)&dev_flags, OFFSET_DEV_FLAGS, 4) < 0)
		dbg("READ DEV Flags: Out of scope\n");
	else if (memcmp(&dev_flags.magic, DEV_FLAGS_MAGIC, sizeof(dev_flags.magic)) != 0)
		dbg("READ DEV Flags: no contents !\n");
	else {
		char buf[128];

		memset(buf, 0, sizeof(buf));
		if (dev_flags.u.has_thermal_pad)
			snprintf(buf, sizeof(buf), " Has Thermal Pad.");
		printf("Flags: 0x%04x\n%s\n", (__u16) dev_flags.u.value, buf);
		ret = 0;
	}
	return ret;
}

int Set_Device_Flags(const char *flags_str)
{
	struct device_flags dev_flags;

	if (flags_str == NULL || strlen(flags_str) != 6
	    || strncmp(flags_str, "0x", 2) != 0)
		return -1;

	memset(&dev_flags, 0, sizeof(dev_flags));
	memcpy(&dev_flags.magic, DEV_FLAGS_MAGIC, sizeof(dev_flags.magic));
	dev_flags.u.value = strtoul(flags_str, NULL, 16);
	FWrite((const char *)&dev_flags, OFFSET_DEV_FLAGS, 4);
	return Get_Device_Flags();
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


#if defined(RTCONFIG_TCODE)
int getTerritoryCode(void)
{
	char buf[6];

	memset(buf, 0, sizeof(buf));
	FRead((unsigned char*)&buf, OFFSET_TERRITORY_CODE, 5);
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

	/* [A-Z][A-Z]/[0-9][0-9] */
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

int
getPSK(void)
{
	char buffer[15];
	memset(buffer,0,sizeof(buffer));
	FRead(buffer, OFFSET_PSK, 14);
	if (!strcmp(buffer, ""))
		puts("NONE");
	else
		puts(buffer);

	return 0;
}

int
setPSK(const char *psk)
{
	int i;
	char buffer[15];

	if (!IS_ATE_FACTORY_MODE())
		return -1;

	if (psk && !strcmp(psk, "NONE")) {
		memset(buffer,0,sizeof(buffer));
		// memcpy(buffer,psk,14);
		FWrite(buffer, OFFSET_PSK, 15);
		return 0;
	}

	if (psk == NULL || strlen(psk) < 8 ||strlen(psk) > 32)
		return -1;

        for (i = 0; i < strlen(psk) ; i++) {
		if (psk[i] == '0' || psk[i] == '1' || psk[i] == '8')
			return -1;
		else if (psk[i] != '_' && !isalnum(psk[i]))
			return -1;
        }

	memset(buffer,0,sizeof(buffer));
	memcpy(buffer,psk,14);
	FWrite(buffer, OFFSET_PSK, 15);
	return 0;
}
#endif

void set_factory_mode()
{
	char *mode_str;
	char magic_str[] = {'a', 't', 'e', 'C', 'o', 'm', 'm', 'a', 'n', 'd', '_', 'f', 'l', 'a', 'g', '\0'};

	if(!nvram_match(magic_str, "1"))
		return;

	mode_str = ATE_QCA_FACTORY_MODE_STR();
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

void ate_run_in(void)
{
	fprintf(stderr, "send_test_packet\n");
	system("brctl addbr br0");
	system("ifconfig br0 up");
	system("ifconfig host0 up");
	system("brctl addif br0 host0");
	sleep(3);
	system("qcsapi_pcie set_test_mode calcmd 6 15 7 20 40 2 0");
	system("qcsapi_pcie send_test_packet calcmd 0");
	system("qcsapi_pcie set_test_mode calcmd 42 255 7 40 40 2 2");
	system("qcsapi_pcie send_test_packet calcmd 0");
	fprintf(stderr, "change calstate from 1 to 3 for next boot\n");
	system("qcsapi_pcie update_bootcfg_param calstate 3");
	system("qcsapi_pcie commit_bootcfg");
	sleep(3);
}

void ate_run_in_preconfig(void)
{
	fprintf(stderr, "change calstate from 3 to 1 for next boot\n");
	system("brctl addbr br0");
	system("ifconfig br0 up");
	system("ifconfig host0 up");
	system("brctl addif br0 host0");
	sleep(3);
	system("qcsapi_pcie update_bootcfg_param calstate 1");
	system("qcsapi_pcie commit_bootcfg");
	sleep(3);
}

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
