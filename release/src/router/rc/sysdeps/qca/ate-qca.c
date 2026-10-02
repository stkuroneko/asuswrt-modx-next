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
#include <qca.h>
#include <asm/byteorder.h>
#include <bcmnvram.h>
//#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <shutils.h>
#if defined(__GLIBC__) || defined(__UCLIBC__) /* not musl */
#include <sys/signal.h>
#else
#include <signal.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <linux/mii.h>
#include <sys/mount.h>
#include <stdint.h>
//#include <linux/if.h>
#include <iwlib.h>
//#include <wps.h>
//#include <stapriv.h>
#include <limits.h>		//PATH_MAX, LONG_MIN, LONG_MAX
#include <inttypes.h>
#include <shared.h>
#include "flash_mtd.h"
#include "ate.h"
#if defined(RTCONFIG_ASUSCTRL)
#include <rtstate.h>
#include <stdlib.h>
#endif

#define RTKSWITCH_DEV  "/dev/rtkswitch"

static struct country_to_code_tbl_s {
	char *country;
	int code_2g, code_5g;
	char *country_60g;
} country_to_code_tbl[] = {
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_SPF11_3_QSDK) || defined(RTCONFIG_SPF11_4_QSDK) || defined(RTCONFIG_QSDK10CS) /*DK SPF10*/
	{ "US",	840, -1, "US" },	/* US or FCC certification. */
#else
	{ "US",	841, -1, "US" },	/* US or FCC certification. */
#endif
	{ "CA",	124, -1, "CA" },
	{ "TW",	158, -1, "TW" },
	{ "CN",	156, -1, "CN" },
	{ "GB",	826, -1, "GB" },
	{ "BY",	112, -1, "BY" },	/* Belarus */
	{ "IL",	376, -1, "IL" },
	{ "UA",	826, -1, "UA" },	/* Ukraine cert. only */
	{ "DE",	276, -1, "DE" },
	{ "SG",	702, -1, "SG" },	/* Only for IMDA certification; FCC certification should use US instead. */
	{ "HU",	348, -1, "HU" },
#if defined(RTCONFIG_SOC_IPQ8074)
	{ "AU",	124, -1, "AU" },
#elif defined(RTCONFIG_QCN550X) || defined(RTCONFIG_SOC_IPQ40XX) || defined(PLAC56) || defined(MAPAC1750)
	{ "AU",	36, -1, "AU" },
#else // AC55 series
	{ "AU",	37, -1, "AU" },
#endif
	{ "KR", 410, -1, "KR" },
#if defined(RTCONFIG_QCN550X) || defined(MAPAC1750) /* QCA95XX SPF6.1.0 CS */ || defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
	{ "JP",	392, -1, "JP" },
#else
	{ "JP",	4015, -1, "JP" },
#endif
	{ "BZ",	84, -1, "BZ" },
	{ "RU",	51, -1, "RU" },
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_SPF11_3_QSDK) || defined(RTCONFIG_SPF11_4_QSDK)
	{ "DB",	840, -1, "US" },	/* US or FCC certification. */
#elif defined(RTCONFIG_QCN550X) || defined(RTCONFIG_SOC_IPQ40XX) || defined(MAPAC1750) /* new driver don't have countryID 392 */
	{ "DB", 4055, 100, "US" },	/* MUST HAVE, 2G ch1~14, 5G_ALL */
#else
	{ "DB", 392, 100, "US" },	/* MUST HAVE, 2G ch1~14, 5G_ALL */
#endif
#if defined(RTCONFIG_ASUSCTRL)
	{ "FR",	250, -1, "FR" },
#endif
	{ NULL, -1, -1, NULL }
};

#if defined(RTCONFIG_SOC_IPQ8074)
static int __Get_U64(unsigned int offset, uint64_t *val)
{
	if (!val || FRead((unsigned char*) val, offset, sizeof(*val)))
		return -1;
	if (*val == UINT64_MAX)
		*val = 0;
	return 0;
}

/* Caller is incharge of checking val */
static int __Set_U64(unsigned int offset, uint64_t val)
{
	int ret = 0;

	if (FWrite((unsigned char*) &val, offset, sizeof(val))) {
		puts("0");
		ret = -1;
	} else {
		puts("1");
	}

	return ret;
}

static int __Get_U32(unsigned int offset, uint32_t *val)
{
	if (!val || FRead((unsigned char*) val, offset, sizeof(*val)))
		return -1;
	if (*val == UINT32_MAX)
		*val = 0;
	return 0;
}

/* Caller is incharge of checking val */
static int __Set_U32(unsigned int offset, uint32_t val)
{
	int ret = 0;

	if (FWrite((unsigned char*) &val, offset, sizeof(val))) {
		puts("0");
		ret = -1;
	} else {
		puts("1");
	}

	return ret;
}
#endif

#if defined(RT4GAC53U)
#include <sys/reboot.h>
/* upgrade 1001/128MB bootcode to 1002/256MB */
void boot_version_ck(void)
{
	unsigned char btv[4], ddr[1];
	FRead(btv, OFFSET_BOOT_VER, 4);
	if (memcmp(btv, "1001", 4) == 0) {
		_dprintf("Buggy version 1001 !!!\n");
		/* double check */
		if ((FlashRead(btv, 0x161af0, 4) == 0) && (memcmp(btv, "1001", 4) ==0 )) {
			//_dprintf("double check bootversion 1001\n");
			if ((FlashRead(ddr, 0xc007b, 1) == 0) && (ddr[0] == 0x0d)) {
				//_dprintf("RAM size is 128MB\n");
				ddr[0] = 0x0e; // 256MB;
				FlashWrite(ddr, 0xc007b, 1);
				btv[3] = '2'; // version 1002
				FlashWrite(btv, 0x161af0, 4);
				//reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART, 0);
				sync();
				_dprintf("Force rebooting!\n");
				f_write("/proc/sysrq-trigger", "b", 1, 0 , 0); /* machine reset */
				sleep(5);
				_dprintf("Force rebooting again!\n");
				exit(-1);
			}
		}
	}
}
#endif

#if defined(MAPAC1750)
#ifndef ROUNDUP
#define ROUNDUP(x, y)           ((((x)+((y)-1))/(y))*(y))
#endif
#include <mtd/mtd-user.h>
#include <sys/reboot.h>
#include "bootcode.h"

static int simple_mtd_write(unsigned char *buf, char *mtd_path, unsigned long blen)
{
	int mtd_fd=-1, len=0, ret=-1;
	mtd_info_t mtd_info;
	erase_info_t erase_info;

	if ((mtd_fd = open(mtd_path, O_RDWR|O_SYNC)) < 0 ||
	    ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0) {
		perror(mtd_path);
		goto fail;
	}

	erase_info.start = 0;
	erase_info.length = ROUNDUP(blen, mtd_info.erasesize);
	_dprintf("[%s]: length:%u\n", __func__, erase_info.length);
	(void) ioctl(mtd_fd, MEMUNLOCK, &erase_info);
	if (ioctl(mtd_fd, MEMERASE, &erase_info) != 0 ||
		    (len = write(mtd_fd, buf, blen)) != blen) {
		_dprintf("[%s]: Erase/Write error, len:%lu !!!!!\n", __func__, len);
		goto fail;
	}
	ret = 0;
fail:
	if (mtd_fd != -1)
		close(mtd_fd);
	return ret;
}

static int convert_char(unsigned char ch)
{
	int val;
	switch (ch) {
		case '0' ... '9' :
				val = ch - '0';
				break;
		case 'a' ... 'f' :
				val = ch - 'a' + 10;
				break;
		case 'A' ... 'F' :
				val = ch - 'A' + 10;
				break;
		default :
				val = -1;
				break;
	}
	return val;
}

static int boot_ver_cmp(unsigned char *verA, unsigned char *verB, int len)
/* return  1 : A > B
 * return  0 : A = B or Error Case => do not upgrade
 * return -1 : A < B */
{
	int i;
	if (!verA || !verB) {
		_dprintf("[%s]: error, invalid arg A:%p, B:%p\n", __func__, verA, verB);
		return 0; /* do nothing */
	}
	for (i=0; i<len; i++) {
		int dA, dB;
		dA = convert_char(verA[i]);
		if (dA < 0) {
			_dprintf("[%s][%d]: invalid char %c\n", __func__, __LINE__, verA[i]);
			return 0; /* do nothing */
		}
		dB = convert_char(verB[i]);
		if (dB < 0) {
			_dprintf("[%s][%d]: invalid char %c\n", __func__, __LINE__, verB[i]);
			return 0; /* do nothing */
		}
		if (dA == dB) continue;
		else if (dA > dB) return 1;
		else return -1;
	}
	return 0;
}

/* check bootcode version & upgrade to 1004 */
void boot_version_ck(void)
{
	unsigned char btv[4];
	FRead(btv, OFFSET_BOOT_VER, 4);
	_dprintf("BOOTCODE: CUR[%c%c%c%c], TARGET[%s]\n", btv[0], btv[1], btv[2], btv[3], BOOT_VERSION);
	if (boot_ver_cmp(btv, BOOT_VERSION, 4) < 0) {
		_dprintf("!!! Upgrade bootcode from[[%c%c%c%c] to [%s], size:%d !!!\n", btv[0], btv[1], btv[2], btv[3], BOOT_VERSION, sizeof(bootcode_bin));
		// 1. write bootcode binary
		if (simple_mtd_write(bootcode_bin, "/dev/mtd0", sizeof(bootcode_bin))) {
			_dprintf("Upgrade fail !!!\n");
			return;
		}
		// 2. reboot immediately
		sync();
		_dprintf("Force rebooting!\n");
		sync();
		f_write("/proc/sysrq-trigger", "b", 1, 0 , 0); /* machine reset */
		sleep(3);
		_dprintf("Force rebooting again!\n");
		exit(-1);
	}
}
#endif

/**
 * Convert RegulationDomain to QCA WiFi driver's CountryID
 * @ctry:	regulation domain, comes from Factory
 * @band:
 * 	2:	2G
 *    1,5:	5G
 *   6,60:	60G
 *  otherwise:	invalid parameter
 * @code_str:	pointer to buffer.
 * @len:	size of @code_str.
 * @return
 * 	0:	success
 *     -1:	invalid parameter
 *     -2:	can't find code for @ctry
 */
int country_to_code(char *ctry, int band, char *code_str, size_t len)
{
	int r = -2;
	struct country_to_code_tbl_s *p;

	if (!ctry || !code_str || !len)
		return -1;

#if defined(RTCONFIG_WIFI_QCN5024_QCN5054)
	if (!strcmp(ctry, "AU")
	 && (!strncmp(nvram_safe_get("territory_code"), "CN", 2)
	  || !strncmp(nvram_safe_get("territory_code"), "AA", 2)
	  || !strncmp(nvram_safe_get("territory_code"), "IN", 2)
	  || !strncmp(nvram_safe_get("territory_code"), "KR", 2)
	  || !strncmp(nvram_safe_get("territory_code"), "HK", 2)
	  || !strncmp(nvram_safe_get("territory_code"), "SG", 2)
	  || (!strncmp(nvram_safe_get("territory_code"), "AU", 2) && nvram_match("location_code", "XX")))
        ) {
		ctry = "CN";
	}
#endif
#if defined(RTCONFIG_ASUSCTRL)
#if !defined(RTCONFIG_WIFI_QCN5024_QCN5054)
	if (nvram_match("EG_mode", "1") && nvram_match("wl_country_code", "GB") && band == 5) {
		ctry = "FR";
	}
#endif
#endif

	for (p = &country_to_code_tbl[0]; r < 0 && p->country != NULL && p->code_2g >= 0; ++p) {
		if (strcmp(p->country, ctry))
			continue;

		switch (band) {
		case 2:		/* 2.4GHz */
			snprintf(code_str, len, "%d", p->code_2g);
			r = 0;
			break;
		case 1:		/* 5GHz, for wl_nband user */
		case 5:		/* 5GHz */
			snprintf(code_str, len, "%d", (p->code_5g > 0)? p->code_5g : p->code_2g);
			r = 0;
			break;
		case 6:		/* 60GHz, for wl_nband user */
		case 60:	/* 60GHz */
			strlcpy(code_str, p->country_60g, len);
			r = 0;
			break;
		default:
			dbg("%s: unknown band %d, ctry %s\n", __func__, band, ctry);
		}
	}

	return r;
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

int stress_pktgen_main(int argc, char *argv[])
{
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_SOC_IPQ60XX)
#define NR_RUNIN_STATS	4
	int i, t1, runin_time, total_runin_time, phase1_t, v, commit, volt_up_1 = 0;
	char vap_2g[IFNAMSIZ], vphy_2g[IFNAMSIZ], phyId_2g[2];
	char vap_5g[IFNAMSIZ], vphy_5g[IFNAMSIZ], phyId_5g[2];
	char *set_fw_recovery[] = { IWPRIV, vphy_2g, "set_fw_recovery", "1", NULL };
	/* 2G TX ON with 2437MHz VHT20 MCS5 Power=17dBm All ANT1-4 */
	char *tx_on_2g[] = { "qcatestcmd", "-i", vphy_2g, "--tx", "tx99", "--phyId", phyId_2g, "--txfreq", "2437",
		"--txrate", "25", "--rateBw", "4", "--nss", "1", "--mode", "vht20", "--txpwr", "34", "--txchain", "15", NULL };
	/* 5G TX ON with 5210MHz VHT80 MCS5 Power=14dBm All ANT1-8 */
	char *tx_on_5g[] = { "qcatestcmd", "-i", vphy_5g, "--tx", "tx99", "--phyId", phyId_5g, "--txfreq", "5210",
		"--txrate", "25", "--rateBw", "6", "--nss", "1", "--mode", "vht80_1", "--txpwr", "28", "--txchain", "255", NULL };
	char *tx_off_2g[] = { "qcatestcmd", "-i", vphy_2g, "--tx", "off", "--phyId", phyId_2g, NULL };
	char *tx_off_5g[] = { "qcatestcmd", "-i", vphy_5g, "--tx", "off", "--phyId", phyId_5g, NULL };
	char tmp[8];

	if (!IS_ATE_FACTORY_MODE() || !nvram_match("Ate_power_on_off_enable", "2"))
		return 0;

#if defined(RTCONFIG_FANCTRL)
	/* Turn off fan */
	nvram_set("fanctrl_dutycycle", "-1");
	restart_fanctrl();
#endif

	strlcpy(vap_2g, WIF_2G, sizeof(vap_2g));
	strlcpy(vap_5g, WIF_5G, sizeof(vap_5g));
	strlcpy(vphy_2g, VPHY_2G, sizeof(vphy_2g));
	strlcpy(vphy_5g, VPHY_5G, sizeof(vphy_5g));
	strlcpy(phyId_2g, vphy_2g + strlen(vphy_2g) - 1, sizeof(phyId_2g));
	strlcpy(phyId_5g, vphy_5g + strlen(vphy_5g) - 1, sizeof(phyId_5g));
	eval("touch", "/tmp/Ate_temp_rec_start");
	nvram_set("Ate_runin_time", "0");
	nvram_set("Ate_limited_to_ceiling", "0");
	if (f_read_string("/sys/devices/platform/soc/b018000.cpr4-ctrl/volt_up", tmp, sizeof(tmp)) > 0) {
		volt_up_1 = safe_atoi(tmp);
	}
	nvram_set_int("Ate_volt_up", volt_up_1);
	for (i = 0; i < 2; ++i) {
		phase1_t = 0;
		if (i == 0) {
			phase1_t = nvram_get_int("Ate_temp_run_in_phase1_t");	/* unit: minutes */
			if (phase1_t < 5)
				phase1_t = 5;
		}

		/* Enter test mode and TX packets via WiFi */
		fini_wl();
		load_testmode_wifi_driver();
		sleep(3);
		_eval(set_fw_recovery, ">/dev/console", 0, NULL);
		nvram_set_int("Ate_temp_state", NR_RUNIN_STATS * i + 1);

		_eval(tx_on_2g, ">/dev/console", 0, NULL);
		sleep(3);	/* small delay between two test command must be add, otherwise, Q6 crash. */
		_eval(tx_on_5g, ">/dev/console", 0, NULL);
		t1 = uptime();
		runin_time = nvram_get_int("Ate_runin_time");
		dbg("%s: run-in phase%d TX packet, t1 %ds, t %d minutes, initial runin_time %d minutes\n", __func__, i + 1, t1, phase1_t, runin_time);
		nvram_set_int("Ate_temp_state", NR_RUNIN_STATS * i + 2);
		while (phase1_t <= 0 || (uptime() - t1) < (phase1_t * 60)) {
			commit = 0;
			sleep(1);
			total_runin_time = runin_time + (uptime() - t1) / 60;			/* unit:minutes */
			if (total_runin_time != nvram_get_int("Ate_runin_time")) {
				nvram_set_int("Ate_runin_time", total_runin_time);
				dbg("runin_time %d minutes\n", total_runin_time);
				commit = 1;
			}

			if (f_read_string("/sys/devices/platform/soc/b018000.cpr4-ctrl/limited_to_ceiling", tmp, sizeof(tmp)) > 0) {
				v = safe_atoi(tmp);
				if (nvram_get_int("Ate_limited_to_ceiling") != v) {
					nvram_set_int("Ate_limited_to_ceiling", v);
					dbg("Ate_limited_to_ceiling = %d\n", v);
					commit = 1;
				}
			}

			if (f_read_string("/sys/devices/platform/soc/b018000.cpr4-ctrl/volt_up", tmp, sizeof(tmp)) > 0) {
				v = safe_atoi(tmp) - volt_up_1;
				if (nvram_get_int("Ate_volt_up") != v) {
					nvram_set_int("Ate_volt_up", v);
					dbg("Ate_volt_up = %d\n", v);
					commit = 1;
				}
			}

			if (commit)
				nvram_commit();
		}
		_eval(tx_off_2g, ">/dev/console", 0, NULL);
		_eval(tx_off_5g, ">/dev/console", 0, NULL);
		nvram_set_int("Ate_temp_state", NR_RUNIN_STATS * i + 3);

		/* Enter mission mode for reading temperature of WiFi */
		nvram_set("acs_dfs", "0");	/* To avoid CAC, don't use DFS channel. */
		nvram_set("wl1_bw", "3");	/* 80MHz */
		eval("restart_wireless");
		nvram_set_int("Ate_temp_state", NR_RUNIN_STATS * i + 4);
		t1 = uptime();
		while ((uptime() -t1) < (3 * 60)) {
			ate_temperature_record();
			sleep(10);
		}
	}
#endif
	return 0;
}

void ate_run_in(void)
{
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_SOC_IPQ60XX)
	pid_t pid;
	char *argv[] = { "stress_pktgen", NULL};

	if (nvram_get("Ate_temp_state") != NULL) {
		dbg("%s: reentry, Ate_temp_state [%s]\n", __func__, nvram_safe_get("Ate_temp_state"));
		return;
	}

	/* Run stress_pktgen in background. */
	_eval(argv, NULL, 0, &pid);
#else
	char ifname[IFNAMSIZ], *next;

	foreach(ifname, nvram_safe_get("wl_ifnames"), next){
		_ifconfig(ifname, IFUP, NULL, NULL, NULL, 0);
	}
	eval("touch", "/tmp/Ate_temp_rec_start");
#endif
}

#if defined(RTCONFIG_HAS_5G_2)
int getMAC_5G_2(void)
{
	unsigned char buffer[6];
	char macaddr[18];
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	if (FRead(buffer, OFFSET_MAC_ADDR_5G_2, 6) < 0)
		dbg("READ MAC address: Out of scope\n");
	else {
		ether_etoa(buffer, macaddr);
		puts(macaddr);
	}
	return 0;
}
#endif

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
#if defined(RTCONFIG_WIFI_QCA9557_QCA9882) || defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) || defined(RTCONFIG_QCN550X)
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
#elif defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
      defined(RTCONFIG_WIFI_QCA9994_QCA9994) || \
      defined(RTCONFIG_WIFI_QCN5024_QCN5054) || \
      defined(RTCONFIG_SOC_IPQ40XX) || \
      defined(RTCONFIG_SOC_IPQ60XX) || \
      defined(RTCONFIG_SOC_IPQ50XX)
	_dprintf("%s: FIXME\n", __func__);
	return 0;
#else
#error
#endif
}

/*
 * Update QCA EEPROM content.
 * @eeprom_size:	size of this eeprom
 * @eeprom_csum_offset:	offset of checksum.
 * @eeprom_offset:	offset in Factory MTD partition
 * @data_offset:	data offset in eeprom
 * @data:
 * @len:
 * @return:
 * 	-1:		invalid parameter
 * 	-2:		out of scope
 * 	-3:		invalid eeprom content
 * 	-4:		allocate memory failed
 * 	 0:		success
 */
#if defined(VZWAC1300)
int update_qca_eeprom(unsigned int eeprom_size, unsigned int eeprom_csum_offset, unsigned int eeprom_offset, unsigned int data_offset, unsigned char *data, unsigned int len)
#else
static int update_qca_eeprom(unsigned int eeprom_size, unsigned int eeprom_csum_offset, unsigned int eeprom_offset, unsigned int data_offset, unsigned char *data, unsigned int len)
#endif
{
	unsigned char *eeprom;
	unsigned short *p_half, cur_sum, l = len / sizeof(unsigned short), csum_idx;
	int i;

	if (data_offset >= eeprom_size || (data_offset + len) > eeprom_size) {
		_dprintf("%s: data_offset %08x len %08x exceed eeprom size %08x\n",
		__func__, data_offset, len, eeprom_size);
		return -1;
	} else if (len % sizeof(unsigned short)) {
		_dprintf("%s: len %08x is not multiple of unsigned short!\n");
		return -1;
	}

	eeprom = malloc(eeprom_size);
	if (!eeprom) {
		dbg("%s: can't allocate %u bytes.\n", __func__, eeprom_size);
		return -4;
	}

	if (FRead(eeprom, MTD_FACTORY_BASE_ADDRESS + eeprom_offset, eeprom_size) < 0) {
		_dprintf("READ EEPROM %08x: Out of scope\n", MTD_FACTORY_BASE_ADDRESS + eeprom_offset);
		free(eeprom);
		return -2;
	}

	//1. check original checksum first
	if (verify_qca_eeprom_csum(eeprom, eeprom_size)) {
		_dprintf("Invalid eeprom (eeprom offset %08x)\n", eeprom_offset);
		free(eeprom);
		return -3;
	}

	csum_idx = eeprom_csum_offset / 2;
	cur_sum = __le16_to_cpu(*((unsigned short *)eeprom + csum_idx));
	//_dprintf("org_sum:%04x\n",cur_sum);
	p_half = (unsigned short *)&eeprom[data_offset];
	for (i = 0; i < l; i++)				// clear original
		cur_sum ^= __le16_to_cpu(p_half[i]);
	memcpy(eeprom + data_offset, data , len);	// update data
	for (i = 0; i < l; i++)				// compute new one
		cur_sum ^= __le16_to_cpu(p_half[i]);
	*((unsigned short *)eeprom + csum_idx) = __cpu_to_le16(cur_sum);
	//_dprintf("new_sum:%04x\n",cur_sum);
	FWrite(eeprom, MTD_FACTORY_BASE_ADDRESS + eeprom_offset, eeprom_size);

	free(eeprom);

	return 0 ;
}

#if defined(RTCONFIG_HAS_5G_2)
int setMAC_5G_2(const char *mac)
{
	unsigned char ea[ETHER_ADDR_LEN];

	if (mac == NULL || !isValidMacAddr(mac))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (ether_atoe(mac, ea)) {
#if defined(RTCONFIG_WIFI_QCA9557_QCA9882) || \
    defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
    defined(RTCONFIG_WIFI_QCA9994_QCA9994) || \
    defined(RTCONFIG_SOC_IPQ40XX)
		update_qca_eeprom(QCA_5G2_EEPROM_SIZE, QCA_5G2_EEPROM_CSUM_OFFSET,
			ETH2_MAC_OFFSET & (~0xFFF), ETH2_MAC_OFFSET & 0xFFF, ea, sizeof(ea));
#elif defined(RTCONFIG_QCA_AXCHIP)
		update_qca_eeprom(QCA_5G2_EEPROM_SIZE, QCA_5G2_EEPROM_CSUM_OFFSET,
			ETH2_MAC_OFFSET & (~0xFF), ETH2_MAC_OFFSET & 0xFF, ea, sizeof(ea));
#else
		FWrite(ea, OFFSET_MAC_ADDR_5G_2, 6);
#endif
		getMAC_5G_2();
	}
	return 1;
}
#endif

int setMAC_5G(const char *mac)
{
	unsigned char ea[ETHER_ADDR_LEN];

	if (mac == NULL || !isValidMacAddr(mac))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (ether_atoe(mac, ea)) {
#if defined(RTCONFIG_WIFI_QCA9557_QCA9882) || \
    defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
    defined(RTCONFIG_WIFI_QCA9994_QCA9994) || \
    defined(RTCONFIG_PCIE_AR9888) || defined(RTCONFIG_PCIE_QCA9888) || \
    defined(RTCONFIG_WIFI_QCN5024_QCN5054) || \
    defined(RTCONFIG_SOC_IPQ40XX)
		update_qca_eeprom(QCA_5G_EEPROM_SIZE, QCA_5G_EEPROM_CSUM_OFFSET,
			ETH1_MAC_OFFSET & (~0xFFF), ETH1_MAC_OFFSET & 0xFFF, ea, sizeof(ea));
#elif defined(RTCONFIG_QCA_AXCHIP)
		update_qca_eeprom(QCA_5G_EEPROM_SIZE, QCA_5G_EEPROM_CSUM_OFFSET,
			ETH1_MAC_OFFSET & (~0xFF), ETH1_MAC_OFFSET & 0xFF, ea, sizeof(ea));
#else
		FWrite(ea, OFFSET_MAC_ADDR, 6);
#endif
		getMAC_5G();
	}
	return 1;
}

int setMAC_2G(const char *mac)
{
	unsigned char ea[ETHER_ADDR_LEN];

	if (mac == NULL || !isValidMacAddr(mac))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	if (ether_atoe(mac, ea)) {
#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
    defined(RTCONFIG_WIFI_QCA9994_QCA9994) || \
    defined(RTCONFIG_WIFI_QCN5024_QCN5054) || \
    defined(RTCONFIG_SOC_IPQ40XX)
		update_qca_eeprom(QCA_2G_EEPROM_SIZE, QCA_2G_EEPROM_CSUM_OFFSET,
			ETH0_MAC_OFFSET & (~0xFFF), ETH0_MAC_OFFSET & 0xFFF, ea, sizeof(ea));
#elif defined(RTCONFIG_QCA_AXCHIP)
		update_qca_eeprom(QCA_2G_EEPROM_SIZE, QCA_2G_EEPROM_CSUM_OFFSET,
			ETH0_MAC_OFFSET & (~0xFF), ETH0_MAC_OFFSET & 0xFF, ea, sizeof(ea));
#else
		FWrite(ea, OFFSET_MAC_ADDR_2G, 6);
#endif
		getMAC_2G();
	}
	return 1;
}

int
getCountryCode_2G(void)
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

void ctl_update(char *, int);
int
setCountryCode_2G(const char *cc)
{
	char CC[3], code_str[10];

	if (cc==NULL || !isValidCountryCode(cc))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;
	/* Please refer to ISO3166 code list for other countries and can be found at
	 * http://www.iso.org/iso/en/prods-services/iso3166ma/02iso-3166-code-lists/list-en1.html#sz
	 */
	if (country_to_code((char*) cc, 2, code_str, sizeof(code_str)) < 0)
		return 0;

	memset(&CC[0], toupper(cc[0]), 1);
	memset(&CC[1], toupper(cc[1]), 1);
	memset(&CC[2], 0, 1);

	FWrite(CC, OFFSET_COUNTRY_CODE, 2);
	puts(CC);
	return 1;
}

int getSN(void)
{
	unsigned char sn[SERIAL_NUMBER_LENGTH + 1];
	unsigned char sn32[SERIAL_NUMBER_LENGTH32 + 1];

	memset(sn, '\0', sizeof(sn));
	memset(sn32, '\0', sizeof(sn));

	if (FRead(sn32, OFFSET_SERIAL_NUMBER32, SERIAL_NUMBER_LENGTH32) < 0)
		dbg("READ Serial Number: Out of scope\n");
	else
		sn32[lenFRead(sn32, SERIAL_NUMBER_LENGTH32)] = '\0';

	if (FRead(sn, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH) < 0)
		dbg("READ Serial Number: Out of scope\n");
	else
		sn[lenFRead(sn, SERIAL_NUMBER_LENGTH)] = '\0';

	if (!strlen(sn) && !strlen(sn32))		// 0xff is default
		puts("NONE");
	else if (strlen(sn32))				// SN32 is set
		puts(sn32);
	else if (strlen(sn))				// SN12 is set
		puts(sn);
	else
		puts("Both SN12 and SN15~SN32 exist.");

	return 1;
}

int setSN(const char *SN)
{
	unsigned char def[SERIAL_NUMBER_LENGTH32 + 1], sn[SERIAL_NUMBER_LENGTH32 + 1];

	memset(def, 0xff, sizeof(def));
	memset(sn, '\0', sizeof(sn));

	if (!IS_ATE_FACTORY_MODE())
                return 0;
	if (isResetFactory(SN)) {		// reset SN
		if (FWrite(def, OFFSET_SERIAL_NUMBER32, SERIAL_NUMBER_LENGTH32) < 0)
			return 0;

		if (FWrite(def, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH) < 0)
			return 0;

		getSN();
		return 1;
	}

	if (SN == NULL || !isValidSN(SN))
		return 0;

        if (strlen(SN) == SERIAL_NUMBER_LENGTH) {	// Set SN12 
		if (FWrite(SN, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH) < 0)
			return 0;

		if (FRead(sn, OFFSET_SERIAL_NUMBER32, (SERIAL_NUMBER_LENGTH32)) < 0)
			dbg("READ Serial Number: Out of scope\n");
		else {
			if (sn[0]!=0xff && sn[0]!=0xFF && sn[0]!=0x00) {	// Check if SN15~SN32 exist! If yes, empty the factory setting.
				if (FWrite(def, OFFSET_SERIAL_NUMBER32, SERIAL_NUMBER_LENGTH32) < 0)
					return 0;
			}
		}
	}
	else {		// Set SN15~SN32
		if (FRead(sn, OFFSET_SERIAL_NUMBER32, SERIAL_NUMBER_LENGTH32) < 0)
			dbg("READ Serial Number: Out of scope\n");
		else {
			if (lenFRead(sn, SERIAL_NUMBER_LENGTH32) > strlen(SN) ) {		// If the original setting is longer, and empy the factory setting.
				if (FWrite(def, OFFSET_SERIAL_NUMBER32, SERIAL_NUMBER_LENGTH32) < 0)
					return 0;
			}
		}

		if (FWrite(SN, OFFSET_SERIAL_NUMBER32, strlen(SN)) < 0)
			return 0;

		memset(sn, '\0', sizeof(sn));
		if (FRead(sn, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH) < 0)
			dbg("READ Serial Number: Out of scope\n");
		else {
			if (sn[0]!=0xff && sn[0]!=0xFF && sn[0]!=0x00) {	// Check if SN12 exist! If yes, empty the factory setting.
				if (FWrite(def, OFFSET_SERIAL_NUMBER, SERIAL_NUMBER_LENGTH) < 0)
					return 0;
			}
		}
	}
	
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

	if (MN == NULL || !is_valid_hostname(MN))
		return 0;
	if (!IS_ATE_FACTORY_MODE())
                return 0;

	memset(modelname, 0, sizeof(modelname));
	strncpy(modelname, MN, sizeof(modelname) - 1);
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
	unsigned char btv[5];
	char output_buf[32];

	memset(btv, 0, sizeof(btv));
	memset(output_buf, 0, sizeof(output_buf));
	FRead(btv, OFFSET_BOOT_VER, 4);
	snprintf(output_buf, sizeof(output_buf), "%s-%c.%c.%c.%c", nvram_safe_get("productid"),
		btv[0], btv[1], btv[2], btv[3]);
	puts(output_buf);

	return 0;
}

//Supports both RTL8367M and RTL8367R Realtek switch
/*
 * This function is used by factory only and always
 * think the LAN port next to WAN port as LAN1
 * even WebUI/case define another LAN port as LAN1.
 */
int GetPhyStatus(int verbose, phy_info_list *list)
{
	ATE_port_status(list);
	return 1;
}

#if defined(RTCONFIG_CONCURRENTREPEATER)

int set_off_led(led_state_t *led)
{
	int model = get_model();
#if defined(RPAC66)
	if (model ==  MODEL_RPAC66) {
		switch(led->id) {
			case LED_POWER:
				led_control(LED_ORANGE_POWER, LED_OFF);
				led_control(LED_POWER, LED_OFF);
				break;
			case LED_2G:
				led_control(LED_2G_BLUE, LED_OFF);	
				led_control(LED_2G_GREEN, LED_OFF);
				led_control(LED_2G_RED, LED_OFF);
				break;
			case LED_5G:
				led_control(LED_5G_BLUE, LED_OFF);			
				led_control(LED_5G_GREEN, LED_OFF);
				led_control(LED_5G_RED, LED_OFF);
				break;
			default:
				dbG("Not support the LED ID:%d\n", led->id);
		}
	}
#elif defined(RPAC51)
	switch (led->id) {
	case LED_POWER:
		led_control(LED_POWER, LED_OFF);
		led_control(LED_RED_POWER, LED_OFF);
		break;
	case LED_SINGLE:
		led_control(LED_SINGLE, LED_OFF);
		break;
	case LED_FAR:
		led_control(LED_FAR, LED_OFF);
		break;
	case LED_NEAR:
		led_control(LED_NEAR, LED_OFF);
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
	int model = get_model();
#if defined(RPAC66)
	if (model ==  MODEL_RPAC66) {
		switch(led->id) {
			case LED_POWER:
				if (led->color == LED_GREEN)
					led_control(LED_POWER, LED_ON);
				else if (led->color == LED_ORANGE)
					led_control(LED_ORANGE_POWER, LED_ON);
				break;
			case LED_2G:
				if (led->color == LED_RED)
					led_control(LED_2G_RED, LED_ON);
				else if (led->color == LED_GREEN)
					led_control(LED_2G_GREEN, LED_ON);
				else if (led->color == LED_BLUE)
					led_control(LED_2G_BLUE, LED_ON);
				else if (led->color == LED_ORANGE) {
					led_control(LED_2G_GREEN, LED_ON);
					led_control(LED_2G_RED, LED_ON);
				}
				break;
			case LED_5G:
				if (led->color == LED_RED)
					led_control(LED_5G_RED, LED_ON);
				else if (led->color == LED_GREEN)
					led_control(LED_5G_GREEN, LED_ON);
				else if (led->color == LED_BLUE)
					led_control(LED_5G_BLUE, LED_ON);
				else if (led->color == LED_ORANGE) {
					led_control(LED_5G_GREEN, LED_ON);
					led_control(LED_5G_RED, LED_ON);
				}
				break;
			default:
				dbG("Not support the LED ID:%d\n", led->id);
		}
	}
#elif defined(RPAC51)
	switch (led->id) {
	case LED_POWER:
		if (led->color == LED_BLUE)
			led_control(LED_POWER, LED_ON);
		else if (led->color == LED_RED)
			led_control(LED_RED_POWER, LED_ON);
		break;
	case LED_SINGLE:
		led_control(LED_SINGLE, LED_ON);
		break;
	case LED_FAR:
		led_control(LED_FAR, LED_ON);
		break;
	case LED_NEAR:
		led_control(LED_NEAR, LED_ON);
		break;
	default:
		dbG("Not support the LED ID:%d\n", led->id);
	}
#endif
	led->state = LED_ON;
	return 0;
}
#endif

/* Turn on ALL LED except WAN RED LED which should be turn on by setAllLedOn2(). */
int setAllLedOn(void)
{
	int model = get_model();

	led_control(LED_POWER, LED_ON);
	led_control(LED_WAN, LED_ON);
#if defined(RTCONFIG_WANLEDX2)
	led_control(LED_WAN2, LED_ON);
#endif
#ifndef RTCONFIG_LAN4WAN_LED
	led_control(LED_LAN, LED_ON);
#endif
	led_control(LED_USB, LED_ON);

	if (have_usb3_led(get_model()))
		led_control(LED_USB3, LED_ON);

	__wps_led_control(LED_ON);
	failover_led_control(LED_ON);
	sata_led_control(LED_ON);
#if defined(GTAXY16000) || defined(RTAX89U)
	if (is_aqr_phy_exist())
		r10g_led_control(LED_ON);
#else
	r10g_led_control(LED_ON);
#endif
	sfpp_led_control(LED_ON);
	logo_led_control(LED_ON);
	all_led_control(LED_ON);

	power_red_led_control(LED_OFF);	/* Turn off Power RED LED */
	wan_red_led_control(LED_OFF);	/* Turn off WAN RED LED */
	wan2_red_led_control(LED_OFF);	/* Turn off WAN2 RED LED */

#ifdef RTCONFIG_INTERNAL_GOBI
#if defined(RT4GAC53U)
	led_control(LED_LTE_OFF, LED_ON);
	led_control(LED_SIG4, LED_ON);
#elif defined(RT4GAC56)
	led_control(LED_SIM_DET, LED_ON);
	led_control(LED_SIM_UNDET, LED_ON);
	led_control(LED_LTE, LED_ON);
	led_control(LED_SIG4, LED_ON);
#else
	led_control(LED_LTE, LED_ON);
#endif
	led_control(LED_SIG1, LED_ON);
	led_control(LED_SIG2, LED_ON);
	led_control(LED_SIG3, LED_ON);
#endif
#ifdef RTCONFIG_LAN4WAN_LED
	led_control(LED_LAN1, LED_ON);
	led_control(LED_LAN2, LED_ON);
	led_control(LED_LAN3, LED_ON);
	led_control(LED_LAN4, LED_ON);
#endif

	switch (model) {
#if defined(RT4GAC53U)
	case MODEL_RT4GAC53U:
		led_control(LED_POWER_RED, LED_ON);
#endif
	case MODEL_GTAXY16000:
	case MODEL_RTAX89U:
#if defined(RTCONFIG_SWITCH_QCA8075_QCA8337_PHY_AQR107_AR8035_QCA8033)
		if (is_aqr_phy_exist()) {
			int aqr_addr = aqr_phy_addr();

			if (aqr_addr >= 0) {
				/* Turn on LED0/1/2 of AQR107 PHY */
				write_phy_reg(aqr_addr, 0x401EC430, 0x100);
				write_phy_reg(aqr_addr, 0x401EC431, 0x100);
				write_phy_reg(aqr_addr, 0x401EC432, 0x100);
			}
		}
		/* fall-through */
#endif
	case MODEL_RTAC55U:
	case MODEL_RTAC55UHP:
	case MODEL_RT4GAC55U:
	case MODEL_RTN19:
#if defined(RTAC59U)
	case MODEL_RTAC59U:
		eval("ssdk_sh", "debug", "reg", "set", "0x50", "0xc735c735", "4");
		eval("ssdk_sh", "debug", "reg", "set", "0x54", "0xc735c735", "4");
		eval("ssdk_sh", "debug", "reg", "set", "0x58", "0xc735c735", "4");
#endif
	case MODEL_BRTAC828:
	case MODEL_RTAD7200:
	case MODEL_PLAC66U:
	case MODEL_RTAC58U:
	case MODEL_RT4GAC56:
	case MODEL_RTAC82U:
		led_control(LED_2G, LED_ON);
#if defined(RTCONFIG_ETRON_XHCI_USB3_LED)
		/* SR1 */
		eval("iwpriv", "wifi1", "gpio_config", "1", "0", "0", "0");	/* Configure 5G LED as GPIO */
		eval("iwpriv", "wifi1", "gpio_output", "1", "1");		/* Turn on 5G LED */
#else
		led_control(LED_5G, LED_ON);
#endif
#if defined(RTAC82U)
		led_control(LED_WAN_RED, LED_ON);
#endif
		break;
#if defined(RTN14U)
	case MODEL_RTN14U:
		led_control(LED_2G, LED_ON);
		break;
#endif
#ifdef PLN12
	case MODEL_PLN12:
		led_control(LED_POWER_RED, LED_ON);
		led_control(LED_2G_GREEN, LED_ON);
		led_control(LED_2G_ORANGE, LED_ON);
		led_control(LED_2G_RED, LED_ON);
		break;
#endif
#ifdef PLAC56
	case MODEL_PLAC56:
		led_control(LED_POWER_RED, LED_ON);
		led_control(LED_2G_GREEN, LED_ON);
		led_control(LED_2G_RED, LED_ON);
		led_control(LED_5G_GREEN, LED_ON);
		led_control(LED_5G_RED, LED_ON);
		break;
#endif
#if defined(RPAC66)
	case MODEL_RPAC66:
		led_control(LED_ORANGE_POWER, LED_ON);
		led_control(LED_2G_BLUE, LED_ON);
		led_control(LED_2G_GREEN, LED_ON);
		led_control(LED_2G_RED, LED_ON);
		led_control(LED_5G_BLUE, LED_ON);		
		led_control(LED_5G_GREEN, LED_ON);
		led_control(LED_5G_RED, LED_ON);
		break;
#endif
#if defined(RPAC51)
	case MODEL_RPAC51:
		led_control(LED_POWER, LED_ON);
		led_control(LED_RED_POWER, LED_ON);
		led_control(LED_SINGLE, LED_ON);
		led_control(LED_FAR, LED_ON);
		led_control(LED_NEAR, LED_ON);	
		break;
#endif
#if defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED)
	case MODEL_MAPAC1750:
	case MODEL_RTAC59CD6R:
	case MODEL_RTAC59CD6N:
	case MODEL_PLAX56XP4:
#if defined(RTAC59_CD6R) || defined(RTAC59_CD6N) || defined(PLAX56_XP4)
		if (RGBLED_WHITE & RGBLED_WLED)
			led_control(LED_WHITE, LED_ON);
#endif
		led_control(LED_BLUE, LED_ON);
		led_control(LED_GREEN, LED_ON);
		led_control(LED_RED, LED_ON);
		break;
#endif
	}

#if defined(RTCONFIG_HAS_5G_2)
	led_control(LED_5G2, LED_ON);
#endif

	wigig_led_control(LED_ON);
	turbo_led_control(LED_ON);

#if defined(RTCONFIG_SWITCH_RTL8370M_PHY_QCA8033_X2) || \
    defined(RTCONFIG_SWITCH_RTL8370MB_PHY_QCA8033_X2)
	eval("rtkswitch", "100", "3");	/* Turn on GROUP0 LEDs */
#endif

#ifdef RTCONFIG_LED_ALL
	led_control(LED_ALL, LED_ON);
#endif

	puts("1");
	return 0;
}

/* Same as setAllLedOn() except WAN RED LED is turn on. */
int setAllLedOn2(void)
{
	int model = get_model();

	setAllLedOn();
	power_red_led_control(LED_ON);	/* Turn on Power RED LED */
	wan_red_led_control(LED_ON);
	wan2_red_led_control(LED_ON);
	switch (model) {
	case MODEL_RTAC55U:
	case MODEL_RTAC55UHP:
	case MODEL_RT4GAC55U:
	case MODEL_RTN19:
	case MODEL_RTAC59U:
	case MODEL_RTAC58U:
	case MODEL_RT4GAC53U:
	case MODEL_RTAC82U:
		led_control(LED_WAN, LED_OFF);
		break;
	case MODEL_BRTAC828:
	case MODEL_RTAD7200:
		led_control(LED_POWER, LED_OFF);
		led_control(LED_WAN, LED_OFF);
#if defined(RTCONFIG_WANLEDX2)
		led_control(LED_WAN2, LED_OFF);
#endif
		break;
	}

	return 0;
}

int setAllLedOff(void)
{
	int model = get_model();

	led_control(LED_POWER, LED_OFF);
	led_control(LED_WAN, LED_OFF);
#if defined(RTCONFIG_WANLEDX2)
	led_control(LED_WAN2, LED_OFF);
#endif
#ifndef RTCONFIG_LAN4WAN_LED
	led_control(LED_LAN, LED_OFF);
#endif
	led_control(LED_USB, LED_OFF);

	if (have_usb3_led(get_model()))
		led_control(LED_USB3, LED_OFF);

	__wps_led_control(LED_OFF);
	failover_led_control(LED_OFF);
	sata_led_control(LED_OFF);
#if defined(GTAXY16000) || defined(RTAX89U)
	if (is_aqr_phy_exist())
		r10g_led_control(LED_OFF);
#else
	r10g_led_control(LED_OFF);
#endif
	sfpp_led_control(LED_OFF);
	logo_led_control(LED_OFF);
	all_led_control(LED_OFF);

	power_red_led_control(LED_OFF);
	wan_red_led_control(LED_OFF);
	wan2_red_led_control(LED_OFF);

#ifdef RTCONFIG_INTERNAL_GOBI
#if defined(RT4GAC53U)
	led_control(LED_LTE_OFF, LED_OFF);
	led_control(LED_SIG4, LED_OFF);
#elif defined(RT4GAC56)
	led_control(LED_SIM_DET, LED_OFF);
	led_control(LED_SIM_UNDET, LED_OFF);
	led_control(LED_LTE, LED_OFF);
	led_control(LED_SIG4, LED_OFF);
#else
	led_control(LED_LTE, LED_OFF);
#endif
	led_control(LED_SIG1, LED_OFF);
	led_control(LED_SIG2, LED_OFF);
	led_control(LED_SIG3, LED_OFF);
#endif

	switch (model) {
#if defined(RT4GAC53U)
	case MODEL_RT4GAC53U:
		led_control(LED_POWER_RED, LED_OFF);
#endif
	case MODEL_GTAXY16000:
	case MODEL_RTAX89U:
#if defined(RTCONFIG_SWITCH_QCA8075_QCA8337_PHY_AQR107_AR8035_QCA8033)
		if (is_aqr_phy_exist()) {
			int aqr_addr = aqr_phy_addr();

			if (aqr_addr >= 0) {
				/* Turn off LED0/1/2 of AQR107 PHY */
				write_phy_reg(aqr_addr, 0x401EC430, 0x00);
				write_phy_reg(aqr_addr, 0x401EC431, 0x00);
				write_phy_reg(aqr_addr, 0x401EC432, 0x00);
			}
		}
		/* fall-through */
#endif
	case MODEL_RTAC55U:
	case MODEL_RTAC55UHP:
	case MODEL_RT4GAC55U:
	case MODEL_RTN19:
#if defined(RTAC59U)
	case MODEL_RTAC59U:
		eval("ssdk_sh", "debug", "reg", "set", "0x50", "0xc035c035", "4");
		eval("ssdk_sh", "debug", "reg", "set", "0x54", "0xc035c035", "4");
		eval("ssdk_sh", "debug", "reg", "set", "0x58", "0xc035c035", "4");
#endif
	case MODEL_BRTAC828:
	case MODEL_RTAD7200:
	case MODEL_PLAC66U:
	case MODEL_RTAC58U:
	case MODEL_RT4GAC56:
	case MODEL_RTAC82U:
		led_control(LED_2G, LED_OFF);
#if defined(RTCONFIG_ETRON_XHCI_USB3_LED)
		/* SR1 */
		eval("iwpriv", "wifi1", "gpio_config", "1", "0", "0", "0");	/* Configure 5G LED as GPIO */
		eval("iwpriv", "wifi1", "gpio_output", "1", "0");	/* Turn off 5G LED */
#else
		led_control(LED_5G, LED_OFF);
#endif
#ifdef RTCONFIG_LAN4WAN_LED
		led_control(LED_LAN1, LED_OFF);
		led_control(LED_LAN2, LED_OFF);
		led_control(LED_LAN3, LED_OFF);
		led_control(LED_LAN4, LED_OFF);
#endif
#if defined(RTAC82U)
		led_control(LED_WAN_RED, LED_OFF);
#endif

		break;
#if defined(RTN14U)
	case MODEL_RTN14U:
		led_control(LED_2G, LED_OFF);
		break;
#endif
#ifdef PLN12
	case MODEL_PLN12:
		led_control(LED_POWER_RED, LED_OFF);
		led_control(LED_2G_GREEN, LED_OFF);
		led_control(LED_2G_ORANGE, LED_OFF);
		led_control(LED_2G_RED, LED_OFF);
		break;
#endif
#ifdef PLAC56
	case MODEL_PLAC56:
		led_control(LED_POWER_RED, LED_OFF);
		led_control(LED_2G_GREEN, LED_OFF);
		led_control(LED_2G_RED, LED_OFF);
		led_control(LED_5G_GREEN, LED_OFF);
		led_control(LED_5G_RED, LED_OFF);
		break;
#endif
#if defined(RPAC66)
	case MODEL_RPAC66:
		led_control(LED_ORANGE_POWER, LED_OFF);
		led_control(LED_2G_BLUE, LED_OFF);	
		led_control(LED_2G_GREEN, LED_OFF);
		led_control(LED_2G_RED, LED_OFF);
		led_control(LED_5G_BLUE, LED_OFF);			
		led_control(LED_5G_GREEN, LED_OFF);
		led_control(LED_5G_RED, LED_OFF);
		break;
#endif
#if defined(RPAC51)
	case MODEL_RPAC51:
		led_control(LED_RED_POWER, LED_OFF);
		led_control(LED_SINGLE, LED_OFF);	
		led_control(LED_FAR, LED_OFF);
		led_control(LED_NEAR, LED_OFF);
		break;
#endif
#if defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED)
	case MODEL_MAPAC1750:
	case MODEL_RTAC59CD6R:
	case MODEL_RTAC59CD6N:
	case MODEL_PLAX56XP4:
#ifdef RTCONFIG_SW_CTRL_ALLLED
		if (nvram_match("AllLED", "0"))
			nvram_set("prelink_pap_status", "0");
		else
#endif
		{
#if defined(RTAC59_CD6R) || defined(RTAC59_CD6N) || defined(PLAX56_XP4)
			if (RGBLED_WHITE & RGBLED_WLED)
				led_control(LED_WHITE, LED_OFF);
#endif
			led_control(LED_BLUE, LED_OFF);
			led_control(LED_GREEN, LED_OFF);
			led_control(LED_RED, LED_OFF);
		}
		break;
#endif
	}

#if defined(RTCONFIG_HAS_5G_2)
	led_control(LED_5G2, LED_OFF);
#endif

	wigig_led_control(LED_OFF);
	turbo_led_control(LED_OFF);

#if defined(RTCONFIG_SWITCH_RTL8370M_PHY_QCA8033_X2) || \
    defined(RTCONFIG_SWITCH_RTL8370MB_PHY_QCA8033_X2)
	eval("rtkswitch", "100", "2");	/* Turn off GROUP0 LEDs */
#endif

#ifdef RTCONFIG_LED_ALL
	led_control(LED_ALL, LED_OFF);
#endif
#if defined(RTCONFIG_LP5523)
	lp55xx_leds_proc(LP55XX_ALL_LEDS_OFF, LP55XX_ACT_NONE);
#endif

	puts("1");
	return 0;
}

#if defined(RTCONFIG_WPS_ALLLED_BTN) || defined(RTCONFIG_SW_CTRL_ALLLED)
void setAllLedNormal(void)
{
#if defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED) || defined(RTCONFIG_LP5523)
	nvram_set_int("prelink_pap_status", 0);
#else /* AllLED */
	int model = get_model();
	char word[16], *next;
	int unit = 0;
	const int wled[] = { LED_2G, LED_5G, LED_5G2, LED_60G };

	led_control(LED_POWER, LED_ON);

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		if(get_radio_status(word))
			led_control(wled[unit], LED_ON);
		unit++;
	}

#ifdef RTCONFIG_LAN4WAN_LED
	LanWanLedCtrl();
#endif

	/* check LED_WAN status */
	kill_pidfile_s("/var/run/wanduck.pid", SIGUSR2);

	switch (model) {
#if defined(RTAC59U)
	case MODEL_RTAC59U:
		eval("ssdk_sh", "debug", "reg", "set", "0x50", "0xc735c735", "4");
		eval("ssdk_sh", "debug", "reg", "set", "0x54", "0xc735c735", "4");
		eval("ssdk_sh", "debug", "reg", "set", "0x58", "0xc735c735", "4");
		break;
#endif
#if defined(GTAXY16000) || defined(RTAX89U)
	case MODEL_GTAXY16000:	/* fall-through */
	case MODEL_RTAX89U:
		{
			int aqr_addr = aqr_phy_addr();

			if (aqr_addr >= 0) {
				/* AQR107 LED0/2: GREEN, LED1: ORANGE */
				write_phy_reg(aqr_addr, 0x401EC430, 0xC0EF);
				write_phy_reg(aqr_addr, 0x401EC432, 0x0080);
				write_phy_reg(aqr_addr, 0x401EC431, 0xC060);
			}
		}
		break;
#endif
	}
#endif
}
#endif

#ifdef RTCONFIG_SW_CTRL_ALLLED
void setAllLedBrightness(void)
{
#if defined(RTCONFIG_LP5523)
	lp55xx_leds_proc(LP55XX_ALL_LEDS_OFF, LP55XX_PREVIOUS_STATE);
#endif
}
#endif

#ifdef RTCONFIG_CONCURRENTREPEATER

int setAllOrangeLedOn(void) {
	int model = get_model();
#if defined(RPAC66)
	switch (model) {
	case MODEL_RPAC66:
		setAllLedOff();
		led_control(LED_ORANGE_POWER, LED_ON);
		break;
	};
#endif
	return 0;	
}

int setAllGreenLedOn(void) {
	int model = get_model();
#if defined(RPAC66)
	switch (model) {
	case MODEL_RPAC66:
		setAllLedOff();
		led_control(LED_2G_GREEN, LED_ON);
		led_control(LED_5G_GREEN, LED_ON);
		led_control(LED_POWER, LED_ON);		
		break;
	}
#endif
	return 0;	
}

int setAllBlueLedOn(void) {
	int model = get_model();
#if defined(RPAC66)
	switch (model) {
	case MODEL_RPAC66:
		setAllLedOff();
		led_control(LED_2G_BLUE, LED_ON);
		led_control(LED_5G_BLUE, LED_ON);
		break;
	}
#endif
#if defined(RPAC51)
	switch (model) {
	case MODEL_RPAC51:
		setAllLedOff();
		led_control(LED_POWER, LED_ON);
		led_control(LED_SINGLE, LED_ON);
		led_control(LED_FAR, LED_ON);
		led_control(LED_NEAR, LED_ON);	
		break;
	}
#endif
	return 0;	
}

int setAllRedLedOn(void) {
	int model = get_model();
#if defined(RPAC66)
	switch (model) {
	case MODEL_RPAC66:
		setAllLedOff();
		led_control(LED_2G_RED, LED_ON);
		led_control(LED_5G_RED, LED_ON);
		break;
	}
#endif
#if defined(RPAC51)
	switch (model) {
	case MODEL_RPAC51:
		setAllLedOff();
		led_control(LED_RED_POWER, LED_ON);
		break;
	}
#endif
	return 0;	
}
#endif

int ResetDefault(void)
{
	int ret;

	ret = eval("mtd-erase", "-d", "nvram");
#ifdef RTCONFIG_QCA_PLC_UTILS
	if(ret == 0)	//do erase on success
		ret = eval("mtd-erase", "-d", "plc");
#endif

	if(ret == 1)
		puts("Timeout");	//timeout
	else if(ret == 0)
		puts("1");		//success
	else
		puts("0");		//erase fail

	return ret;
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

#if defined(RTCONFIG_HAS_5G_2)
int Get_ChannelList_5G_2(void)
{
	return Get_channel_list(2);
}
#endif	/* RTCONFIG_HAS_5G_2 */

#if defined(RTCONFIG_WIFI6E)
int Get_ChannelList_6G(void)
{
	return Get_channel_list(is_6g(WL_5G_2_BAND) ? WL_5G_2_BAND : WL_6G_BAND);
}
#endif

#if defined(RTCONFIG_WIGIG)
int Get_ChannelList_60G(void)
{
	return Get_channel_list(WL_60G_BAND);
}
#endif	/* RTCONFIG_WIGIG */

#if defined(RTCONFIG_WIFI_QCA9557_QCA9882) || defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) || defined(RTCONFIG_QCN550X)
#ifdef RTCONFIG_ART2_BUILDIN
void Set_ART2(void)
#else
void Set_ART2(const char *tftpd_ip)
#endif
{
#ifdef RTCONFIG_ART2_BUILDIN
	pid_t pid0, pid1;
	char instance_id[] = "0XXX", log_name[] = "/tmp/nart0.logXXXXXX";
	char *nart_argv[] = {"/usr/sbin/nart.out",
		"-instance", instance_id,
		"-console",
		NULL
	};
#else
	const char *lib[] = {
		"libanwi.so", "libar9287.so", "libar9300.so","libcal-2p.so",
		"libfield.so", "liblinkAr9k.so", "libLinkQc9K.so", "libpart.so",
		"libqc98xx.so", "libtlvtemplate.so", "libtlvutil.so",
		NULL };
	const char *bin[] = {
		"boardData_2_QC98XX_cus223_523_gld.bin", "boardData_2_QC98XX_cus223_gld.bin",
		"boardData_2_QC98XX_xb140_gld.bin", "boardData_2_QC98XX_xb143_gld.bin",
		"boardData_3_QC98XX_cus223_120_gld.bin", "boardData_3_QC98XX_cus261_gld.bin",
		"boardData_3_QC98XX_xb141_gld.bin", "boardData_4_QC98XX_xb241_gld.bin",
		"boardData_4_QC98XX_xb243_gld.bin", "nart.out",
		NULL}, **fn;

	mkdir("/tmp/art2", 0777);
	_dprintf("%s: TFTP get ART2 from %s\n", __func__, tftpd_ip);
	doSystem("cd /tmp/art2 && tftp -g %s -r lib/modules/3.3.8/art.ko", tftpd_ip);
	for (fn = &lib[0]; *fn != NULL; fn++ )
		doSystem("cd /tmp/art2 && tftp -g %s -r usr/lib/%s", tftpd_ip, *fn);
	for (fn = &bin[0]; *fn != NULL; fn++ )
		doSystem("cd /tmp/art2 && tftp -g %s -r usr/sbin/%s", tftpd_ip, *fn);
	doSystem("chmod 755 /tmp/art2/*");
#endif

	eval("killall", "rstats", "udhcpc", "wanduck", "networkmap", "hostapd");
#if defined(RTCONFIG_PCIE_AR9888) || defined(RTCONFIG_PCIE_QCA9888)
	eval("killall", "Qcmbr");
#endif

	fini_wl();

	load_testmode_wifi_driver();
#ifdef RTCONFIG_ART2_BUILDIN
	modprobe("art");
#else
	eval("insmod", "/tmp/art2/art.ko");
#endif

#ifdef RTCONFIG_ART2_BUILDIN
	strcpy(instance_id, "0");
	strcpy(log_name, "/tmp/nart0.log");
	_eval(nart_argv, log_name, 0, &pid0);
#if defined(RTCONFIG_HAS_5G) && !defined(RTCONFIG_QSDK6PLUS)
	/* For QCA95XX old SDK with QCA9880/QCA9882 */
	strcpy(instance_id, "1");
	strcpy(log_name, "/tmp/nart1.log");
	_eval(nart_argv, log_name, 0, &pid1);
#endif
#else
	doSystem("export LD_LIBRARY_PATH=/tmp/art2 && /tmp/art2/nart.out -instance 0 -console &");
#if defined(RTCONFIG_HAS_5G) && !defined(RTCONFIG_QSDK6PLUS)
	/* For QCA95XX old SDK with QCA9880/QCA9882 */
	doSystem("export LD_LIBRARY_PATH=/tmp/art2 && /tmp/art2/nart.out -instance 1 -console &");
#endif
#endif
}

void Get_EEPROM_X(char *command)
{
	unsigned char buffer[2560];
	unsigned short len;
	int lret;
	char *pt;
	len=sizeof(buffer);
	pt = (char*) command + 11;
	if (!strcmp(pt, "2G"))
		lret=getEEPROM(&buffer[0], &len, pt);
	else if (!strcmp(pt, "5G"))
		lret=getEEPROM(&buffer[0], &len, pt);
	else if (!strcmp(pt, "CAL_2G"))
		lret=getEEPROM(&buffer[0], &len, pt);
	else if (!strcmp(pt, "CAL_5G"))
		lret=getEEPROM(&buffer[0], &len, pt);
	else {
		puts("ATE_UNSUPPORT");
		return;
	}
	if ( !lret )
		hexdump(&buffer[0], len);
}

void Get_CalCompare(void)
{
	unsigned char buffer[2560], buffer2[2560];
	unsigned short len, len2;
	int lret=0, cret=0;
	len=sizeof(buffer);
	len2=sizeof(buffer2);
	lret+=getEEPROM(&buffer[0], &len, "2G");
	lret+=getEEPROM(&buffer2[0], &len2, "CAL_2G");
	if (lret)
		return;
	if ((len!=len2) || (memcmp(&buffer[0],&buffer2[0],len)!=0)) {
		puts("2G EEPROM different!");
		cret++;
	}
	len=sizeof(buffer);
	len2=sizeof(buffer2);
	lret+=getEEPROM(&buffer[0], &len, "5G");
	lret+=getEEPROM(&buffer2[0], &len2, "CAL_5G");
	if (lret)
		return;
	if ((len!=len2) || (memcmp(&buffer[0],&buffer2[0],len)!=0)) {
		puts("5G EEPROM different!");
		cret++;
	}
	if (!cret)
		puts("1");
	else
		puts("0");
}
#endif	/* RTCONFIG_WIFI_QCA9557_QCA9882 || RTCONFIG_QCA953X || RTCONFIG_QCA956X || RTCONFIG_QCN550X */

#if defined(RPAC51)
/* Concept taken from the e2fsprogs/ismounted.c.
 * Find wherever 'file' (actually: device) is mounted.
 * Either the exact same device-name, or another device-name.
 * The latter is detected by comparing the rdev or dev&inode.
 * So aliasing won't fool us---we'll still find if it's mounted.
 * Return its mnt entry.
 * In particular, the caller would look at the mnt->mountpoint.
 *
 * Find the matching devname(s) in mounts or swaps.
 * If func is supplied, call it for each match.  If not, return mnt on the first match.
 */

static inline int is_same_device(char *fsname, dev_t file_rdev, dev_t file_dev, ino_t file_ino)
{
	struct stat st_buf;

	if (stat(fsname, &st_buf) == 0) {
		if (S_ISBLK(st_buf.st_mode)) {
			if (file_rdev && (file_rdev == st_buf.st_rdev))
				return 1;
		}
		else {
			if (file_dev && ((file_dev == st_buf.st_dev) &&
				(file_ino == st_buf.st_ino)))
				return 1;
			/* Check for [swap]file being on the device. */
			if (file_dev == 0 && file_ino == 0 && file_rdev == st_buf.st_dev)
				return 1;
		}
	}
	return 0;
}


struct mntent *findmntents(char *file, int swp, int (*func)(struct mntent *mnt, uint flags), uint flags)
{
	struct mntent	*mnt;
	struct stat	st_buf;
	dev_t		file_dev=0, file_rdev=0;
	ino_t		file_ino=0;
	FILE		*f;

	if ((f = setmntent(swp ? "/proc/swaps": "/proc/mounts", "r")) == NULL)
		return NULL;

	if (stat(file, &st_buf) == 0) {
		if (S_ISBLK(st_buf.st_mode)) {
			file_rdev = st_buf.st_rdev;
		}
		else {
			file_dev = st_buf.st_dev;
			file_ino = st_buf.st_ino;
		}
	}
	while ((mnt = getmntent(f)) != NULL) {
		/* Always ignore rootfs mount */
		if (strcmp(mnt->mnt_fsname, "rootfs") == 0)
			continue;

		if (strcmp(file, mnt->mnt_fsname) == 0 ||
		    strcmp(file, mnt->mnt_dir) == 0 ||
		    is_same_device(mnt->mnt_fsname, file_rdev , file_dev, file_ino)) {
			if (func == NULL)
				break;
			(*func)(mnt, flags);
		}
	}

	endmntent(f);
	return mnt;
}
#endif

#define LIB_FW_DIR	"/lib/firmware"
#define TEMP_FW_DIR	"/tmp/firmware"

#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
    defined(RTCONFIG_WIFI_QCA9994_QCA9994) || \
    defined(RTCONFIG_WIFI_QCN5024_QCN5054) || \
    defined(RTCONFIG_QCA_AXCHIP) || \
    defined(RTCONFIG_PCIE_AR9888) || defined(RTCONFIG_PCIE_QCA9888) || \
    defined(RTCONFIG_SOC_IPQ40XX)
void Set_Qcmbr(const char *value)
{
	pid_t pid0, pid1;
#if defined(RTCONFIG_HAS_5G_2) || defined(RTAC82U)
	pid_t pid2;
#endif
	char instance_id[] = "0XXX", pcie_id[] = "0XXX", log_name[] = "/tmp/qcmbr0.logXXXXXX", wifi_nic[] = "wifiX";
	char *qcmbr_argv[] = {"/usr/sbin/Qcmbr",
		"-instance", instance_id,
		"-pcie", pcie_id,
		"-interface", wifi_nic,
		NULL
	};

	// temp solution
	eval("killall", "Qcmbr");
#if !defined(RTCONFIG_TEST_BOARDDATA_FILE)
#ifdef RTCONFIG_USB
	if (findmntents(LIB_FW_DIR, 0, NULL, 0) != NULL &&
	    umount(LIB_FW_DIR) < 0 && umount2(LIB_FW_DIR, MNT_FORCE) < 0)
	{
		_dprintf("%s: Umount %s w/ MNT_FORCE flag fail!!! errno %d (%s) \n",
			__func__, LIB_FW_DIR, errno, strerror(errno));
		return;
	}
#else
	umount(LIB_FW_DIR);
	umount2(LIB_FW_DIR, MNT_FORCE);
#endif

	if (d_exists(TEMP_FW_DIR))
		eval("rm", "-fr", TEMP_FW_DIR);

	/* Copy /lib/firmware to /tmp/firmware,
	* Rename /tmp/firmware/{AR900B,QCA9984}/hw.[12]/otp.bin, and
	* bind mount /tmp/firmware to /lib/firmware.
	*/
	_dprintf("Rebuild %s\n", LIB_FW_DIR);
	eval("cp", "-a", LIB_FW_DIR, TEMP_FW_DIR);
	if (!value || strncmp(value, "verify", 6)) {
		_dprintf("Rename otp.bin as otp.bin.orig\n");
#if defined(RTAC82U) || defined(RTAC95U)
		eval("mv", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin.orig");
		eval("mv", TEMP_FW_DIR "/QCA9984/hw.1/otp.bin", TEMP_FW_DIR "/QCA9984/hw.1/otp.bin.orig");
#elif defined(MAPAC1300) || defined(VZWAC1300) || defined(SHAC1300)
		eval("mv", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin.orig");
#elif defined(MAPAC2200)
		eval("mv", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin.orig");
		eval("mv", TEMP_FW_DIR "/QCA9888/hw.2/otp.bin", TEMP_FW_DIR "/QCA9888/hw.2/otp.bin.orig");
#elif defined(RTAC58U) || defined(RT4GAC53U) || defined(RT4GAC56)
//TBD
/*
		eval("mv", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin", TEMP_FW_DIR "/IPQ4019/hw.1/otp.bin.orig");
*/
#elif defined(RPAC51) || defined(RTAC59U) || defined(RTAC59_CD6R) || defined(RTAC59_CD6N)
//TBD
/*
		eval("mv", TEMP_FW_DIR "/QCA9888/hw.2/otp.bin", TEMP_FW_DIR "/QCA9888/hw.2/otp.bin.orig");
*/
#elif defined(MAPAC1750)
//TBD
#else
		eval("mv", TEMP_FW_DIR "/AR900B/hw.1/otp.bin", TEMP_FW_DIR "/AR900B/hw.1/otp.bin.orig");
		eval("mv", TEMP_FW_DIR "/AR900B/hw.2/otp.bin", TEMP_FW_DIR "/AR900B/hw.2/otp.bin.orig");
		eval("mv", TEMP_FW_DIR "/QCA9984/hw.1/otp.bin", TEMP_FW_DIR "/QCA9984/hw.1/otp.bin.orig");
#endif
	}

	if (mount(TEMP_FW_DIR, LIB_FW_DIR, NULL, MS_BIND, NULL) != 0) {
		_dprintf("%s: bind mount %s fail! errno %d (%s)\n",
			__func__, TEMP_FW_DIR, strerror(errno));
	}
#endif

	eval("killall", "rstats", "udhcpc", "wanduck", "networkmap");
#if defined(RPAC51)
	eval("killall", "sysstate", "wlcconnect", "avahi-daemon", "lld2d" ,"led_monitor", "ntp");
#endif
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) || defined(RTCONFIG_QCN550X)
	if (module_loaded("art")) {
		eval("killall", "nart.out");
#ifdef RTCONFIG_ART2_BUILDIN
		modprobe_r("art");
#else
		eval("rmmod", "art");
#endif
	}
#endif
	fini_wl();

#if defined(RPAC51)
	/*As for Qcmdr ahbskip is given so the Radio chip connect to PCI will be wifi0 instead of wifi1 */
	doSystem("rm -rf /tmp/wifi0.caldata");
	doSystem("dd if=/dev/mtdblock2 of=/tmp/wifi0.caldata bs=32 count=377 skip=640");  //5G
	doSystem("echo 3 > /proc/sys/vm/drop_caches");
	if (access("/tmp/boarddata_0.bin",0) == 0){
		doSystem("cp -rf /tmp/boarddata_0.bin /lib/firmware/QCA9888/hw.2/boarddata_0.bin");
	}
#endif

	load_testmode_wifi_driver();

	sleep(3);
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) || defined(RTCONFIG_QCN550X)
	strcpy(instance_id, "1");
	strcpy(pcie_id, "0");
	strcpy(wifi_nic, "wifi0");
	strcpy(log_name, "/tmp/qcmbr0.log");
	_eval(qcmbr_argv, log_name, 0, &pid0);
#else
	strcpy(instance_id, "0");
	strcpy(pcie_id, "0");
	strcpy(wifi_nic, "wifi0");
	strcpy(log_name, "/tmp/qcmbr0.log");
	_eval(qcmbr_argv, log_name, 0, &pid0);
	strcpy(instance_id, "1");
	strcpy(pcie_id, "1");
	strcpy(wifi_nic, "wifi1");
	strcpy(log_name, "/tmp/qcmbr1.log");
	_eval(qcmbr_argv, log_name, 0, &pid1);
#if defined(RTCONFIG_HAS_5G_2) || defined(RTAC82U)
	strcpy(instance_id, "2");
	strcpy(pcie_id, "2");
	strcpy(wifi_nic, "wifi2");
	strcpy(log_name, "/tmp/qcmbr2.log");
	_eval(qcmbr_argv, log_name, 0, &pid2);
#endif
#endif
}

#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
void Set_Ftm(const char *value)
{
	pid_t pid0, pid1;
	char log_name[] = "/tmp/diag_socket_app.logXXXXXX", ipaddr[sizeof("192.168.001.075XXXXXX")];
	char *ping_argv[] = { "ping", "-c2", ipaddr, NULL };
	char *diag_argv[] = { "/usr/sbin/diag_socket_app", "-a", ipaddr, NULL };
	char *ftm_argv[] = { "/usr/sbin/ftm", "-n", NULL };

	// temp solution
	eval("killall", "diag_socket_app");
	eval("killall", "ftm");

	strlcpy(ipaddr, nvram_safe_get("ftm_pc_ipaddr"), sizeof(ipaddr));
	if (*ipaddr == '\0' || illegal_ipv4_address(ipaddr)) {
#if !defined(RTCONFIG_SOC_IPQ60XX)
		dbg("%s is not legal IPv4 address, use 192.168.1.75 instead.\n", ipaddr);
		strlcpy(ipaddr, "192.168.1.75", sizeof(ipaddr));
#else
		dbg("%s is not legal IPv4 address, use 192.168.50.4 instead.\n", ipaddr);
		strlcpy(ipaddr, "192.168.50.4", sizeof(ipaddr));
#endif
	}

#ifdef RTCONFIG_USB
	if (findmntents(LIB_FW_DIR, 0, NULL, 0) != NULL &&
	    umount(LIB_FW_DIR) < 0 && umount2(LIB_FW_DIR, MNT_FORCE) < 0)
	{
		dbg("%s: Umount %s w/ MNT_FORCE flag fail!!! errno %d (%s) \n",
			__func__, LIB_FW_DIR, errno, strerror(errno));
		return;
	}
#else
	umount(LIB_FW_DIR);
	umount2(LIB_FW_DIR, MNT_FORCE);
#endif

	if (d_exists(TEMP_FW_DIR))
		eval("rm", "-fr", TEMP_FW_DIR);

	/* Copy /lib/firmware to /tmp/firmware, and
	 * bind mount /tmp/firmware to /lib/firmware.
	 */
	dbg("Rebuild %s\n", LIB_FW_DIR);
	eval("cp", "-a", LIB_FW_DIR, TEMP_FW_DIR);
	if (mount(TEMP_FW_DIR, LIB_FW_DIR, NULL, MS_BIND, NULL) != 0) {
		dbg("%s: bind mount %s fail! errno %d (%s)\n",
			__func__, TEMP_FW_DIR, strerror(errno));
	}

	eval("killall", "rstats", "udhcpc", "wanduck", "networkmap");
#ifdef RTCONFIG_WLCEVENTD
	eval("killall", "wlceventd");
#endif
	fini_wl();

	if (!module_loaded("usb_f_diag"))
		modprobe("usb_f_diag");
	if (!module_loaded("diagchar"))
		modprobe("diagchar");

#if defined(RTCONFIG_SPF11_QSDK) || defined(RTCONFIG_SPF11_1_QSDK) \
 || defined(RTCONFIG_SPF11_3_QSDK) || defined(RTCONFIG_SPF11_4_QSDK)
	/* Remove WLFW_CAL_01_BIN, do_cold_boot_calibration() will trigger cold calibration w/ testmode=10.
	 * If cnssdaemon is not terminated, the cold boot calibration is blocked and timeout,
	 * eventually, causes kernel oops.
	 */
	if (f_exists(WLFW_CAL_01_BIN)) {
		unlink(WLFW_CAL_01_BIN);
		killall_tk("cnssdaemon");
	}
#elif defined(RTCONFIG_SPF11_3_QSDK) || defined(RTCONFIG_SPF11_4_QSDK)
	system("rm -f /tmp/wifi/*");
	killall_tk("cnssdaemon");
#endif

	load_testmode_wifi_driver();

	sleep(3);
	_eval(ping_argv, ">/dev/console", 0, NULL);
	strlcpy(log_name, ">/tmp/diag_socket_app.log", sizeof(log_name));
	_eval(diag_argv, log_name, 0, &pid0);
	strlcpy(log_name, ">/tmp/ftm.log", sizeof(log_name));
	_eval(ftm_argv, log_name, 0, &pid1);
}
#endif

/**
 * This function hexdump gziped boarddata of 2G/5G.
 * @command:	The @command should be prefix by "Get_BData_" and suffix by "2G"/"5G"
 */
void Get_BData_X(const char *command)
{
#if defined(BD_2G_PREFIX) || defined(BD_5G_PREFIX)
	int band = -1, len = 0;
	size_t size = 0;
#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
    defined(RTCONFIG_WIFI_QCA9994_QCA9994)
	FILE *fp = NULL;
#endif
	char path[PATH_MAX], path2[PATH_MAX];
	struct stat s;
	const uint8_t *buf = NULL;
	uint8_t line[1024];
	uint8_t bdata_buf[QCA_5G_EEPROM_SIZE];
	const char *chip_dir, *hw_dir;

	if (!command)
		return;

	/* Because I don't want to provide an interface to dump our boarddata in normal case.
	 * The ATE Get_BData_2G/ATE Get_BData_5G commands are protected by same mechanism as
	 * ATE set commands.  If possible, I'd like to encrypt gzipped boarddata too.
	 */
	if (!IS_ATE_FACTORY_MODE())
                return;

	/* Skip leading Get_BData_ */
#if defined(BD_2G_PREFIX)
	if (!strcmp(command + 10, "2G")) {
		band = 0;
		chip_dir = BD_2G_CHIP_DIR;
		hw_dir = BD_2G_HW_DIR;
	}
	else
#endif
#if defined(BD_5G_PREFIX)
	if (!strcmp(command + 10, "5G")) {
		band = 1;
		chip_dir = BD_5G_CHIP_DIR;
		hw_dir = BD_5G_HW_DIR;
	}
	else
#endif
#if defined(BD_5G2_PREFIX)
	if (!strcmp(command + 10, "5G2")) {
		band = 2;
		chip_dir = BD_5G2_CHIP_DIR;
		hw_dir = BD_5G2_HW_DIR;
	}
	else
#endif

	if (band < 0 || band >= 3) {
		puts("ATE_UNSUPPORT");
		return;
	}

#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_SOC_IPQ60XX)
	if (get_soc_version_major() == 2)
		chip_dir = "IPQ8074A";
#endif

#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
    defined(RTCONFIG_WIFI_QCA9994_QCA9994)
	/* boarddata for this regulation is not hook by req_fw_hook().
	 * Find it in /lib/firmware/QCA9984/hw.1/ via trying
	 * content of .filenames in same directory instead.
	 */
	snprintf(path, sizeof(path), "%s/%s/%s/.filenames", LIB_FW_DIR, chip_dir, hw_dir);
	fp = fopen(path, "r");
	if (fp == NULL)
		return;

	while ((fscanf(fp, "%[^\n]", line)) != EOF) {
		fgetc(fp);

		if (band == 0) {
			if (!strstr(line, "_2g") && !strstr(line, "_2G"))
				continue;
		}
		else if (band == 1) {
			if (!strstr(line, "_5g") && !strstr(line, "_5G"))
				continue;
		}
		else
			continue;
#elif defined(RTCONFIG_PCIE_QCA9888) || \
      defined(RTCONFIG_SOC_IPQ40XX) || \
      defined(RTCONFIG_WIFI_QCN5024_QCN5054) || \
      defined(RTCONFIG_QCA_AXCHIP)
	/* IPQ40XX/QCN50X4 not have .filenames file */
#if defined(BD_2G_PREFIX)
	if (band == 0) /* 2G */
		snprintf(line, sizeof(line), BD_2G_PREFIX".bin");
	else
#endif
#if defined(BD_5G_PREFIX)
	if (band == 1) /* 5G */
		snprintf(line, sizeof(line), BD_5G_PREFIX".bin");
	else
#endif
#if defined(BD_5G2_PREFIX)
	if (band == 2) /* 5G2 */
		snprintf(line, sizeof(line), BD_5G2_PREFIX".bin");
	else
#endif
	;
	while (1) {
#endif

		/* Get boarddata via same hook, req_fw_hook(), in hotplug_firmware() first. */
		buf = req_fw_hook(line, &size);
		if (buf && size == sizeof(bdata_buf)) {
			len = size;
			break;
		}

		/* If boarddata file of a regulation is not hook by req_fw_hook(),
		 * read it from /lib/firmware/QCA9984/hw.1 directory instead.
		 */
		snprintf(path, sizeof(path), "%s/%s/%s/%s", LIB_FW_DIR, chip_dir, hw_dir, line);
		len = f_read(path, bdata_buf, sizeof(bdata_buf));
		if (len != sizeof(bdata_buf))
			continue;

		buf = bdata_buf;
		break;
	}
#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || \
    defined(RTCONFIG_WIFI_QCA9994_QCA9994)
	fclose(fp);
#endif

	/* Write boarddata to /tmp/.tmp and gzip it as /tmp/.tmp.gz */
	snprintf(path, sizeof(path), "/%s/.%s", "tmp", "tmp");
	snprintf(path2, sizeof(path2), "/%s/.%s.%s", "tmp", "tmp", "gz");
	if (f_exists(path))
		unlink(path);
	if (f_exists(path2))
		unlink(path2);
	f_write(path, buf, len, 0, 0400);
	if (stat(path, &s) || s.st_size != len)
		return;

	eval("gzip", path);
	if (!f_exists(path2))
		return;

	if (stat(path2, &s))
		return;
	len = f_read(path2, bdata_buf, sizeof(bdata_buf));
	if (len != s.st_size)
		return;

	printf("len:%d\n", len);
	hexdump(bdata_buf, len);
	unlink(path2);
#endif /* defined(BD_2G_PREFIX) || defined(BD_5G_PREFIX) */
}
#endif	/* RTCONFIG_WIFI_QCA9990_QCA9990 || RTCONFIG_WIFI_QCA9994_QCA9994 || RTCONFIG_WIFI_QCN5024_QCN5054 || RTCONFIG_QCA_AXCHIP ||RTCONFIG_PCIE_AR9888 || RTCONFIG_PCIE_QCA9888 || RTCONFIG_SOC_IPQ40XX */
//End of new ATE Command

#if defined(RTCONFIG_SOC_IPQ8074)
void Get_VoltUp(void)
{
	uint64_t val = 0;

	if (!__Get_U64(OFFSET_VOLTUP, &val))
		printf("%"PRIu64"\n", val);
}

void Set_VoltUp(const char *value)
{
	uint64_t val = UINT64_MAX;

	if (!IS_ATE_FACTORY_MODE() || !value || strcmp(value, "FFFFFFFF"))
		return;

	__Set_U64(OFFSET_VOLTUP, val);
}

void Get_L2Ceiling(void)
{
	uint32_t val = 0;

	if (!__Get_U32(OFFSET_L2CEILING, &val))
		printf("%"PRIu32"\n", val);
}

void Set_L2Ceiling(const char *value)
{
	uint32_t val = UINT32_MAX;

	if (!IS_ATE_FACTORY_MODE() || !value || strcmp(value, "FFFFFFFF"))
		return;

	__Set_U32(OFFSET_L2CEILING, val);
}

void Get_PwrCycleCnt(void)
{
	uint32_t val = 0;

	if (!__Get_U32(OFFSET_PWRCYCLECNT, &val))
		printf("%"PRIu32"\n", val);
}

void Set_PwrCycleCnt(const char *value)
{
	uint32_t val = UINT32_MAX;

	if (!IS_ATE_FACTORY_MODE() || !value || strcmp(value, "FFFFFFFF"))
		return;

	__Set_U32(OFFSET_PWRCYCLECNT, val);
}

void Get_AvgUptime(void)
{
	uint32_t val = 0;

	if (!__Get_U32(OFFSET_AVGUPTIME, &val))
		printf("%"PRIu32"\n", val);
}

void Set_AvgUptime(const char *value)
{
	uint32_t val = UINT32_MAX;

	if (!IS_ATE_FACTORY_MODE() || !value || strcmp(value, "FFFFFFFF"))
		return;

	__Set_U32(OFFSET_AVGUPTIME, val);
}
#endif

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
	else if (memcmp
		 (&dev_flags.magic, DEV_FLAGS_MAGIC,
		  sizeof(dev_flags.magic)) != 0)
		dbg("READ DEV Flags: no contents !\n");
	else {
		int l, len;
		char buf[128];
		char *p = buf;

		len = sizeof(buf);
		if (dev_flags.u.has_thermal_pad) {
			l = snprintf(p, len, " Has Thermal Pad.");
			len -= l;
			p += l;
		}
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

	/* [A-Z][0-9A-Z]/[0-9][0-9] */
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

int checkPSK(const char *psk)
{
#warning FIXME
}

int
getPSK(void)
{
	char buffer[15];
	memset(buffer,0,sizeof(buffer));
	FRead(buffer, OFFSET_PSK, 14);
	puts(buffer);
	return 0;
}

int
setPSK(const char *psk)
{
	int i;
	char buffer[15];
	if(strcmp(psk,"NONE"))
	{
		if (psk == NULL || strlen(psk) < 8 ||strlen(psk) > 32)
			return -1;

       		 for (i = 0; i < strlen(psk) ; i++) {
			if (psk[i] == '0' || psk[i] == '1' || psk[i] == '8')
				return -1;
			else if (psk[i] != '_' && !isalnum(psk[i]))
				return -1;
        	}
	}
	if (!IS_ATE_FACTORY_MODE())
                return -1;

	memset(buffer,0,sizeof(buffer));
	memcpy(buffer,psk,14);
	FWrite(buffer, OFFSET_PSK, 15);
	return 0;
}
#endif

void set_factory_mode(void)
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

#define EEPROM_2G_CTL_OFFSET    0x136
#define EEPROM_2G_CTL_SIZE      108
#define EEPROM_5G_CTL_OFFSET    0x610
#define EEPROM_5G_CTL_SIZE      308
int _dump_powertable()
{
#if defined(RTCONFIG_WIFI_QCA9557_QCA9882) || defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X) || defined(RTCONFIG_QCN550X) || defined(RTCONFIG_RALINK_EDCCA)
	unsigned char buf[QC98XX_EEPROM_SIZE_LARGEST];
	int count = 0;
	if (FRead(buf, OFFSET_MAC_ADDR_2G - QCA9557_EEPROM_MAC_OFFSET + EEPROM_2G_CTL_OFFSET, EEPROM_2G_CTL_SIZE) < 0) {
		printf("Dump 2.4g power table failed\n");
	}
	else {
		printf("2.4g power table:\n");

		while (count < EEPROM_2G_CTL_SIZE) {
			printf("0x%02x\t", buf[count]);
			count++;
			if (count % 10 == 0 || count == EEPROM_2G_CTL_SIZE)
				printf("\n");
		}
	}
	count = 0;
	if (FRead(buf, OFFSET_MAC_ADDR - QC98XX_EEPROM_MAC_OFFSET, QC98XX_EEPROM_SIZE_LARGEST) < 0) {
		printf("Dump 5g power table failed\n");
	}
	else {
		printf("5g power table:\n");
		while (count < EEPROM_5G_CTL_SIZE) {
			printf("0x%02x\t", buf[EEPROM_5G_CTL_OFFSET + count]);
			count++;
			if (count % 10 == 0 || count == EEPROM_5G_CTL_SIZE)
				printf("\n");
		}
	}
#endif
	return 0;
}

#if defined(RTCONFIG_WIFI_DRV_DISABLE) /* for IPQ40XX */
int setDisableWifiDrv(const char *str)
{
	unsigned char buf[1];
	if (!IS_ATE_FACTORY_MODE())
                return EINVAL;

	if (str == NULL)
		return EINVAL;

	if ((str[0] == 'Y') || (str[0] == 'y'))
		buf[0] = 'Y';
	else if ((str[0] == 'N') || (str[0] == 'n'))
		buf[0] = 0xFF;
	else
		return EINVAL;

	FWrite(buf, OFFSET_DISABLE_WIFI_DRV, 1);
	return getDisableWifiDrv();
}

int getDisableWifiDrv(void)
{
	unsigned char buf[1];

	if (FRead(buf, OFFSET_DISABLE_WIFI_DRV, 1) < 0) {
		dbg("READ: Out of scope\n");
		return EINVAL;
	}
	else {
		if (buf[0] == 'Y')
			puts("Y");
		else
			puts("N");
	}
	return 0;
}
#endif /* Lyra */

void set_IpAddr_Lan(const char *value){
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

#ifdef RTCONFIG_AMAS
int get_amas_bdl(void)
{
	unsigned char value;
	char buf[6];

	FRead(&value, OFFSET_AMAS_BUNDLE_FLAG, 1);
	if (value == 0xff)
		value = 0; // empty
	snprintf(buf, sizeof(buf)-1, "%u", value);
	puts(buf);

	return 1;
}

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
		puts("1");

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
			return 0;
		}
	}
	return 1;
}

int set_amas_bdlkey(const char *str) /*parameter checking is handled by caller*/
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
	return 1;
}
#endif

int checkPASS(const char *jppwd)
{
#warning FIXME
}

int getPASS(void)
{
#warning FIXME
}

int set_HwId(const char *HwId)
{
	unsigned char buf[HWID_LENGTH + 1] = { 0 };

	if (!IS_ATE_FACTORY_MODE() || !HwId)
                return -1;

	strlcpy(buf, HwId, sizeof(buf));
	if (FWrite(buf, OFFSET_HWID, HWID_LENGTH))
		return -1;

	nvram_set("HwId", HwId);
	puts(nvram_safe_get("HwId"));

	return 0;
}

int set_HwVersion(const char *HwVer)
{
	unsigned char buf[HWVERSION_LENGTH + 1] = { 0 };

	if (!IS_ATE_FACTORY_MODE() || !HwVer)
                return -1;

	strlcpy(buf, HwVer, sizeof(buf));
	if (FWrite(buf, OFFSET_HWVERSION, HWVERSION_LENGTH))
		return -1;

	nvram_set("HwVer", HwVer);
	puts(nvram_safe_get("HwVer"));

	return 0;
}

int set_HwBom(const char *HwBom)
{
	unsigned char buf[HWBOM_LENGTH + 1] = { 0 };

	if (!IS_ATE_FACTORY_MODE() || !HwBom)
                return -1;

	strlcpy(buf, HwBom, sizeof(buf));
	if (FWrite(buf, OFFSET_HWBOM, HWBOM_LENGTH))
		return -1;

	nvram_set("HwBom", HwBom);
	puts(nvram_safe_get("HwBom"));

	return 0;
}

int set_DateCode(const char *DateCode)
{
	int i, year, month, day;
	char buf[DATECODE_LENGTH + 1];

	if (!IS_ATE_FACTORY_MODE() || !DateCode || strlen(DateCode) != 8)
                return -1;

	/* YYYYMMDD */
	for (i = 0; i < 8; ++i) {
		if (!isdigit(DateCode[i]))
			return -1;
	}

	strlcpy(buf, DateCode, 4 + 1);
	year = safe_atoi(buf);
	strlcpy(buf, DateCode + 4, 2 + 1);
	month = safe_atoi(buf);
	strlcpy(buf, DateCode + 6, 2 + 1);
	day = safe_atoi(buf);

	if (year < 2018 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31)
		return -1;

	strlcpy(buf, DateCode, sizeof(buf));
	if (FWrite(buf, OFFSET_DATECODE, DATECODE_LENGTH))
		return -1;

	nvram_set("DCode", DateCode);
	puts(nvram_safe_get("DCode"));

	return 0;
}

int get_HwId(void)
{
	char *p, hwid[HWID_LENGTH + 1] = { 0 };

	if (FRead((unsigned char*) hwid, OFFSET_HWID, HWID_LENGTH))
		return -1;
	if ((p = strchr(hwid, 0xff)) != NULL)
		*p = '\0';
	puts(hwid);
	return 0;
}

int get_HwVersion(void)
{
	char *p, hwver[HWVERSION_LENGTH + 1] = { 0 };

	if (FRead((unsigned char*) hwver, OFFSET_HWVERSION, HWVERSION_LENGTH))
		return -1;
	if ((p = strchr(hwver, 0xff)) != NULL)
		*p = '\0';
	puts(hwver);
	return 0;
}

int get_HwBom(void)
{
	char *p, hwbom[HWBOM_LENGTH + 1] = { 0 };

	if (FRead((unsigned char*) hwbom, OFFSET_HWBOM, HWBOM_LENGTH))
		return -1;
	if ((p = strchr(hwbom, 0xff)) != NULL)
		*p = '\0';
	puts(hwbom);
	return 0;
}

int get_DateCode(void)
{
	char *p, datecode[DATECODE_LENGTH + 1] = { 0 };

	if (FRead((unsigned char*) datecode, OFFSET_DATECODE, DATECODE_LENGTH))
		return -1;
	if ((p = strchr(datecode, 0xff)) != NULL)
		*p = '\0';
	puts(datecode);
	return 0;
}

#ifdef RTCONFIG_FANCTRL
static int set_tz_gov(const char *basedir, const struct dirent *de, size_t de_size, void *arg)
{
	const char *gov = arg;
	char val[sizeof("tsens_tz_sensorXXXXXX")];
	char path[sizeof("/sys/class/thermal/thermal_zoneXXX/policyXXXXXX")];

	if (sizeof(*de) != de_size) {
		/* If size of struct dirent mismatch, make sure readdir_wrapper() and this function see same struct dirent.h.
		 * e.g., it's different in uclibc if _FILE_OFFSET_BITS=64 is defined or not.
		 */
		dbg("%s: size of struct dirent mismatch (%u v.s. %u)!\n", __func__, sizeof(*de), de_size);
		return -1;
	}
	/* If a thermal zone is not tsens_tz_sensor, skip it. */
	snprintf(path, sizeof(path), "%s/%s/type", basedir, de->d_name);
	if (f_read_string(path, val, sizeof(val)) <= 0)
		return -1;
	if (strncmp(val, "tsens_tz_sensor", 15))
		return 0;

	/* If a thermal zone is not associated with cooling device, skip it. */
	snprintf(path, sizeof(path), "%s/%s/cdev0", basedir, de->d_name);
	if (!d_exists(path))
		return 0;

	snprintf(path, sizeof(path), "%s/%s/policy", basedir, de->d_name);
	if (f_write_string(path, gov, 0, 0) <= 0)
		return -1;

	return 0;
}

static int set_gpio_fan_state(const char *basedir, const struct dirent *de, size_t de_size, void *arg)
{
	int v, onoff = *(int*)arg;
	char val[16], path[sizeof("/sys/class/thermal/cooling_deviceXXX/max_stateXXXXXX")];

	if (sizeof(*de) != de_size) {
		/* If size of struct dirent mismatch, make sure readdir_wrapper() and this function see same struct dirent.h.
		 * e.g., it's different in uclibc if _FILE_OFFSET_BITS=64 is defined or not.
		 */
		dbg("%s: size of struct dirent mismatch (%u v.s. %u)!\n", __func__, sizeof(*de), de_size);
		return -1;
	}
	/* If a cooling device is not gpio-fan, skip it. */
	snprintf(path, sizeof(path), "%s/%s/type", basedir, de->d_name);
	if (f_read_string(path, val, sizeof(val)) <= 0)
		return -1;
	if (strncmp(val, "gpio-fan", 8))
		return 0;

	if (onoff <= 0) {
		strlcpy(val, "0", sizeof(val));
	} else {
		/* Find maximum state this gpio-fan supported. */
		snprintf(path, sizeof(path), "%s/%s/max_state", basedir, de->d_name);
		if (f_read_string(path, val, sizeof(val)) <= 0)
			return -2;
		v = safe_atoi(val);

		if (onoff == 100 || onoff > v)
			onoff = v;
		snprintf(val, sizeof(val), "%d", onoff);
	}
	snprintf(path, sizeof(path), "%s/%s/cur_state", basedir, de->d_name);
	if (f_write_string(path, val, 0, 0) <= 0)
		return -1;

	return 0;
}

/* Set policy and state of gpio-fan
 * @onoff:
 * 	0:	turn off FAN, policy=user_space.
 *    > 0:	FAN state = min(@onoff, max_state), policy=user_space.
 *    < 0:	state 1, policy=step_wise, step_wise decides new state.
 * @return:
 * 	0:	success
 *  otherwise:	fail
 */
int __setFanOnOff(const int onoff)
{
	int v = onoff;
	char *policy = "user_space";


	if (onoff < 0) {
		v = 1;
		policy = "step_wise";
	}

	/* Set governor of all thermal zone that associated with cooling device as user_space or step_wise. */
	if (readdir_wrapper(SYS_CLASS_THERMAL, "thermal_zone", set_tz_gov, policy) < 0)
		return -1;

	if (onoff >= 0) {
		/* Set cur_state to all cooling device if it's gpio-fan. */
		if (readdir_wrapper(SYS_CLASS_THERMAL, "cooling_device", set_gpio_fan_state, &v) < 0)
			return -2;
	}

	return 0;
}

void setFanOnOff(const int onoff)
{
	if (__setFanOnOff(onoff)) {
		puts("ATE_ERROR");
	} else {
		puts("1");
	}
}

int setFanOn(void)
{
	setFanOnOff(100);	/* Maximum FAN state */
	return 0;
}

int setFanOff(void)
{
	setFanOnOff(0);
	return 0;
}

int getFanSpeed(void)
{
	int val;
	char val_str[8];

	if (f_read_string(FAN_RPM, val_str, sizeof(val_str)) <= 0) {
		puts("ATE_ERROR");
		return 0;
	}
	val = safe_atoi(val_str);
	printf("%d\n", val);
	return 0;
}
#endif

/* Read thermal_zoneX temperature.
 * @t:
 * @arg:	if specified, thermal_zone index.
 * @return:
 * 	0:	success
 *     -1:	invalid parameter
 *  otherwise:	error
 */
int cpu_temperature(int *t, long arg)
{
	unsigned int tz = 0;
	char temperature[6] = { 0 };
	char path[sizeof("/sys/class/thermal/thermal_zone0/tempXXXXXX")];

	if (!t)
		return -1;
	if (arg)
		tz = *(unsigned int*) arg;

	snprintf(path, sizeof(path), SYS_CLASS_THERMAL "/thermal_zone%u/temp", tz);
	if (f_read_string(path, temperature, sizeof(temperature)) <= 0)
		return -2;

	*t = safe_atoi(temperature);
	return 0;
}

/* Read WiFi temperature via thermaltool.
 * @t:
 * @arg:	enum wl_band_id
 * @return:
 * 	0:	success
 *     -1:	invalid parameter
 *  otherwise:	error
 */
static int wifi_temperature(int *t, long arg)
{
	enum wl_band_id band = (enum wl_band_id) arg;

	if (!t || band < 0 || band >= MAX_NR_WL_IF)
		return -1;

	*t = get_wifi_temperature(band);
	return (*t > 0 && *t < 200)? 0 : -2;
}

#if defined(RTCONFIG_SWITCH_QCA8075_QCA8337_PHY_AQR107_AR8035_QCA8033)
/* Read AQR107/113 temperature.
 * @t:
 * @arg:	PHY address
 * @return:
 * 	0:	success
 *     -1:	invalid parameter
 *  otherwise:	error
 */
int aqr_temperature(int *t, long arg)
{
	int r, phy = aqr_phy_addr();
	int16_t v;

	if (!t || arg < 0 || arg >= 32)
		return -1;

	phy = arg;
	if (!is_aqr_phy_exist()) {
		*t = 30;
		return 0;
	}

	if ((r = read_phy_reg(phy, 0x401EC820)) < 0)
		return -3;

	/* 2's complement, unit: 1/256 .C */
	v = r & 0xFFFF;
	*t = v >> 8;
	return 0;
}
#endif

/* Check CPU/2G/5G/(10G)PHY temperature during run-in period.
 * 1. Print CPU/2G/5G/(10G)PHY temperature.
 * 2. Save maximum CPU/2G/5G/5G2/(10G)PHY temperature to Ate_temp_XXX_max.
 * 3. Save uptime to Ate_temp_XXX_over_sec if it exceed Ate_temp_XXX_limit.
 */
void ate_temperature_record(void)
{
        int limit, temp, need_commit = 0;
	time_t timestamp;
	char tmp[32];
	const struct temp_chk_items_s {
		char *name;
		char *nv_max;		/* e.g. Ate_temp_cpu_max */
		char *nv_limit;		/* e.g. Ate_temp_cpu_limit */
		char *nv_over_sec;	/* e.g. Ate_temp_cpu_over_sec */
		int (*read_func)(int *t, long arg);
		long arg;
	} temp_chk_items[] = {
		{	/* CPU */
			.name = "cpu_temp",
			.nv_max = "Ate_temp_cpu_max", .nv_limit = "Ate_temp_cpu_limit", .nv_over_sec = "Ate_temp_cpu_over_sec",
			.read_func = cpu_temperature, .arg = 0,
		},
		{	/* 2G */
			.name = "2G_temp",
			.nv_max = "Ate_temp_2G_max", .nv_limit = "Ate_temp_2G_limit", .nv_over_sec = "Ate_temp_2G_over_sec",
			.read_func = wifi_temperature, .arg = WL_2G_BAND,
		},
#if defined(RTCONFIG_HAS_5G)
		{	/* 5G */
			.name = "5G_temp",
			.nv_max = "Ate_temp_5G_max", .nv_limit = "Ate_temp_5G_limit", .nv_over_sec = "Ate_temp_5G_over_sec",
			.read_func = wifi_temperature, .arg = WL_5G_BAND,
		},
#if defined(RTCONFIG_HAS_5G_2)
		{	/* 5G2 */
			.name = "5G2_temp",
			.nv_max = "Ate_temp_5G2_max", .nv_limit = "Ate_temp_5G2_limit", .nv_over_sec = "Ate_temp_5G2_over_sec",
			.read_func = wifi_temperature, .arg = WL_5G_2_BAND,
		},
#endif
#endif
#if defined(RTCONFIG_SWITCH_QCA8075_QCA8337_PHY_AQR107_AR8035_QCA8033)
		{	/* AQR107/AQR113 PHY */
			.name = "phy_temp",
			.nv_max = "Ate_temp_phy_max", .nv_limit = "Ate_temp_phy_limit", .nv_over_sec = "Ate_temp_phy_over_sec",
			.read_func = aqr_temperature, .arg = aqr_phy_addr(),
		},
#endif

		{ .nv_max = NULL, .nv_limit = NULL, .nv_over_sec = NULL, .read_func = NULL, .arg = 0 }
	}, *p;

	if (!IS_ATE_FACTORY_MODE() || !f_exists("/tmp/Ate_temp_rec_start"))
		return;

	timestamp = uptime();
	for (p = &temp_chk_items[0]; p->read_func != NULL; ++p) {
		limit = safe_atoi(nvram_safe_get(p->nv_limit));
		if (p->read_func(&temp, p->arg)) {
			dbg("%s: can't read %s\n", __func__, p->name);
			continue;
		}

		dbg("%s = %d\n", p->name, temp);
		if (temp <= nvram_get_int(p->nv_max))
			continue;

		nvram_set_int(p->nv_max, temp);
		need_commit++;

		if (strlen(nvram_safe_get(p->nv_over_sec)) || temp <= limit)
			continue;

		snprintf(tmp, sizeof(tmp), "%ld", timestamp);
		nvram_set(p->nv_over_sec, tmp);
	}

	if (need_commit)
		nvram_commit();
}

#if defined(RTCONFIG_CSR8811)
int setMAC_BT(const char *mac)
{
	char ea[ETHER_ADDR_LEN];
	char buff[6];
	int offset = OFFSET_CSR8811_MAC;
	if (mac==NULL || !isValidMacAddr(mac))
	{
		dbg("Invalid MAC address!\n");
		return 0;
	}

	if (!IS_ATE_FACTORY_MODE())
	{
		dbg("Not in fatory mode.\n");
		return 0;
	}

	if (ether_atoe(mac, ea))
	{
		FWrite(ea,offset,6);
		getMAC_BT(buff, sizeof(buff));
	}

	return 1;
}

int getMAC_BT(unsigned char *mac, const size_t len)
{
	unsigned char buffer[6];
	char macaddr[18];
	int offset = OFFSET_CSR8811_MAC;
	memset(buffer, 0, sizeof(buffer));
	memset(macaddr, 0, sizeof(macaddr));

	FRead(buffer,offset,6);

	memcpy(mac, buffer, len >= 6? 6: len);

	ether_etoa(buffer, macaddr);
	puts(macaddr);

	return 1;
}

int setCal_BT(const char *cal)
{
	int i;
	unsigned char caldata = 0, tmp = 0;

	if(!cal || !IS_ATE_FACTORY_MODE() || strlen(cal) != 2)
	{
		return 0;
	}

	for(i = 0; i < 2; ++i)
	{
		if(!isxdigit(cal[i]))
		{
			dbg("Not hexadecimal digit!!\n");
			return 0;
		}
		if(cal[i] >= '0' && cal[i] <= '9')
			tmp = cal[i] - '0';
		else if(cal[i] >= 'a' && cal[i] <= 'f')
			tmp = cal[i] - 'a' + 10;
		else if(cal[i] >= 'A' && cal[i] <= 'F')
			tmp = cal[i] - 'A' + 10;

		caldata += i? tmp: (tmp * 16);
	}

	FWrite(&caldata, OFFSET_CSR8811_CAL, 1);
	getCal_BT(&caldata);

	return 1;
}

int getCal_BT(unsigned char *cal)
{
	char buffer[4];
	if(!cal)
		return 0;

	memset(cal, 0, sizeof(char));
	FRead(cal, OFFSET_CSR8811_CAL, 1);
	snprintf(buffer, sizeof(buffer), "%x", *cal);
	puts(buffer);

	return 1;
}

#if defined(RTCONFIG_SOC_IPQ40XX)
#define BTDEV "/dev/ttyQHS0"
#elif defined(RTCONFIG_SOC_IPQ60XX)
#define BTDEV "/dev/ttyMSM1"
#else
#error "Defined the bt device!!"
#endif
void setStartBTDiag()
{
	uint32_t bt_reset;

#if defined(MAPAC2200V)
	bt_reset = 48;
#elif defined(PLAX56_XP4)
        bt_reset = 79;
#else
	#error NEED bt_reset defined
#endif

	if (pids("bluetoothd")) {
		killall_tk("bluetoothd");
	}

	if (pids("hciattach")) {
		killall_tk("hciattach");
	}

	set_gpio(bt_reset, 0);
	sleep(1);
	set_gpio(bt_reset, 1);
	sleep(1);

#if !defined(PLAX56_XP4)
	doSystem("Btdiag UDT=yes PORT=2390 IOType=SERIAL BTDEVICE=%s BT-BAUDRATE=115200 QDARTIOType=ethernet &", BTDEV);
	sleep(5);
#endif
}
#endif /*RTCONFIG_CSR8811*/

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
		memset(buf, 0xff, sizeof(buf));
		FWrite(buf, OFFSET_ASUSCTRL_FLAGS, ASUSCTRL_FLAGS_LENGTH);
		nvram_set("asusctrl_flags", "0");

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
		nvram_set("asusctrl_chg_sku", "");

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
	/*case MODEL_RTAC95U:*/
	default:
		asus_ctrl_get();
		break;
	}
}

struct tcode_to_regdomain_s {
	char *tcode;
	char *regdom;
};

/* If regulation domain is not same as first two character of TCode, define it here. */
static const struct tcode_to_regdomain_s tcode_to_regdomain_tbl[] = {
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054)
	{ "EU", "GB" },
	{ "AA", "US" },
	{ "S2", "US" },
	{ "TW", "US" },
	{ "IL", "GB" },
#endif

	{ NULL, NULL}
};

/**
 * Description:
 * If chg_sku is enabled and we can figure out regulation domain via it,
 * set wl*_country_code as new regulation domain and set territory_code
 * as chg_sku.
 * @return: 
 * 	None.
 */
void asus_ctrl_sku_check()
{
	int band;
	char tcode[6] = {0}, chg_sku[6] = {0};
	char new_regdom[3] = { 0 }, test_regdom[6] = { 0 };
	const struct tcode_to_regdomain_s *p;

	asus_ctrl_get();
	if (!asus_ctrl_en(ASUSCTRL_CHG_SKU))
		return;

	asus_ctrl_sku_get();
	strlcpy(chg_sku, nvram_safe_get("asusctrl_chg_sku"), sizeof(chg_sku));
	strlcpy(tcode, nvram_safe_get("territory_code"), sizeof(tcode));

	if (strlen(chg_sku) != 2) {
		/* If chg_sku is empty or other value, provide the tcode value for it. */
		strlcpy(chg_sku, tcode, ASUSCTRL_CHG_SKU_LENGTH + 1);
	}

	/* Fix-up country_code at run-time, based on modified chg_sku. */
	for (p = &tcode_to_regdomain_tbl[0]; p->tcode && p->regdom; ++p ) {
		if (strncmp(chg_sku, p->tcode, strlen(p->tcode)))
			continue;

		strlcpy(new_regdom, p->regdom, sizeof(new_regdom));
		break;
	}
	/* If not found, assume new regulation domain same as first two character of tcode. */
	if (*new_regdom == '\0')
		strlcpy(new_regdom, chg_sku, sizeof(new_regdom));
	dbg("new_regdom [%s] location_code [%s]\n", new_regdom, nvram_get("location_code")? : "NULL");
	/* Set new_regdom as new country_code if it exist in country_to_code_tbl[]. */
	if (!country_to_code(new_regdom, 2, test_regdom, sizeof(test_regdom))
	 && *test_regdom != '\0')
	{
		/* Fix-up territory_code at run-time, based on chg_sku. */
		if (strncmp(tcode, chg_sku, 2) != 0) {
			memcpy(tcode, chg_sku, 2);
			nvram_set("territory_code", tcode);
		}

		nvram_set("wl_country_code", new_regdom);
		for (band = WL_2G_BAND; band < MAX_NR_WL_IF; ++band) {
			char prefix[sizeof("wlXXX_")];
			if (__absent_band(band))
				continue;

			snprintf(prefix, sizeof(prefix), "wl%d_", band);
			nvram_pf_set(prefix, "country_code", new_regdom);
		}
		dbg("chg_sku [%s]: new ccode [%s] asusctrl_flags [%s] asusctrl_chg_sku [%s]\n",
			chg_sku, new_regdom, nvram_get("asusctrl_flags")? : "NULL",
			nvram_get("asusctrl_chg_sku")? : "NULL");
	}

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
