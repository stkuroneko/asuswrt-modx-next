
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bcmnvram.h>
#include <bcmdevs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <wlutils.h>
#include <linux_gpio.h>
#include <etioctl.h>
#include "utils.h"
#include "shutils.h"
#include "shared.h"
#include <trxhdr.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <trxhdr.h>
#include "version.h"
#ifdef HND_ROUTER
#include <linux/mii.h>
//#include "bcmnet.h"
//#include "bcm/bcmswapitypes.h"
#include "ethctl.h"
#include "ethswctl.h"
#include "ethswctl_api.h"
#include "bcm/bcmswapistat.h"
#include "boardparms.h"
#include <asm/byteorder.h>
#endif

static bool g_swap = FALSE;
#ifndef htod32
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#endif
#ifndef dtoh32
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))
#endif

#ifdef RTAC68U
#define MODEL_STR_RTAC66UV2		"RT-AC66U_B1"
#define MODEL_STR_RTAC66UV2_ODM0	"RT-AC1900U"
#define MODEL_STR_RTAC66UV2_ODM1	"RT-AC1750_B1"
#define MODEL_STR_RTAC66UV2_ODM2	"RT-N66U_C1"
#define MODEL_STR_RTAC66UV2_ODM3	"RP-AC1900"
#define MODEL_STR_RTAC66UV2_ODM4	"RT-AC67U"
#define MODEL_STR_4GAC68U		"4G-AC68U"
int is_ac66u_v2_series();
int is_ac68u_v3_series();
#endif

#ifdef RTCONFIG_BCM5301X_TRAFFIC_MONITOR

#define MIB_P0_PAGE 0x20	/* port 0 */
#define MIB_RX_REG 0x88
#define MIB_TX_REG 0x00

#if defined(RTN18U) || defined(RTAC56U) || defined(RTAC56S) || defined(RTAC68U) || defined(RTAC3200) || defined(DSL_AC68U)
#define CPU_PORT "5"
#endif

#ifdef RTAC5300
#define CPU_PORT "7"
#ifdef RTCONFIG_LACP
#define LACP_PORT1 "1"
#define LACP_PORT2 "2"
#endif	/* RTCONFIG_LACP */
#endif

#if defined(RTAC88U) || defined(RTAC3100)
#ifdef RTCONFIG_EXT_RTL8365MB
#define CPU_PORT "7"
#ifdef RTCONFIG_LACP
#define LACP_PORT1 "3"
#define LACP_PORT2 "2"
#endif	/* RTCONFIG_LACP */
#else
#define CPU_PORT "5"
#ifdef RTCONFIG_LACP
#define LACP_PORT1 "3"
#define LACP_PORT2 "2"
#endif	/* RTCONFIG_LACP */
#endif
#endif

#ifdef RTAC87U
#define CPU_PORT "7"	/* RT-AC87U */
#define LACP_PORT1 "1"	/* LAN4 */
#define LACP_PORT2 "2"	/* LAN3 */
#define RGMII_PORT "5"	/* RT-AC87U */
#endif

#ifdef RTCONFIG_GMAC3
#define CPU_PORT_GMAC3 "8"
#define FWD_PORT0 "5"
#define FWD_PORT1 "7"
#endif

uint32_t robo_ioctl_len(int fd, int write, int page, int reg, uint32_t *value, uint32_t len)
{
	static int __ioctl_args[2] = { SIOCGETCROBORD, SIOCSETCROBOWR };
	struct ifreq ifr;
	int ret, vecarg[4];

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, WAN_IF_ETH);
	ifr.ifr_data = (caddr_t) vecarg;

	vecarg[0] = (page << 16) | reg;
	vecarg[1] = len;

	ret = ioctl(fd, __ioctl_args[write], (caddr_t)&ifr);

	*value = vecarg[2];

	return ret;
}

#ifdef RTCONFIG_LACP
int is_lacp_port(char *port)
{
	if (nvram_get_int("lacp_enabled") == 0) return 0;

	if (strncmp(port, LACP_PORT1, 1) == 0) return 1;

	if (strncmp(port, LACP_PORT2, 1) == 0) return 1;

	return 0;
}

uint32_t traffic_trunk(int port_num, uint32_t *rx, uint32_t *tx)
{
	int fd;
	uint32_t value;
	unsigned int real_port = 0;

	*rx = 0;
	*tx = 0;

	if (port_num == 1) real_port = atoi(LACP_PORT1);
	else if (port_num == 2) real_port = atoi(LACP_PORT2);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return 0;

	/* RX */
	if (robo_ioctl_len(fd, 0 /* robord */, MIB_P0_PAGE + real_port,
		MIB_RX_REG, &value, 8) < 0)
		_dprintf("et ioctl SIOCGETCROBORD failed!\n");
	else{
		*rx = *rx + value;
	}

	/* TX */
	if (robo_ioctl_len(fd, 0 /* robord */, MIB_P0_PAGE + real_port,
		MIB_TX_REG, &value, 8) < 0)
		_dprintf("et ioctl SIOCGETCROBORD failed!\n");
	else{
		*tx = *tx  + value;
	}
	close(fd);
	return 1;
}
#endif

uint32_t traffic_wanlan(char *ifname, uint32_t *rx, uint32_t *tx)
{
	int fd;
	uint32_t value;
	char port_name[30] = {0};
	char port[30], *next;
	char cpu_port[3] = {0};

	*rx = 0;
	*tx = 0;

	strcat_r(ifname, "ports", port_name);
	strcpy(cpu_port, CPU_PORT);
#ifdef RTCONFIG_GMAC3
	if (nvram_get_int("gmac3_enable") == 1) {
		strcpy(cpu_port, CPU_PORT_GMAC3);
	}
#endif

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return 0;

	/* RX */
	foreach (port, nvram_safe_get(port_name), next) {
		if (strncmp(port, cpu_port, 1) != 0
#ifdef RTCONFIG_GMAC3
			&& strncmp(port, FWD_PORT0, 1) != 0
			&& strncmp(port, FWD_PORT1, 1) != 0
#endif
#ifdef RTAC87U
			&& strncmp(port, RGMII_PORT, 1) != 0
#endif
		) {
			if (robo_ioctl_len(fd, 0 /* robord */, MIB_P0_PAGE + atoi(port),
				MIB_RX_REG, &value, 8) < 0)
				_dprintf("et ioctl SIOCGETCROBORD failed!\n");
			else{
				*rx = *rx + value;
			}
		}
	}

	/* TX */
	foreach (port, nvram_safe_get(port_name), next) {
		if (strncmp(port, cpu_port, 1) != 0
#ifdef RTCONFIG_GMAC3
			&& strncmp(port, FWD_PORT0, 1) != 0
			&& strncmp(port, FWD_PORT1, 1) != 0
#endif
#ifdef RTAC87U
			&& strncmp(port, RGMII_PORT, 1) != 0
#endif
		) {
			if (robo_ioctl_len(fd, 0 /* robord */, MIB_P0_PAGE + atoi(port),
				MIB_TX_REG, &value, 8) < 0)
				_dprintf("et ioctl SIOCGETCROBORD failed!\n");
			else{
				*tx = *tx  + value;
			}
		}
	}
	close(fd);
	return 1;
}
#endif	/* RTCONFIG_BCM5301X_TRAFFIC_MONITOR */

/*
 * 0: illegal image
 * 1: legal image
 */

int check_trx(char *fname, uint8_t target)
{
	FILE *fp;
	struct trx_header trx;
	unsigned char rand, key;
	unsigned int offset;
	int ret = 0;

	fp = fopen(fname, "r");
	if (fp == NULL) {
		dbg("Open trx fail!!!\n");
		return 0;
	}

	/* Read header */
	ret = fread((unsigned char *) &trx, 1, sizeof(trx), fp);
	if (ret != sizeof(trx)) {
		dbg("Read header error!!!\n");
		goto end;
	}

	if (trx.len > sizeof(trx) - sizeof(trx.offsets) + 2357 * sizeof(trx.offsets[0]))
		offset = 2357;
	else
		offset = 0;
	if (fseek(fp, (void *)&trx.offsets[offset] - (void *)&trx, SEEK_SET) < 0 ||
	    fread(&rand, 1, 1, fp) < 0)
		goto end;

	if (trx.len > sizeof(trx) - sizeof(trx.offsets) + 2357000 * sizeof(trx.offsets[0]))
		offset = 2357000;
	else if (trx.len > sizeof(trx) - sizeof(trx.offsets) + 2357 * sizeof(trx.offsets[0]))
		offset = (trx.len - (sizeof(trx) - sizeof(trx.offsets)))/sizeof(trx.offsets[0]) - 2357;
	else
		offset = 0;
	if (fseek(fp, (void *)&trx.offsets[offset] - (void *)&trx, SEEK_SET) < 0 ||
	    fread(&key, 1, 1, fp) < 0)
		goto end;

	if (key == 0x0)
		key = 0xfd + rand % 3;
	else
		key = 0xff - key + rand;
	ret = (target == key) ? 1 : 0;

end:
	fclose(fp);
	return ret;
}

extern int check_crc(char *fname);

#define MAX_TAIL_LEN	64
#ifdef HND_ROUTER
#define TOKEN_LEN	20
#define MAX_PID_LEN	20
#define BUF_SIZE	100 * 1024
#else
#define MAX_PID_LEN	12
#define MAX_HW_COUNT	4
#endif

typedef struct {
	uint8_t major;
	uint8_t minor;
} version_t;

#ifdef HND_ROUTER
typedef struct _WFI_TAG
{
	unsigned int wfiCrc;
	unsigned int wfiVersion;
	unsigned int wfiChipId;
	unsigned int wfiFlashType;
	unsigned int wfiFlags;
} WFI_TAG, *PWFI_TAG;

void dumpWfiTag(WFI_TAG *wtP)
{
	dbg("WFI tag:\n");
	dbg("  CRC:        0x%08x\n", wtP->wfiCrc);
	dbg("  Version:    0x%08x\n", wtP->wfiVersion);
	dbg("  Chip ID:    0x%08x\n", wtP->wfiChipId);
	dbg("  Flash Type: 0x%08x\n", wtP->wfiFlashType);
	dbg("  Flags:      0x%08x\n", wtP->wfiFlags);
}

uint32
img_crc_hnd(char *fname)
{
	FILE *fp;
	int count;
	uint32 imageCrc = CRC32_INIT_VALUE;
	unsigned char buffer[BUF_SIZE];

	if ((fp = fopen(fname, "r")) == NULL)
	{
		dbg("failed on open file: %s\n", fname);
		return 0;
	}

	while (!feof(fp))
	{
		count = fread(buffer, sizeof(char), BUF_SIZE, fp);
		if (ferror(fp))
		{
			dbg("Read error");
			fclose(fp);
			return 0;
		}

		if (count < BUF_SIZE)
			imageCrc = hndcrc32(buffer, count - TOKEN_LEN, imageCrc);
		else
			imageCrc = hndcrc32(buffer, count, imageCrc);
	}

	fclose(fp);

	return imageCrc;
}
#endif

#ifdef RTAC68U
int truncate_trx(char *fname)
{
	FILE *fp;
	int fd;
	struct trx_header trx;
	int ret = 0;
	unsigned int size;

	fp = fopen(fname, "r+");
	if (fp == NULL) {
		dbg("Error open trx!!!\n");
		return -1;
	} else
		fd = fileno(fp);

	/* Read header */
	ret = fread((unsigned char *) &trx, 1, sizeof(trx), fp);
	if (ret != sizeof(trx)) {
		ret = -1;
		dbg("Error read header!!!\n");
		goto end;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	dbg("size: %d\n", size);

	if (size > trx.len) {
		fseek(fp, 0, SEEK_SET);
		ret = ftruncate(fd, trx.len);
	} else {
		ret = -1;
		dbg("non-combo firmware\n");
	}

end:
	fclose(fp);
	return ret;
}
#endif

#ifdef RTAC68U_V4
int cut_trx(char *fname)
{
	FILE *pSrcFile = fopen(fname, "r");
	FILE *pDstFile = fopen(fname, "r+");
	int pDstFile_fd = fileno(pDstFile);
	struct trx_header trx;
	char buf[4096] = { 0 };
	long size, write_total_size = 0;
	int count;
	int ret = -1;

	if (!pSrcFile || !pDstFile || pDstFile_fd == -1) {
		dbg("Error open file!!!\n");
		ret = -1;
		goto end;
	}

	ret = fread((unsigned char *) &trx, 1, sizeof(trx), pSrcFile);
	if (ret != sizeof(trx)) {
		ret = -1;
		dbg("Read header error!!!\n");
		goto end;
	}

	fseek(pSrcFile, 0, SEEK_END);
	size = ftell(pSrcFile) - trx.len;
	dbg("size: %d\n", size);
	fseek(pSrcFile, trx.len, SEEK_SET);

	do {
		count = fread(buf, 1, sizeof(buf), pSrcFile);
		fwrite(buf, 1, count, pDstFile);
		write_total_size += count;
		size -= count;
	} while (size > 0);

	/* resize new firmware file */
	fseek(pDstFile, 0, SEEK_SET);
	ret = ftruncate(pDstFile_fd, write_total_size);
	if (ret != 0)
		dbg("Error ftruncate file\n");
end:
	fclose(pSrcFile);
	fclose(pDstFile);
	return ret;
}
#endif

/*
 * 0: legal image
 * 1: illegal image
 * 2: new trx format validation failure
 *
 * check product id, crc ..
 */

int check_imagefile(char *fname)
{
	FILE *fp;
	struct tail_t {
		version_t kernel;		/* Kernel version */
		version_t fs;			/* Filsystem version */
#ifdef HND_ROUTER
		uint16_t  sn;
		uint16_t  en;
		char pid[MAX_PID_LEN];
		uint32_t  en2;
		uint32_t sf;			/* Supported feature */
		uint8_t pad[27];
		uint8_t flag;
#else
		uint8_t pid[MAX_PID_LEN];	/* Product Id */
		uint8_t hw[MAX_HW_COUNT][4];	/* Compatible hw list lo maj.min, hi maj.min */
#ifdef TRX_NEW
		uint16_t sn;
		uint16_t en;
		uint8_t key;
#endif
		uint8_t pad[3];
		uint32_t en2;
		uint32_t sf;			/* Supported feature */
		uint8_t pad2[15];
		uint8_t flag;
#endif
	} tail;
#ifdef HND_ROUTER
	WFI_TAG wt;
#endif
	int i, model = get_model();
#ifdef TRX_NEW
	uint32_t en;
#endif

#ifdef RTAC68U
	if (nvram_match("fw_check", "1"))
		return 0;
#endif

#if defined(RTAC68U) || defined(RTAC68U_V4)
	if (check_crc(fname)) {
		dbg("found trx preamble\n");
#ifdef RTAC68U
		if (!truncate_trx(fname))
			dbg("truncate trx ok\n");
#else
		if (!cut_trx(fname))
			dbg("cut trx ok\n");
#endif
	}
#endif

	fp = fopen(fname, "r");
	if (fp == NULL)
		return 1;

#ifdef HND_ROUTER
	fseek(fp, -(MAX_TAIL_LEN + TOKEN_LEN), SEEK_END);
#else
	fseek(fp, -MAX_TAIL_LEN, SEEK_END);
#endif
	fread(&tail, 1, MAX_TAIL_LEN, fp);
#ifdef HND_ROUTER
	fread(&wt, 1, TOKEN_LEN, fp);
#endif
	fclose(fp);

	_dprintf("productid field in image: %.12s\n", tail.pid);

	for (i = 0; i < sizeof(tail); i++)
		_dprintf("%02x ", ((uint8_t *)&tail)[i]);
	_dprintf("\n");

	/* safe strip trailing spaces */
	for (i = 0; i < MAX_PID_LEN && tail.pid[i] != '\0'; i++);
	for (i--; i >= 0 && tail.pid[i] == '\x20'; i--)
		tail.pid[i] = '\0';

#ifdef HND_ROUTER
	dumpWfiTag(&wt);

	if (wt.wfiCrc != img_crc_hnd(fname)) {
		_dprintf("check crc error!!!\n");
		return 1;
	}
#else
	if (!check_crc(fname)) {
		_dprintf("check crc error!!!\n");
		return 1;
	}
#endif


#ifdef TRX_NEW
	en = (tail.flag == 1) ? tail.en2 : tail.en;

	if (!check_trx(fname, tail.key))
		return 2;

#ifdef RTCONFIG_BCMARM
	doSystem("nvram set cpurev=`cat /dev/mtd0 | grep cpurev | cut -d \"=\" -f 2`");
	if (nvram_match("cpurev", "c0") &&
	   (!tail.sn ||
	    !en ||
	     tail.sn < 380 ||
	    (tail.sn == 380 && en < 738)))
	{
		dbg("version check fail!\n");
		return 2;
	}
#ifdef RTAC68U
	else if (nvram_match("cpurev", "c0") &&
		 ((!nvram_get_int("PA") && ((tail.sn < 384) || (tail.sn == 384 && en < 9123))) ||
		  (is_ac68u_v3_series() && ((tail.sn < 385) || (tail.sn == 385 && en <= 20490))))) {
		dbg("version check fail!!\n");
		return 2;
	}
	else if ((get_model() == MODEL_RTAC68U) &&
		is_ac66u_v2_series() &&
		((tail.sn < 380) ||
		 (tail.sn == 380 && en < 7979) ||
		 (tail.sn == 382 && en < 15614))) {
		dbg("version check fail!!\n");
		return 2;
	}
#endif
#ifdef RTAC3200
	else if ((get_model() == MODEL_RTAC3200) && (tail.sn < 382)) {
		dbg("version check fail!!\n");
		return 2;
	}
#endif
#ifdef RTCONFIG_NVRAM_ENCRYPT
	int enc_sp_extendno = nvram_get_int("enc_sp_extendno");
	if (!tail.sn ||
	!en ||
	tail.sn < 382 ||
	(tail.sn == 382 && en < enc_sp_extendno))
	{
		dbg("nvram enc version check fail!\n");
		return 2;
	}
#endif
#endif
#endif

#ifdef CUSTOM_MODEL
	// by odmpid if is set
	if (strncmp(get_productid(), (char *) tail.pid, MAX_PID_LEN) == 0
	// || strncmp(nvram_safe_get("productid"), (char *) tail.pid, MAX_PID_LEN) == 0
	)
		return 0;
	else
		return 1;
#endif

	/* compare up to the first \0 or MAX_PID_LEN
	 * nvram productid or hw model's original productid */
	if (strncmp(nvram_safe_get("productid"), (char *) tail.pid, MAX_PID_LEN) == 0
#if !defined(GTAC2900) && !defined(TUFAX3000) && !defined(TUFAX5400)  && !defined(RTAX82U) && !defined(RTAX82_XD6) && !defined(RTAX82_XD6S) && !defined(GSAX3000) && !defined(GSAX5400) && !defined(TUFAX5400)
		|| strncmp(get_modelid(model), (char *) (char *) tail.pid, MAX_PID_LEN) == 0
#endif
	)
	{
		firmware_downgrade_check(tail.sf);
		return 0;
	}

	/* common RT-N12 productid FW image */
	if ((model == MODEL_RTN12B1 || model == MODEL_RTN12C1 ||
	     model == MODEL_RTN12D1 || model == MODEL_RTN12VP || model == MODEL_RTN12HP || model == MODEL_RTN12HP_B1 ||model == MODEL_APN12HP) &&
	     strncmp(get_modelid(MODEL_RTN12), (char *) tail.pid, MAX_PID_LEN) == 0)
		return 0;

	return 1;
}

#ifdef RTAC68U
#ifdef RTCONFIG_TCODE
#include "version.h"
#include "tcode.h"
#endif

int is_ac66u_v2_series()
{
	if ((get_model() == MODEL_RTAC68U) &&
		(!strcmp(get_productid(), MODEL_STR_RTAC66UV2)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM0)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM1)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM2)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM3)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM4)))
		return 1;

	return 0;
}

int is_n66u_v2()
{
	if (get_model() == MODEL_RTAC68U &&
		!strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM2))
		return 1;

	return 0;
}

int is_ac68u_v3_series()
{
	if (get_model() == MODEL_RTAC68U &&
		nvram_match("cpurev", "c0") && (nvram_get_int("PA") == 8527))
		return 1;

	return 0;
}

#ifdef RTAX86U
int is_ax86u_series()
{
	if(get_model() == MODEL_RTAX86U)
		return 1;

	return 0;
}
#endif

int hw_usb_cap()
{
	if (get_model() == MODEL_RTAC68U &&
		!strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM3))
		return 0;

	return 1;
}

int is_ssid_rev3_series()
{
	if ((get_model() == MODEL_RTAC68U) &&
		(!strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM0)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM2)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM3)
			|| !strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM4)
			|| !strcmp(get_productid(), MODEL_STR_4GAC68U)))
		return 1;

	return 0;
}

#ifdef RTCONFIG_TCODE
unsigned int hardware_flag() {
#ifdef RT4GAC68U
	if (strcmp(RT_BUILD_NAME, nvram_safe_get("productid")))
#else
	if (strcmp(RT_BUILD_NAME, nvram_safe_get("model")))
#endif
		return 0;

	if (nvram_match("cpurev", "c0")) {
#ifdef RT4GAC68U
		return RT4GAC68U_V1_C0;
#endif
		if (is_ac66u_v2_series())
			return RTAC66U_V2;
		else if (nvram_get_int("PA") == 8527)
			return RTAC68U_V3_C0;
		else if (nvram_get_int("PA") == 5023)
			return RTAC68U_V1;
		else if (nvram_get_int("PA") == 0)
			return RTAC68U_V1;
		else if (nvram_match("clkfreq", "1400,800"))
			return RTAC68U_V2_C0;
		else
			return RTAC68U_V1_C0;
	} else {
		if (nvram_get_int("PA"))
			return RTAC68U_V2;
		else
			return RTAC68U_V1;
	}

	return 0;
}
#endif

int is_dpsta_repeater()
{
	if ((get_model() == MODEL_RTAC68U) &&
		(!strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM3)))
		return 1;

	return 0;
}

void ac68u_cofs()
{
	if ((get_model() == MODEL_RTAC68U) &&
		!strcmp(get_productid(), MODEL_STR_RTAC66UV2_ODM2))
		nvram_set("COFS", "1");
	else
		nvram_unset("COFS");
}

int fw_check(void)
{
	if (!nvram_match("cpurev", "c0") && nvram_match("fw_check", "1")) {
		unlink("/tmp/linux.trx");
		eval("/usr/sbin/webs_update_enc.sh");

		if (nvram_get_int("webs_state_update") &&
		    !nvram_get_int("webs_state_error") &&
		    strlen(nvram_safe_get("webs_state_info"))) {
			dbg("retrieve firmware information\n");

			if (!nvram_get_int("webs_state_flag"))
			{
				dbg("no need to upgrade firmware\n");
				return -1;
			}

			eval("/usr/sbin/webs_upgrade_enc.sh");

			if (nvram_get_int("webs_state_error"))
			{
				dbg("error execute upgrade script\n");
				return -1;
			}
		} else dbg("could not retrieve firmware information!\n");
	}

	return 0;
}
#else

#if defined(RPAX56) || defined(RPAX58)
int is_dpsta_repeater()
{
        if (get_model() == MODEL_RPAX56 || get_model()==MODEL_RPAX58)
		return 1;

	return 0;
}
#endif

int fw_check(void)
{
	return 0;
}
#endif

#ifdef DSL_AX82U
#define MODEL_STR_DSLAX5400 "DSL-AX5400"
#ifdef OPDBG
#define OPDBG 1
#else
#define OPDBG 0
#endif
int is_ax5400_i1()
{
	if (get_model() == MODEL_DSLAX82U
	 && !strcmp(get_productid(), MODEL_STR_DSLAX5400)
	 && !strncmp(nvram_safe_get("territory_code"), "OP", 2)
	)
		return 1;

	return 0;
}
int is_ax5400_i1d()
{
	return (is_ax5400_i1() && OPDBG);
}
int is_ax5400_i1n()
{
	return (is_ax5400_i1() && !OPDBG);
}
#endif

#define NVRAM_BUFSIZE   100
#ifdef RTCONFIG_AMAS
#define VNDR_IE_OK_FLAGS \
	(VNDR_IE_BEACON_FLAG | VNDR_IE_PRBRSP_FLAG | VNDR_IE_ASSOCRSP_FLAG | \
	 VNDR_IE_AUTHRSP_FLAG | VNDR_IE_PRBREQ_FLAG | VNDR_IE_ASSOCREQ_FLAG | \
	 VNDR_IE_IWAPID_FLAG)

static int
wl_mk_ie_setbuf(const char *command, uint32 pktflag, int ielen, uchar *oui, uchar *data, vndr_ie_setbuf_t **buf, int *buf_len)
{
	vndr_ie_setbuf_t *ie_setbuf;
	int datalen, buflen, iecount;
	int err = 0;
#if defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_BCM_502L07P2)
	struct ether_addr sta_mac;

	memset(&sta_mac, 0, sizeof(sta_mac));
#endif

	if (pktflag & ~VNDR_IE_OK_FLAGS) {
		_dprintf("Invalid packet flag 0x%x (%d)\n", pktflag, pktflag);
		return -1;
	}

	if (ielen > VNDR_IE_MAX_LEN) {
		_dprintf("IE length is %d, should be <= %d\n", ielen, VNDR_IE_MAX_LEN);
		return -1;
	}
	else if (ielen < VNDR_IE_MIN_LEN) {
		_dprintf("IE length is %d, should be >= %d\n", ielen, VNDR_IE_MIN_LEN);
		return -1;
	}

	datalen = ielen - VNDR_IE_MIN_LEN;
	buflen = sizeof(vndr_ie_setbuf_t) + datalen - 1;
	ie_setbuf = (vndr_ie_setbuf_t *) malloc(buflen);

	if (ie_setbuf == NULL) {
		_dprintf("memory alloc failure\n");
		return -1;
	}

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strncpy(ie_setbuf->cmd, command, VNDR_IE_CMD_LEN - 1);
	ie_setbuf->cmd[VNDR_IE_CMD_LEN - 1] = '\0';


	/* Buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy((void *)&ie_setbuf->vndr_ie_buffer.iecount, &iecount, sizeof(int));

	/*
	 * The packet flag bit field indicates the packets that will
	 * contain this IE
	 */
	pktflag = htod32(pktflag);
	memcpy((void *)&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].pktflag,
	       &pktflag, sizeof(uint32));

	/* Now, add the IE to the buffer */
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.id = (uchar) DOT11_MNG_PROPR_ID;
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len = (uchar) ielen;
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[0], oui, DOT11_OUI_LEN);
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data[0], data, datalen);
#if defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_BCM_502L07P2)
#if VENDOR_IE_VERSION >= 2
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].sta_addr, &sta_mac, sizeof(struct ether_addr));
#endif
#endif
	/* Copy-out */
	if (buf) {
		*buf = ie_setbuf;
		ie_setbuf = NULL;
	}
	if (buf_len)
		*buf_len = buflen;

	/* Clean-up */
	if (ie_setbuf)
		free(ie_setbuf);

	return (err);
}

static int
wl_vndr_ie(int unit, int subunit, const char *command, uint32 pktflag, int ielen, uchar *oui, uchar *data)
{
	vndr_ie_setbuf_t *ie_setbuf;
	int buflen;
	int err = 0;
	char buf[WLC_IOCTL_MAXLEN];
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };

	if ((err = wl_mk_ie_setbuf(command, pktflag, ielen, oui, data, &ie_setbuf, &buflen)) != 0)
		return err;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
#if defined(RTCONFIG_HND_ROUTER_AX)
	strcpy(buf, "vndr_ie");
#else
	strcpy(buf, "ie");
#endif
	memcpy(buf + strlen(buf) + 1, ie_setbuf, buflen);

	if (subunit <= 0) {
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		if (!nvram_match(strcat_r(prefix, "mode", tmp), "ap"))
			snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
	} else {
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
		if (!nvram_match(strcat_r(prefix, "mode", tmp), "ap"))
			return err;
	}

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	err = wl_ioctl(ifname, WLC_SET_VAR, buf, sizeof(buf));

	free(ie_setbuf);

	return (err);
}

int
wl_add_ie(int unit, int subunit, uint32 pktflag, int ielen, uchar *oui, uchar *data)
{
	int err;

	err = wl_vndr_ie(unit, subunit, "add", pktflag, ielen, oui, data);

	if (err != 0)
		_dprintf("error adding IE: %d\n", err);

	return err;
}

int
wl_del_ie(int unit, int subunit, uint32 pktflag, int ielen, uchar *oui, uchar *data)
{
	int err;

	err = wl_vndr_ie(unit, subunit, "del", pktflag, ielen, oui, data);

	if (err != 0)
		_dprintf("error deleting IE: %d\n", err);

	return err;
}

void
wl_del_ie_with_oui(int unit, int subunit, uchar *oui)
{
	int err;
	ie_getbuf_t param;
	char buf[WLC_IOCTL_MAXLEN];
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	vndr_ie_buf_t *ie_getbuf;
	uchar *iebuf;
	int tot_ie, pktflag, iecount;
	vndr_ie_info_t *ie_info;
	vndr_ie_t *ie;
#if defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_BCM_502L07P2)
	uint32 *p_pktflag;
#endif

	param.pktflag = (uint32) -1;
	param.id = (uint8) DOT11_MNG_PROPR_ID;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
#if defined(RTCONFIG_HND_ROUTER_AX)
	strcpy(buf, "vndr_ie");
#else
	strcpy(buf, "ie");
#endif
	memcpy(buf + strlen(buf) + 1, &param, sizeof(param));

	if (subunit <= 0) {
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		if (!nvram_match(strcat_r(prefix, "mode", tmp), "ap"))
			snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
	}
	else {
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
		if (!nvram_match(strcat_r(prefix, "mode", tmp), "ap"))
			return;
	}

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	err = wl_ioctl(ifname, WLC_GET_VAR, buf, sizeof(buf));
	if (err == 0) {
		ie_getbuf = (vndr_ie_buf_t *) buf;

		memcpy(&tot_ie, (void *)&ie_getbuf->iecount, sizeof(int));
		tot_ie = dtoh32(tot_ie);
		iebuf = (uchar *)&ie_getbuf->vndr_ie_list[0];

		for (iecount = 0; iecount < tot_ie; iecount++) {
#if defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_BCM_502L07P2)
			ie_info = (vndr_ie_info_t *) iebuf;
			p_pktflag = &ie_info->pktflag;
			memcpy(&pktflag, (void *)p_pktflag, sizeof(uint32));
			pktflag = dtoh32(pktflag);
			iebuf += OFFSETOF(vndr_ie_info_t, vndr_ie_data);
#else
			ie_info = (vndr_ie_info_t *) iebuf;
			memcpy(&pktflag, (void *)&ie_info->pktflag, sizeof(uint32));
			pktflag = dtoh32(pktflag);
			iebuf += sizeof(uint32);
#endif
			ie = &ie_info->vndr_ie_data;

			if (!memcmp(ie->oui, oui, DOT11_OUI_LEN))
				wl_del_ie(unit, subunit, pktflag, ie->len, ie->oui, ie->data);

			iebuf += ie->len + VNDR_IE_HDR_LEN;
		}
	} else
		_dprintf("error getting IE: %d\n", err);
}
#endif

#ifdef RTCONFIG_BCMWL6
int with_non_dfs_chspec(char *wif)
{
	wl_uint32_list_t *list;
	chanspec_t c = 0;
	int ret = 0, i, count;
	char data_buf[WLC_IOCTL_MAXLEN];

	memset(data_buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_getbuf(wif, "chanspecs", &c, sizeof(chanspec_t),
		data_buf, WLC_IOCTL_MAXLEN);
	if (ret < 0) {
		dbg("failed to get valid chanspec list\n");
		return 0;
	}

	list = (wl_uint32_list_t *)data_buf;
	count = dtoh32(list->count);

	if (!count) {
		dbg("number of valid chanspec is 0\n");
		return 0;
	}

	for (i = 0; i < count; i++) {
		c = (chanspec_t)dtoh32(list->element[i]);
		if (wf_chspec_ctlchan(c) <= 48 || wf_chspec_ctlchan(c) >= 149)
			return 1;
	}

	return 0;
}

chanspec_t select_band1_chspec_with_same_bw(char *wif, chanspec_t chanspec)
{
	wl_uint32_list_t *list;
	chanspec_t c = 0;
	int ret = 0, i, count;
	char data_buf[WLC_IOCTL_MAXLEN];

	memset(data_buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_getbuf(wif, "chanspecs", &c, sizeof(chanspec_t),
		data_buf, WLC_IOCTL_MAXLEN);
	if (ret < 0) {
		dbg("failed to get valid chanspec list\n");
		return 0;
	}

	list = (wl_uint32_list_t *)data_buf;
	count = dtoh32(list->count);

	if (!count) {
		dbg("number of valid chanspec is 0\n");
		return 0;
	}

	for (i = 0; i < count; i++) {
		c = (chanspec_t)dtoh32(list->element[i]);
		if (wf_chspec_ctlchan(c) <= 48 && CHSPEC_BW(c) == CHSPEC_BW(chanspec))
			return c;
	}

	return 0;
}

chanspec_t select_band4_chspec_with_same_bw(char *wif, chanspec_t chanspec)
{
	wl_uint32_list_t *list;
	chanspec_t c = 0;
	int ret = 0, i, count;
	char data_buf[WLC_IOCTL_MAXLEN];

	memset(data_buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_getbuf(wif, "chanspecs", &c, sizeof(chanspec_t),
		data_buf, WLC_IOCTL_MAXLEN);
	if (ret < 0) {
		dbg("failed to get valid chanspec list\n");
		return 0;
	}

	list = (wl_uint32_list_t *)data_buf;
	count = dtoh32(list->count);

	if (!count) {
		dbg("number of valid chanspec is 0\n");
		return 0;
	}

	for (i = 0; i < count; i++) {
		c = (chanspec_t)dtoh32(list->element[i]);
		if (wf_chspec_ctlchan(c) >= 149 && CHSPEC_BW(c) == CHSPEC_BW(chanspec))
			return c;
	}

	return 0;
}

#define CHANNEL_5G_BAND_GROUP(c) \
	(((c) < 52) ? 1 : (((c) < 100) ? 2 : (((c) < 149) ? 3 : (((c) < 169) ? 4 : 5))))

#define CHANNEL_BANDWIDTH(a, b, bw) \
	((bw == 0) ? CHSPEC_BW(a) == CHSPEC_BW(b) : ((bw == 1) ? CHSPEC_IS20(a) : ((bw == 2) ? CHSPEC_IS40(a) : ((bw == 3) ? CHSPEC_IS80(a) : CHSPEC_IS160(a)))))

chanspec_t select_chspec_with_band_bw(char *wif, int band, int bw, chanspec_t chanspec)
{
	wl_uint32_list_t *list;
	chanspec_t c = 0;
	int ret = 0, i, count;
	char data_buf[WLC_IOCTL_MAXLEN];

	memset(data_buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_getbuf(wif, "chanspecs", &c, sizeof(chanspec_t),
		data_buf, WLC_IOCTL_MAXLEN);
	if (ret < 0) {
		dbg("failed to get valid chanspec list\n");
		return 0;
	}

	list = (wl_uint32_list_t *)data_buf;
	count = dtoh32(list->count);

	if (!count) {
		dbg("number of valid chanspec is 0\n");
		return 0;
	}

	for (i = 0; i < count; i++) {
		c = (chanspec_t)dtoh32(list->element[i]);
		if (CHANNEL_5G_BAND_GROUP(wf_chspec_ctlchan(c)) == band && CHANNEL_BANDWIDTH(c, chanspec, bw))
			return c;
	}

	return 0;
}

void wl_list_5g_chans(int unit, int band, int war, char *buf, int len)
{
	wl_uint32_list_t *list;
	chanspec_t c = 0;
	int ret = 0, i, count;
	char tmp[100], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	char data_buf[WLC_IOCTL_MAXLEN];
	char chanspecbuf[32];
	int first = 1;
	int b, d;

	memset(buf, 0, len);

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	memset(data_buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_getbuf(ifname, "chanspecs", &c, sizeof(chanspec_t),
		data_buf, WLC_IOCTL_MAXLEN);
	if (ret < 0) {
		dbg("failed to get valid chanspec list\n");
		return;
	}

	list = (wl_uint32_list_t *)data_buf;
	count = dtoh32(list->count);

	if (!count) {
		dbg("number of valid chanspec is 0\n");
		return;
	}

	for (i = 0; i < count; i++) {
		c = (chanspec_t)dtoh32(list->element[i]);
		b = CHANNEL_5G_BAND_GROUP(wf_chspec_ctlchan(c));
		d = war ? 0 : (CHSPEC_IS160(c) && (((band == 1) && (b == 2)) || ((band == 2) && (b == 1))));

		if ((b == band) || d) {
			if (first)
			{
				first = 0;
				sprintf(chanspecbuf, "0x%04x", c);
			}
			else
				sprintf(chanspecbuf, ",0x%04x", c);
			strncat(buf, chanspecbuf, len - strlen(buf) - 1);
		}
	}
}
#endif

#ifdef HND_ROUTER
static inline int ethswctl_init(struct ifreq *p_ifr)
{
    int skfd;

#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO) || defined(RTAX56U) || defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4) || defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
	return 1;
#endif
    /* Open a basic socket */
    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket open error\n");
        return -1;
    }

    /* Get the name -> if_index mapping for ethswctl */
    strcpy(p_ifr->ifr_name, "bcmsw");
    if (ioctl(skfd, SIOCGIFINDEX, p_ifr) < 0 ) {
        strcpy(p_ifr->ifr_name, WAN_IF_ETH);
        if (ioctl(skfd, SIOCGIFINDEX, p_ifr) < 0 ) {
            close(skfd);
            printf("neither bcmsw nor %s exist\n", WAN_IF_ETH);
            return -1;
        }
    }

    return skfd;
}

#if (!defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM6756)) || defined(RTCONFIG_EXTPHY_BCM84880)
#if !defined(RTCONFIG_BCM_502L07P2)
int mdio_read(int skfd, struct ifreq *ifr, int phy_id, int location)
{
	struct mii_ioctl_data *mii = (void *)&ifr->ifr_data;

	PHYID_2_MII_IOCTL(phy_id, mii);
	mii->reg_num = location;
	if (ioctl(skfd, SIOCGMIIREG, ifr) < 0) {
		fprintf(stderr, "SIOCGMIIREG on %s failed: %s\n", ifr->ifr_name,
		strerror(errno));
		return 0;
	}
	return mii->val_out;
}

static void mdio_write(int skfd, struct ifreq *ifr, int phy_id, int location, int value)
{
	struct mii_ioctl_data *mii = (void *)&ifr->ifr_data;

	PHYID_2_MII_IOCTL(phy_id, mii);
	mii->reg_num = location;
	mii->val_in = value;

	if (ioctl(skfd, SIOCSMIIREG, ifr) < 0) {
		fprintf(stderr, "SIOCSMIIREG on %s failed: %s\n", ifr->ifr_name,
			strerror(errno));
	}
}

static int et_dev_subports_query(int skfd, struct ifreq *ifr)
{
	int port_list = 0;

	ifr->ifr_data = (char*)&port_list;
	if (ioctl(skfd, SIOCGQUERYNUMPORTS, ifr) < 0) {
		fprintf(stderr, "Error: Interface %s ioctl SIOCGQUERYNUMPORTS error!\n", ifr->ifr_name);
		return -1;
	}
	return port_list;;
}

static int get_bit_count(int i)
{
	i = i - ((i >> 1) & 0x55555555);
	i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
	return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

static int et_get_phyid2(int skfd, struct ifreq *ifr, int sub_port)
{
	unsigned long phy_id;
	struct mii_ioctl_data *mii = (void *)&ifr->ifr_data;

	mii->val_in = sub_port;

	if (ioctl(skfd, SIOCGMIIPHY, ifr) < 0)
		return -1;

	phy_id = MII_IOCTL_2_PHYID(mii);
	/*
	* returned phy id carries mii->val_out flags if phy is
	* internal/external phy/phy on ext switch.
	* we save it in higher byte to pass to kernel when
	* phy is accessed.
	*/
	return phy_id;
}

static int et_get_phyid(int skfd, struct ifreq *ifr, int sub_port)
{
	int sub_port_map;
#ifdef RTCONFIG_HND_ROUTER_AX
#define MAX_SUB_PORT_BITS (sizeof(int)*8)
#else
#define MAX_SUB_PORT_BITS (sizeof(sub_port_map)*8)
#endif
	if ((sub_port_map = et_dev_subports_query(skfd, ifr)) < 0) {
		return -1;
	}

	if (sub_port_map > 0) {
		if (sub_port == -1) {
			if (get_bit_count(sub_port_map) > 1) {
				fprintf(stderr, "Error: Interface %s has sub ports, please specified one of port map: 0x%x\n",
				ifr->ifr_name, sub_port_map);
				return -1;
			}
			else if (get_bit_count(sub_port_map) == 1) {
				// get bit position
				for(sub_port = 0; sub_port < MAX_SUB_PORT_BITS; sub_port++) {
					if ((sub_port_map & (1 << sub_port)))
					break;
				}
			}
		}

		if ((sub_port_map & (1 << sub_port)) == 0) {
			fprintf(stderr, "Specified SubPort %d is not interface %s's member port with map %x\n",
				sub_port, ifr->ifr_name, sub_port_map);
			return -1;
		}
	} else {
		if (sub_port != -1) {
			fprintf(stderr, "Interface %s has no sub port\n", ifr->ifr_name);
			return -1;
		}
	}

	return et_get_phyid2(skfd, ifr, sub_port);
}
#endif // RTCONFIG_BCM_502L07P2

int ethctl_get_link_status(char *ifname)
{
#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
	char tmp[100], buf[32];

	snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/operstate", ifname);

	f_read_string(tmp, buf, sizeof(buf));
	if(!strncmp(buf, "up", 2))
		return 1;
	else
		return 0;
#else
	int skfd=0, err, bmsr;
	struct ethswctl_data ifdata;
	struct ifreq ifr;
	int phy_id = 0, sub_port = -1;

	if ( strstr(ifname, "eth") == ifname ||
	     strstr(ifname, "epon") == ifname) {
		strcpy(ifr.ifr_name, ifname);
	} else {
		fprintf(stderr, "invalid interface name %s\n", ifname);
		goto error;
	}

	/* Open a basic socket */
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ethctl: socket open error\n");
		return -1;
	}

	/* Get the name -> if_index mapping for ethctl */
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFINDEX, &ifr) < 0 ) {
		fprintf(stderr, "No %s interface exist\n", ifr.ifr_name);
		goto error;
	}

	if ((phy_id = et_get_phyid(skfd, &ifr, sub_port)) == -1)
		goto error;

	if (ETHCTL_GET_FLAG_FROM_PHYID(phy_id) & ETHCTL_FLAG_ACCESS_SERDES) {
		ifr.ifr_data = (void*) &ifdata;
		ifdata.op = ETHSWPHYMODE;
		ifdata.type = TYPE_GET;
		ifdata.addressing_flag = ETHSW_ADDRESSING_DEV;
		if (sub_port != -1) {
			ifdata.sub_unit = -1; // Set sub_unit to -1 so that main unit of dev will be used
			ifdata.sub_port = sub_port;
			ifdata.addressing_flag |= ETHSW_ADDRESSING_SUBPORT;
		}

		if ((err = ioctl(skfd, SIOCETHSWCTLOPS, &ifr))) {
			fprintf(stderr, "ioctl command return error %d!\n", err);
			goto error;
		}

		close(skfd);

		return (ifdata.speed == 0) ? 0 : 1;
	}

	bmsr = mdio_read(skfd, &ifr, phy_id, MII_BMSR);
	if (bmsr == 0x0000) {
		fprintf(stderr, "No MII transceiver present!.\n");
		goto error;
	}
	//printf("Link is %s\n", (bmsr & BMSR_LSTATUS) ? "up" : "down");

	close(skfd);
	return (bmsr & BMSR_LSTATUS) ? 1 : 0;
error:
	if (skfd) close(skfd);
	return -1;
#endif
}

#define _MB 0x1
#define _GB 0x2
#define _2GB 0x4
static int ethctl_get_link_speed(char *ifname)
{
	int skfd=0, err;
	struct ethswctl_data ifdata;
	struct ifreq ifr;
	int phy_id = 0, sub_port = -1;
	int bmcr, bmsr, gig_ctrl, gig_status, v16;

	if ( strstr(ifname, "eth") == ifname ||
	     strstr(ifname, "epon") == ifname) {
		strcpy(ifr.ifr_name, ifname);
	} else {
		fprintf(stderr, "invalid interface name %s\n", ifname);
		goto error;
	}

	/* Open a basic socket */
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ethctl: socket open error\n");
		return -1;
	}

	/* Get the name -> if_index mapping for ethctl */
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFINDEX, &ifr) < 0 ) {
		printf("No %s interface exist\n", ifr.ifr_name);
		goto error;
	}

	if ((phy_id = et_get_phyid(skfd, &ifr, sub_port)) == -1)
		goto error;

	if (ETHCTL_GET_FLAG_FROM_PHYID(phy_id) & ETHCTL_FLAG_ACCESS_SERDES) {
		ifr.ifr_data = (void*) &ifdata;
		ifdata.op = ETHSWPHYMODE;
		ifdata.type = TYPE_GET;
		ifdata.addressing_flag = ETHSW_ADDRESSING_DEV;
		if (sub_port != -1) {
			ifdata.sub_unit = -1; // Set sub_unit to -1 so that main unit of dev will be used
			ifdata.sub_port = sub_port;
			ifdata.addressing_flag |= ETHSW_ADDRESSING_SUBPORT;
		}

		if ((err = ioctl(skfd, SIOCETHSWCTLOPS, &ifr))) {
			fprintf(stderr, "ioctl command return error %d!\n", err);
			goto error;;
		}

		close(skfd);
		return (ifdata.speed >= 2000 ? _2GB : (ifdata.speed >= 1000 ? _GB : _MB));
	}

	bmsr = mdio_read(skfd, &ifr, phy_id, MII_BMSR);
	bmcr = mdio_read(skfd, &ifr, phy_id, MII_BMCR);
	if (bmcr == 0xffff ||  bmsr == 0x0000) {
		fprintf(stderr, "No MII transceiver present!.\n");
		goto error;
	}

	if (!(bmsr & BMSR_LSTATUS)) {
		fprintf(stderr, "Link is down!.\n");
		goto error;
	}

	if (bmcr & BMCR_ANENABLE) {
		gig_ctrl = mdio_read(skfd, &ifr, phy_id, MII_CTRL1000);
		// check ethernet@wirspeed only for PHY support 1G
		if (gig_ctrl & ADVERTISE_1000FULL || gig_ctrl & ADVERTISE_1000HALF) {
			// check if ethernet@wirespeed is enabled, reg 0x18, shodow 0b'111, bit4
			mdio_write(skfd, &ifr, phy_id, 0x18, 0x7007);
			v16 = mdio_read(skfd, &ifr, phy_id, 0x18);
			if (v16 & 0x0010) {
				// get link speed from ASR if ethernet@wirespeed is enabled
				v16 = mdio_read(skfd, &ifr, phy_id, 0x19);
#define MII_ASR_1000(r) (((r & 0x0700) == 0x0700) || ((r & 0x0700) == 0x0600))
#define MII_ASR_100(r)  (((r & 0x0700) == 0x0500) || ((r & 0x0700) == 0x0300))
#define MII_ASR_10(r)   (((r & 0x0700) == 0x0200) || ((r & 0x0700) == 0x0100))
				close(skfd);
				return MII_ASR_1000(v16) ? _GB : (MII_ASR_100(v16) || MII_ASR_10(v16)) ? _MB : -1;
			}
		}

		gig_status = mdio_read(skfd, &ifr, phy_id, MII_STAT1000);
		close(skfd);
		if (((gig_ctrl & ADVERTISE_1000FULL) && (gig_status & LPA_1000FULL)) ||
		    ((gig_ctrl & ADVERTISE_1000HALF) && (gig_status & LPA_1000HALF))) {
			close(skfd);
			return _GB;
		}
		else {
			return _MB;
		}
	}
	else {
		close(skfd);
		return (bmcr & BMCR_SPEED1000) ? _GB : _MB;
	}

error:
	if (skfd) close(skfd);
	return -1;
}

static int ethctl_get_link_duplex(char *ifname)
{
	int skfd=0, err;
	struct ethswctl_data ifdata;
	struct ifreq ifr;
	int phy_id = 0, sub_port = -1;
	int bmcr, bmsr, gig_ctrl, gig_status, v16;

	if ( strstr(ifname, "eth") == ifname ||
	     strstr(ifname, "epon") == ifname) {
		strcpy(ifr.ifr_name, ifname);
	} else {
		fprintf(stderr, "invalid interface name %s\n", ifname);
		goto error;
	}

	/* Open a basic socket */
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ethctl: socket open error\n");
		return -1;
	}

	/* Get the name -> if_index mapping for ethctl */
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(skfd, SIOCGIFINDEX, &ifr) < 0 ) {
		printf("No %s interface exist\n", ifr.ifr_name);
		goto error;
	}

	if ((phy_id = et_get_phyid(skfd, &ifr, sub_port)) == -1)
		goto error;

	if (ETHCTL_GET_FLAG_FROM_PHYID(phy_id) & ETHCTL_FLAG_ACCESS_SERDES) {
		ifr.ifr_data = (void*) &ifdata;
		ifdata.op = ETHSWPHYMODE;
		ifdata.type = TYPE_GET;
		ifdata.addressing_flag = ETHSW_ADDRESSING_DEV;
		if (sub_port != -1) {
			ifdata.sub_unit = -1; // Set sub_unit to -1 so that main unit of dev will be used
			ifdata.sub_port = sub_port;
			ifdata.addressing_flag |= ETHSW_ADDRESSING_SUBPORT;
		}

		if ((err = ioctl(skfd, SIOCETHSWCTLOPS, &ifr))) {
			fprintf(stderr, "ioctl command return error %d!\n", err);
			goto error;;
		}

		close(skfd);
		return (ifdata.speed >= 2000 ? _2GB : (ifdata.speed >= 1000 ? _GB : _MB));
	}

	bmsr = mdio_read(skfd, &ifr, phy_id, MII_BMSR);
	bmcr = mdio_read(skfd, &ifr, phy_id, MII_BMCR);
	if (bmcr == 0xffff ||  bmsr == 0x0000) {
		fprintf(stderr, "No MII transceiver present!.\n");
		goto error;
	}

	if (!(bmsr & BMSR_LSTATUS)) {
		fprintf(stderr, "Link is down!.\n");
		goto error;
	}

	if (bmcr & BMCR_ANENABLE) { // auto nego
		gig_ctrl = mdio_read(skfd, &ifr, phy_id, MII_CTRL1000);
		// check ethernet@wirspeed only for PHY support 1G
		if (gig_ctrl & ADVERTISE_1000FULL || gig_ctrl & ADVERTISE_1000HALF) {
			// check if ethernet@wirespeed is enabled, reg 0x18, shodow 0b'111, bit4
			mdio_write(skfd, &ifr, phy_id, 0x18, 0x7007);
			v16 = mdio_read(skfd, &ifr, phy_id, 0x18);
			if (v16 & 0x0010) {
				// get link speed from ASR if ethernet@wirespeed is enabled
				v16 = mdio_read(skfd, &ifr, phy_id, 0x19);
#define MII_ASR_FDX(r)  (((r & 0x0700) == 0x0700) || ((r & 0x0700) == 0x0500) || ((r & 0x0700) == 0x0200))
				close(skfd);
				return MII_ASR_FDX(v16);
			}
		}

		gig_status = mdio_read(skfd, &ifr, phy_id, MII_STAT1000);
		close(skfd);
		if (((gig_ctrl & ADVERTISE_1000FULL) && (gig_status & LPA_1000FULL)) ||
		    (gig_ctrl & ADVERTISE_100FULL) || 
		    (gig_ctrl & ADVERTISE_10FULL)) {
			close(skfd);
			return 1;
		}
		else {
			return 0;
		}
	}
	else {
		close(skfd);
		return (bmcr & BMCR_FULLDPLX);
	}

error:
	if (skfd) close(skfd);
	return -1;
}
#else
int ethctl_get_link_status(char *ifname)
{
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM4912) || defined(BCM6756)
	char tmp[100], buf[32];
	int ret = 0;

	snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/operstate", ifname);
	f_read_string(tmp, buf, sizeof(buf));

	if(strcmp(buf, "up\n")==0) ret = 1;
	else ret = 0;
#else
	char *cmd[] = {"ethctl", ifname, "media-type", NULL};
	char *output = "/tmp/ethctl_get_link_status.txt";
	char *str;
	int ret;
	int lock;

	lock = file_lock("ethctl_link");

	unlink(output);
	_eval(cmd, output, 0, NULL);

	str = file2str(output);
	if(!strstr(str, "Enabled"))
		ret = -1;
	else{
		if(strstr(str, "Up"))
			ret = 1;
		else
			ret = 0;
	}

	free(str);
	unlink(output);

	file_unlock(lock);

#endif
	return ret;
}
#endif //!defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_EXTPHY_BCM84880)

struct ethctl_data ethctl;
int ethctl_phy_op(char* phy_type, int addr, unsigned int reg, unsigned int value, int wr)
{
	struct ifreq ifr;
    	int skfd;
	int err, phy_id = 0, phy_flag = 0;
	unsigned int phy_reg = 0;

	strcpy(ifr.ifr_name, "bcmsw");
	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "socket open error\n");
		return -1;
	}

	if (ioctl(skfd, SIOCGIFINDEX, &ifr) < 0 ) {
		fprintf(stderr, "ioctl failed. check if %s exists\n", ifr.ifr_name);
		close(skfd);
		return -1;
	}


	if (strcmp(phy_type, "ext") == 0) {
		phy_flag = ETHCTL_FLAG_ACCESS_EXT_PHY;
	} else if (strcmp(phy_type, "int") == 0) {
		phy_flag = ETHCTL_FLAG_ACCESS_INT_PHY;
	} else if (strcmp(phy_type, "extsw") == 0) { // phy connected to external switch
		phy_flag = ETHCTL_FLAG_ACCESS_EXTSW_PHY;
	} else if (strcmp(phy_type, "i2c") == 0) { // phy connected through I2C bus
		phy_flag = ETHCTL_FLAG_ACCESS_I2C_PHY;
#ifdef RTCONFIG_EXTPHY_BCM84880
	} else if (strcmp(phy_type, "10gserdes") == 0) { // phy connected through I2C bus
		phy_flag = ETHCTL_FLAG_ACCESS_10GSERDES;
	} else if (strcmp(phy_type, "10gpcs") == 0) { // phy connected through I2C bus
		phy_flag = ETHCTL_FLAG_ACCESS_10GPCS;
#endif
	} else if (strcmp(phy_type, "serdespower") == 0) { // Serdes power saving mode
		phy_flag = ETHCTL_FLAG_ACCESS_SERDES_POWER_MODE;
	} else if (strcmp(phy_type, "ext32") == 0) { // Extended 32bit register access.
		phy_flag = ETHCTL_FLAG_ACCESS_32BIT|ETHCTL_FLAG_ACCESS_EXT_PHY;
	} else {
		fprintf(stderr, "Unknown phy type!\n");
		close(skfd);
		return -1;
	}

	phy_id = addr;
	phy_reg = reg;

	if ((phy_id < 0) || (phy_id > 31)) {
		fprintf(stderr, "Invalid Phy Address 0x%02x\n", phy_id);
		close(skfd);
		return -1;
        }

	if(phy_flag == ETHCTL_FLAG_ACCESS_SERDES_POWER_MODE && (reg < 0 || reg > 2))
        {
		fprintf(stderr, "Invalid Serdes Power Mode%02x\n", reg);
		close(skfd);
		return -1;
	}

	ethctl.phy_addr = phy_id;
	ethctl.phy_reg = phy_reg;
	ethctl.flags = phy_flag;

	if(wr) { // Write
		ethctl.op = ETHSETMIIREG;
		ethctl.val = value;
		ifr.ifr_data = (void *)&ethctl;
		err = ioctl(skfd, SIOCETHCTLOPS, &ifr);
		if (ethctl.ret_val || err) {
			_dprintf("SET ERROR!!!\n");
            		fprintf(stderr, "command return error!\n");
			close(skfd);
			return -1;
		}

//		_dprintf("[SET] %08x = %08x\n", phy_reg, value);
	}
	else { // Read
		ethctl.op = ETHGETMIIREG;
		ifr.ifr_data = (void *)&ethctl;
		err = ioctl(skfd, SIOCETHCTLOPS, &ifr);
		if (ethctl.ret_val || err) {
			_dprintf("GET ERROR!!!\n");
			fprintf(stderr, "command return error!\n");
			close(skfd);
			return -1;
		}
		else {
//			_dprintf("[GET] %08x = %04x\n", phy_reg, ethctl.val);
			close(skfd);
			return ethctl.val;
		}
	}

	return 0;
}

#ifdef RTCONFIG_EXTPHY_BCM84880
int extphy_bit_op(unsigned int reg, unsigned int val, int wr, unsigned int start_bit, unsigned int end_bit, unsigned int wait_ms){
#define MIN_BIT 0
#define MAX_BIT 15
	struct ifreq ifr;
	int skfd, err;
	int orig_val, val_mask, val_reverse_mask;
	int bit;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		fprintf(stderr, "socket open error\n");
		return -1;
	}

	strcpy(ifr.ifr_name, "bcmsw");
	if(ioctl(skfd, SIOCGIFINDEX, &ifr) < 0 ){
		fprintf(stderr, "ioctl failed. check if %s exists\n", ifr.ifr_name);
		close(skfd);
		return -1;
	}

	if(nvram_get_int("ext_phy_model") == EXT_PHY_GPY211)
		ethctl.phy_addr = EXTPHY_GPY_ADDR;
	else
	if(nvram_get_int("ext_phy_model") == EXT_PHY_RTL8226)
		ethctl.phy_addr = EXTPHY_RTL_ADDR;
	else
		ethctl.phy_addr = EXTPHY_ADDR;
	ethctl.phy_reg = reg;
	ethctl.flags = ETHCTL_FLAG_ACCESS_EXT_PHY;

	// Read
	ethctl.op = ETHGETMIIREG;
	ifr.ifr_data = (void *)&ethctl;
	err = ioctl(skfd, SIOCETHCTLOPS, &ifr);
	if(ethctl.ret_val || err){
		_dprintf("GET ERROR!!!\n");
		fprintf(stderr, "command return error!\n");
		close(skfd);
		return -1;
	}

	if(start_bit < MIN_BIT || start_bit > MAX_BIT)
		start_bit = MIN_BIT;

	if(end_bit < MIN_BIT || end_bit > MAX_BIT)
		end_bit = MAX_BIT;

	val_mask = 0;
	for(bit = start_bit; bit <= end_bit; ++bit)
		val_mask |= 0x1<<bit;
	//_dprintf("[val_mask] [%u:%u], 0x%04x\n", end_bit, start_bit, val_mask);

	val_reverse_mask = val_mask^0xffff;
	//_dprintf("[val_reverse_mask] [%u:%u], 0x%04x\n", end_bit, start_bit, val_reverse_mask);

	orig_val = ethctl.val;
	if(!wr){
		ethctl.val &= val_mask;
		ethctl.val >>= start_bit;
		_dprintf("[GET] 0x%08x [%u:%u] = 0x%04x, full 0x%04x\n", reg, end_bit, start_bit, ethctl.val, orig_val);
		close(skfd);
		return ethctl.val;
	}
	else
		_dprintf("[Ori] 0x%08x [%u:%u] = 0x%04x\n", reg, MAX_BIT, MIN_BIT, orig_val);

	// Write
	ethctl.op = ETHSETMIIREG;
	ethctl.val = (orig_val&val_reverse_mask) + (val<<start_bit);
	ifr.ifr_data = (void *)&ethctl;
	err = ioctl(skfd, SIOCETHCTLOPS, &ifr);
	if (ethctl.ret_val || err) {
		_dprintf("SET ERROR!!!\n");
		fprintf(stderr, "command return error!\n");
		close(skfd);
		return -1;
	}

	_dprintf("[SET] 0x%08x [%u:%u] = 0x%04x, full 0x%04x\n", reg, end_bit, start_bit, val, ethctl.val);
	close(skfd);

	if(wait_ms > 0){
		//_dprintf("Sleeping %u mini seconds...\n", wait_ms);
		usleep(wait_ms*1000);
	}

	//_dprintf("done\n");

	return ethctl.val;
}
#endif

int bcm_reg_read_X(int unit, unsigned int addr, char* data, int len)
{
    int skfd, err = 0;
    struct ifreq ifr;
    struct ethswctl_data ifdata;
    struct ethswctl_data *e = &ifdata;

    if ((skfd=ethswctl_init(&ifr)) < 0) {
        printf("ethswctl_init failed. \n");
        return skfd;
    }
    ifr.ifr_data = (char *)&ifdata;

    e->op = ETHSWREGACCESS;
    e->type = TYPE_GET;
    e->offset = addr;
    e->length = len;
    e->unit = unit;

    if ((err = ioctl(skfd, SIOCETHSWCTLOPS, &ifr))) {
        printf("ioctl command return error!\n");
        goto out;
    }

    memcpy(data, e->data, len);

out:
    close(skfd);
    return err;
}

int bcm_reg_write_X(int unit, unsigned int addr, char* data, int len)
{
    int skfd, err = 0;
    struct ifreq ifr;
    struct ethswctl_data ifdata;
    struct ethswctl_data *e = &ifdata;

    if ((skfd=ethswctl_init(&ifr)) < 0) {
        printf("ethswctl_init failed. \n");
        return skfd;
    }
    ifr.ifr_data = (char *)&ifdata;

    e->op = ETHSWREGACCESS;
    e->type = TYPE_SET;
    e->offset = addr;
    e->length = len;
    e->unit = unit;
    memcpy(e->data, data, len);

    if ((err = ioctl(skfd, SIOCETHSWCTLOPS, &ifr))) {
        printf("ioctl command return error!\n");
        goto out;
    }

out:
    close(skfd);
    return err;
}

int bcm_pseudo_mdio_read(unsigned int addr, char* data, int len)
{
    int skfd, err = 0;
    struct ifreq ifr;
    struct ethswctl_data ifdata;
    struct ethswctl_data *e = &ifdata;

    if ((skfd=ethswctl_init(&ifr)) < 0) {
        printf("ethswctl_init failed. \n");
        return skfd;
    }
    ifr.ifr_data = (char *)&ifdata;

    e->op = ETHSWPSEUDOMDIOACCESS;
    e->type = TYPE_GET;
    e->offset = addr;
    e->length = len;

    if ((err = ioctl(skfd, SIOCETHSWCTLOPS, &ifr))) {
        printf("ioctl command return error!\n");
        goto out;
    }

    memcpy(data, e->data, len);

out:
    close(skfd);
    return err;
}

int bcm_pseudo_mdio_write(unsigned int addr, char* data, int len)
{
    int skfd, err = 0;
    struct ifreq ifr;
    struct ethswctl_data ifdata;
    struct ethswctl_data *e = &ifdata;

    if ((skfd=ethswctl_init(&ifr)) < 0) {
        printf("ethswctl_init failed. \n");
        return skfd;
    }
    ifr.ifr_data = (char *)&ifdata;

    e->op = ETHSWPSEUDOMDIOACCESS;
    e->type = TYPE_SET;
    e->offset = addr;
    e->length = len;
    memcpy(e->data, data, sizeof(e->data));

    if ((err = ioctl(skfd, SIOCETHSWCTLOPS, &ifr))) {
        printf("ioctl command return error!\n");
        goto out;
    }

out:
    close(skfd);
    return err;
}

uint64_t hnd_ethswctl(ecmd_t act, unsigned int val, int len, int wr, unsigned long long regdata)
{
	unsigned long long data64 = 0;
	int ret_val = 0, i;
	unsigned char data[8];

	switch(act) {
		case REGACCESS:
			if (wr) {
				data64 = cpu_to_le64(regdata);
				//_dprintf("w Data: %08x %08x \n", (unsigned int)(data64 >> 32), (unsigned int)(data64) );
				ret_val = bcm_reg_write_X(1, val, (char *)&data64, len);
			} else {
				ret_val = bcm_reg_read_X(1, val, (char *)&data64, len);
				data64 = le64_to_cpu(data64);
				//_dprintf("Data: %08x %08x \n", (unsigned int)(data64 >> 32), (unsigned int)(data64) );
				return data64;
			}
			break;
		case PMDIOACCESS:
#ifdef RTCONFIG_HND_ROUTER_AX
			data64 = cpu_to_le64(regdata);
			for(i = 0; i < 8; i++)
			{
				data[i] = (unsigned char) (*( ((char *)&data64) + i));
			}
#else
			for(i = 0; i < 8; i++)
			{
 				data[i] = (unsigned char) (*( ((char *)&regdata) + 7-i));
			}
#endif
			if (wr) {
				//_dprintf("\npw data\n");
				ret_val = bcm_pseudo_mdio_write(val, (char*)data, len);
			} else {
				memset(data, 0, sizeof(data));
				ret_val = bcm_pseudo_mdio_read(val, (char*)data, len);
				//_dprintf("pr Data: %02x%02x%02x%02x %02x%02x%02x%02x\n",
				//data[7], data[6], data[5], data[4], data[3], data[2], data[1], data[0]);
				memcpy(&data64, data, 8);
				return data64;
			}
			break;
	}

	return ret_val;
}

typedef struct {
	unsigned int link[4];
	unsigned int speed[4];
	unsigned int duplex[4];
} phyState;

#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
uint32_t hnd_get_phy_status(char *ifname)
{
	char tmp[100], buf[32];

	snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/operstate", ifname);

	f_read_string(tmp, buf, sizeof(buf));
	if(!strncmp(buf, "up", 2))
		return 1;
	else
		return 0;
}
#elif defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
uint32_t hnd_get_phy_status(int port)
{
	char ifname[16], tmp[100], buf[32];

#if defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
	int fd;
	phyState pS;

	if (port)
	{
		fd = open("/dev/rtkswitch", O_RDONLY);
		if (fd < 0) {
			perror("/dev/rtkswitch");
		} else {
			memset(&pS, 0, sizeof(pS));
			if (ioctl(fd, 0, &pS) < 0) {
				perror("rtkswitch ioctl");
				close(fd);
			}

			close(fd);
		}

		return pS.link[port - 1];
	}
	else
#endif
	{
		snprintf(ifname, sizeof(ifname), "eth%d", port);
		snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/operstate", ifname);

		f_read_string(tmp, buf, sizeof(buf));
		if(!strncmp(buf, "up", 2))
			return 1;
		else
			return 0;
	}
}
#else
uint32_t hnd_get_phy_status(int port, int offs, unsigned int regv, unsigned int pmdv)
{
	if (port == 7
#ifdef RTCONFIG_EXTPHY_BCM84880
	    || port == 4
#endif 
	) {			// wan port
#ifdef RTCONFIG_EXTPHY_BCM84880
		// port4(eth0)->1G WAN, port7(eth5)->2.5G LAN
		return ethctl_get_link_status(port == 4 ? WAN_IF_ETH : "eth5");
#else
		return ethctl_get_link_status(WAN_IF_ETH);
#endif
	} else if (!offs || (port-offs < 0)) {	// main switch
		return regv & (1<<port) ? 1 : 0;
	} else {				// externai switch
		return pmdv & (1<<(port-offs)) ? 1 : 0;
	}
}
#endif

#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
uint32_t hnd_get_phy_speed(char *ifname)
{
	char tmp[100], buf[32];

	snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/speed", ifname);

	f_read_string(tmp, buf, sizeof(buf));
	return strtoul(buf, NULL, 10);
}
#elif defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
uint32_t hnd_get_phy_speed(int port)
{
	char ifname[16], tmp[100], buf[32];

#if defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
	int fd;
	phyState pS;

	if (port)
	{
		fd = open("/dev/rtkswitch", O_RDONLY);
		if (fd < 0) {
			perror("/dev/rtkswitch");
		} else {
			memset(&pS, 0, sizeof(pS));
			if (ioctl(fd, 0, &pS) < 0) {
				perror("rtkswitch ioctl");
				close(fd);
			}

			close(fd);
		}

		if (pS.link[port - 1])
			return ((pS.speed[port - 1] == 2) ? 1000 : 100);
		else
			return 0;
	}
	else
#endif
	{
		snprintf(ifname, sizeof(ifname), "eth%d", port);
		snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/speed", ifname);

		f_read_string(tmp, buf, sizeof(buf));
		return strtoul(buf, NULL, 10);
	}
}
#else
uint32_t hnd_get_phy_speed(int port, int offs, unsigned int regv, unsigned int pmdv)
{
	int val = 0;
	if (port == 7
#ifdef RTCONFIG_EXTPHY_BCM84880
            || port == 4
#endif
	) {			// wan port
#ifdef RTCONFIG_EXTPHY_BCM84880
                // port4(eth0)->1G WAN, port7(eth5)->2.5G LAN
		return ethctl_get_link_speed(port == 4 ? WAN_IF_ETH : "eth5");
#else
		return ethctl_get_link_speed(WAN_IF_ETH);
#endif
	}
	else if (!offs || (port-offs < 0)) {	// main switch
		val = regv & (0x0003<<(port*2));
		return val>>(port*2);
	} else {				// externai switch
		val = pmdv & (0x0003<<((port-offs)*2));
		return val>>((port-offs)*2);
	}
}
#endif

#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
uint32_t hnd_get_phy_duplex(char *ifname)
{
	char tmp[100], buf[32];

	snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/duplex", ifname);

	f_read_string(tmp, buf, sizeof(buf));
	if(!strncmp(buf, "full", 4))
		return 1;
	else
		return 0;
}
#elif defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
uint32_t hnd_get_phy_duplex(int port)
{
	char ifname[16], tmp[100], buf[32];

#if defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
	int fd;
	phyState pS;

	if (port)
	{
		fd = open("/dev/rtkswitch", O_RDONLY);
		if (fd < 0) {
			perror("/dev/rtkswitch");
		} else {
			memset(&pS, 0, sizeof(pS));
			if (ioctl(fd, 0, &pS) < 0) {
				perror("rtkswitch ioctl");
				close(fd);
			}

			close(fd);
		}

		return pS.duplex[port - 1];
	}
	else
#endif
	{
		snprintf(ifname, sizeof(ifname), "eth%d", port);
		snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/duplex", ifname);

		f_read_string(tmp, buf, sizeof(buf));
		if(!strncmp(buf, "full", 4))
			return 1;
		else
			return 0;
	}
}
#else
uint32_t hnd_get_phy_duplex(int port, int offs, unsigned int regv, unsigned int pmdv)
{
	if (port == 7
#ifdef RTCONFIG_EXTPHY_BCM84880
	    || port == 4
#endif 
	) {			// wan port
#ifdef RTCONFIG_EXTPHY_BCM84880
		// port4(eth0)->1G WAN, port7(eth5)->2.5G LAN
		return ethctl_get_link_duplex(port == 4 ? WAN_IF_ETH : "eth5");
#else
		return ethctl_get_link_duplex(WAN_IF_ETH);
#endif
	} else if (!offs || (port-offs < 0)) {	// main switch
		return regv & (1<<port) ? 1 : 0;
	} else {				// externai switch
		return pmdv & (1<<(port-offs)) ? 1 : 0;
	}
}
#endif

static uint64_t hnd_get_phy_mib_by_ifname(char *ifname, char *type)
{
	char tmp[100], buf[32];
	int result = 0;

	if (!ifname || !type)
		return result;

	snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/statistics/%s", ifname, type);

	f_read_string(tmp, buf, sizeof(buf));
	return strtoull(buf, NULL, 10);
}

#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
uint64_t hnd_get_phy_mib(char *ifname, char *type)
{
	return hnd_get_phy_mib_by_ifname(ifname, type);
}
#elif defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
uint64_t hnd_get_phy_mib(int port, char *type)
{
	char ifname[16], tmp[100], buf[32];
	int result = 0;

	if (!type)
		return result;

#if defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
	int fd;
	int *p = NULL;
	rtk_stat_port_cntr_t Port_cntrs;

	if (port)
	{
		fd = open("/dev/rtkswitch", O_RDONLY);
		if (fd < 0) {
			perror("/dev/rtkswitch");
		} else {
			memset(&Port_cntrs, 0, sizeof(Port_cntrs));
			p = (int *) &Port_cntrs;
			*p = port - 1;
			if (ioctl(fd, 1, &Port_cntrs) < 0) {
				perror("rtkswitch ioctl");
				close(fd);
			} else {
				if (!strcmp(type, "tx_bytes"))
					result = Port_cntrs.ifOutOctets;
				else if (!strcmp(type, "rx_bytes"))
					result = Port_cntrs.ifInOctets;
				else if (!strcmp(type, "tx_packets"))
					result = Port_cntrs.ifOutUcastPkts + Port_cntrs.ifOutMulticastPkts + Port_cntrs.ifOutBrocastPkts;
				else if (!strcmp(type, "rx_packets"))
					result = Port_cntrs.ifInUcastPkts + Port_cntrs.ifInMulticastPkts;
				else if (!strcmp(type, "rx_crc_errors"))
					result = Port_cntrs.dot3StatsFCSErrors;
			}

			close(fd);
		}
		return result;
	}
	else
#endif
	{
		snprintf(ifname, sizeof(ifname), "eth%d", port);
		snprintf(tmp, sizeof(tmp), "/sys/class/net/%s/statistics/%s", ifname, type);

		f_read_string(tmp, buf, sizeof(buf));
		return strtoull(buf, NULL, 10);
	}
}
#else
static uint64_t hnd_get_phy_mib_by_ethswctl(int port, int offs, char *type)
{
	uint64_t val = 0;
	int addr_cnt = 0, i = 0;
	unsigned int addr[8] = {0};
	unsigned long long data = 0;
	unsigned int port_id = (!offs || (port-offs < 0)) ? port : port-offs;
	ecmd_t act = (!offs || (port-offs < 0)) ? REGACCESS : PMDIOACCESS;
	if (!strcmp(type, "tx_bytes")) {
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_TX_BYTES;
	}
	else if (!strcmp(type, "rx_bytes")) {
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_RX_BYTES;
	}
	else if (!strcmp(type, "tx_packets")) {
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_TX_BROADCAST_PACKETS;
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_TX_MULTICAST_PACKETS;
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_TX_UNICAST_PACKETS;
	}
	else if (!strcmp(type, "rx_packets")) {
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_RX_UNICAST_PACKETS;
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_RX_MULTICAST_PACKETS;
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_RX_BROADCAST_PACKETS;
	}
	else if (!strcmp(type, "rx_crc_errors")) {
		addr[addr_cnt++] = ((PAGE_MIB_BASE+port_id)<<8) + REG_OFFSET_RX_FCS_ERROR;
	}

	for (i = 0; i < addr_cnt; i++) {
		data = 0;
		data = hnd_ethswctl(act, addr[i], 8, 0, 0);
		//fprintf(stderr, "addr=%x, data=%llu\n", addr[i], data);
		val += data;
	}
	return val;
}

uint64_t hnd_get_phy_mib(int port, int offs, char *type)
{
	if (port == 7
#ifdef RTCONFIG_EXTPHY_BCM84880
            || port == 4
#endif
	) {			// wan port
#ifdef RTCONFIG_EXTPHY_BCM84880
                // port4(eth0)->1G WAN, port7(eth5)->2.5G LAN
		return hnd_get_phy_mib_by_ifname(port == 4 ? WAN_IF_ETH : "eth5", type);
#else
		return hnd_get_phy_mib_by_ifname(WAN_IF_ETH, type);
#endif
	} else {
		return hnd_get_phy_mib_by_ethswctl(port, offs, type);
	}
}
#endif /* RTCONFIG_HND_ROUTER_AX_6710 */

#endif /* HND_ROUTER */

int wanport_status_brcm(int wan_unit)
{
#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
	if(!is_router_mode())
		return hnd_get_phy_status(nvram_safe_get("eth_ifnames"));
	else
		return hnd_get_phy_status(get_wanx_ifname(wan_unit));
#elif defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
	int i = 0;
	char word[100], *next;

	foreach(word, nvram_safe_get("wanports"), next) {
		if (i == wan_unit)
			return hnd_get_phy_status(atoi(word));

		i++;
	}

	return 0;
#else // RTCONFIG_HND_ROUTER_AX_675X
	char word[100], *next;
	int mask;
	char wan_ports[16];
#ifdef HND_ROUTER
	int i, ret = 0, extra_p0 = 0;
	unsigned int regv=0, pmdv=0;
	char word2[100], *next2;
#endif

	memset(wan_ports, 0, 16);
	mask = 0;

#ifdef HND_ROUTER
	if(sw_mode() == SW_MODE_AP && nvram_get_int("re_mode") == 0){
		strcpy(wan_ports, "lanports");

		foreach(word, nvram_safe_get(wan_ports), next) {
			mask |= (0x0001<<atoi(word));
			if(sw_mode() == SW_MODE_AP)
				break;
		}
	}
	else{
		strcpy(wan_ports, "wanports");
		i = 0;
		foreach(word2, nvram_safe_get(wan_ports), next2){
			if(i == wan_unit)
				break;

			++i;
		}

		mask |= (0x0001<<atoi(word2));
#ifdef RTCONFIG_BONDING_WAN
		if (nvram_match("bond_wan", "1")){
			memset(wan_ports, 0, 16);
			mask = 0;
			strcpy(wan_ports, "wanports_bond");
			foreach(word2, nvram_safe_get(wan_ports), next2){
				mask |= (0x0001<<atoi(word2));
				// _dprintf("wan_bond: port mask[%08X]\n", mask);
			}
		}
#endif
	}
#else // HND_ROUTER
#ifndef RTN53
	if(sw_mode() == SW_MODE_AP && nvram_get_int("re_mode") == 0)
		strcpy(wan_ports, "lanports");
	else
#endif
	if(wan_unit == 1)
		strcpy(wan_ports, "wan1ports");
	else
		strcpy(wan_ports, "wanports");

	foreach(word, nvram_safe_get(wan_ports), next) {
		mask |= (0x0001<<atoi(word));
		if(sw_mode() == SW_MODE_AP)
			break;
	}
#endif // HND_ROUTER

#ifdef RTCONFIG_WIRELESSWAN
	// to do for report wireless connection status
	if(is_wirelesswan_enabled())
		return 1;
#endif

#ifdef HND_ROUTER
#ifdef RTCONFIG_EXT_BCM53134
	regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0);
	pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0);
#else
	regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0) & 0xf;
#endif

#ifdef RTCONFIG_EXT_BCM53134
	switch(get_model()) {
		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56U:
		case MODEL_GTAX11000:
		case MODEL_GTAXE11000:
			extra_p0 = S_53134;
			break;
	}
#endif

	for(i = 0; i < 9; ++i){
		if(mask & 1<<i) {
			ret |= hnd_get_phy_status(i, extra_p0, regv, pmdv);
		}
	}
	return ret;
#else // HND_ROUTER
	return get_phy_status(mask);
#endif // HND_ROUTER
#endif	/* RTCONFIG_HND_ROUTER_AX_675X */
}

#ifdef HND_ROUTER
int get_port_status_hnd(int unit)
{
	int mask = 0;
	int i, ret = 0;
#if !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM6756)
	int extra_p0 = 0;
	unsigned int regv=0, pmdv=0;

#ifdef RTCONFIG_EXT_BCM53134
	regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0);
	pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0);
#else
	regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0) & 0xf;
#endif

#ifdef RTCONFIG_EXT_BCM53134
	switch(get_model()) {
		case MODEL_GTAC5300:
			extra_p0 = S_53134;
			break;
	}
#endif
#endif

#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
	char word[100], *next;

	foreach(word, nvram_safe_get("wan_ifnames"), next)
		ret |= hnd_get_phy_status(word);

	foreach(word, nvram_safe_get("lan_ifnames"), next)
		ret |= hnd_get_phy_status(word);
#else
	for(i = 0; i < 9; ++i){
		if(mask & 1<<i) {
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
			ret |= hnd_get_phy_status(i);
#else
			ret |= hnd_get_phy_status(i, extra_p0, regv, pmdv);
#endif
		}
	}
#endif
	return ret;
}
#endif
