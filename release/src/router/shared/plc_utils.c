#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <bcmnvram.h>

#include <rtconfig.h>
#include <flash_mtd.h>
#include <shutils.h>
#include <shared.h>
#include <plc_utils.h>

#ifdef RTCONFIG_QCA
#include <qca.h>
#endif

/*
 * Convert PLC Key (e.g. NMK, DAK) string representation to binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx notation
 * @param	e	binary data
 * @return	TRUE if conversion was successful and FALSE otherwise
 */
int
key_atoe(const char *a, unsigned char *e)
{
	char *c = (char *) a;
	int i = 0;

	memset(e, 0, PLC_KEY_LEN);
	for (;;) {
		e[i++] = (unsigned char) strtoul(c, &c, 16);
		if (!*c++ || i == PLC_KEY_LEN)
			break;
	}
	return (i == PLC_KEY_LEN);
}

/*
 * Convert PLC Key binary data to string representation
 * @param	e	binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx notation
 * @return	a
 */
char *
key_etoa(const unsigned char *e, char *a)
{
	char *c = a;
	int i;

	for (i = 0; i < PLC_KEY_LEN; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", e[i] & 0xff);
	}
	return a;
}

/*
 * Convert password (DEK) to DAK
 * dek: input
 * dak: output
 *
 * return
 *  0: success
 * -1: fail
 */
static int dek2dak(char *dek, char *dak)
{
	FILE *fp;
	int len, i, ret = 0;
	char cmd[64], buf[64];

	snprintf(cmd, sizeof(cmd), "/usr/local/bin/hpavkey -D %s", dek);
	fp = popen(cmd, "r");
	if (fp) {
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			char *p = dak;
			buf[len - 1] = '\0';

			for (i = 0; i < PLC_KEY_LEN; i++) {
				if (i == 0)
					p += sprintf(p, "%c%c", buf[0], buf[1]);
				else
					p += sprintf(p, ":%c%c", buf[i*2], buf[i*2+1]);
			}
			//dbg("%s: Password (DEK) [%s] convert to DAK [%s]\n", __func__, dek, dak);
		}
		else
			ret = -1;
	}
	else
		ret = -1;

	return ret;
}

/*
 * Convert Private Network Name to NMK
 * pnn: input
 * nmk: output
 *
 * return
 *  0: success
 * -1: fail
 */
static int pnn2nmk(char *pnn, char *nmk)
{
	FILE *fp;
	int len, i, ret = 0;
	char cmd[64], buf[64];

	snprintf(cmd, sizeof(cmd), "/usr/local/bin/hpavkey -M %s", pnn);
	fp = popen(cmd, "r");
	if (fp) {
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			char *p = nmk;
			buf[len - 1] = '\0';

			for (i = 0; i < PLC_KEY_LEN; i++) {
				if (i == 0)
					p += sprintf(p, "%c%c", buf[0], buf[1]);
				else
					p += sprintf(p, ":%c%c", buf[i*2], buf[i*2+1]);
			}
			//dbg("%s: Private network name [%s] convert to NMK [%s]\n", __func__, pnn, nmk);
		}
		else
			ret = -1;
	}
	else
		ret = -1;

	return ret;
}

/*
 * get current NMK
 * nmk: output
 *
 * return
 *  0: success
 * -1: fail
 */
int current_nmk(char *nmk)
{
	FILE *fp;
	int len, ret = -1;
	char buf[1024];
	char *ptr;
	char plc_ifname[16];
	char bridge[16];

	get_plc_ifname(plc_ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif
	sprintf(buf, "/usr/local/bin/plctool -i %s %s -I -e %s", plc_ifname, bridge, nvram_safe_get("plc_macaddr"));
	fp = popen(buf, "r");
	if (fp) {
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len - 1] = '\0';

			if ((ptr = strstr(buf, "NMK"))) {
			    if(nmk) {
				ptr += 4;
				ptr[47] = '\0';
				sprintf(nmk, "%s", ptr);
			    }
				ret = 0;
			}
			//dbg("%s: current NMK is %s\n", __func__, nmk);
		}
	}

	return ret;
}

#ifdef RTCONFIG_QCA_PLC_UTILS
/*
 * increase n to mac last 24 bits and handle a carry problem
 */
static void inc_mac(unsigned char n, unsigned char *mac)
{
	int c = 0;

	//dbg("MAC + %u\n", n);

	if (mac[5] >= (0xff - n + 1))
		c = 1;
	else
		c = 0;
	mac[5] += n;

	if (c == 1) {
		if (mac[4] >= 0xff)
			c = 1;
		else
			c = 0;
		mac[4] += 1;

		if (c == 1)
			mac[3] += 1;
	}
}

/*
 * check PLC MAC/Key
 * reference isValidMacAddr() in rc/ate.c
 */
int isValidPara(const char* str, int len)
{
	#define MULTICAST_BIT	0x0001
	#define UNIQUE_OUI_BIT	0x0002
	int sec_byte;
	int i = 0, s = 0;

	if (strlen(str) != ((len * 2) + len - 1))
		return 0;

	while (*str && i < (len * 2)) {
		if (isxdigit(*str)) {
			if (i == 1 && len == ETHER_ADDR_LEN) {
				sec_byte = strtol(str, NULL, 16);
				if ((sec_byte & MULTICAST_BIT) || (sec_byte & UNIQUE_OUI_BIT))
					break;
			}
			i++;
		}
		else if (*str == ':') {
			if (i == 0 || i/2-1 != s)
				break;
			++s;
		}
		++str;
	}
	return (i == (len * 2) && s == (len - 1));
}

static int __getPLC_para(char *ebuf, int addr)
{
	int len;

	if (addr == OFFSET_PLC_MAC)
		len = ETHER_ADDR_LEN;
	else if (addr == OFFSET_PLC_NMK)
		len = PLC_KEY_LEN;
	else
		return 0;

	memset(ebuf, 0, len);

	if (FRead(ebuf, addr, len) < 0) {
		dbg("READ PLC parameter: Out of scope\n");
		return 0;
	}

	return 1;
}

/*
 * get PLC MAC from factory partition
 */
int getPLC_MAC(char *abuf)
{
	unsigned char ebuf[ETHER_ADDR_LEN];

	if (__getPLC_para(ebuf, OFFSET_PLC_MAC)) {
		memset(abuf, 0, ETHER_ADDR_LEN);
		if (ether_etoa(ebuf, abuf))
			return 1;
	}

	return 0;
}

/*
 * get PLC NMK from factory partition
 */
int getPLC_NMK(char *abuf)
{
	unsigned char ebuf[PLC_KEY_LEN];

	if (__getPLC_para(ebuf, OFFSET_PLC_NMK)) {
		memset(abuf, 0, PLC_KEY_LEN);
		if (key_etoa(ebuf, abuf))
			return 1;
	}

	return 0;
}

/*
 * ATE get PLC password from MAC
 */
static int __getPLC_PWD(unsigned char *emac, char *pwd)
{
	FILE *fp;
	int len;
	char cmd[64], buf[32];

	inc_mac(2, emac);
	snprintf(cmd, sizeof(cmd), "/usr/local/bin/mac2pw -q %02x%02x%02x%02x%02x%02x", emac[0], emac[1], emac[2], emac[3], emac[4], emac[5]);
	fp = popen(cmd, "r");
	if (fp) {
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len - 1] = '\0';
			strcpy(pwd, buf);
		}
		else
			return 0;
	}
	else
		return 0;

	return 1;
}

int getPLC_PWD(void)
{
	unsigned char ebuf[ETHER_ADDR_LEN];
	char pwd[32];

	if (__getPLC_para(ebuf, OFFSET_PLC_MAC)) {
		memset(pwd, 0, sizeof(pwd));
		if (!__getPLC_PWD(ebuf, pwd))
			return 0;

		puts(pwd);
	}
	else
		return 0;

	return 1;
}

/*
 * ATE get/set PLC parameter from/to factory partition, e.g. MAC, NMK
 */
int getPLC_para(int addr)
{
	char abuf[64], ebuf[16];


	if (__getPLC_para(ebuf, addr)) {
		memset(abuf, 0, sizeof(abuf));
		if (addr == OFFSET_PLC_MAC)
			ether_etoa(ebuf, abuf);
		else
			key_etoa(ebuf, abuf);
		puts(abuf);
	}
	else
		return 0;

	return 1;
}

int setPLC_para(const char *abuf, int addr)
{
	unsigned char ebuf[32];
	int len, ret;

	if (abuf == NULL)
		return 0;

	memset(ebuf, 0, sizeof(ebuf));

	if (addr == OFFSET_PLC_MAC) {
		len = ETHER_ADDR_LEN;
		if (!isValidPara(abuf, len))
			return 0;

		ret = ether_atoe(abuf, ebuf);
	} else if (addr == OFFSET_PLC_NMK) {
		len = PLC_KEY_LEN;
		if (!isValidPara(abuf, len))
			return 0;

		ret = key_atoe(abuf, ebuf);
	} else
		return 0;

	if (ret) {
		FWrite(ebuf, addr, len);
		getPLC_para(addr);
		return 1;
	}
	else
		return 0;
}

/*
 * modify the value of specific offset
 */
static int modify_pib_byte(unsigned int offset, unsigned int value)
{
	return doSystem("/usr/local/bin/setpib -x %s 0x%x data %02x", BOOT_PIB_PATH, offset, value);
}

/*
 * disable all LED event of PLC except Power event
 */
void ate_ctl_plc_led(void)
{
	int i = 0;

	for (i = 0; i < 18; i++) {
#if defined(RTCONFIG_AR7420)
		if (i == 7) /* Power event */
			continue;
		modify_pib_byte((0x1B13 + (8 * i)), 0x1);
#elif defined(RTCONFIG_QCA7500)
		if (i == 11) /* Power event */
			continue;
		modify_pib_byte((0x21A7 + (8 * i)), 0x1);
#endif
	}
}

/*
 * ATE turn on/off all LED of PLC
 */
int set_plc_all_led_onoff(int on)
{
	char *plc_mac;
	char plc_ifname[16];
	char bridge[16];

	get_plc_ifname(plc_ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif
	if (on) {
#if defined(RTCONFIG_AR7420)
		modify_pib_byte(0x1B49, 0x61);	/* GPIO 0, 5, 6 */
#elif defined(RTCONFIG_QCA7500)
		modify_pib_byte(0x21FD, 0xC0);	/* GPIO 6, 7 */
		modify_pib_byte(0x21FE, 0x0);
#endif
	}
	else {
#if defined(RTCONFIG_AR7420)
		modify_pib_byte(0x1B49, 0x0);
#elif defined(RTCONFIG_QCA7500)
		modify_pib_byte(0x21FD, 0x0);
		modify_pib_byte(0x21FE, 0x02);	/* GPIO 9 */
#endif
	}

	plc_mac = nvram_safe_get("plc_macaddr");
	doSystem("/usr/local/bin/plctool -i %s %s -R -e %s > /dev/null", plc_ifname, bridge, plc_mac);

	return 0;
}


/*
 * backup user's .nvm and .pib mechanism
 */
#define PLC_MAGIC		0x27051956	/* PLC Image Magic Number */
#define DEFAULT_NVM_PATH	"/usr/local/bin/asus.nvm"
#define DEFAULT_PIB_PATH	"/usr/local/bin/asus.pib"
#define USER_NVM_PATH		"/tmp/user.nvm"
#define USER_PIB_PATH		"/tmp/user.pib"
#define HDR_PATH		"/tmp/plc.hdr"
#define IMAGE_PATH		"/tmp/plc.img"
#define RD_SIZE			65536

#define PLC_MTD_NAME		"plc"
#define PLC_MTD_DEV		"mtd5"

#ifndef MAP_FAILED
#define MAP_FAILED (-1)
#endif

typedef struct _plc_image_header {
	unsigned int	magic;		/* PLC Image Header Magic Number */
	unsigned int	hdr_crc;	/* PLC Image Header crc checksum */
#if defined(PLN12)
	unsigned int	nvm_size;	/* PLC .nvm size */
	unsigned int	nvm_crc;	/* PLC .nvm crc checksum */
#endif
	unsigned int	pib_size;	/* PLC .pib size */
	unsigned int	pib_crc;	/* PLC .pib crc checksum */
} plc_image_header;

plc_image_header header;

/*
 * check crc of header
 *
 * : input,  file name
 *
 * return
 * 1: match
 * 0: mismatch or fail
 */
static int hdr_match_crc(plc_image_header *hdr)
{
	unsigned int checksum, checksum_org;

	checksum_org = hdr->hdr_crc;
	hdr->hdr_crc = 0;
	checksum = crc_calc(0, (const char *)hdr, sizeof(plc_image_header));
	fprintf(stderr, "%s: crc %x/%x of header\n", __func__, checksum_org, checksum);

	if (checksum != checksum_org) {
		fprintf(stderr, "%s: header crc mismatch!\n", __func__);
		return 0;
	}

	return 1;
}

/*
 * get file length and crc
 *
 * fname: input,  file name
 * len:   output, file length
 * crc:   output, file crc
 */
static int get_crc(char* fname, unsigned int *len, unsigned int *crc)
{
	int fd, ret = -1;
	struct stat fs;
	unsigned char *ptr = NULL;

	if ((fd = open(fname, O_RDONLY)) < 0) {
		fprintf(stderr, "%s: Can't open %s\n", __func__, fname);
		goto open_fail;
	}

	if (fstat(fd, &fs) < 0) {
		fprintf(stderr, "%s: Can't stat %s\n", __func__, fname);
		goto checkcrc_fail;
	}
	*len = fs.st_size;

	ptr = (unsigned char *)mmap(0, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		fprintf(stderr, "%s: Can't map %s\n", __func__, fname);
		goto checkcrc_fail;
	}
	*crc = crc_calc(0, (const char *)ptr, fs.st_size);

	ret = 0;

checkcrc_fail:
	if (ptr != NULL)
		munmap(ptr, fs.st_size);
#if defined(_POSIX_SYNCHRONIZED_IO) && !defined(__sun__) && !defined(__FreeBSD__)
	(void)fdatasync(fd);
#else
	(void)fsync(fd);
#endif
	close(fd);

open_fail:
	return ret;
}

/*
 * check crc of file and header record
 *
 * fname: input,  file name
 * crc:   input,  header record
 *
 * return
 * 1: match
 * 0: mismatch or fail
 */
static int match_crc(char *fname, unsigned int crc)
{
	unsigned int len, checksum;

	if (get_crc(fname, &len, &checksum)) {
		fprintf(stderr, "%s: Can't check crc of %s\n", __func__, fname);
		return 0;
	}
	fprintf(stderr, "%s: crc %x/%x of %s\n", __func__, crc, checksum, fname);

	if (checksum != crc) {
		fprintf(stderr, "%s: %s crc mismatch!\n", __func__, fname);
		return 0;
	}

	return 1;
}

/*
 * read .nvm and .pib from flash
 */
#if defined(PLN12)
static int plc_read_from_flash(char *nvm_path, char *pib_path)
#else
static int plc_read_from_flash(char *pib_path)
#endif
{
	int rfd, wfd, ret = -1;
	unsigned int rlen, wlen;
	plc_image_header *hdr = &header;
	char cmd[32], buf[RD_SIZE];

	snprintf(cmd, sizeof(cmd), "cat /dev/%s > %s", PLC_MTD_DEV, IMAGE_PATH);
	system(cmd);

	memset(hdr, 0, sizeof(plc_image_header));
	// header
	if ((rfd = open(IMAGE_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "%s: Can't open %s\n", __func__, IMAGE_PATH);
		goto open_fail;
	}
	rlen = read(rfd, hdr, sizeof(plc_image_header));
	// check header crc and magic number
	if (hdr_match_crc(hdr) == 0 || hdr->magic != PLC_MAGIC)
		goto mismatch;

	memset(buf, 0, sizeof(buf));
#if defined(PLN12)
	// .nvm
	wlen = hdr->nvm_size;
	if ((wfd = open(nvm_path, O_RDWR|O_CREAT, 0666)) < 0) {
		fprintf(stderr, "%s: Can't open %s\n", __func__, nvm_path);
		goto mismatch;
	}
	while (wlen > 0) {
		if (wlen > RD_SIZE)
			rlen = read(rfd, buf, RD_SIZE);
		else
			rlen = read(rfd, buf, wlen);
		write(wfd, buf, rlen);
		wlen -= rlen;
	}
	close(wfd);
	// check .nvm crc
	if (match_crc(nvm_path, hdr->nvm_crc) == 0)
		goto mismatch;
#endif

	// .pib
	wlen = hdr->pib_size;
	if ((wfd = open(pib_path, O_RDWR|O_CREAT, 0666)) < 0) {
		fprintf(stderr, "%s: Can't open %s\n", __func__, pib_path);
		goto mismatch;
	}
	while (wlen > 0) {
		if (wlen > RD_SIZE)
			rlen = read(rfd, buf, RD_SIZE);
		else
			rlen = read(rfd, buf, wlen);
		write(wfd, buf, rlen);
		wlen -= rlen;
	}
	close(wfd);
	// check .pib crc
	if (match_crc(pib_path, hdr->pib_crc) == 0)
		goto mismatch;

	ret = 0;

mismatch:
	close(rfd);

open_fail:
	unlink(IMAGE_PATH);

	return ret;
}

/*
 * write .nvm and .pib to flash
 */
#if defined(PLN12)
static int plc_write_to_flash(char *nvm_path, char *pib_path)
#else
static int plc_write_to_flash(char *pib_path)
#endif
{
	int fd, fl;
	plc_image_header *hdr = &header;
	char cmd[128];

	memset(hdr, 0, sizeof(plc_image_header));
	hdr->magic = PLC_MAGIC;

#if defined(PLN12)
	// get length and crc of .nvm
	if (get_crc(nvm_path, &hdr->nvm_size, &hdr->nvm_crc)) {
		fprintf(stderr, "%s: Can't check crc of %s\n", __func__, nvm_path);
		return -1;
	}
#endif

	// get length and crc of .pib
	if (get_crc(pib_path, &hdr->pib_size, &hdr->pib_crc)) {
		fprintf(stderr, "%s: Can't check crc of %s\n", __func__, pib_path);
		return -1;
	}

	// create header
	hdr->hdr_crc = crc_calc(0, (const char *)hdr, sizeof(plc_image_header));
	if ((fd = open(HDR_PATH, O_RDWR|O_CREAT, 0666)) < 0) {
		fprintf(stderr, "%s: Can't open %s\n", __func__, HDR_PATH);
		return -1;
	}
	write(fd, hdr, sizeof(plc_image_header));
	close(fd);

	// write to plc partition
	while (1) {
		if ((fl = open(PLC_LOCK_FILE, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0600)) >= 0) {
#if defined(PLN12)
			snprintf(cmd, sizeof(cmd), "cat %s %s %s > %s", HDR_PATH, nvm_path, pib_path, IMAGE_PATH);
#else
			snprintf(cmd, sizeof(cmd), "cat %s %s > %s", HDR_PATH, pib_path, IMAGE_PATH);
#endif
			system(cmd);
			snprintf(cmd, sizeof(cmd), "mtd-write -i %s -d %s", IMAGE_PATH, PLC_MTD_NAME);
			system(cmd);
			close(fl);
			unlink(PLC_LOCK_FILE);
			break;
		}
		else {
			dbg("%s: PLC file lock! Try again after waiting 1 sec\n", __func__);
			sleep(1);
		}
	}

	unlink(HDR_PATH);
	unlink(IMAGE_PATH);

	return 0;
}

/*
 * write default .nvm and .pib to flash
 */
int default_plc_write_to_flash(void)
{
	char buf[64];
	char mac[18], dak[48], nmk[48];
	unsigned char emac[ETHER_ADDR_LEN], enmk[PLC_KEY_LEN];

#if defined(PLN12)
	doSystem("cp %s %s", DEFAULT_NVM_PATH, BOOT_NVM_PATH);
#endif
	doSystem("cp %s %s", DEFAULT_PIB_PATH, BOOT_PIB_PATH);

	// modify .pib
	// MAC
	if (!__getPLC_para(emac, OFFSET_PLC_MAC)) {
		_dprintf("READ PLC MAC: Out of scope\n");
	}
	else {
		if (emac[0] != 0xff) {
			if (ether_etoa(emac, mac))
				doSystem("/usr/local/bin/modpib %s -M %s", BOOT_PIB_PATH, mac);

			// DAK
			if (__getPLC_PWD(emac, buf)) {
				if (dek2dak(buf, dak) == 0)
					doSystem("/usr/local/bin/modpib %s -D %s", BOOT_PIB_PATH, dak);
			}
		}
	}

	// NMK
	if (!__getPLC_para(enmk, OFFSET_PLC_NMK))
		_dprintf("READ PLC NMK: Out of scope\n");
	else {
		if (enmk[0] != 0xff && enmk[1] != 0xff && enmk[2] != 0xff) {
			if (key_etoa(enmk, nmk))
				doSystem("/usr/local/bin/modpib %s -N %s", BOOT_PIB_PATH, nmk);
		}
	}

#if defined(PLN12)
	return plc_write_to_flash(BOOT_NVM_PATH, BOOT_PIB_PATH);
#else
	return plc_write_to_flash(BOOT_PIB_PATH);
#endif
}

/*
 * write default .nvm and .pib to flash, if plc partition is empty.
 * reload .nvm and .pib to /tmp from flash for plchost utility
 */
int load_plc_setting(void)
{
#if defined(PLN12)
	if (plc_read_from_flash(BOOT_NVM_PATH, BOOT_PIB_PATH))
#else
	if (plc_read_from_flash(BOOT_PIB_PATH))
#endif
		return default_plc_write_to_flash();
	return 0;
}

/*
 * set plc_flag nvram for save_plc_setting() function
 *
 * because of plc-utils/plc/plchost.c cannot include bcmnvram.h
 * 	error: conflicting types for 'bool' from
 * 		src-qca/include/typedefs.h
 * 		plc-utils/tools/types.h
 */
void set_plc_flag(int flag)
{
	nvram_set_int("plc_flag", flag);
}

/*
 * write user .nvm or .pib to flash
 * case1: backup .nvm
 * case2: backup .pib
 * case3: backup .nvm and .pib
 */
void save_plc_setting(void)
{
	switch (atoi(nvram_safe_get("plc_flag"))) {
	case 2:
		_dprintf("sleep 10 second for wait pairing done!\n");
		sleep(10);
#if defined(PLN12)
		plc_write_to_flash(BOOT_NVM_PATH, USER_PIB_PATH);
#else
		plc_write_to_flash(USER_PIB_PATH);
#endif
		break;
#if defined(PLN12)
	case 1:
		plc_write_to_flash(USER_NVM_PATH, BOOT_PIB_PATH);
		break;
	case 3:
		plc_write_to_flash(USER_NVM_PATH, USER_PIB_PATH);
		break;
#endif
	default:
		fprintf(stderr, "%s: wrong flag!", __func__);
	}

	set_plc_flag(-1);
}
#endif	/* RTCONFIG_QCA_PLC_UTILS */

void turn_led_pwr_off(void)
{
	if (!nvram_match("asus_mfg", "0"))
		return;

	_dprintf("#PLC# plc_ready\n");
	nvram_set("plc_ready", "1");

#if (defined(PLN12) || defined(PLAC56))
	led_control(LED_POWER_RED, LED_OFF);
#endif
}


/*
 * manage remote PLC by GUI
 *
 * get connected remote PLC by plctool
 * rplc: output
 *
 * return amount of remote PLC
 *
 * Note: You need to free rplc pointer if call this function
 */
int get_connected_plc(struct remote_plc **rplc)
{
	#define PLCTOOL_M	"/tmp/plctool-m"
	FILE *fp;
	char buf[100], *ptr1, *ptr2;
	char ifname[8], plc_mac[18], resp_mac[18];
	int found = 0, idx = 0, chk = 0, cnt = 0;
	int i = 0;
	struct remote_plc *p;
	char bridge[16];

	get_plc_ifname(ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif
	strlcpy(plc_mac, nvram_safe_get("plc_macaddr"), sizeof(plc_mac));
	snprintf(buf, sizeof(buf), "/usr/local/bin/plctool -i %s %s -m -e %s > %s", ifname, bridge, plc_mac, PLCTOOL_M);
	system(buf);

	if ((fp = fopen(PLCTOOL_M, "r")) == NULL) {
		_dprintf("%s: Can't open %s\n", __func__, PLCTOOL_M);
		return 0;
	}

	// parse content
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		// check response MAC
		if (!found && (ptr1 = strstr(buf, ifname))) {
			ptr2 = strstr(buf, " Found 1");
			if (ptr2) {
				idx++;
				ptr1 += strlen(ifname) + 1;
				strlcpy(resp_mac, ptr1, sizeof(resp_mac));
				if (!strncmp(resp_mac, plc_mac, 17))
					found = 1;
				continue;
			}
		}

		if (found == 0)
			continue;

		// check amount of remote plc
		if (strstr(buf, "network->TEI")) {
			idx--;
			if (idx == 0)
				chk = 1;
			else
				chk = 0;
			continue;
		}
		if (chk && (ptr1 = strstr(buf, "network->STATIONS"))) {
			ptr1 += strlen("network->STATIONS") + 3;
			cnt = atoi(ptr1);
			break;
		}
	}

	if (cnt == 0 || rplc == NULL)
		goto exit;

	*rplc = malloc(sizeof(struct remote_plc) * cnt);
	if (rplc == NULL) {
		cnt = 0;
		goto exit;
	}
	p = rplc[0];
	memset(p, 0x0, sizeof(struct remote_plc) * cnt);

	// get information of remote plc
	while (i < cnt && fgets(buf, sizeof(buf), fp) != NULL) {
		// MAC
		if ((ptr1 = strstr(buf, "station->MAC"))) {
			ptr1 += strlen("station->MAC") + 3;
			ptr2 = ptr1 + 17;
			*ptr2 = '\0';
			snprintf(p[i].mac, sizeof(p[i].mac), "%s", ptr1);
			p[i].status = 3;
			//dbg("%s: MAC=%s\n", __func__, p[i].mac);
		}
		else if ((ptr1 = strstr(buf, "station->AvgPHYDR_RX"))) {
			ptr1 += strlen("station->AvgPHYDR_RX") + 3;
			ptr2 = ptr1 + 3;
			*ptr2 = '\0';
			p[i].rx = atoi(ptr1);
			p[i].rx_mimo = !strncmp(ptr2+6, "MIMO", 4);	//station->AvgPHYDR_RX = 136 mbps MIMO
			//dbg("%s: PHY Rx=%d\n", __func__, p[i].rx);
		}
		else if ((ptr1 = strstr(buf, "station->AvgPHYDR_TX"))) {
			ptr1 += strlen("station->AvgPHYDR_TX") + 3;
			ptr2 = ptr1 + 3;
			*ptr2 = '\0';
			p[i].tx = atoi(ptr1);
			p[i].tx_mimo = !strncmp(ptr2+6, "MIMO", 4);	//station->AvgPHYDR_TX = 009 mbps Primary
			//dbg("%s: PHY Tx=%d\n", __func__, p[i].tx);

			i++;
		}
	}

exit:
	fclose(fp);
	unlink(PLCTOOL_M);

	return cnt;
}

#ifdef RTCONFIG_QCA_PLC_UTILS
/*
 * get known PLC from nvram
 * rplc: output
 *
 * return amount of known PLC
 *
 * Note: You need to free rplc pointer if call this function
 */
int get_known_plc(struct remote_plc **rplc)
{
	char *nv, *nvp, *b;
	char *mac, *pwd;
	int i = 0, cnt = 0;
	struct remote_plc *p;

	// check amount of known plc
	nv = nvp = strdup(nvram_safe_get("plc_known_dev"));
	while ((b = strsep(&nvp, "<")) != NULL) {
		if ((vstrsep(b, ">", &mac, &pwd) != 2)) continue;
		cnt++;
	}
	free(nv);

	if (cnt == 0)
		goto exit;

	*rplc = malloc(sizeof(struct remote_plc) * cnt);
	p = rplc[0];
	memset(p, 0, sizeof(struct remote_plc) * cnt);

	// get information of known plc
	nv = nvp = strdup(nvram_safe_get("plc_known_dev"));
	while ((b = strsep(&nvp, "<")) != NULL) {
		if ((vstrsep(b, ">", &mac, &pwd) != 2)) continue;

		strlcpy(p[i].mac, mac, sizeof(p[i].mac));
		strlcpy(p[i].pwd, pwd, sizeof(p[i].pwd));
		p[i].status = 2;
		//dbg("%s: known PLC: MAC=%s, PWD=%s\n", __func__, p[i].mac, p[i].pwd);
		i++;
	}
	free(nv);

exit:
	return cnt;
}

/*
 * apply Private Network Name to local and known remote PLC
 * pnn: input,  private network name
 * nv: input,  known remote PLC: <MAC1>PWD1<MAC2>PWD2 ...
 *
 * return
 * -1: fail
 */
int apply_private_name(char *pnn, char *nv)
{
	struct remote_plc *plc = NULL;
	int cnt, i, ret = 0;
	char nmk[48], dak[48];
	char plc_mac[18];
	char plc_ifname[16];
	char bridge[16];

	nvram_set("plc_known_dev", nv);
	cnt = get_known_plc(&plc);
	if (strcmp(pnn, ""))
		ret = pnn2nmk(pnn, nmk);
	else
		ret = current_nmk(nmk);

	strlcpy(plc_mac, nvram_safe_get("plc_macaddr"), sizeof(plc_mac));
	get_plc_ifname(plc_ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif
	ret = doSystem("/usr/local/bin/plctool -i %s %s -MK %s %s", plc_ifname, bridge, nmk, plc_mac);
	for (i = 0; i < cnt; i++) {
		ret = dek2dak(plc[i].pwd, dak);
		ret = doSystem("/usr/local/bin/plctool -i %s -J %s -D %s -K %s %s", plc_ifname, plc[i].mac, dak, nmk, plc_mac);
	}

	if (ret != -1) {
		nvram_set("plc_pnn", pnn);
		nvram_commit();
	}

	if (plc)
		free(plc);

	return ret;
}

/*
 * trigger local PLC pair
 *
 * return
 * -1: fail
 */
int trigger_plc_pair(void)
{
	FILE *fp;
	int len, cnt = 0;
	char buf[1024], mac[32];
	char *plc_mac;
	char plc_ifname[16];
	char bridge[16];

	snprintf(mac, sizeof(mac), "MAC %s", nvram_safe_get("plc_macaddr"));
	plc_mac = mac + 4;
	get_plc_ifname(plc_ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif
	while (1) {
		snprintf(buf, sizeof(buf, "/usr/local/bin/plctool -i %s %s -I -e %s", plc_ifname, bridge, plc_mac));
	    if ((fp = popen(buf, "r"))) {
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			if (strstr(buf, mac))
				break;
		}
	    }

		if (cnt > 3)
			goto exit;
		cnt++;
		sleep(1);
	}

	return doSystem("/usr/local/bin/plctool -i %s -B 1 %s", plc_ifname, plc_mac);

exit:
	dbg("%s: Can't identity PLC. Maybe pairing...\n", __func__);
	return -1;
}

/*
 * add remote device by MAC and Password
 * mac: input,  MAC address
 * pwd: input,  password (DEK)
 *
 * return
 * -1: fail
 */
int add_remote_plc(char *mac, char *pwd)
{
	int ret = 0;
	char buf[1024];
	char dak[48], nmk[48];
	char plc_ifname[16];
	char bridge[16];

	ret = dek2dak(pwd, dak);
	ret = current_nmk(nmk);
	get_plc_ifname(plc_ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif

	//dbg("%s: MAC=%s, DAK=%s, NMK=%s\n", __func__, mac, dak, nmk);
	ret = doSystem("/usr/local/bin/plctool -i %s %s -J %s -D %s -K %s %s", plc_ifname, bridge, mac, dak, nmk, nvram_safe_get("plc_macaddr"));
	if (ret != -1) {
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%s<%s>%s", nvram_safe_get("plc_known_dev"), mac, pwd);
		nvram_set("plc_known_dev", buf);
		nvram_commit();
	}

	return ret;
}
#else
int load_plc_setting(void)
{
	int ret;
	char *pib_path = BOOT_PIB_PATH;
	char *pib_name;
	char *pib_mb;
	char plc_mac[32];
	char buff[128];
	char *cfg_group;
	char str_KEY[64];
	char str_NMK[PLC_KEY_LEN * 3];
	char str_DAK[PLC_KEY_LEN * 3];
	char *plc_nmk;

	cfg_group = nvram_get("cfg_group");

	/* prepare original pib */
	if (!strncmp(nvram_safe_get("territory_code"), "EU", 2))
		pib_name = "eu";	/* EU */
	else
		pib_name = "us";	/* others */

	if(cfg_group && *cfg_group)
		pib_mb = "_mb";
	else
		pib_mb = "";

	snprintf(buff, sizeof(buff), "/lib/firmware/plc/%s%s.pib", pib_name, pib_mb);
	doSystem("md5sum %s | logger -t 'PLC'", buff);
	file_copy(buff, pib_path);

	/* set MAC */
	strlcpy(plc_mac, nvram_safe_get("plc_macaddr"), sizeof(plc_mac));
	if (isxdigit((int)plc_mac[0])) {
		doSystem("/usr/local/bin/modpib %s -M %s", pib_path, plc_mac);
	}

	/* set NMK */
	*str_NMK = '\0';
	*str_KEY = '\0';
	if(cfg_group && *cfg_group)
	{
		strlcpy(str_KEY, cfg_group, sizeof(str_KEY));
		nvram_unset("plc_nmk");
	}
	else if ((plc_nmk = nvram_get("plc_nmk")) && strlen(plc_nmk) == 47) {
		strlcpy(str_NMK, plc_nmk, sizeof(str_NMK));
	}
	else
		strlcpy(str_KEY, plc_mac, sizeof(str_KEY));

    if (*str_NMK == '\0') {
	ret = pnn2nmk(str_KEY, str_NMK);
	_dprintf("#PLC# pnn2nmk: (%s)(%s) ret(%d)\n", str_KEY, str_NMK, ret);
    }
	if (isxdigit((int)str_NMK[0])) {
		doSystem("/usr/local/bin/modpib %s -N %s", pib_path, str_NMK);
	}

	/* set DAK */
	*str_DAK = '\0';
	snprintf(buff, sizeof(buff), "%s%s", str_KEY, plc_mac);
	ret = dek2dak(buff, str_DAK);
	_dprintf("#PLC# dek2dak: (%s)(%s) ret(%d)\n", buff, str_DAK, ret);
	if (isxdigit((int)str_DAK[0])) {
		doSystem("/usr/local/bin/modpib %s -D %s", pib_path, str_DAK);
	}

	return 0;
}
#endif	/* RTCONFIG_QCA_PLC_UTILS */

char *get_plc_ifname(char ifname[])
{
#ifdef RTCONFIG_QCA_PLC2
	const char *plc_ifname = PLC_INTERFACE;

			strcpy(ifname, plc_ifname);
			return ifname;
#else
	strcpy(ifname, nvram_safe_get("lan_ifname"));

	return ifname;
#endif	/* RTCONFIG_QCA_PLC2 */
}

void run_plcrate(int duration)
{
	char plc_ifname[16];
	char str[16];
	char *plcrate_argv[] = {"/usr/local/bin/plcrate", "-i", plc_ifname
#ifdef RTCONFIG_QCA_PLC2
			, "-A", nvram_safe_get("lan_ifname")
#endif
			, "-tn", "-d", str, NULL};
	pid_t pid;

	get_plc_ifname(plc_ifname);
	if (duration <= 0 || duration > 100)
		duration = 1;
	snprintf(str, sizeof(str), "%d", duration);
	_eval(plcrate_argv, NULL, 0, &pid);
}

int chk_plc_alive(void)
{
	char buf[256];
	return (plctool_get("-B 3", buf, sizeof(buf), NULL));
}

void do_plc_reset(int force)
{
	char plc_macaddr[18], *plc_mac;
	char plc_ifname[16];

	get_plc_ifname(plc_ifname);
	if (force || strcmp(plc_ifname, PLC_INTERFACE) == 0) {
		plc_mac = NULL;
	}
	else {
		strlcpy(plc_macaddr, nvram_safe_get("plc_macaddr"), sizeof(plc_macaddr));
		plc_mac = plc_macaddr;
	}
#ifdef RTCONFIG_QCA_PLC2
	eval("/usr/local/bin/plctool", "-i", plc_ifname, "-A", nvram_safe_get("lan_ifname"), "-R", plc_mac);
#else
	eval("/usr/local/bin/plctool", "-i", plc_ifname, "-R", plc_mac);
#endif
	nvram_set("plc_ready", "0");
	_dprintf("#PLC# reset\n");
}

char *plctool_cmd(const char *cmd, char buf[], int size)
{
	char plc_ifname[16];
	char plc_mac[18];
	char bridge[16];

	if (cmd == NULL || buf == NULL || size < 64)
		return "";

	get_plc_ifname(plc_ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif
	snprintf(plc_mac, sizeof(plc_mac), "%s", nvram_safe_get("plc_macaddr"));
	snprintf(buf, size, "/usr/local/bin/plctool -i %s %s %s -e %s", plc_ifname, bridge, cmd, plc_mac);
	return cmd;
}

int plctool_get(const char *cmd, char buf[], int size, const char *chk_str)
{
	FILE *fp;
	int len, cnt = 0;
	char mac[32];
	char *plc_mac;
	char plc_ifname[16];
	char bridge[16];

	get_plc_ifname(plc_ifname);
#ifdef RTCONFIG_QCA_PLC2
	snprintf(bridge, sizeof(bridge), "-A %s", nvram_safe_get("lan_ifname"));
#else
	bridge[0] = '\0';
#endif
	snprintf(mac, sizeof(mac), "%s %s", plc_ifname, nvram_safe_get("plc_macaddr"));
	plc_mac = mac + strlen(plc_ifname) +1;

	while (1) {
		snprintf(buf, size, "/usr/local/bin/plctool -i %s %s %s -e %s", plc_ifname, bridge, cmd, plc_mac);
	    if ((fp = popen(buf, "r"))) {
		len = fread(buf, 1, size, fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			if (strstr(buf, mac)) {
				if (chk_str == NULL || strstr(buf, chk_str))
					return 1;
			}
		}
	    }

		if (cnt > 3)
			break;
		cnt++;
		sleep(1);
	}
	dbg("%s: failed! cmd(%s) chk_str(%s)\n", __func__, cmd, chk_str);
	return 0;
}


int plc_wait_busy(void)
{
	char buf[1024];
	return plctool_get("-I", buf, sizeof(buf), "NMK ");
}


/* 
 * int do_plc_pushbutton(int pb_act)
 *
 * pb_act:
 * 	1: join
 * 	2: leave
 * 	3: status
 * 	4: reset
 * 	5: stop
 * 	6: start/extend
 * 	7: pbstat
 */
int do_plc_pushbutton(int pb_act)
{
	char cmd[16];
	char buf[512];
	char *chk_str = NULL;
	int ret;

	if(pb_act == 1)      chk_str = "Joining ...";
	else if(pb_act == 5) chk_str = "Stopping ...";
	else if(pb_act == 6) chk_str = "Starting/Extending timeout ...";


	snprintf(cmd, sizeof(cmd), "-B %d", pb_act);
	ret = plctool_get(cmd, buf, sizeof(buf), chk_str);
	return ret;
}

/* 
	get pbstat
0x001A 1 Previous Push Button state 
=0x00 = Idle
=0x01 = In Process
=0x02 = Adder
=0x03 = Joiner
=0x04 = Complete
=0x05 = Timeout
=0x06 = SCError

0x001B 1 Current Push Button state 
=0x00 = Idle
=0x01 = In Process
=0x02 = Adder
=0x03 = Joiner
=0x04 = Complete
=0x05 = Timeout
=0x06 = SCError

*/

int get_plc_pb_state(void)
{
	char buf[512];
	const char *chk_str = "Current PB State";
	char *p;
	int pb_state;

	if (plctool_get("-B 7", buf, sizeof(buf), chk_str) == 0)
		return -1;

	if ((p = strstr(buf, chk_str)) == NULL)
		return -1;

	pb_state = atoi(p + strlen(chk_str) + 1);
	return pb_state;
}


