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
#include <bcmutils.h>
#include <bcmendian.h>
#include <trxhdr.h>
#include <sys/mman.h>
#if defined(RTCONFIG_SOC_IPQ8074)
#include <qca.h>
#endif
#include "image.h"

#ifndef O_BINARY
#define O_BINARY 	0
#endif

int check_trx(char *fname, char *buf);

/* 0: it is not a legal image
 * 1: it is legal image
 * 2: it is multiple firmware
 */
int check_imageheader(char *buf, long *filelen)
{
	uint32_t checksum;
	image_header_t header2;
	image_header_t *hdr, *hdr2;
	char productid[16];

	hdr = (image_header_t *) buf;
	hdr2 = &header2;

	/* check header magic */
	if (ntohl(hdr->ih_magic) != IH_MAGIC) {
		_dprintf("Bad Magic Number\n");
		return 0;
	}

	/* check header crc */
	memcpy(hdr2, hdr, sizeof(image_header_t));
	hdr2->ih_hcrc = 0;
	checksum = crc_calc(0, (const char *)hdr2, sizeof(image_header_t));
	_dprintf("header crc: %X\n", checksum);
	_dprintf("org header crc: %X\n", ntohl(hdr->ih_hcrc));
	if (checksum != ntohl(hdr->ih_hcrc)) {
		_dprintf("Bad Header Checksum\n");
		return 0;
	}

	snprintf(productid, sizeof(productid), "%s", nvram_safe_get("productid"));
#ifdef RTCONFIG_MULTIFW
	if (!strncmp(buf + 36, "MULTIFW", 7)) {
		*filelen = ntohl(hdr->ih_size);
		*filelen += sizeof(image_header_t);
		_dprintf("%s: multiple firmware!\n", __func__);
		return 2;
	}
	else
#endif
	if (!strncmp(buf + 36, productid, strlen(productid))) {
		*filelen = ntohl(hdr->ih_size);
		*filelen += sizeof(image_header_t);
		_dprintf("image len: %x\n", *filelen);
		return 1;
	}
	return 0;
}

#ifdef RTCONFIG_MULTIFW
static int find_trx(char *buf, int filelen)
{
	int len;
	int count = filelen;
	int hdr_len = sizeof(image_header_t);
	image_header_t *hdr;

	buf += hdr_len;
	count -= hdr_len;
	do {
		hdr = (image_header_t *) buf;
		if (!check_imageheader((char *)hdr, (long *)&len)) {
			int skip_len = ntohl(hdr->ih_size) + hdr_len;

			count -= skip_len;
			buf += skip_len;
		}
		else {
			nvram_set_int("trx_skip", filelen - count);
			nvram_set_int("trx_count", len);

			return 1;
		}
	} while (count > 0);

	return 0;
}
#endif

/* Verify firmware.
 * @fname:	reuglar filename, or /dev/mtdblockX which points to "linux" or "linux2" mtd partition.
 * @return:
 * 	0:	legal firmware
 *  otherwise:	illegal firmware or error.
 */
int checkcrc(char *fname)
{
	int ifd = -1;
	uint32_t checksum;
	struct stat sbuf;
	unsigned char *ptr = NULL;
	image_header_t h, *hdr;
	char *imagefile, dpath[sizeof("/dev/mtdblockXYYYYYY")];
	int ret = -1;
	int len, dev;
	uint32_t sf = 0;

	if (!fname || *fname == '\0')
		return -1;

	dev = !strncmp(fname, "/dev/mtd", 8);
	if (dev) {
		/* /dev/mtdX, /dev/mtdblockX */
		if (!strncmp(fname, "/dev/mtdblock", 13))
			imagefile = fname;
		else {
			/* /dev/mtdX ==> /dev/mtdblockX */
			snprintf(dpath, sizeof(dpath), "/dev/mtdblock%s", fname + 8);
			imagefile = dpath;
		}

		if (f_read(imagefile, &h, sizeof(h)) < sizeof(h)) {
			_dprintf("Can't read header: %s\n", imagefile, strerror(errno));
			goto checkcrc_end;
		}

		hdr = &h;
		/* check image header and get firmware length */
		if (!check_imageheader((char *)hdr, (long *)&len)) {
			_dprintf("Check image heaer fail !!!\n");
			goto checkcrc_fail;
		}

		len = ntohl(hdr->ih_size);
		ifd = open(imagefile, O_RDONLY | O_BINARY);
		if (ifd < 0) {
			_dprintf("Can't open %s: %s\n", imagefile, strerror(errno));
			goto checkcrc_end;
		}

		ptr = (unsigned char *)mmap(0, len + sizeof(h), PROT_READ, MAP_SHARED, ifd, 0);
		if (ptr == (unsigned char *)MAP_FAILED) {
			_dprintf("Can't map %s: %s\n", imagefile, strerror(errno));
			goto checkcrc_fail;
		}
		hdr = (image_header_t *) ptr;
	} else {
		/* regular file, e.g., /tmp/linux.trx */
		imagefile = fname;
		ifd = open(imagefile, O_RDONLY | O_BINARY);
		if (ifd < 0) {
			_dprintf("Can't open %s: %s\n", imagefile, strerror(errno));
			goto checkcrc_end;
		}

		/* We're a bit of paranoid */
		fdatasync(ifd);
		if (fstat(ifd, &sbuf) < 0) {
			_dprintf("Can't stat %s: %s\n", imagefile, strerror(errno));
			goto checkcrc_fail;
		}

		ptr = (unsigned char *)mmap(0, sbuf.st_size,
					    PROT_READ, MAP_SHARED, ifd, 0);
		if (ptr == (unsigned char *)MAP_FAILED) {
			_dprintf("Can't map %s: %s\n", imagefile, strerror(errno));
			goto checkcrc_fail;
		}
		hdr = (image_header_t *) ptr;

		/* check image header */
		ret = check_imageheader((char *)hdr, (long *)&len);
#ifdef RTCONFIG_MULTIFW
		nvram_set("trx_skip", "");
		nvram_set("trx_count", "");
		if (ret == 2)
			ret = find_trx(ptr, len);
#endif
		if (!ret) {
			_dprintf("Check image heaer fail !!!\n");
			goto checkcrc_fail;
		}

		len = ntohl(hdr->ih_size);
	}

#ifdef TRX_NEW
	if (!check_trx(fname, (char*)hdr))
	{
		_dprintf("check trx fail!!\n");
		return 2;
	}
#endif

	if (!dev && sbuf.st_size < (len + sizeof(image_header_t))) {
		_dprintf("Size mismatch %lx/%lx !!!\n", sbuf.st_size, len + sizeof(image_header_t));
		goto checkcrc_fail;
	}

	/* check body crc */
	_dprintf("Verifying Checksum ... ");
	checksum = crc_calc(0, (const char *)ptr + sizeof(image_header_t), len);
	if (checksum != ntohl(hdr->ih_dcrc)) {
		_dprintf("Bad Data CRC\n");
		goto checkcrc_fail;
	}
	_dprintf("OK\n");

#ifdef RTCONFIG_TAIL_INFO
	nvram_unset("tail_buildno");
	nvram_unset("tail_extendno");
	if (!dev) { /* check incoming trx file */
		basic_tailhdr_t tail_hdr, *thdr_pt;
		uint32_t content_len;
		unsigned char *content_pt;
		uint16_t *p, bk_sum, sum;
		int i;

		thdr_pt = (basic_tailhdr_t *)(ptr + sizeof(image_header_t) + len - sizeof(basic_tailhdr_t));
		memcpy(&tail_hdr, thdr_pt, sizeof(basic_tailhdr_t));

		if (TAIL_MAGIC != ntohl(tail_hdr.magic)) {
			_dprintf("__TAIL__: invalid tail magic\n");
			goto invalid_tail;
		}

		bk_sum = ntohs(tail_hdr.hdr_checksum);
		tail_hdr.hdr_checksum = 0;
		p = (uint16_t *)&tail_hdr;
		for (i = 0, sum = 0; i < ( sizeof(basic_tailhdr_t)/ 2); ++i, ++p)
			sum ^= __le16_to_cpu(*p);
		sum ^= 0xFFFF;
		if (bk_sum != sum) {
			_dprintf("__TAIL__: hdr checksum mismatch: %04x, c:%04x\n", bk_sum, sum);
			goto invalid_tail;
		}

		tail_hdr.content_checksum = ntohs(tail_hdr.content_checksum);
		tail_hdr.content_len_l = ntohs(tail_hdr.content_len_l);
		// _dprintf("content_len_l:%04x, content_len_h:%02x\n", tail_hdr.content_len_l, tail_hdr.content_len_h);
		content_len = tail_hdr.content_len_l;
		content_len += ((uint32_t)tail_hdr.content_len_h) << 16;
		_dprintf("__TAIL__: type:%02x, flags:%02x, content len:%08x, checksum:%04x\n", tail_hdr.type, tail_hdr.flags, content_len, tail_hdr.content_checksum);

		if (content_len + sizeof(basic_tailhdr_t) > len) {
			_dprintf("__TAIL__: content len too big: %08x(trx len:%08x)\n", content_len, len);
			goto invalid_tail;
		}

		content_pt = (unsigned char *)thdr_pt - content_len;
		p = (uint16_t *)content_pt;
		for (i = 0, sum = 0; i < ( content_len/ 2); ++i, ++p)
			sum ^= __le16_to_cpu(*p);
		sum ^= 0xFFFF;
		if (tail_hdr.content_checksum != sum) {
			_dprintf("__TAIL__: content checksum mismatch: %04x, c:%04x\n", tail_hdr.content_checksum, sum);
			goto invalid_tail;
		}

		// OK, go to handle content
		switch (tail_hdr.type) {
			case 1: {
				t1_content_t t1_hdr;
				memcpy(&t1_hdr, content_pt, sizeof(t1_content_t));
				t1_hdr.buildno = ntohs(t1_hdr.buildno);
				t1_hdr.extendno = ntohl(t1_hdr.extendno);
				t1_hdr.reserved16 = ntohs(t1_hdr.reserved16);
				t1_hdr.reserved32 = ntohl(t1_hdr.reserved32);
				sf = t1_hdr.reserved32;	/* supported feature */
				_dprintf("__TAIL__: buildno: %04x, extendno: %08x, r16:%08x, r32:%08x\n", \
						t1_hdr.buildno, t1_hdr.extendno, t1_hdr.reserved16, t1_hdr.reserved32);
				nvram_set_int("tail_buildno", t1_hdr.buildno);
				nvram_set_int("tail_extendno", t1_hdr.extendno);
				break;
				}
			default:
				_dprintf("__TAIL__: not support type: %02x\n", tail_hdr.type);
				break;
		}
	}
invalid_tail:
#endif
	ret = 0;

	/* We're a bit of paranoid */
checkcrc_fail:
	if (ptr != NULL)
		munmap(ptr, sbuf.st_size);
	if (!dev && ifd >= 0)
		fdatasync(ifd);
	if (ifd >= 0 && close(ifd)) {
		_dprintf("Read error on %s: %s\n", imagefile, strerror(errno));
		ret = -1;
	}

checkcrc_end:
	if (ret == 0)
		firmware_downgrade_check(sf);
	return ret;
}

#ifdef TRX_NEW
#if defined(RTCONFIG_SOC_IPQ8074)
#define HE20_Q6FWVERFILE	"lib/firmware/IPQ8074A/fw_version.txt"
/** Platform-specific check_trx.
 * @buf:	pointer to a firmware image.
 * @return:
 * 	0:	illegal image
 * 	1:	legal image
 */
static int platform_check_trx(char *fname, char *buf)
{
	int socver_maj = get_soc_version_major();

	if (socver_maj != 2 || !f_exists(UNSQUASHFS))
		return 1;

	/* Hawkeye 2.0 need SPF10 or above, that have both /lib/firmware/{IPQ8074,IPQ8074A} */
	if (socver_maj == 2) {
		/* Extract U-Boot binaries from /lib/firmware/.u-boot of @fname. */
		if (d_exists(SQUASHFS_ROOT))
			eval("rm", "-fr", SQUASHFS_ROOT);
		eval(UNSQUASHFS, "-d", SQUASHFS_ROOT, fname, HE20_Q6FWVERFILE);
		system("ls -al " SQUASHFS_ROOT "/lib/firmware");
		if (!f_exists(SQUASHFS_ROOT "/" HE20_Q6FWVERFILE)) {
			dbg("%s doesn't support HE20!\n", fname);
			logmessage("CHKTRX", "%s doesn't support HE20!\n", fname);
			return 0;
		}
		unlink(SQUASHFS_ROOT "/" HE20_Q6FWVERFILE);
	}

	return 1;
}
#else
static inline int platform_check_trx(char *fname, char *buf) { return 1; }
#endif

/*
 * 0: illegal image
 * 1: legal image
 */

int check_trx(char *fname, char *buf)
{
	image_header_t header2;
	image_header_t *hdr, *hdr2;

	hdr  = (image_header_t *) buf;
	hdr2 = &header2;
	int i = 0;
	uint8_t lrand = 0;
	uint8_t rrand = 0;
	uint32_t rfs_offset=0;	
	uint32_t linux_offset = 0;
	uint32_t rootfs_offset = 0;
	uint8_t key = 0;
	uint32_t image_size = ntohl(hdr->ih_size);
	uint16_t sn, en;

		version_t *hw = &(hdr->u.tail.hw[0]);
		union {
			uint32_t rfs_offset_net_endian;
			uint8_t p[4];
		} u;
		rfs_offset = u.rfs_offset_net_endian = 0;

	memcpy (hdr2, hdr, sizeof(image_header_t));

	/* mkimage store little endian sn & en... */
	sn = __le16_to_cpu(hdr->u.tail.sn);
	en = __le16_to_cpu(hdr->u.tail.en);
       _dprintf("##### hdr2.tail.sn = %04x\n", sn);
       _dprintf("##### hdr2.tail.en = %04x\n", en);
       _dprintf("##### hdr2.tail.key = %02x\n", hdr->u.tail.key);

#ifdef RTCONFIG_NVRAM_ENCRYPT
	int enc_sp_extendno = nvram_get_int("enc_sp_extendno");
	if (!sn || !en || sn < 382 || (sn == 382 && en < enc_sp_extendno))
	{
		_dprintf("version check fail!\n");
		return 0;
	}
#endif
#if defined(RTCONFIG_QSDK6PLUS) && (defined(RTCONFIG_QCA953X) || \
				    defined(RTCONFIG_QCA956X) || \
				    defined(RTCONFIG_QCN550X))
	/* sn/en is the latest firmware on the official website */
	if (!sn || !en 
#if defined(MAPAC1750)
/* TBD if firmware enter 386 branch */
#elif defined(RTN19)
/* TBD if firmware enter 386 branch */
#elif defined(RTAC59U) /* for V2 */
	 || sn < 386 || (sn == 386 && en <= 21649)
#elif defined(RTAC59_CD6R) || defined(RTAC59_CD6N)
	 || sn < 386 || (sn == 386 && en <= 39421)
#endif
	) {
		_dprintf("Downgrade firmware is not allowed, otherwise nvram will be cleared\n");
		return 0;
	}
#endif

	u.rfs_offset_net_endian = 0;

	for (i = 0; i < (MAX_VER); ++i, ++hw) 	
	{
		if (hw->major != ROOTFS_OFFSET_MAGIC
#if !defined(RTCONFIG_FITFDT)
		 || (hw + 1)->minor & 0x3
#endif
		   )
			continue;
		u.p[1] = hw->minor;
		hw++;
		u.p[2] = hw->major;
		u.p[3] = hw->minor;
		rfs_offset = ntohl(u.rfs_offset_net_endian);
	}

		
		linux_offset = rfs_offset / 2 ;  
		lrand = *(buf + linux_offset); //get kernel data
	//_dprintf("rfs_offset = %02x  lrand = %02x linux_offset=%02x\n", rfs_offset, lrand, linux_offset);	
		rootfs_offset = rfs_offset  + ((image_size + sizeof(image_header_t)  - rfs_offset) / 2) ;
		rrand = *(buf  + rootfs_offset );	//get kernel data
	//_dprintf("rfs_offset = %02x  rrand = %02x  rootfs_offset=%02x\n", rfs_offset, rrand , rootfs_offset);		
	
	if (rrand== 0x0)
		key = 0xfd + lrand % 3;
	else
		key = 0xff - rrand + lrand;

	_dprintf ("##### Key = %02x\n", key);
	
	if (!platform_check_trx(fname, buf))
		return 0;

	if (hdr->u.tail.key == key)
		return 1; 

	return 0;
}
#endif

/* 
 * 0: legal image
 * 1: illegal image
 * 2: new trx format validation failure
 * check product id, crc ..
 */

int check_imagefile(char *fname)
{
	return checkcrc(fname);
}

#if defined(RTCONFIG_QCA) && !defined(RTCONFIG_SOC_IPQ40XX)
/* Get firmware length
 * NOTE:	This function checks header checksum and return firmware length only.
 * @ptr:	pointer to a firmware image.
 * @return:
 * 	> 0:	firmware length.
 * 	<= 0:	invalid parameter, invalid firmware image, etc
 */
int get_firmware_length(void *ptr)
{
	long len = 0;

	if (!ptr || !check_imageheader(ptr, &len))
		return 0;

	return len;
}
#endif
