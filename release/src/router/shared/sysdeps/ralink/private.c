
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
#if !defined(__GLIBC__) && !defined(__UCLIBC__) /* musl */
#else
#include <linux/sockios.h>
#endif
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
#include <image.h>

#ifndef O_BINARY
#define O_BINARY 	0
#endif

typedef uint32_t __u32;

#define SWAP_LONG(x) \
	((__u32)( \
		(((__u32)(x) & (__u32)0x000000ffUL) << 24) | \
		(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) | \
		(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) | \
		(((__u32)(x) & (__u32)0xff000000UL) >> 24) ))

/* 0: it is not a legal image
 * 1: it is legal image
 */
int check_imageheader(char *buf, long *filelen)
{
	uint32_t checksum;
	image_header_t header2;
	image_header_t *hdr, *hdr2;
	char buf_productid[MAX_STRING + 1]= {0};
	hdr  = (image_header_t *) buf;
	hdr2 = &header2;
	
	/* check header magic */
	if (SWAP_LONG(hdr->ih_magic) != IH_MAGIC) {
		_dprintf ("Bad Magic Number\n");
		return 0;
	}

	/* check header crc */
	memcpy (hdr2, hdr, sizeof(image_header_t));
	hdr2->ih_hcrc = 0;
	checksum = crc_calc(0, (const char *)hdr2, sizeof(image_header_t));
	_dprintf("header crc: %X\n", checksum);
	_dprintf("org header crc: %X\n", SWAP_LONG(hdr->ih_hcrc));
	if (checksum != SWAP_LONG(hdr->ih_hcrc))
	{
		_dprintf("Bad Header Checksum\n");
		return 0;
	}

	{
		strncpy(buf_productid, buf + 36, MAX_STRING);
		if(strcmp(buf_productid, nvram_safe_get("productid"))==0) {
			*filelen  = SWAP_LONG(hdr->ih_size);
			*filelen += sizeof(image_header_t);
#ifdef RTCONFIG_DSL
			// DSL product may have modem firmware
			*filelen+=(512*1024);			
#endif		
			_dprintf("image len: %x\n", *filelen);	
			return 1;
		}
	}
	return 0;
}

int
checkcrc(char *fname)
{
	int ifd = -1;
	uint32_t checksum;
	struct stat sbuf;
	unsigned char *ptr = NULL;
	image_header_t *hdr;
	char *imagefile;
	int ret = -1;
	int len, dev;

	imagefile = fname;
	dev = !strncmp(fname, "/dev/mtd", 8);
//	fprintf(stderr, "img file: %s\n", imagefile);

	ifd = open(imagefile, O_RDONLY|O_BINARY);

	if (ifd < 0) {
		_dprintf("Can't open %s: %s\n",
			imagefile, strerror(errno));
		goto checkcrc_end;
	}

	/* We're a bit of paranoid */
#if defined(_POSIX_SYNCHRONIZED_IO) && !defined(__sun__) && !defined(__FreeBSD__)
	(void) fdatasync (ifd);
#else
	(void) fsync (ifd);
#endif
	if (fstat(ifd, &sbuf) < 0) {
		_dprintf("Can't stat %s: %s\n",
			imagefile, strerror(errno));
		goto checkcrc_fail;
	}

	ptr = (unsigned char *)mmap(0, sbuf.st_size,
				    PROT_READ, MAP_SHARED, ifd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		_dprintf("Can't map %s: %s\n",
			imagefile, strerror(errno));
		goto checkcrc_fail;
	}
	hdr = (image_header_t *)ptr;

	/* check image header */
	if(check_imageheader((char*)hdr, (long*)&len) == 0)
	{
		_dprintf("Check image heaer fail !!!\n");
		goto checkcrc_fail;
	}

	len = SWAP_LONG(hdr->ih_size);

#ifdef TRX_NEW
	if (!check_trx((char*)hdr))
		return 2;
#endif

	if (sbuf.st_size < (len + sizeof(image_header_t))) {
		_dprintf("Size mismatch %lx/%lx !!!\n", sbuf.st_size, (len + sizeof(image_header_t)));
		goto checkcrc_fail;
	}

	/* check body crc */
	_dprintf("Verifying Checksum ... ");
	checksum = crc_calc(0, (const char *)ptr + sizeof(image_header_t), len);
	if(checksum != SWAP_LONG(hdr->ih_dcrc))
	{
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
	if(ptr != NULL)
		munmap(ptr, sbuf.st_size);
#if defined(_POSIX_SYNCHRONIZED_IO) && !defined(__sun__) && !defined(__FreeBSD__)
	(void) fdatasync (ifd);
#else
	(void) fsync (ifd);
#endif
	if (close(ifd)) {
		_dprintf("Read error on %s: %s\n",
			imagefile, strerror(errno));
		ret=-1;
	}
checkcrc_end:
	return ret;
}
#ifdef TRX_NEW
/*
 * 0: illegal image
 * 1: legal image
 */

int check_trx(char *buf)
{
	uint32_t checksum;
	image_header_t header2;
	image_header_t *hdr, *hdr2;

	hdr  = (image_header_t *) buf;
	hdr2 = &header2;
	int i = 0;
	char *sn = NULL, *en = NULL;
	char tmp[10];
	uint8_t lrand = 0;
	uint8_t rrand = 0;
	uint32_t rfs_offset=0;	
	uint32_t linux_offset = 0;
	uint32_t rootfs_offset = 0;
	uint8_t key = 0;
	uint8_t get_key = 0;
	uint32_t image_size = SWAP_LONG(hdr->ih_size);

		version_t *hw = &(hdr->u.tail.hw[0]);
		union {
			uint32_t rfs_offset_net_endian;
			uint8_t p[4];
		} u;
		rfs_offset = u.rfs_offset_net_endian = 0;


	//_dprintf("##### image_size = %02x\n", image_size);

	memcpy (hdr2, hdr, sizeof(image_header_t));

	//_dprintf("##### hdr2.tail.sn = %02x\n", hdr->u.tail.sn);
	//_dprintf("##### hdr2.tail.en = %02x\n", hdr->u.tail.en);
	//_dprintf("##### hdr2.tail.key = %02x\n", hdr->u.tail.key);

#ifdef RTCONFIG_NVRAM_ENCRYPT
	int enc_sp_extendno = nvram_get_int("enc_sp_extendno");
	if (!hdr->u.tail.sn || !hdr->u.tail.en || hdr->u.tail.sn < 382 || (hdr->u.tail.sn == 382 && hdr->u.tail.en < enc_sp_extendno))
	{
		_dprintf("version check fail!\n");
		return 0;
	}
#endif

	u.rfs_offset_net_endian = 0;

	for (i = 0; i < (MAX_VER); ++i, ++hw) 	
	{
		if (hw->major != ROOTFS_OFFSET_MAGIC || (hw + 1)->minor & 0x3)
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

	//_dprintf ("Key:          %02x\n", key);    

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
