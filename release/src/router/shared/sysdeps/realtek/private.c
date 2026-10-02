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
#include <errno.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <linux_gpio.h>
#include <etioctl.h>
#include "utils.h"
#include "shutils.h"
#include <sys/mman.h>
#include <trxhdr.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <wlioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#include "image.h"
#include "realtek_common.h"
#include <wlscan.h>

#define rtklog(fmt,args...) do {} while(0)
#define rtk_printf(fmt,args...) do {} while(0)
#ifndef O_BINARY
#define O_BINARY        0
#endif

/*
 * 0: illegal image
 * 1: legal image
 */
int check_imageheader(char *buf, long *filelen)
{
	uint32_t checksum;
	image_header_t header2;
	image_header_t *hdr, *hdr2;

	hdr  = (image_header_t *) buf;
	hdr2 = &header2;

	/* check header magic */
	if (ntohl(hdr->ih_magic) != IH_MAGIC) {
		//rtklog("Bad Magic Number\n");
		return 0;
	}

	/* check header crc */
	memcpy (hdr2, hdr, sizeof(image_header_t));
	hdr2->ih_hcrc = 0;
	checksum = crc_calc(0, (const char *)hdr2, sizeof(image_header_t));
	rtklog("header crc: %X\n", checksum);
	rtklog("org header crc: %X\n", ntohl(hdr->ih_hcrc));
	if (checksum != ntohl(hdr->ih_hcrc))
	{
		rtklog("Bad Header Checksum\n");
		return 0;
	}

	{
		if(strcmp(buf+36, nvram_safe_get("productid"))==0) {
			*filelen  = ntohl(hdr->ih_size);
			*filelen += sizeof(image_header_t);
#ifdef RTCONFIG_DSL
			// DSL product may have modem firmware
			*filelen+=(512*1024);			
#endif		
			rtklog("image len: %x\n", *filelen);	
			return 1;
		}
	}
	return 0;
}

/*
 * 0: illegal image
 * 1: legal image
 */
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
	int len;

	imagefile = fname;
//	fprintf(stderr, "img file: %s\n", imagefile);

	ifd = open(imagefile, O_RDONLY|O_BINARY);

	if (ifd < 0) {
		rtklog("Can't open %s: %s\n",
			imagefile, strerror(errno));
		goto checkcrc_end;
	}

	/* We're a bit of paranoid */
#if defined(_POSIX_SYNCHRONIZED_IO) && !defined(__sun__) && !defined(__FreeBSD__) && !defined(RPAC92) 
	(void) fdatasync (ifd);
#else
	(void) fsync (ifd);
#endif
	if (fstat(ifd, &sbuf) < 0) {
		rtklog("Can't stat %s: %s\n",
			imagefile, strerror(errno));
		goto checkcrc_fail;
	}

	ptr = (unsigned char *)mmap(0, sbuf.st_size,
				    PROT_READ, MAP_SHARED, ifd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		rtklog("Can't map %s: %s\n",
			imagefile, strerror(errno));
		goto checkcrc_fail;
	}
	hdr = (image_header_t *)ptr;

	/* check image header */
	if(check_imageheader((char*)hdr, (long*)&len) == 0)
	{
		rtklog("Check image heaer fail !!!\n");
		goto checkcrc_fail;
	}

	len = ntohl(hdr->ih_size);

#ifdef TRX_NEW
	if (!check_trx((char*)hdr))
		return 2;
#endif
	if (sbuf.st_size < (len + sizeof(image_header_t))) {
		rtklog("Size mismatch %lx/%lx !!!\n", sbuf.st_size, (len + sizeof(image_header_t)));
		goto checkcrc_fail;
	}

	/* check body crc */
	rtklog("Verifying Checksum ... ");
	checksum = crc_calc(0, (const char *)ptr + sizeof(image_header_t), len);
	if(checksum != ntohl(hdr->ih_dcrc))
	{
		rtklog("Bad Data CRC\n");
		goto checkcrc_fail;
	}
	rtklog("OK\n");

	ret = 0;

	/* We're a bit of paranoid */
checkcrc_fail:
	if(ptr != NULL)
		munmap(ptr, sbuf.st_size);
#if defined(_POSIX_SYNCHRONIZED_IO) && !defined(__sun__) && !defined(__FreeBSD__) && !defined(RPAC92)
	(void) fdatasync (ifd);
#else
	(void) fsync (ifd);
#endif
	if (close(ifd)) {
		rtklog("Read error on %s: %s\n",
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
	uint32_t image_size = ntohl(hdr->ih_size);

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

	u.rfs_offset_net_endian = 0;

	for (i = 0; i < (MAX_VER); ++i, ++hw) 	
	{
		if (hw->major != ROOTFS_OFFSET_MAGIC)
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
 *
 * check product id, crc ..
 */

int check_imagefile(char *fname)
{
	rtklog("%d fname=%s \n",__LINE__,fname);
	if(checkcrc(fname)==0) return 0;
	return 1;
}

