
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <typedefs.h>
#include <bcmnvram.h>
#include <sys/ioctl.h>
#include <alpine.h>
#include <iwlib.h>
#include "utils.h"
#include "shutils.h"
#include <shared.h>
#include <trxhdr.h>
#include <bcmutils.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

int update_trx(char *imagefile)
{
	int ifd = -1;
	int ret = 1;
	struct stat sbuf;
	unsigned char *ptr = NULL;
	struct trx_header *trx;
	long uimage_offset, uimage_size, target_offset, target_size;
	char update_cmd[255];
	char tmp_file[15]="/tmp/trx.tmp";

	ifd = open(imagefile, O_RDONLY);
	if (ifd < 0) {
		_dprintf("Can't open %s: %d\n", imagefile, strerror(errno));
		ret = 0;
		goto update_trx_fail;
	}

	(void)fdatasync(ifd);

	if (fstat(ifd, &sbuf) < 0) {
		_dprintf("Can't stat %s: %d\n", imagefile, strerror(errno));
		ret = 0;
		goto update_trx_fail;
	}

	ptr = (unsigned char *)mmap(0, sbuf.st_size,
				    PROT_READ, MAP_SHARED, ifd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		_dprintf("Can't map %s: %s\n", imagefile, strerror(errno));
		ret = 0;
		goto update_trx_fail;
	}

	trx = (struct trx_header *) ptr;

	uimage_offset = trx->offsets[0];
	uimage_size = trx->offsets[1] - trx->offsets[0];
	target_offset = uimage_offset + uimage_size;
	target_size = trx->offsets[2] - trx->offsets[1];
#if 0
	_dprintf("uimage_offset:[%08X][%d]\n", uimage_offset, uimage_offset);
	_dprintf("uimage_size:[%08X][%d]\n", uimage_size, uimage_size);
	_dprintf("target_offset:[%08X][%d]\n", target_offset, target_offset);
	_dprintf("target_size:[%08X][%d]\n", target_size, target_size);
#endif

	snprintf(update_cmd, sizeof(update_cmd),
		"dd if=%s bs=%d skip=1 of=%s", imagefile, uimage_offset, tmp_file);
	_dprintf(update_cmd);
	system(update_cmd);

	system("flash_erase -q /dev/mtd2 0 0");

	snprintf(update_cmd, sizeof(update_cmd),
		"dd if=%s bs=%d count=1 | nandwrite -q -m -p -s 0x100000 /dev/mtd2",
		tmp_file, uimage_size);
	system(update_cmd);

	snprintf(update_cmd, sizeof(update_cmd), "rm -f %s", tmp_file);
	system(update_cmd);

	snprintf(update_cmd, sizeof(update_cmd),
		"dd if=%s bs=%d skip=1 of=%s", imagefile, target_offset, tmp_file);
	system(update_cmd);

	system("flash_erase -q /dev/mtd4 0 0");

	snprintf(update_cmd, sizeof(update_cmd),
		"dd if=%s bs=%d count=1 | nandwrite -q -m -p /dev/mtd4",
		tmp_file, target_size);
	system(update_cmd);

	snprintf(update_cmd, sizeof(update_cmd), "rm -f %s", tmp_file);
	system(update_cmd);


update_trx_fail:
	close(ifd);
	return ret;
}

int checkcrc(char *imagefile)
{
	int ifd = -1;
	int ret = 1;
	struct stat sbuf;
	unsigned char *ptr = NULL;
	uint32_t checksum;
	int len = 0;
	struct trx_header *trx;

	ifd = open(imagefile, O_RDONLY);
	if (ifd < 0) {
		_dprintf("Can't open %s: %d\n", imagefile, strerror(errno));
		ret = 0;
		goto checkcrc_end;
	}

	(void)fdatasync(ifd);

	if (fstat(ifd, &sbuf) < 0) {
		_dprintf("Can't stat %s: %d\n", imagefile, strerror(errno));
		ret = 0;
		goto checkcrc_fail;
	}

	ptr = (unsigned char *)mmap(0, sbuf.st_size,
				    PROT_READ, MAP_SHARED, ifd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		_dprintf("Can't map %s: %s\n", imagefile, strerror(errno));
		ret = 0;
		goto checkcrc_fail;
	}

	trx = (struct trx_header *) ptr;
	len = trx->len;

	checksum = crc_calc(0xffffffff,
		&trx->flag_version, len - sizeof(trx->magic) - sizeof(trx->len) - sizeof(trx->crc32));

	if(ntohl(trx->crc32) != ntohl(checksum)) ret = 0 ;

checkcrc_fail:
	if (ptr != NULL)
		munmap(ptr, sbuf.st_size);
	(void)fdatasync(ifd);

checkcrc_end:
	if (close(ifd)) {
		_dprintf("Read error on %s: %s\n", imagefile, strerror(errno));
		ret = -1;
	}
	return ret;
}

