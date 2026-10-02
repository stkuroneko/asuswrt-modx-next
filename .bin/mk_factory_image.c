/*
 * (C) Copyright 2000-2004
 * DENX Software Engineering
 * Wolfgang Denk, wd@denx.de
 * All rights reserved.
 *
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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#define FACTORY_IMAGE_MAGIC	0x46545259	/* 'F', 'T', 'R', 'Y' */

#ifndef O_BINARY
#define O_BINARY 0
#endif

typedef struct eeprom_set_hdr_s {
	uint32_t ih_magic;	/* Image Header Magic Number = 'F', 'T', 'R', 'Y' */
	uint32_t ih_hcrc;	/* Image Header CRC Checksum    */
	uint32_t ih_hdr_ver;	/* Image Header Version Number  */
	uint32_t ih_write_ver;	/* Number of writes             */
	uint32_t ih_dcrc;	/* Image Data CRC Checksum      */
} eeprom_set_hdr_t;

extern unsigned long crc32(unsigned long crc, const char *buf,
			   unsigned int len);
void usage(void);
static void copy_file(int ifd, const char *datafile, int pad, int count);

char *cmdname;

int main(int argc, char **argv)
{
	int i, ifd, opt, count = 1;
	int tmp;
	long hdr_offset = (128 - 2) * 1024L, block_size = (128) * 1024L;
	const char *datafile = NULL, *imagefile = NULL;
	unsigned char *ptr = NULL, *data = NULL;
	unsigned long checksum;
	struct stat sbuf;
	eeprom_set_hdr_t *hdr;

	cmdname = argv[0];
	while ((opt = getopt(argc, argv, "d:s:p:o:c:")) != -1) {
		switch (opt) {
		case 'd':
			datafile = optarg;
			break;
		case 'o':
			imagefile = optarg;
			break;
		case 'c':
			tmp = atoi(optarg);
			if (tmp <= 0) {
				printf("Invalid duplicate count %d\n", count);
				return -1;
			}
			count = tmp;
			break;
		default:
			usage();
		}
	}

	if (!datafile) {
		printf("datafile is not specified!\n");
		return -1;
	}
	if (!imagefile) {
		printf("imagefile is not specified!\n");
		return -1;
	}

	printf("===============================\n");
	printf("datafile:	%s\n", datafile);
	printf("imagefile:	%s\n", imagefile);
	printf("header offset:	0x%lx\n", hdr_offset);
	printf("Block size:	0x%lx\n", block_size);
	printf("Dup. count:	%d\n", count);
	printf("===============================\n");

	ifd = open(imagefile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0666);
	if (ifd < 0) {
		fprintf(stderr, "%s: Can't open %s: %s\n", cmdname, imagefile,
			strerror(errno));
		return -2;
	}

	copy_file(ifd, datafile, 0, count);

	/* We're a bit of paranoid */
	fsync(ifd);

	if (fstat(ifd, &sbuf) < 0) {
		fprintf(stderr, "%s: Can't stat %s: %s\n", cmdname, imagefile,
			strerror(errno));
		return -3;
	}
	ptr = mmap(0, sbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, ifd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		fprintf(stderr, "%s: Can't map %s: %s\n", cmdname, imagefile,
			strerror(errno));
		return -2;
	}

	data = ptr;
	for (i = 0; i < count; ++i) {
		printf("hdr offset:\t0x%x\n", (data + hdr_offset - ptr));
		hdr = (eeprom_set_hdr_t *) (data + hdr_offset);
		checksum = crc32(0, (const char *)data, hdr_offset);

		/* Build new header */
		hdr->ih_magic = htonl(FACTORY_IMAGE_MAGIC);
		hdr->ih_hcrc = 0;
		hdr->ih_hdr_ver = htonl(1);
		hdr->ih_write_ver = htonl(0);
		hdr->ih_dcrc = htonl(checksum);

		checksum =
		    crc32(0, (const char *)hdr, sizeof(eeprom_set_hdr_t));
		hdr->ih_hcrc = htonl(checksum);

		printf("hdr checksum:\t0x%08x\n", ntohl(hdr->ih_hcrc));
		printf("data checksum:\t0x%08x\n", ntohl(hdr->ih_dcrc));

		data += block_size;
		fsync(ifd);
	}

	munmap((void *)ptr, sbuf.st_size);

	/* We're a bit of paranoid */
	fsync(ifd);

	if (close(ifd)) {
		fprintf(stderr, "%s: Write error on %s: %s\n", cmdname,
			imagefile, strerror(errno));
		return -2;
	}

	return 0;
}

/* Copy datafile to ifd descriptor.
 * @ifd:	output file descriptor
 * @datafile:	input file name
 * @pad:	if true, pad to 4-byte boundary
 */
static void copy_file(int ifd, const char *datafile, int pad, int count)
{
	int dfd;
	struct stat sbuf;
	unsigned char *ptr;
	int tail;
	int zero = 0;
	int offset = 0;
	int size;

	if (count <= 0)
		exit(-2);

	if ((dfd = open(datafile, O_RDONLY | O_BINARY)) < 0) {
		fprintf(stderr, "%s: Can't open %s: %s\n", cmdname, datafile,
			strerror(errno));
		exit(-2);
	}

	if (fstat(dfd, &sbuf) < 0) {
		fprintf(stderr, "%s: Can't stat %s: %s\n", cmdname, datafile,
			strerror(errno));
		exit(-2);
	}

	ptr = mmap(0, sbuf.st_size, PROT_READ, MAP_SHARED, dfd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		fprintf(stderr, "%s: Can't read %s: %s\n", cmdname, datafile,
			strerror(errno));
		exit(-2);
	}

	while (count-- > 0) {
		size = sbuf.st_size - offset;
		if (write(ifd, ptr + offset, size) != size) {
			fprintf(stderr, "%s: Write error: %s\n", cmdname,
				strerror(errno));
			exit(-2);
		}
	}

	if (pad && ((tail = size % 4) != 0)) {
		if (write(ifd, (char *)&zero, 4 - tail) != 4 - tail) {
			fprintf(stderr, "%s: Write error: %s\n", cmdname,
				strerror(errno));
			exit(-2);
		}
	}

	munmap((void *)ptr, sbuf.st_size);
	close(dfd);
}

void usage(void)
{
	fprintf(stderr,
		"Usage: %s [-c dup_count] -d data_file -o image\n",
		cmdname);
	exit(-3);
}
