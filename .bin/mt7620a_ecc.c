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

#define	ROUNDUP(x, y)		((((x)+((y)-1))/(y))*(y))

static char *cmdname;

static void usage(void)
{
	fprintf(stderr,
		"Usage: %s [-p page_size(512|2048*)] [-e ECC data size(256|512*)] [-l ecc log file] -d data_file -o image\n",
		cmdname);
	exit(-3);
}

/* Return offset of last non-0xFF byte.
 * @return:
 *     -1:	All bytes between *p ~ *(p + len - 1) is 0xFF.
 *    >=0:	Last non 0xFF between *p ~ *(p + len - 1)
 */
static int last_non_ff(unsigned char *p, size_t len)
{
	int i;

	if (!p || !len)
		return 0;

	for (i = len - 1; i >= 0; --i) {
		if (*(p + i) != 0xFF)
			break;
	}

	return i;
}

static void __calc_ecc(const unsigned char *buf, const size_t ecc_data_len, unsigned char *code)
{
	int i;
	const unsigned char *p;
	unsigned int b0, b1, b2, b3, b4, b5, b6, b7;
	unsigned int CP00, CP01, CP02, CP03, CP04, CP05;
	unsigned int LP00, LP01, LP02, LP03, LP04, LP05, LP06, LP07, LP08, LP09, LP10, LP11, LP12, LP13, LP14, LP15, LP16, LP17;

	if (!buf || ecc_data_len != 512 || !code)
		return;

	LP00 = LP01 = LP02 = LP03 = LP04 = LP05 = LP06 = LP07 = LP08 = 0;
	LP09 = LP10 = LP11 = LP12 = LP13 = LP14 = LP15 = LP16 = LP17 = 0;
	CP00 = CP01 = CP02 = CP03 = CP04 = CP05  =  0;
	for (i = 0, p = buf; i < ecc_data_len; ++i, ++p) {
		b0 = *p & 1;
		b1 = (*p >> 1) & 1;
		b2 = (*p >> 2) & 1;
		b3 = (*p >> 3) & 1;
		b4 = (*p >> 4) & 1;
		b5 = (*p >> 5) & 1;
		b6 = (*p >> 6) & 1;
		b7 = (*p >> 7) & 1;

		if (i & 0x01)
			LP01 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP01;
		else
			LP00 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP00;

		if (i & 0x02)
			LP03 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP03;
		else
			LP02 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP02;

		if (i & 0x04)
			LP05 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP05;
		else
			LP04 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP04;

		if (i & 0x08)
			LP07 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP07;
		else
			LP06 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP06;

		if (i & 0x10)
			LP09 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP09;
		else
			LP08 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP08;

		if (i & 0x20)
			LP11 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP11;
		else 
			LP10 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP10;
	
		if (i & 0x40)
			LP13 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP13;
		else 
			LP12 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP12;

		if (i & 0x80)
			LP15 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP15;
		else 
			LP14 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP14;

		if (i & 0x100)
			LP17 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP17;
		else
			LP16 = b7 ^ b6 ^ b5 ^ b4 ^ b3 ^ b2 ^ b1 ^ b0 ^ LP16;

		CP00 = b6 ^ b4 ^ b2 ^ b0 ^ CP00;
		CP01 = b7 ^ b5 ^ b3 ^ b1 ^ CP01;
		CP02 = b5 ^ b4 ^ b1 ^ b0 ^ CP02;
		CP03 = b7 ^ b6 ^ b3 ^ b2 ^ CP03;
		CP04 = b3 ^ b2 ^ b1 ^ b0 ^ CP04;
		CP05 = b7 ^ b6 ^ b5 ^ b4 ^ CP05;
	}

	code[0] = (LP07 << 7) | (LP06 << 6) | (LP05 << 5) | (LP04 << 4) | (LP03 << 3) | (LP02 << 2) | (LP01 << 1) | LP00;
	code[1] = (LP15 << 7) | (LP14 << 6) | (LP13 << 5) | (LP12 << 4) | (LP11 << 3) | (LP10 << 2) | (LP09 << 1) | LP08;
	code[2] = (CP05 << 7) | (CP04 << 6) | (CP03 << 5) | (CP02 << 4) | (CP01 << 3) | (CP00 << 2) | (LP17 << 1) | LP16;
}

int main(int argc, char **argv)
{
	int i, ifd, ofd, opt, ecc_per_page = 4, wlen, pos;
	int page_size = 2048, ecc_data_size = 512, tmp;
	const char *datafile = NULL, *imagefile = NULL, *ecclogfile = NULL;
	unsigned char *ptr = NULL, *data = NULL, *p, *e, *q;
	FILE *efp = NULL;
	struct stat isbuf;
	off_t total_len, len;
	unsigned int block = 0, page = 0, oob_size = 64;
	unsigned char ecc[4], oob[64], *block_buf = NULL;
	const int eccpos = 6;
	const int block_size = 128*1024;
	int pages_per_block = block_size / page_size;

	cmdname = argv[0];
	while ((opt = getopt(argc, argv, "d:o:p:e:l:")) != -1) {
		switch (opt) {
		case 'd':
			datafile = optarg;
			break;
		case 'o':
			imagefile = optarg;
			break;
		case 'p':
			tmp = atoi(optarg);
			if (tmp != 512 && tmp != 2048) {
				printf("page size must be 512 or 2048!\n");
				return -1;
			}
			page_size = tmp;
			break;
		case 'e':
			tmp = atoi(optarg);
			if (tmp != 256 && tmp != 512) {
				printf("ECC data size must be 256 or 512!\n");
				return -1;
			}
			ecc_data_size = tmp;
			break;
		case 'l':
			ecclogfile = optarg;
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

	if (block_size % page_size) {
		printf("block size is not multiple of page size!\n");
		return -1;
	}
	pages_per_block = block_size / page_size;
	if (!(block_buf = malloc(block_size))) {
		printf("allocate buffer %d bytes for block fail!\n", block_size);
		return -1;
	}

	if ((ifd = open(datafile, O_RDONLY)) < 0) {
		fprintf(stderr, "%s: Can't open %s: %s\n", cmdname, datafile,
			strerror(errno));
		exit(-2);
	}
	if (fstat(ifd, &isbuf) < 0) {
		fprintf(stderr, "%s: Can't stat %s: %s\n", cmdname, datafile,
			strerror(errno));
		exit(-2);
	}
	total_len = isbuf.st_size;
	if (isbuf.st_size % block_size)
		printf("data file (%s) length is not multiple of block size!\n", datafile);

	ofd = open(imagefile, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (ofd < 0) {
		fprintf(stderr, "%s: Can't open %s: %s\n", cmdname, imagefile,
			strerror(errno));
		return -3;
	}

	if (ecclogfile) {
		efp = fopen(ecclogfile, "w");
		if (!efp) {
			fprintf(stderr, "%s: Can't open %s: %s\n", cmdname, ecclogfile,
				strerror(errno));
			return -3;
		}
	}

	printf("===============================\n");
	printf("datafile:	%s\n", datafile);
	printf("imagefile:	%s\n", imagefile);
	printf("ecc log file:	%s\n", (ecclogfile)? ecclogfile:"N/A");
	printf("page size:	%d\n", page_size);
	printf("ECC data size:	%d\n", ecc_data_size);
	printf("ECC position:	%d\n", eccpos);
	printf("===============================\n");

	ptr = mmap(0, total_len, PROT_READ, MAP_SHARED, ifd, 0);
	if (ptr == (unsigned char *)MAP_FAILED) {
		fprintf(stderr, "%s: Can't map %s: %s\n", cmdname, datafile,
			strerror(errno));
		return -4;
	}

	data = ptr;
	ecc_per_page = page_size / ecc_data_size;
	oob_size = ecc_per_page * 16;
	for (block = 0, page = 0, data = ptr, len = total_len;
		len > 0;
		block++, data += block_size, len -= block_size)
	{
		if (efp)
			fprintf(efp, "=== block %4x (dec: %4d) ========================================\n",
				block, block);

		p = data;
		wlen = block_size;
		if (len < block_size) {
			p = block_buf;
			memcpy(p, data, len);
			memset(p + len, 0xFF, block_size - len);
		}

		/* find 1st non-0xFF from tail of block */
		pos = last_non_ff(p, wlen);
		q = p + ROUNDUP(pos + 1, page_size);

		for (; wlen > 0; wlen -= page_size, page++) {
			if (efp) {
			       if (p == q)
					fprintf(efp, "--- tailed empty page(s) of the block -----------------------------\n");
				fprintf(efp, "page %4x (dec: %4d): ", page, page);
			}

			/* write a page to image file */
			if (write(ofd, p, page_size) != page_size) {
				fprintf(stderr, "%s: Write error: %s\n", cmdname,
					strerror(errno));
				exit(-5);
			}

			/* calculate ecc and write oob to image file */
			memset(oob, 0xFF, sizeof(oob));
			if (p < q) {
				for (i = 0, e = &oob[0] + eccpos;
					i < ecc_per_page;
					++i, p += ecc_data_size, e += 16)
				{
					__calc_ecc(p, ecc_data_size, ecc);
					memcpy(e, ecc, 3);
				}
			} else {
				p += page_size;
			}

			/* write oob to image file */
			if (write(ofd, oob, oob_size) != oob_size) {
				fprintf(stderr, "%s: Write error: %s\n", cmdname,
					strerror(errno));
				exit(-5);
			}

			/* generate ECC log file */
			for (i = 0, e = &oob[0] + eccpos;
				efp && i < ecc_per_page;
				++i, e += 16)
			{
				fprintf(efp, "  %02X %02X %02X%c", *e, *(e + 1), *(e + 2), (i == ecc_per_page - 1)? ' ':',');
			}
			if (efp)
				fprintf(efp, "\n");
		}
	}
	munmap((void *)ptr, total_len);

	/* We're a bit of paranoid */
	fsync(ofd);

	free(block_buf);
	if (close(ifd)) {
		fprintf(stderr, "%s: Read error on %s: %s\n", cmdname,
			datafile, strerror(errno));
		return -6;
	}
	if (close(ofd)) {
		fprintf(stderr, "%s: Write error on %s: %s\n", cmdname,
			imagefile, strerror(errno));
		return -6;
	}

	return 0;
}
