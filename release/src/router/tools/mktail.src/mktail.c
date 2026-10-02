#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include "tailinfo.h"

void usage()
{
	printf("Usage:\n");
	printf("  mktail -o outfile -t type [-f flags]\n");
	printf("  [for type 1:]    -b buildno -e extendno [-r reserved16 [-r reserved32]]\n");
	exit(-1);
}

uint8_t * t1_pack(int argc, char **argv, uint32_t *lenpt)
{
	int op, param_required=0;
	int reserved_cnt = 0;
	t1_content_t *t1_buf = (t1_content_t *)malloc(sizeof(t1_content_t));
	if (!t1_buf) {
		printf("malloc");
		return NULL;
	}
	*lenpt = sizeof(t1_content_t);
	memset (t1_buf, 0x0, *lenpt);

	while ((op = getopt(argc,argv,"b:e:r:")) != -1) {
		switch (op) {
			case 'b':
				// printf("b=> %s, optind:%d\n", optarg, optind);
				t1_buf->buildno = strtol(optarg, NULL, 0);
				param_required |= 1;
				break;
			case 'e':
				// printf("e=> %s, optind:%d\n", optarg, optind);
				t1_buf->extendno = strtol(optarg, NULL, 0);
				param_required |= 2;
				break;
			case 'r':
				// printf("r=> %s, optind:%d\n", optarg, optind);
				if (reserved_cnt == 0) {
					t1_buf->reserved16 = strtol(optarg, NULL, 0);
					param_required |= 4;
				}
				else if (reserved_cnt == 1) {
					t1_buf->reserved32 = strtol(optarg, NULL, 0);
					param_required |= 8;
				}
				else
					printf("Warning, too many reserved arguments!\n");
				reserved_cnt++;
				break;
		}
	}
	if (param_required & 3 == 0) {
		usage ();
	}
	//printf("t1: buildno:%04x, extendno:%08x, reserved16:%04x, reserved32:%08x\n", t1_buf->buildno, t1_buf->extendno, t1_buf->reserved16, t1_buf->reserved32);

	// translate to netowrk order
	t1_buf->buildno = htons(t1_buf->buildno);
	t1_buf->extendno = htonl(t1_buf->extendno);
	t1_buf->reserved16 = htons(t1_buf->reserved16);
	t1_buf->reserved32 = htonl(t1_buf->reserved32);
	//printf("t1: buildno:%04x, extendno:%08x, reserved16:%04x, reserved32:%08x\n", t1_buf->buildno, t1_buf->extendno, t1_buf->reserved16, t1_buf->reserved32);
	return (uint8_t *)t1_buf;
}

uint16_t calc_csum(void *ptr, unsigned int size, uint16_t sum)
{
	int i;
	uint16_t *p = ptr;

	for (i = 0; i < (size / 2); ++i, ++p)
		sum ^= __le16_to_cpu(*p);

	return sum;
}

int main (int argc, char **argv)
{
	int param_required = 0;
	unsigned int type = 0, flags = 0;
	uint8_t *content;
	uint32_t content_len = 0;
	basic_tailhdr_t tail_hdr;
	char tail_filename[PATH_MAX];
	uint16_t checksum;
	int fd;

	tail_filename[0]='\0';
	argc--; argv++; // skip program name
	while (argc > 0 && argv[0][0] == '-') {
		// printf("argv[0]:%s\n", argv[0]);
		switch (argv[0][1]) {
			case 'o':
				if (--argc <= 0)
					usage ();
				strcpy(tail_filename, *++argv);
				param_required |= 1;
				break;
			case 't':
				if (--argc <= 0)
					usage ();
				type = strtol(*++argv, NULL, 0);
				param_required |= 2;
				break;
			case 'f':
				if (--argc <= 0)
					usage ();
				flags = strtol(*++argv, NULL, 0);
				param_required |= 4;
				break;
			default:
				if (param_required == 3) {
					param_required |= 4;
					argc++; argv--; // roll back one argument
					break;
				} else {
					usage ();
				}
		}
		// printf("out param_required is %d, argc is %d, argv[0] is %s\n", param_required, argc, argv[0]);
		if (param_required == 7) break;
		argc--;
		argv++;
	}

	if ((param_required!=7) || (type> 15) || (flags > 15))
		usage ();

	//printf("file:\"%s\", type:%d(%x), flags:%d(%x)\n", tail_filename, type, type, flags, flags);
	switch (type) {
		case 1 :
			content = t1_pack(argc, argv, &content_len);
			break;
		default:
			printf("Not support type:%u!\n", type);
			exit(-1);
	}
	if (content_len > 0xffffff || content_len & 1) {
		free(content);
		usage ();
	}
	memset(&tail_hdr, 0x0, sizeof(basic_tailhdr_t));
	tail_hdr.magic = htonl(TAIL_MAGIC);
	tail_hdr.type= (uint8_t)type;
	tail_hdr.flags = (uint8_t)flags;
	tail_hdr.content_len_h = (uint8_t)((content_len >> 16) & 0xff);
	tail_hdr.content_len_l = htons(content_len & 0xffff);
	// caculate checksum
	checksum = calc_csum(content, content_len, 0);
	checksum ^= 0xFFFF;
	tail_hdr.content_checksum = htons(checksum);
	//printf("content checksum is %04x\n", checksum);
	checksum = calc_csum(&tail_hdr, sizeof(basic_tailhdr_t), 0);
	checksum ^= 0xFFFF;
	tail_hdr.hdr_checksum = htons(checksum);
	//printf("hdr checksum is %04x\n", checksum);
	// write to file
	fd = open(tail_filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (fd == -1) {
		printf("Cannot generate tail file:%s\n", tail_filename);
		free(content);
		return -1;
	}
	write(fd, content, content_len);
	write(fd, &tail_hdr, sizeof(basic_tailhdr_t));
	close(fd);
	free(content);
	printf("tailinfo=> content_len:%d, tailhdr:%d, total:%d\n", content_len, sizeof(basic_tailhdr_t), content_len+sizeof(basic_tailhdr_t));
	return 0;
}
