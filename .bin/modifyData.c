#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int convertHexStr(const char *str, unsigned char *hex)
{
	int count = 0;
	int len;
	char tmp[3];
	const char *p;

	if(str == NULL)
		return -1;

	len = strlen(str);
	p = str;

	while(1)
	{
		if(len <= 0)
			break;
		else if(len < 2)
			return -1;
		//printf("count(%3d): [0](%02x) [1](%02x) [2](%02x)\n", count, p[0], p[1], p[2]);
 		if(!(isxdigit(p[0]) && isxdigit(p[1]) && (p[2] == ':' || p[2] == '\0')))
			return -1;

		tmp[0] = p[0];
		tmp[1] = p[1];
		tmp[2] = '\0';
		hex[count++] = (unsigned char) strtoul(tmp, NULL, 16);
		p += 3;
		len -= 3;
	}
	return count;
}

int convertBitMask(const char *str, unsigned char *bitMask)
{
	int len = 8;
	int i;

	if(strlen(str) != len)
		return -1;

	*bitMask = 0;
	for (i = 0; i < len; i++)
	{
		if(str[i] == '1')
			*bitMask |= (1 << (len - 1 - i));
	}
	return 0;
}


void usage(const char *prog)
{
	printf("Usage: %s <filename> <offset> <data>\n", prog);
	printf("Usage: %s <filename> <offset> hex <hex:data>\n", prog);
	printf("Usage: %s <filename> <offset> bit <set bitMask 7~0> <clr bitMask 7~0> <tog bitMask 7~0>\n", prog);
}

int main(int argc, char **argv)
{
	int fd;
	unsigned int offset;
	int idx = 0;
	int filesize, len;
	int ret = -1;
	int act_hex = 0;
	int act_bit = 0;
	unsigned char buf[512];
	unsigned char *data;

	if(!(           (argc == 4)
	      || (act_hex = (argc == 5 && strcmp(argv[3], "hex") == 0))
	      || (act_bit = (argc == 7 && strcmp(argv[3], "bit") == 0))
	    ))
	{
		usage(argv[0]);
		return -1;
	}

	//check input
	if(argv[2][0] == '-')
		idx = 1;
	if(!isdigit(argv[2][idx]))
	{
		printf("<offset> is not a digit string\n");
		usage(argv[0]);
		return -1;
	}

	//check file
	if((fd = open(argv[1], O_RDWR)) < 0)
	{
		perror("open()");
		usage(argv[0]);
		return -1;
	}
	offset = strtoul(&argv[2][idx], NULL, 0);

	if(act_bit == 1)
	{
		data = buf;
		len = 1;
	}
	else if(act_hex == 1)
	{
		if((len = convertHexStr(argv[4], buf)) <= 0)
		{
			printf("invalid hex:data. Example: 01:02\n");
			goto error;
		}
		data = buf;
	}
	else
	{
		data = argv[3];
		len = strlen(argv[3]);
	}

	//check filesize and offset
	filesize = lseek(fd, 0, SEEK_END);
	if(filesize < offset)
	{
		printf("<offset> is larger than file size\n");
		goto error;
	}
	if(idx)
	{
		offset = filesize - offset;
	}
	if(offset + len > filesize)
	{
		printf("<offset> + <data> is larger than file size\n");
		goto error;
	}

	if(act_bit == 1)
	{
		int bit_offset;
		unsigned char setBit, clrBit, togBit;
		unsigned char orig;

		if(convertBitMask(argv[4], &setBit) || convertBitMask(argv[5], &clrBit) || convertBitMask(argv[6], &togBit))
		{
			printf("invalid bitMask\n");
			usage(argv[0]);
			goto error;
		}
		if((setBit & clrBit) || (setBit & togBit) || (clrBit & togBit))
		{
			printf("bitMask has overlap\n");
			goto error;
		}

		lseek(fd, offset, SEEK_SET);
		read(fd, &orig, 1);

		data[0] = orig;
		data[0] |= setBit;
		data[0] &= ~clrBit;
		data[0] ^= togBit;
	}

	//write new data
	lseek(fd, offset, SEEK_SET);
	write(fd, data, len);

	//success
	ret = 0;
error:
	close(fd);
	return ret;
}

