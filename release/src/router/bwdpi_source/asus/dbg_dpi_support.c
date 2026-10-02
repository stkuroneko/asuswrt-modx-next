/*
	dbg_dpi_support.c to verify dpi_support v1.03
*/

#include <stdio.h>
#include <stdlib.h>
#include <bwdpi_common.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char *index = NULL;
	int input = 0;
	int c;

	if (!strcmp(argv[1], "bitmap")) {
		setup_dpi_support_bitmap();
		printf("%s: setup_dpi_support_bitmap\n", __FUNCTION__);
		return 1;
	}

	if (argc != 3) {
		printf("wrong command!\n");
		return -1;
	}

	while ((c = getopt(argc, argv, "i:")) != -1)
	{
		switch(c)
		{
			case 'i':
				index = optarg;
				break;
			case '?':
				printf("%s: option %c has wrong command\n", __FUNCTION__, optopt);
				return -1;
			default:
				break;
		}
	}

	if (index != NULL) input = strtol(index, NULL, 10);
	if (input > 256 || input < -1) input = 0;

	printf("[dbg_dpi_support] %d\n", dump_dpi_support(input));

	return 1;
}
