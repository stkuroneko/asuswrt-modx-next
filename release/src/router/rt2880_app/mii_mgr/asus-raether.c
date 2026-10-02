#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/mii.h>
#include <linux/types.h>
#include <string.h>

#include <linux/autoconf.h>
#include "ra_ioctl.h"

int main(int argc, char *argv[])
{
	int sk, opt, ret;
	char options[] = "Rs";
	int method;
	struct ifreq ifr;
	ra_mii_ioctl_data mii;
	raeth_asus_data_t asus_data;

	sk = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		printf("Open socket failed\n");
		return -1;
	}

	strncpy(ifr.ifr_name, "eth2", 5);
	ifr.ifr_data = &mii;

	while ((opt = getopt(argc, argv, options)) != -1) {
		switch (opt) {
			case 'R':
				method = RAETH_ASUS;
				asus_data.subcmd = RAETH_ASUS_RESET;
				ifr.ifr_data = &asus_data;
				break;
			case 's':
				method = RAETH_ASUS;
				asus_data.subcmd = RAETH_ASUS_STATS;
				ifr.ifr_data = &asus_data;
				break;
		}
	}

	ret = ioctl(sk, method, &ifr);
	if (ret < 0) {
		printf("%s: ioctl error\n", argv[0]);
	} else if (method == RAETH_ASUS) {
		switch (asus_data.subcmd) {
		case RAETH_ASUS_RESET:
			printf("Issue reset to raether driver.\n");
			break;
		}
	}

	close(sk);
	return ret;
}
