/*
	for bwdpi_cmd
*/
#include "bwdpi.h"

extern void ProgControl3_PEM();

int main(int argc, char **argv)
{
	int c;
	char *action = NULL, *mac = NULL, *input_type = NULL, *input = NULL;
	int type = 0;

	if (argc == 1) return 0;

	if (!strcmp(argv[1], "qosd") && argc == 2)
	{
		qosd_main(argv[2]);
	}
	else if (!strcmp(argv[1], "sig_ver") && argc == 2)
	{
		save_version_of_bwdpi();
	}
	else if (!strcmp(argv[1], "qos_conf") && argc == 2)
	{
		setup_qos_conf();
	}
	else if (!strcmp(argv[1], "pem") && argc == 2)
	{
		ProgControl3_PEM();
	}
	else if (!strcmp(argv[1], "run_service") && argc == 2)
	{
		run_dpi_engine_service();
	}
	else if (!strcmp(argv[1], "wrs_wbl"))
	{
		while ((c = getopt(argc, argv, "wrdt:m:a:i:")) != -1)
		{
			switch(c)
			{
				case 'w':
					action = "add";
					break;
				case 'r':
					action = "get";
					break;
				case 'd':
					action = "del";
					break;
				case 't':
					type = atoi(optarg);
					break;
				case 'm':
					mac = optarg;
					break;
				case 'a':
					input_type = optarg;
					break;
				case 'i':
					input = optarg;
					break;
				case '?':
					printf("%s: option %c has wrong command\n", __FUNCTION__, optopt);
					return -1;
				default:
					break;
			}
		}
		return wrs_wbl_main(action, type, mac, input_type, input);
	}
	else if (!strcmp(argv[1], "wred_conf"))
	{
		setup_wrs_conf();
	}
	else if (!strcmp(argv[1], "wbl_conf"))
	{
		while ((c = getopt(argc, argv, "t:m:")) != -1)
		{
			switch(c)
			{
				case 't':
					type = atoi(optarg);
					break;
				case 'm':
					mac = optarg;
					break;
				case '?':
					printf("%s: option %c has wrong command\n", __FUNCTION__, optopt);
					return -1;
				default:
					break;
			}
		}
		return setup_wbl_conf(type, mac);
	}
	else if (!strcmp(argv[1], "clean_wbl_conf"))
	{
		return clean_wbl_conf();
	}
	else if (!strcmp(argv[1], "app_rulelist"))
	{
		char out[100] = {0};
		char *key = NULL;
		while ((c = getopt(argc, argv, "k:")) != -1)
		{
			switch(c)
			{
				case 'k':
					key = optarg;
					break;
				case '?':
					printf("%s: option %c has wrong command\n", __FUNCTION__, optopt);
					return -1;
				default:
					break;
			}
		}
		AppRuleModify(nvram_safe_get("bwdpi_app_rulelist"), key, out);
	}
	else
	{
		printf("no such command\n");
	}

	return 1;
}
