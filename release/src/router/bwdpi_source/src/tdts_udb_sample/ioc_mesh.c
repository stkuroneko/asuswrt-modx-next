/*
 * Copyright 2014 Trend Micro Incorporated
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "udb/shell/shell_ioctl.h"
#include "ioc_common.h"
#include "ioc_mesh.h"

#define GET_MAC	0x01
#define GET_IP	0x02
#define GET_ACT 0x04

#ifdef __INTERNAL__
#include "ioc_internal.h"
#endif

//#define MESH_DBG(fmt, args...)	fprintf(stderr, fmt, ##args);
#define MESH_DBG(fmt, args...)
/****************ioctl set to kernel*****************/
int set_fw_mesh_user(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_MESH;
	msg.op = UDB_IOCTL_MESH_OP_SET_USER;
	udb_shell_ioctl_set_in_raw(&msg, input, length);

	return  run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_MESH, &msg);
}

int set_fw_mesh_extender(void *input, unsigned int length)
{
	udb_shell_ioctl_t msg;

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_MESH;
	msg.op = UDB_IOCTL_MESH_OP_SET_EXTENDER;
	udb_shell_ioctl_set_in_raw(&msg, input, length);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_MESH, &msg);
}
/**************************************************/
/**************ioctl get from kernel***************/
int get_fw_mesh_user(void **output, unsigned int *buf_used_len)
{
	udb_shell_ioctl_t msg;
	const int buf_len = sizeof(mesh_user_ioc_list_t) + (sizeof(mesh_user_ioc_entry_t) * MESH_USER_MAX);

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		ERR("cannot allocate buffer space %u bytes\n", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_MESH;
	msg.op = UDB_IOCTL_MESH_OP_GET_USER;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_MESH, &msg);
}

int get_fw_mesh_extender(void **output, unsigned int *buf_used_len)
{
	udb_shell_ioctl_t msg;
	const int buf_len = sizeof(mesh_ext_ioc_list_t) + (sizeof(mesh_ext_ioc_entry_t) * MESH_EXT_MAX);

	*output = calloc(buf_len, sizeof(char));
	if (!*output)
	{
		ERR("cannot allocate buffer space %u bytes\n", buf_len);
		return -1;
	}

	/* prepare and do ioctl */
	udb_shell_init_ioctl_entry(&msg);
	msg.nr = UDB_IOCTL_NR_MESH;
	msg.op = UDB_IOCTL_MESH_OP_GET_EXTENDER;
	udb_shell_ioctl_set_out_buf(&msg, (*output), buf_len, buf_used_len);

	return run_ioctl(UDB_SHELL_IOCTL_CHRDEV_PATH, UDB_SHELL_IOCTL_CMD_MESH, &msg);
}
/**************************************************/
/***********some utils*****************/
#define STRDUP(_p)\
	do {\
		if (optarg != NULL) {\
			_p = (char *) strdup(optarg);\
			assert(_p != NULL);\
		} else {\
			printf("Invalid command option '%c'. Try --help.\n", opt);\
			ret = -1;\
			goto __exit;\
		}\
} while (0)

/* Parse string to tokens by delimiter */
int __line2tok(char **tok, int tok_size, char *in, const char *delim)
{
	int index;
	char *tok_save = NULL;

	for (index = 0;; index++)
	{
		if (index >= tok_size)
		{
			ERR("Token array overflow\n");
			break;
		}

		if (index == 0)
		{
			tok[index] = strtok_r(in, delim, &tok_save);
		}
		else
		{
			tok[index] = strtok_r(NULL, delim, &tok_save);
		}

		if (tok[index] == NULL)
		{
			break;
		}
	}
	return index;
}

/* Convert string to the correct format of mac address */
int get_u8(uint8_t *val, const char *arg, int base)
{
#if __WORDSIZE == 64
#define LONG_MAX   0x7fffffffffffffffL
#define LLONG_MAX  0x7fffffffffffffffLL
#define SIZE_MAX   UINT64_MAX
typedef uint64_t    uintmax_t;
#else
#define LONG_MAX    0x7fffffffL
#define LLONG_MAX   0x7fffffffffffffffLL
#define SIZE_MAX    UINT32_MAX
typedef uint32_t    uintmax_t;
#endif
#define ULONG_MAX (2UL*LONG_MAX+1)

	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
	{
		return -1;
	}

	res = strtoul((char *)arg, &ptr, base);

	/* empty string or trailing non-digits */
	if (!ptr || ptr == arg)// || *ptr)
	{
		return -1;
	}

	/* overflow */
	if (res == ULONG_MAX)
	{
		return -1;
	}

	if (res > 0xFFUL)
	{
		return -1;
	}

	*val = res;
	 return 0;
}

int __macstr2octet(uint8_t *mac, uint32_t mac_len,
        uint8_t *macstr, uint32_t macstr_len)
{
	int i;
	uint32_t tok_no;
	char *tok[6 + 1];
	
	tok_no = __line2tok(tok, sizeof(tok) / sizeof(tok[0]), macstr, ": \t\r\n");
	if (6 != tok_no)
	{
		ERR("mac format is incorrect, example XX:XX:XX:XX:XX:XX\n");
		return -1;
	}

	for (i = 0; i < 6; i++)
	{
		if (strlen(tok[i]) != 2)
		{
			ERR("mac format is incorrect, example XX:XX:XX:XX:XX:XX\n");
			return -1;
		}
		if (get_u8(&mac[i], tok[i], 16))
		{
			ERR("mac format is incorrect\n");
			return -1;
		}
	}

	return 0;
}

/* Convert string to the correct format of ip address */
int __ipstr2octet(uint8_t *ip, uint8_t *ipstr)
{
	int i;
	uint32_t tok_no;
	char *tok[4 + 1];

	tok_no = __line2tok(tok, sizeof(tok) / sizeof(tok[0]), ipstr, ". \t\r\n");
	if (4 != tok_no)
	{
		ERR("ip format is incorrect, example 192.168.2.66\n");
		return -1;
	}

	for (i = 0; i < 4; i++)
	{
		if (strlen(tok[i]) > 3)
		{
			ERR("ip format is incorrect, example 192.168.2.66\n");
			return -1;
		}
		ip[i] = atoi(tok[i]);

		/* 0 is a valid IP digit : 192.168.0.1 */
		if (ip[i] < 0 || ip[i] > 255)
		{
			ERR("ip format is incorrect\n");
			return -1;
		}
	}

	return 0;
}
/*****************************************/
/**************cmd help*******************/
void mesh_show_user_help(char *base)
{
	printf("%s -a mesh_set_user -m [user mac] -i [user ip] -a [a/d/u]\n", base);
	printf("add/delete/update mesh user mac and ip in udb\n");
	printf("user mac: example C8:0E:C6:F6:03:DF\n");
	printf("user ip: example 192.168.2.66\n");
	printf("a/d/u: a means add, d means delete, u means update\n");
	printf("\n");

	printf("%s -a mesh_get_extender"
		"\t\t\t\t\tget mesh extender\n", base);
}

void mesh_show_extender_help(char *base)
{
	printf("%s -a mesh_set_extender -m [user mac] -a [a/d]\n", base);
	printf("add/delete mesh extender mac in SHN modules\n");
	printf("user mac: example 14:DD:A9:81:CF:A0\n");
	printf("a/d: a means add, d means delete\n");
	printf("\n");
}

/*****************************************/
/************parse cmd arg****************/
int mesh_set_user_parse_arg(int argc, char **argv)
{
	int ret = 0, opt, sta = 0;
	char *macstr = NULL;
	char *ipstr = NULL;
	uint8_t action = 0;
	
	if (0 >= (argc - optind))
	{
		mesh_show_user_help(argv[0]);
		goto __exit;
	}

	while (1)
	{
		opt = getopt(argc, argv, "m:i:a:");
		if (opt <0)
		{
			break; // no more
		}
		
		switch (opt)
		{
			case 'm': //mac
				STRDUP(macstr);
				sta += GET_MAC;
				break;

			case 'i': //ip
				STRDUP(ipstr);
				sta += GET_IP;
				break;

			case 'a': //action
				if (optarg[0] == 'a') //add
				{
					action = ACT_ADD;
					sta += GET_ACT;
				}
				else if (optarg[0] == 'u') //update
				{
					action = ACT_UPDATE;
					sta += GET_ACT;
				}
				else if (optarg[0] == 'd') //delete
				{
					action = ACT_DELETE;
					sta += GET_ACT;
				}
				else
				{
					mesh_show_user_help(argv[0]);
					ret = -2;
					goto __exit;
				}
				break;

			default:
				mesh_show_user_help(argv[0]);
				ret = -3;
				goto __exit;
		}
	}

	if ((GET_MAC + GET_IP + GET_ACT) == sta)
	{
		//MESH_DBG("[shn_ctrl]set user mac %s ip %s act %u\n", macstr, ipstr, action);
		if (mesh_set_user(macstr, ipstr, action))
		{
			ret = -4;
			goto __exit;
		}
	}
	else
	{
		mesh_show_user_help(argv[0]);
		ret = -5;
		goto __exit;
	}

	ret = 0;
__exit:
	if (ret)
	{
		fprintf(stderr, "Failed to parse mesh_set_user arguments (%d)\n", ret);
	}

	if (macstr) free(macstr);
	if (ipstr) free(ipstr);

	return ret;
}
int mesh_set_extender_parse_arg(int argc, char **argv)
{
	int ret = 0, opt, sta = 0;
	char *macstr = NULL;
	uint8_t action = 0;

	if (0 >= (argc - optind))
	{
		mesh_show_extender_help(argv[0]);
		goto __exit;
	}

	while (1)
	{
		opt = getopt(argc, argv, "m:a:");
		if (opt <0)
		{
			break; // no more
		}

		switch (opt)
		{
			case 'm': //mac
				STRDUP(macstr);
				sta += GET_MAC;
				break;
			case 'a': //action
				if (optarg[0] == 'a') //add
				{
					action = ACT_ADD;
					sta += GET_ACT;
				}
				else if (optarg[0] == 'd') //delete
				{
					action = ACT_DELETE;
					sta += GET_ACT;
				}
				else
				{
					mesh_show_extender_help(argv[0]);
					ret = -2;
					goto __exit;
				}
				break;

			default:
				mesh_show_extender_help(argv[0]);
				ret = -3;
				goto __exit;
		}
	}
	
	if ((GET_MAC + GET_ACT) == sta)
	{
		//MESH_DBG("[shn_ctrl]set extender mac %s act %u\n", macstr, action);
		if (mesh_set_extender(macstr, action))
		{
			ret = -4;
			goto __exit;
		}
	}
	else
	{
		mesh_show_extender_help(argv[0]);
		ret = -5;
		goto __exit;
	}

	ret = 0;
__exit:
	if (ret)
	{
		fprintf(stderr, "Failed to parse mesh_set_extender arguments (%d)\n", ret);
	}

	if (macstr) free(macstr);

	return ret;
}
/**********************************************************/
int mesh_set_user(char *macstr, char *ipstr, uint8_t action)
{
	int ret = 0;
	uint32_t len = 0;
	uint8_t mac[6];
	uint8_t ip[4];

	len = sizeof(mesh_user_ioc_entry_t);
	mesh_user_ioc_entry_t *mesh_user =  calloc(len, sizeof(char));
	
	if (!mesh_user)
	{
		ERR("mesh_user memory allocate failed\n");
	}

	if (__macstr2octet(mac, sizeof(mac), (uint8_t *)macstr, strlen(macstr)))
	{
		return -1;
	}
	memcpy(mesh_user->mac, mac, sizeof(mesh_user->mac));

	if (__ipstr2octet(ip, (uint8_t *)ipstr))
	{
		return -2;
	}
	memcpy(mesh_user->ipv4, ip, sizeof(mesh_user->ipv4));

	mesh_user->action = action;

	ret = set_fw_mesh_user(mesh_user, len);
	MESH_DBG("[shn_ctrl]Mesh set user "MAC_OCTET_FMT" "IPV4_OCTET_FMT" action %u result: %s\n",
		MAC_OCTET_EXPAND(mesh_user->mac), IPV4_OCTET_EXPAND(mesh_user->ipv4),
		action, ret ? "Fail" : "Pass");

	if (mesh_user) free(mesh_user);

	return ret;
}

int mesh_set_extender(char *macstr, uint8_t action)
{
	int ret = 0;
	uint32_t len = 0;
	uint8_t mac[6];

	len = sizeof(mesh_ext_ioc_entry_t);
	mesh_ext_ioc_entry_t *mesh_ext = calloc(len, sizeof(char));

	if (!mesh_ext)
	{
		printf("mesh_ext memory allocate failed\n");
		return -1;
	}

	if (__macstr2octet(mac, sizeof(mac), (uint8_t *)macstr, strlen(macstr)))
	{
		return -2;
	}
	memcpy(mesh_ext->mac, mac, sizeof(mesh_ext->mac));

	mesh_ext->action = action;

	ret = set_fw_mesh_extender((void *)mesh_ext, len);
	MESH_DBG("[shn_ctrl]Mesh set extender "MAC_OCTET_FMT" action %u result: %s\n",
		MAC_OCTET_EXPAND(mesh_ext->mac), action, ret ? "Fail" : "Pass");

	if (mesh_ext) free(mesh_ext);

	return ret;
}

int mesh_get_user(void)
{
	int ret = 0;
	unsigned int buf_pos, buf_used_len;
	int i;
	char *buf = NULL;
	mesh_user_ioc_list_t *tbl = NULL;
	mesh_user_ioc_entry_t *entry = NULL;

	if (ret = get_fw_mesh_user((void **) &buf, &buf_used_len))
	{
		//ERR("ioctl get mesh user error (%d)\n", ret);
		goto __ret;
	}
	
	if (!buf || !buf_used_len)
	{
		printf("\nThere are 0 mesh user in SHN control\n");
		goto __ret;
	}

	buf_pos = 0;
	tbl = (mesh_user_ioc_list_t *)buf;

	if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(mesh_user_ioc_list_t), buf_used_len))
	{
		goto __ret;
	}

	printf("\n");
	printf("There are %u mesh user in SHN control\n", tbl->entry_cnt);

	for (i = 0; i < tbl->entry_cnt; i++)
	{
		entry = (mesh_user_ioc_entry_t *)(buf + buf_pos);
		if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(mesh_user_ioc_entry_t), buf_used_len))
		{
			goto __ret;
		}
		printf("%d\t"MAC_OCTET_FMT"\t"IPV4_OCTET_FMT"\n", 
			i+1, MAC_OCTET_EXPAND(entry->mac), IPV4_OCTET_EXPAND(entry->ipv4));
		
	}

	ret = 0;
__ret:
	if (buf)
	{
		free (buf);
	}
	return ret;
}

int mesh_get_extender(void)
{
	int ret = 0;
	unsigned int buf_pos, buf_used_len;
	int i;
	char *buf = NULL;
	mesh_ext_ioc_list_t *tbl = NULL;
	mesh_ext_ioc_entry_t *entry = NULL;

	if (ret = get_fw_mesh_extender((void **) &buf, &buf_used_len))
	{
		//ERR("ioctl get mesh extender error (%d)\n", ret);
		goto __ret;
	}

	if (!buf || !buf_used_len)
	{
		printf("\nThere are 0 mesh node in SHN control\n");
		goto __ret;
	}

	buf_pos = 0;
	tbl = (mesh_ext_ioc_list_t *)buf;

	if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(mesh_ext_ioc_list_t), buf_used_len))
	{
		goto __ret;
	}

	printf("\n");
	printf("There are %u mesh node in SHN control\n", tbl->entry_cnt);
	
	for (i = 0; i < tbl->entry_cnt; i++)
	{
		entry = (mesh_ext_ioc_entry_t *)(buf + buf_pos);
		if (!IOC_SHIFT_LEN_SAFE(buf_pos, sizeof(mesh_ext_ioc_entry_t), buf_used_len))
		{
			goto __ret;
		}

		printf("%d\t"MAC_OCTET_FMT"\n", i+1, MAC_OCTET_EXPAND(entry->mac));
	}

	ret = 0;

__ret:
	if (buf)
	{
		free(buf);
	}
	return ret;
}
/************************************************************************/
int mesh_options_init(struct cmd_option *cmd)
{
#define HELP_LEN_MAX 1024
	int i = 0, j;
	char help[HELP_LEN_MAX];
	int len = 0;

	cmd->opts[i].name = "mesh_set_user";
	cmd->opts[i].parse_arg = mesh_set_user_parse_arg;
	OPTS_IDX_INC(i);

	cmd->opts[i].name = "mesh_get_user";
	cmd->opts[i].cb = mesh_get_user;
	OPTS_IDX_INC(i);

	cmd->opts[i].name = "mesh_set_extender";
	cmd->opts[i].parse_arg = mesh_set_extender_parse_arg;
	OPTS_IDX_INC(i);

	cmd->opts[i].name = "mesh_get_extender";
	cmd->opts[i].cb = mesh_get_extender;
	OPTS_IDX_INC(i);

	len += snprintf(help + len, HELP_LEN_MAX - len, "%*s \n",
		HELP_INDENT_L, "");

	for (j = 0; j < i; j++)
	{
		len += snprintf(help + len, HELP_LEN_MAX - len, "%*s %s\n",
			HELP_INDENT_L, (j == 0) ? "mesh actions:" : "",
			cmd->opts[j].name);
	}

	cmd->help = help;
	return 0;
}

