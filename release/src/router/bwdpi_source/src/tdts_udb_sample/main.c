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
#include <string.h>

#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

#include "udb/shell/shell_ioctl.h"

#include "conf_app.h"

#include "ioc_common.h"

#if TMCFG_E_UDB_CORE_IQOS_SUPPORT
#include "ioc_qos.h"
#endif
#if TMCFG_E_UDB_CORE_URL_QUERY
#include "ioc_wrs.h"
#endif
#if TMCFG_E_UDB_CORE_WBL
#include "ioc_wbl.h"
#endif
#if TMCFG_E_UDB_CORE_APP_WBL
#include "ioc_app_wbl.h"
#endif
#if TMCFG_E_UDB_CORE_PATROL_TIME_QUOTA
#include "ioc_patrol_tq.h"
#endif
#if TMCFG_E_UDB_CORE_VIRTUAL_PATCH
#include "ioc_vp.h"
#endif
#if TMCFG_E_UDB_CORE_ANOMALY_PREVENT
#include "ioc_anomaly.h"
#endif
#if TMCFG_E_UDB_CORE_TMDBG
#include "ioc_dlog.h"
#endif
#if TMCFG_E_UDB_CORE_MESH
#include "ioc_mesh.h"
#endif

static char *action = NULL;
static struct cmd_option cmd_options[UDB_IOCTL_NR_MAX];

#ifndef BIN_MAJ
#define BIN_MAJ 0
#endif

#ifndef BIN_MIN
#define BIN_MIN 0
#endif

#ifndef BIN_REV
#define BIN_REV 0
#endif

static void show_help(char *pname)
{
	int i = 0;
	char *anc;

	fprintf(stdout, "%s version %d.%d.%d\n",
		(anc = strrchr(pname, '/')) ? anc + 1 : pname,
		BIN_MAJ, BIN_MIN, BIN_REV);
#ifdef __INTERNAL__
	fprintf(stdout, "build-date: %lu\n", get_build_date());
	fprintf(stdout, "build-number: %lu\n", get_build_number());
#endif
	fprintf(stdout, "options:\n");
	fprintf(stdout, "-h --help          print this help\n");
	fprintf(stdout, "-a --action \n");

	for (i = 0; i < UDB_IOCTL_NR_MAX; i++)
	{
		if (cmd_options[i].help)
		{
			fprintf(stdout, cmd_options[i].help);
		}
	}

	fprintf(stdout, "\n");
}

static int parse_arg(int argc, char **argv, action_cb_t *cb)
{
	int i = 0, ret = 0;
	int optret = 0;
	int more_opt_index = 0;
	uint8_t more_opt = 0;
	uint8_t help_act = 0;

	if (argc < 2)
	{
		show_help(argv[0]);
		return 1;
	}

	while (-1 != (optret = getopt(argc, argv, ":a:h")))
	{
		switch (optret)
		{
		case 'a':
			if (optarg && !action)
			{
				asprintf(&action, "%s", optarg);
			}
			break;

		case 'h':
			if (!action)
			{
				show_help(argv[0]);
				return 1;
			}
			help_act = 1;
			break;

		default:
			more_opt = 1;
			break;
		}

		if (more_opt || help_act)
		{
			break;
		}
	}

	/* for current opt index */
	if (more_opt)
	{
		more_opt_index = optind - 1;
	}
	else
	{
		more_opt_index = optind;
	}

	if (action && *action)
	{
		int j;

		for (i = UDB_IOCTL_NR_COMMON; i < UDB_IOCTL_NR_MAX; i++)
		{
			for (j = 0; j < CMD_OPTIONS_MAX; j++)
			{
				if (!cmd_options[i].opts[j].name)
				{
					break;
				}

				if (0 == strcasecmp(action, cmd_options[i].opts[j].name))
				{
					struct delegate *cmd_opt = &cmd_options[i].opts[j];
					int act = cmd_opt->action;
					ret = 0;

					if (cmd_opt->cb)
					{
						*cb = cmd_opt->cb;
					}

					if (help_act)
					{
						if (cmd_opt->show_help)
						{
							cmd_opt->show_help(argv[0]);
						}
						return 1;
					}

					if (cmd_opt->parse_arg)
					{
						optind = more_opt_index;
						ret = cmd_opt->parse_arg(argc, argv);
					}

					return ret;
				}
			}
		}

		ERR("unknown action \"%s\"\n", action);
		return 1;
	}
	else
	{
		ERR("no action?\n");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	int i;
	action_cb_t act_cb = NULL;

	for (i = 0; i < UDB_IOCTL_NR_MAX; i++)
	{
		memset(&cmd_options[i], 0, sizeof(struct cmd_option));
	}

	if (common_options_init(&cmd_options[UDB_IOCTL_NR_COMMON]))
	{
		return -1;
	}

#if TMCFG_E_UDB_CORE_URL_QUERY
	if (wrs_options_init(&cmd_options[UDB_IOCTL_NR_WRS]))
	{
		return -1;
	}
#endif

#if TMCFG_E_UDB_CORE_WBL
	if (wbl_options_init(&cmd_options[UDB_IOCTL_NR_WBL]))
	{
		return -1;
	}
#endif

#if TMCFG_E_UDB_CORE_APP_WBL
    if (app_wbl_options_init(&cmd_options[UDB_IOCTL_NR_APP_WBL]))
    {
        return -1;
    }
#endif

#if TMCFG_E_UDB_CORE_IQOS_SUPPORT
	if (iqos_options_init(&cmd_options[UDB_IOCTL_NR_IQOS]))
	{
		return -1;
	}
#endif

#if TMCFG_E_UDB_CORE_PATROL_TIME_QUOTA
	if (patrol_tq_options_init(&cmd_options[UDB_IOCTL_NR_PATROL_TQ]))
	{
		return -1;
	}
#endif

#if TMCFG_E_UDB_CORE_VIRTUAL_PATCH
	if (vp_options_init(&cmd_options[UDB_IOCTL_NR_VP]))
	{
		return -1;
	}
#endif

#if TMCFG_E_UDB_CORE_ANOMALY_PREVENT
	if (anomaly_options_init(&cmd_options[UDB_IOCTL_NR_ANOMALY]))
	{
		return -1;
	}
#endif

#if TMCFG_E_UDB_CORE_TMDBG
	if (dlog_options_init(&cmd_options[UDB_IOCTL_NR_DLOG]))
	{
		return -1;
	}
#endif

# if TMCFG_E_UDB_CORE_MESH
	if (mesh_options_init(&cmd_options[UDB_IOCTL_NR_MESH]))
	{
		return -1;
	}
#endif

	if ((ret = parse_arg(argc, argv, &act_cb)))
	{
		goto __exit;
	}

	if (act_cb)
	{
		ret = act_cb();
	}

__exit:
	if (action)
	{
		free(action);
	}

	return ret;
}
