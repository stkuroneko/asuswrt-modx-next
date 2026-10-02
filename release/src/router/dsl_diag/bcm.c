/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dsl_diag.h"

#define KBUF_SIZE        51200
#define BCM_DIAG_PATH    "/proc/xdsldiaglogs"

void start_diag(DIAG_PARAM *p)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "xdslctl diag --logstart %d", KBUF_SIZE);
	system(cmd);
}

void stop_diag(DIAG_PARAM *p)
{
	system("xdslctl diag --logstop");
}

void dump_diag_log(DIAG_PARAM *p)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "cat %s >> %s", BCM_DIAG_PATH, p->log_path);
	system(cmd);
}

void dsl_downup()
{
	system("xdslctl connection --down");
	system("xdslctl connection --up");
}
