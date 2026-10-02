/*
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
/*
 * This is the implementation of a routine to notify the ahs that it
 * should take some action.
 *
 * Copyright 2019, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of ASUSTeK Inc.;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of ASUSTeK Inc..
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <bcmnvram.h>
#include "shutils.h"
#include "shared.h"

static int notify_ahs_internal(const char *event_name, bool do_wait, int wait);

int notify_ahs(const char *event_name)
{
	return notify_ahs_internal(event_name, FALSE, 15);
}

int notify_ahs_after_wait(const char *event_name)
{
	return notify_ahs_internal(event_name, FALSE, 30);
}

int notify_ahs_after_period_wait(const char *event_name, int wait)
{
	return notify_ahs_internal(event_name, FALSE, wait);
}

int notify_ahs_and_wait(const char *event_name)
{
	return notify_ahs_internal(event_name, TRUE, 10);
}

int notify_ahs_and_wait_1min(const char *event_name)
{
	return notify_ahs_internal(event_name, TRUE, 60);
}

int notify_ahs_and_wait_2min(const char *event_name)
{
	return notify_ahs_internal(event_name, TRUE, 120);
}

int notify_ahs_and_period_wait(const char *event_name, int wait)
{
	return notify_ahs_internal(event_name, TRUE, wait);
}

/*
 * int wait_ahs_service(int wait)
 * wait: seconds to wait and check
 *
 * @return:
 * 0: no  right
 * 1: get right
 */
int wait_ahs_service(int wait)
{
	int i=wait;
	int first_try = 1;
	char p1[16];

	psname(nvram_get_int("ahs_service_pid"), p1, sizeof(p1));

	while (*nvram_safe_get("ahs_service")) {
		if(--i < 0) {
			/* now the dead go peace */
			if(!*p1)
				nvram_set("ahs_service", "");
			return 0;
		}

		if(first_try){
			logmessage_normal("ahs_service", "waitting \"%s\" via %s ...", nvram_safe_get("ahs_service"), p1);
			first_try = 0;
		}

		_dprintf("%d: wait for previous script(%d/%d): %s %d %s.\n", getpid(), i, wait, nvram_safe_get("ahs_service"), nvram_get_int("ahs_service_pid"), p1);
		sleep(1);
	}

	return 1;
}


/* @return:
 * 	0:	success
 *     -1:	invalid parameter
 *      1:	wait pending ahs_service timeout
 */
static int notify_ahs_internal(const char *event_name, bool do_wait, int wait)
{
	int i;
	char p2[16];

	if (!event_name || !(*event_name) || wait < 0)
		return -1;

	psname(getpid(), p2, sizeof(p2));
	_dprintf("<ahs_service> [i:%s] %d:notify_ahs %s", p2, getpid(), event_name);
	logmessage_normal("ahs_service", "%s %d:notify_ahs %s", p2, getpid(), event_name);

	// finish the last ahs_service as soon as possibly.
	if(strstr(event_name, "reboot")){
		_dprintf("%s: kill the shell scripts for reboot.\n", event_name);
		eval("killall", "sh");
	}

	if (!wait_ahs_service(wait)) {
		logmessage_normal("ahs_service", "skip the event: %s.", event_name);
		_dprintf("ahs_service: skip the event: %s.\n", event_name);
		return 1;
	}

	nvram_set("ahs_service", event_name);
	nvram_set_int("ahs_service_pid", getpid());

	kill_pidfile_s("/var/run/ahs.pid", SIGUSR1);

	if(do_wait)
	{
		i = wait;
		while((nvram_match("ahs_service", (char *)event_name))&&(i-- > 0)) {
			_dprintf("%s %d: waiting after %d/%d.\n", event_name, getpid(), i, wait);
			sleep(1);
		}
		if(i == 0 && nvram_match("ahs_service", (char *)event_name))
			return 2;
	}

	return 0;
}


