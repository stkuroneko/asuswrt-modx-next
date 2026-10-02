#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_sched.h"

#ifdef MIN
#undef MIN
#endif
#define MIN(a, b) ((a) > (b) ? (b) : (a))

static struct sched place_hold = {
	-1,
	NULL,
	NULL
};

static struct {
	struct sched *first;
	struct sched *last;
	int count;
	int status;
} sched_header = { &place_hold, &place_hold, 1, 0};

static long cur_time = -1;
int sched_stopped = 0;

int add_sched( struct sched *s )
{
	sched_header.last->next = s;
	sched_header.last = s;
	s->next = NULL;
	sched_header.count++;
	return 0;
}

time_t current_time()
{
	if( cur_time == -1 ) {
		cur_time = uptime();
	}

	return cur_time;
}

void start_sched()
{
	for( ;; ) {
		struct sched *prev, *cur;
		cur_time = uptime();

		if (sched_stopped)
			break;

		if (nvram_get("cfg_sdm"))
			DBG_INFO("sched_header.count (%d), cur_time (%ld)", sched_header.count, cur_time);

		for( prev = sched_header.first, cur = prev->next; cur; ) {
			if (sched_stopped)
				break;

			if (nvram_get("cfg_sdm"))
				DBG_INFO("cur.name (%s), cur.timeout(%ld)", cur->name, cur->timeout);
			
			if( cur->timeout > 0 && cur->timeout <= cur_time ) {
				if (nvram_get("cfg_sdm"))
					DBG_INFO("execute %s", cur->name);
				
				if( cur->on_timeout ) {
					if (sched_stopped)
						break;
					sched_header.status = (sched_header.status == 0 ? 1: 0);
					cur->on_timeout( cur );
				} else {
					DBG_INFO("scheduler without timeout handler and timeout" );
				}

				continue;
			}

			prev = cur;
			cur = cur->next;
		}

		sleep(nvram_get("cfg_dswt") ? nvram_get_int("cfg_dswt") : DEF_SCHED_WAIT_TIME);
	}

	DBG_INFO("exit sched");
}

int get_sched_status()
{
	return sched_header.status;
}

void stop_sched()
{
	DBG_INFO("stop sched");
	sched_stopped = 1;
}
