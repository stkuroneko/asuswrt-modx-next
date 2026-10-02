#ifndef __CFG_SCHED_H__
#define __CFG_SCHED_H__

#define DEF_SCHED_WAIT_TIME	2

struct sched {
	time_t timeout;
	void ( *on_timeout )( struct sched * );
	struct sched *next;
	const char *name;
};

extern int add_sched( struct sched *s );
extern time_t current_time();
extern void start_sched();
extern int get_sched_status();
extern void stop_sched();

#endif /* __CFG_SCHED_H__ */
/* End of cfg_sched.h */
