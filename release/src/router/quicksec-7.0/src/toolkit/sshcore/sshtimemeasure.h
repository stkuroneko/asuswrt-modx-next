/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Real time measuring.

   <keywords time/measuring, measuring/time, real time measuring,
   utility functions/real time measuring, utility functions/time>
*/

#ifndef SSHTIMEMEASURE_H
#define SSHTIMEMEASURE_H

typedef enum {
  SSH_TIME_GRANULARITY_NANOSECOND = 0,   /* 1/1000000000 seconds */
  SSH_TIME_GRANULARITY_MICROSECOND,      /*    1/1000000 seconds */
  SSH_TIME_GRANULARITY_MILLISECOND,      /*       1/1000 seconds */
  SSH_TIME_GRANULARITY_SECOND,           /*            1 second  */
  SSH_TIME_GRANULARITY_MINUTE,           /*           60 seconds */
  SSH_TIME_GRANULARITY_HOUR,             /*        60x60 seconds */
  SSH_TIME_GRANULARITY_DAY,              /*     24x60x60 seconds */
  SSH_TIME_GRANULARITY_WEEK,             /*   7x24x60x60 seconds */
  SSH_TIME_GRANULARITY_MONTH_SIDEREAL,   /*      2360592 seconds */
  SSH_TIME_GRANULARITY_MONTH_SYNODIC,    /*      2551443 seconds */
  SSH_TIME_GRANULARITY_YEAR_ANOMALISTIC, /*     31558433 seconds */
  SSH_TIME_GRANULARITY_YEAR_TROPICAL,    /*     31556926 seconds */
  SSH_TIME_GRANULARITY_YEAR_SIDEREAL     /*     31558149 seconds */
} SshTimeGranularity;

#define SSH_TIME_GRANULARITY_MONTH SSH_TIME_GRANULARITY_MONTH_SIDEREAL
#define SSH_TIME_GRANULARITY_YEAR  SSH_TIME_GRANULARITY_YEAR_SIDEREAL

struct SshTimeValRec {
  uint64_t seconds;    /* Overlaps in 584 billion years (if really 64 bits) */
  uint32_t nanoseconds;
};

typedef struct SshTimeValRec *SshTimeVal;

struct SshTimeMeasureRec {
  struct SshTimeValRec start;
  struct SshTimeValRec cumulated;
  bool running;
  };

typedef struct SshTimeMeasureRec *SshTimeMeasure, SshTimeMeasureStruct;

/**
 * SshTimeT is a return type for functions returning seconds,
 * milliseconds etc.  In systems that do not support floating
 * point numbers, it is always an integer type.  Otherwise
 * it can be either double precision floating point number or
 * some integer type.
 */
#define HAVE_DOUBLE_FLOAT





#ifdef HAVE_DOUBLE_FLOAT
typedef double SshTimeT;
#else
typedef uint64_t SshTimeT;
#endif

/**
 * Maximum value of time stamp.  Time stamps never overwrap.
 * They stop at SSH_TIME_STAMP_MAX if maximum value
 * is exceeded.
 */
#define SSH_TIME_STAMP_MAX      (~((uint64_t)0))

/**
 * Can be used to initialize statically allocated timer.
 * No separate `init' or `uninit' is needed, if this
 * method is used.
 *
 * e.g. `static struct SshTimeMeasure timer = SSH_TIME_MEASURE_INITIALIZER;'
 */
#define SSH_TIME_MEASURE_INITIALIZER { { 0, 0 }, { 0, 0 }, false }

/**
 * Init time measure structure to initial
 * nonrunning state with zero cumulated time.
 * This can be used instead of ssh_time_measure_allocate,
 * if the timer structure is statically allocated by
 * the application.  In this case, no `uninit' function
 * is needed.  It is also initialize statically allocated
 * timer structure with SSH_TIME_MEASURE_INITIALIZER.
 */
void ssh_time_measure_init(SshTimeMeasure timer);

/**
 * Allocates and returns a new nonrunning timer object.
 */
SshTimeMeasure ssh_time_measure_allocate(void);

/**
 * Frees an allocated timer object.
 */
void ssh_time_measure_free(SshTimeMeasure timer);

/**
 * Start the timer.
 */
void ssh_time_measure_start(SshTimeMeasure timer);

/**
 * Stop the timer.
 */
void ssh_time_measure_stop(SshTimeMeasure timer);

/**
 * Return true if timer is running.
 */
bool ssh_time_measure_running(SshTimeMeasure timer);

/**
 * Reset the timer to zero.
 * If timer is running before this call, the timer runs
 * also after reset.
 */
void ssh_time_measure_reset(SshTimeMeasure timer);

/**
 * Set the timer to given value in seconds and nanoseconds (10e-9s).
 * If timer is running before this call, the timer runs
 * also after set operation.
 */
void ssh_time_measure_set_value(SshTimeMeasure timer,
                                uint64_t seconds,
                                uint32_t nanoseconds);

/**
 * Get the cumulated running time of the timer.
 * Timer can be either running or stopped.
 */
void ssh_time_measure_get_value(SshTimeMeasure timer,
                                uint64_t *seconds,
                                uint32_t *nanoseconds);

/**
 * Return a time stamp from timer.  Values returned by this function
 * never overwrap.  Instead if maximum timer value is exceeded,
 * SSH_TIME_STAMP_MAX is always returned.
 */
uint64_t ssh_time_measure_stamp(SshTimeMeasure timer,
                                 SshTimeGranularity granularity);

/**
 * Get the cumulated running time of the timer in seconds.
 * Be aware that depending on SshTimeT, timer can overwrap
 * at some point.
 */
SshTimeT ssh_time_measure_get(SshTimeMeasure timer,
                              SshTimeGranularity granularity);

/**
 * Calculate difference between time values beg and end and store
 * result to ret.
 */
void ssh_time_measure_difference(SshTimeVal ret,
                                 SshTimeVal beg,
                                 SshTimeVal end);

/**
 * Add time values tv1 and tv2 together and store result to ret.
 */
void ssh_time_measure_add(SshTimeVal ret,
                          SshTimeVal tv1,
                          SshTimeVal tv2);

/**
 * A function implementing system time queries for different platforms.
 * Be aware that granularity of time measurement may vary on different
 * hardware and operating systems.  Returns false, if system time can't
 * be retrieved (i.e. system call fails).  This function returns time
 * measured from arbitrary moment in the past.  This can be time of
 * last boot or some other random epoch.
 */
bool ssh_time_measure_system_time(SshTimeVal timeval);

/**
 * Set timeval to the minimum granularity of the time measurement.
 * In some systems this value may be more like guess based
 * on the structure carrying the time information.
 * In any case, significant granularity is not finer than
 * the value returned by this function.
 * Return false if operation failed.  In any case a best guess
 * is stored to timeval.
 */
bool ssh_time_measure_system_granularity_time(SshTimeVal timeval);

/**
 * Set argument seconds and nanoseconds to the minimum granularity
 * of time measurement in the system.
 */
void ssh_time_measure_granularity(uint64_t *seconds,
                                  uint32_t *nanoseconds);


#endif /* ! SSHTIMEMEASURE_H */
/* eof (sshtimemeasure.h) */
