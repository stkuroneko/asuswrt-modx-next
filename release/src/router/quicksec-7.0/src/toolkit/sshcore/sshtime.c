/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Calendar time retrieval and manipulation.
*/

#include "sshincludes.h"
#undef time

#define SSH_DEBUG_MODULE "SshTime"

/* For windows we do not have gettimeofday or anything similar.
   We need to use our own version utilizing the GetSystemTimeAsFileTime. */





























/* Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldom provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
SshTime ssh_time(void)
{
#ifdef HAVE_GETTIMEOFDAY
    struct timeval tv;

    /* This can not fail */
    gettimeofday(&tv, NULL);
    return (SshTime)tv.tv_sec;
#else
    return (SshTime)(time(NULL));
#endif
}


MonotonicTime monotonic_time_get(void)
{
    struct timespec timespec;

    if (clock_gettime(CLOCK_MONOTONIC, &timespec) < 0)
    {
        SSH_NOTREACHED;
    }

    return (MonotonicTime) timespec.tv_sec;
}

int monotonic_time_value(MonotonicTime monotonic_time)
{
    return (int)(intptr_t) monotonic_time;
}


SshTime ssh_time_from_monotonic_time(MonotonicTime monotonic_time)
{
    SshTime difference;

    difference = monotonic_time - monotonic_time_get();

    return ssh_time() + difference;
}

MonotonicTime monotonic_time_from_ssh_time(SshTime time_value)
{
    SshTime difference;

    difference = time_value - ssh_time();

    return monotonic_time_get() + difference;
}


/* Returns seconds and microseconds to 'time' from epoch
   "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldom provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
void ssh_get_time_of_day(SshTimeValue tptr)
{
#ifdef HAVE_GETTIMEOFDAY
    struct timeval tv;

    /* This can not fail */
    gettimeofday(&tv, NULL);

    tptr->seconds = (int64_t) tv.tv_sec;
    tptr->microseconds = (int64_t) tv.tv_usec;

#else /* HAVE_GETTIMEOFDAY */



    tptr->seconds = (int64_t) (time(NULL));
    tptr->microseconds = (int64_t) 0;

#endif /* HAVE_GETTIMEOFDAY */
    return;
}


/* eof (sshtime.c) */
