/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Calendar time retrieval and manipulation.

   <keywords calender time, time, retrieval/time, manipulation/time,
   utility functions/time>
*/

#ifndef SSHTIME_H
#define SSHTIME_H

typedef int64_t SshTime;

typedef char * MonotonicTime;

/** Calendar time. */
typedef struct SshCalendarTimeRec {
  uint8_t second;     /** 0-61. */
  uint8_t minute;     /** 0-59. */
  uint8_t hour;       /** 0-23. */
  uint8_t monthday;   /** 1-31. */
  uint8_t month;      /** 0-11. */
  int32_t year;       /** Absolute value of year, 1999=1999. */
  uint8_t weekday;    /** 0-6, 0=sunday. */
  uint16_t yearday;   /** 0-365. */
  int32_t utc_offset; /** Seconds from UTC (positive=east). */
  bool dst;         /** false=non-DST, true=DST. */
} *SshCalendarTime, SshCalendarTimeStruct;

typedef struct SshTimeValueRec {
  int64_t seconds;
  int64_t microseconds;
} *SshTimeValue, SshTimeValueStruct;


/** Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  */
SshTime ssh_time(void);

int monotonic_time_value(MonotonicTime monotonic_time);

SshTime ssh_time_from_monotonic_time(MonotonicTime monotonic_time);

MonotonicTime monotonic_time_from_ssh_time(SshTime time_value);

/** Returns a monotonically increasing time in seconds. */
MonotonicTime monotonic_time_get(void);

/** Returns seconds and microseconds from epoch
    "January 1 1970,00:00:00 UTC". */
void ssh_get_time_of_day(SshTimeValue time);


/** Fills the calendar structure according to ''current_time''. */
void ssh_calendar_time(SshTime current_time,
                       SshCalendarTime calendar_ret,
                       bool local_time);




/** Return time string in RFC-2550 compatible format.

    @return
    The returned string is allocated with ssh_malloc and has to be
    freed with ssh_free by the caller.

    */
char *ssh_time_string(SshTime input_time);

/** Format time string in RFC-2550 compatible format as snprintf renderer.
    The datum points to the SshTime. */
int ssh_time_render(char *buf, int buf_size, int precision,
                    void *datum);

/** Format time string in RFC-2550 compatible format as snprintf renderer.
    The datum points to the memory buffer having the 32-bit long time
    in seconds from the epoch in the network byte order. */
int ssh_time32buf_render(char *buf, int buf_size, int precision,
                    void *datum);


/** Return a time string that is formatted to be more or less human
    readable.  It is somewhat like the one returned by ctime(3) but
    contains no newline in the end.  Returned string is allocated with
    ssh_malloc and has to be freed with ssh_free by the caller. */
char *ssh_readable_time_string(SshTime input_time, bool local_time);

/** Convert SshCalendarTime to SshTime. If the dst is set to true,
    then daylight saving time is assumed to be set, if dst field is
    set to false then it is assumed to be off. It if it is set to -1
    then the function tries to find out if the dst was on or off at
    the time given.

    Weekday and yearday fields are ignored in the conversion, but
    filled with appropriate values during the conversion. All other
    values are normalized to their normal range during the conversion.

    @param local_time
    If the local_time is set to true, then dst and utc_offset values
    are ignored.

    @return
    If the time cannot be expressed as SshTime, this function returns
    false, otherwise returns true.

    */
bool ssh_make_time(SshCalendarTime calendar_time, SshTime *time_return,
                      bool local_time);

#endif /* SSHTIME_H */

/* eof (sshtime.h) */
