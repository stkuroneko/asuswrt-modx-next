#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>		//struct timeval
#include <unistd.h>

#define TIME_LEN	64
#define DEFAULT_FMT "%Y-%m-%d_%H:%M:%S"
char* alloc_time_string(const char* tf, int is_msec, char** time_string)
{
    struct timeval tv;
    struct tm* ptm;
    char*  mtf = NULL;
    if(!tf) mtf = DEFAULT_FMT;
    else    mtf = (char *)tf;
    *time_string = (char*) malloc(TIME_LEN);
    memset(*time_string, 0, TIME_LEN);
    long milliseconds;

    /* Obtain the time of day, and convert it to a tm struct. */
    gettimeofday (&tv, NULL);
    ptm = localtime (&tv.tv_sec);
    /* Format the date and time, down to a single second. */
    strftime (*time_string, TIME_LEN, mtf, ptm);
    /* Compute milliseconds from microseconds. */
    milliseconds = tv.tv_usec / 1000;
    /* Print the formatted time, in seconds, followed by a decimal point
    *    and the milliseconds. */
    if(is_msec) {
        char msec [8] ; memset(msec, 0, 8);
        sprintf (msec, ".%03ld", milliseconds);
        strcat(*time_string, msec);
    }
//  fprintf(stderr, "time string =%s", time_string );
    return *time_string; 
}

void dealloc_time_string(char* ts)
{
	if(ts) free(ts);
}

int is_device_ticket_expired(const char *exp_time_str)
{
    struct timeval tv;
    struct tm tm_expire_utc, tm_curr_utc;
    time_t timet_expire_utc, timet_curr_utc;

    if (!strlen(exp_time_str))
        return 0;
    strptime(exp_time_str, "%Y-%m-%d %H:%M:%S", &tm_expire_utc);
    timet_expire_utc = mktime(&tm_expire_utc);
    /* Obtain the time of day, and convert it to a tm struct. */
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm_curr_utc);
    timet_curr_utc = mktime(&tm_curr_utc);
    //printf("%s %lld < %lld\n", exp_time_str, (long long)timet_expire_utc, (long long)timet_curr_utc);
    return timet_expire_utc < timet_curr_utc;
}
