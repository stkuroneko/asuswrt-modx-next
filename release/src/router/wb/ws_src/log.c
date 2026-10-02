#ifndef NDEBUG
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <log.h>
#include <time_util.h>
#include <errno.h>
#include <syslog.h>

#define LOG_PATH_LEN 150 
#define LOG_PATH_EXT "%Y-%m-%d_%H:%M:%S"
FILE* g_file_fp = NULL;
FILE* g_console_fp = NULL;
const char* ident =  "aaews";
int logopt = LOG_PID | LOG_CONS;
int facility = LOG_USER;
int g_stream_type =0;
int priority = LOG_ERR | LOG_USER;
int g_is_log_opened =0;



int isFileExist(char *fname)
{
	struct stat fstat;
	
	if (lstat(fname,&fstat)==-1)
		return 0;
	if (S_ISREG(fstat.st_mode))
		return 1;
	
	return 0;
}

#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
void Debug2File(const char *FilePath, const char * format, ...)
{
        FILE *f;
        //int nfd;
        va_list args;

        if ((f = fopen(FilePath, "a+")) > 0) {
                va_start(args, format);
                vfprintf(f, format, args);
                va_end(args);
                fclose(f);
        } else {
                printf("Open %s Error!\n", FilePath);
        }
}
#endif

int open_log(const char* log_path, int stream_type )
{
	g_stream_type = stream_type;
	if ((stream_type & SYSLOG_TYPE) == SYSLOG_TYPE) {
		openlog(ident, logopt, facility);
		g_is_log_opened = 1;
		g_stream_type = SYSLOG_TYPE;
	}
	if ((stream_type & STDOUT_TYPE) == STDOUT_TYPE) {
		g_is_log_opened = 1;
		g_stream_type = STDOUT_TYPE;
	}
	if ((stream_type & STD_ERR) == STD_ERR) {
		g_is_log_opened = 1;
		g_stream_type |= STD_ERR;
	}
	if ((stream_type & FILE_TYPE) == FILE_TYPE) {
		//char* ts;
		//alloc_time_string(LOG_PATH_EXT, 0, &ts);
		char *path;
		int len = strlen(log_path)/*+strlen(ts)*/+2;
		path = malloc(len); 
		memset(path, 0, len);
		strcpy(path,log_path );
		//strcat(path, ts);
		//		sprintf(path,"%s%s", log_path,ts);
		//dealloc_time_string(ts);
		g_file_fp = fopen(path, "w+");
		if(path) free(path);
		g_is_log_opened = 1;
		g_stream_type |= FILE_TYPE;
	}
	if ((stream_type & CONSOLE_TYPE) == CONSOLE_TYPE) {
		int nfd;
		if ((nfd = open("/dev/console", O_WRONLY | O_NONBLOCK)) > 0) {
			g_console_fp = fdopen(nfd, "w");
			g_stream_type |= CONSOLE_TYPE;
			g_is_log_opened = 1;
		}
	}
	return 0;
}

void close_log()
{
	if(g_file_fp){
	 	fclose(g_file_fp);
		g_file_fp = NULL;
	}

	if (g_console_fp) {
	 	fclose(g_console_fp);
		g_console_fp = NULL;
	}

	if((g_stream_type & SYSLOG_TYPE) == SYSLOG_TYPE) 
		closelog();
}

void dprintf_impl(const char* file,const char* func, size_t line, int enable, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    dprintf_impl2(file, func, line, enable, 0, fmt, ap);
    va_end(ap);
}

void dprintf_virtual(const char* file,const char* func, size_t line, int enable, int level, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    dprintf_impl2(file, func, line, enable, level, fmt, ap);
    va_end(ap);
}

void dprintf_impl2(const char* file,const char* func, size_t line, int enable, int level, const char* fmt, va_list ap)
{
    //va_list ap;
    if(!g_is_log_opened)
        return;
    if (enable) {
        char* ts;
        alloc_time_string(NULL, 1, &ts);
        //va_start(ap, fmt);
        // Log to file
        if (isFileExist(WB_DEBUG_TO_FILE)) {
            if (g_file_fp) {
                fprintf(g_file_fp, WHERESTR, ts, file, func, line);
                vfprintf(g_file_fp, fmt, ap);
                fprintf(g_file_fp, "\n");
                fflush(g_file_fp);
            }
        }

        // Log to console
        if (isFileExist(WB_DEBUG_TO_CONSOLE)) {
            if (g_console_fp) {
                fprintf(g_console_fp, WHERESTR, ts, file, func, line);
                vfprintf(g_console_fp, fmt, ap);
                fprintf(g_console_fp, "\n");
            }
            else {
                fprintf(stderr, WHERESTR, ts, file, func, line);
                vfprintf(stderr, fmt, ap);
                fprintf(stderr, "\n");
            }
        }

        if (isFileExist(WB_DEBUG_TO_STDOUT)) {
            fprintf(stdout, WHERESTR, ts, file, func, line);
            vfprintf(stdout, fmt, ap);
            fprintf(stdout, "\n");
        }

        // Log to syslog
        if (level == 1 || isFileExist(WB_DEBUG_TO_SYSLOG)) {
            vsyslog(priority, fmt, ap);
            fprintf(stdout, WHERESTR, ts, file, func, line);
            vfprintf(stdout, fmt, ap);
            fprintf(stdout, "\n");
        }
        
        //va_end(ap);
        dealloc_time_string(ts);
    }
}
#if 0
void get_fp(const char* log_path)
{
	FILE* fp = NULL;
	if(!log_path){
	//	fp = stderr;
		gfp = stderr;
	}else{
//		char path [LOG_PATH_LEN]={0};
		char* ts;
		alloc_time_string(LOG_PATH_EXT, 0, &ts);
		int len = strlen(log_path)+strlen(ts)+2;
		char* path = malloc(len); memset(path, 0, len);
		strcpy(path,log_path );
		strcat(path, ts);
//		sprintf(path,"%s%s", log_path,ts);
		dealloc_time_string(ts);
		fp = fopen(path, "w+");
		if(!fp) {
			fprintf(stderr, "App open log path failed errno=%d", errno);
			gfp = stderr;
		}else {
			gfp = fp;
		}
		if(path) free(path);
	}
}
#endif
//void closefp(FILE* fp)

#endif


