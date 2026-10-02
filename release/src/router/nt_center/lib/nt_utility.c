#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <libnt.h>
#include <stdarg.h>
#include <math.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define READ_BUF_SIZE   1024

#define FW_CREATE       0
#define FW_APPEND       1
#define FW_NEWLINE      2

void Debug2Console(const char * format, ...)
{
	FILE *f;
	int nfd;
	va_list args;
	
	if (((nfd = open("/dev/console", O_WRONLY | O_NONBLOCK)) > 0) &&
	    (f = fdopen(nfd, "w")))
	{
		va_start(args, format);
		vfprintf(f, format, args);
		va_end(args);
		fclose(f);
	}
	else
	{
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
	}
	
	if (nfd != -1) close(nfd);
}

void Debug2File(const char *FilePath, const char * format, ...)
{
	FILE *f;
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

int isFileExist(char *fname)
{
	struct stat fstat;
	
	if (lstat(fname,&fstat)==-1)
		return 0;
	if (S_ISREG(fstat.st_mode))
		return 1;
	
	return 0;
}

int isDirectoryExist(char *fname)
{
	struct stat fstat;
	
	return (stat(fname, &fstat) == 0) && (S_ISDIR(fstat.st_mode));
}

static void remove_delimitor(char *s)
{
	char *p1, *p2;
	
	p1 = p2 = s;
	while(*p1 != '\0' || *(p1 + 1) != '\0') {
		if(*p1 != '\0') {
			*p2 = *p1;
			p2++;
		}
		p1++;
	}
	*p2 = '\0';
}

int get_pid_num_by_name(char *pidName)
{
	DIR *dir;
	struct dirent *next;
	int match_cnt = 0;
	FILE *cmdline;
	char filename[READ_BUF_SIZE];
	char buffer[READ_BUF_SIZE];
	
	dir = opendir("/proc");
	if(!dir) {
		printf("Cannot open /proc\n");
		return 0;
	}
	
	while((next = readdir(dir)) != NULL) {
		memset(filename, 0, sizeof(filename));
		memset(buffer, 0, sizeof(buffer));
		
		if(strcmp(next->d_name, "..") == 0) {
			continue;
		}
		
		if(!isdigit(*next->d_name)) {
			continue;
		}
		
		sprintf(filename, "/proc/%s/cmdline", next->d_name);
		if(!(cmdline = fopen(filename, "r"))) {
			continue;
		}
		if(fgets(buffer, READ_BUF_SIZE - 1, cmdline) == NULL) {
			fclose(cmdline);
			continue;
		}
		fclose(cmdline);
		
		remove_delimitor(buffer);
		
		if(strstr(buffer, pidName) != NULL) {
			match_cnt++;
		}
	}
	closedir(dir);
	
	return match_cnt;
}

void StampToDate(unsigned long timestamp, char *date)
{
	struct tm *local;
	time_t now;
	
	now = timestamp;
	local = localtime(&now);
	strftime(date, 30, "%Y-%m-%d %H:%M:%S", local);
}

int xfile_lock(char *tag)
{
	char fn[64];
	struct flock lock;
	int lockfd = -1;
	pid_t lockpid;
	
	sprintf(fn, "/var/lock/%s.lock", tag);
	if ((lockfd = open(fn, O_CREAT | O_RDWR, 0666)) < 0)
		goto lock_error;
	
	pid_t pid = getpid();
	if (read(lockfd, &lockpid, sizeof(pid_t))) {
		// check if we already hold a lock
		if (pid == lockpid) {
			// don't close the file here as that will release all locks
			return -1;
		}
	}
	
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_pid = pid;
	
	if (fcntl(lockfd, F_SETLKW, &lock) < 0) {
		close(lockfd);
		goto lock_error;
	}
	
	lseek(lockfd, 0, SEEK_SET);
	write(lockfd, &pid, sizeof(pid_t));
	return lockfd;
lock_error:
	// No proper error processing
	printf("Error %d locking %s, proceeding anyway", errno, fn);
	return -1;
}

void xfile_unlock(int lockfd)
{
	if (lockfd >= 0) {
		ftruncate(lockfd, 0);
		close(lockfd);
	}
}

static int f_read(const char *path, void *buffer, int max)
{
	int f;
	int n;
	
	if ((f = open(path, O_RDONLY)) < 0) return -1;
	n = read(f, buffer, max);
	close(f);
	return n;
}

int f_read_string(const char *path, char *buffer, int max)
{
	if (max <= 0) return -1;
	int n = f_read(path, buffer, max - 1);
	buffer[(n > 0) ? n : 0] = 0;
	return n;
}

static int f_write(const char *path, const void *buffer, int len, unsigned flags, unsigned cmode)
{
	static const char nl = '\n';
	int f;
	int r = -1;
	mode_t m;
	
	m = umask(0);
	if (cmode == 0) cmode = 0666;
	if ((f = open(path, (flags & FW_APPEND) ? (O_WRONLY|O_CREAT|O_APPEND) : (O_WRONLY|O_CREAT|O_TRUNC), cmode)) >= 0) {
		if ((buffer == NULL) || ((r = write(f, buffer, len)) == len)) {
			if (flags & FW_NEWLINE) {
				if (write(f, &nl, 1) == 1) ++r;
			}
		}
		close(f);
	}
	umask(m);
	return r;
}

int f_write_string(const char *path, const char *buffer, unsigned flags, unsigned cmode)
{
	return f_write(path, buffer, strlen(buffer), flags, cmode);
}

/*
 * Wrapper for malloc/realloc/strdup/free
 */
void *xmalloc(size_t size)
{
	void *ret=NULL;
	
	if (size == 0) {
		fprintf(stderr, "Cannot allocate buffer of size 0.\n");
		abort();
	}
	ret = malloc(size);
	if (!ret) {
		perror("libnt-xmalloc");
		abort();
	}
	memset(ret, '\0', size);
	return ret;
}

void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret) {
		perror("libnt-xrealloc");
		abort();
	}
	return ret;
}

char *xstrdup(const char *str)
{
	char *ret=NULL;
	if (str) {
		ret = strdup(str);
		if (!ret) {
			perror("libnt-xstrdup");
			abort();
		}
	}
	return ret;
}

void __xfree(void *ptr)
{
	if (ptr) {
		free(ptr);
	}
}

/**
 * Return the next prime number out of the number from the
 * input integer.
 *
 * Params
 *      n - The number to find the next prime from
 *
 * Return
 *      The next prime number of n
 */
int nextprime(int n)
{
	int i, div, ceilsqrt = 0;
	int retval=0;
	
	for (;; n++) {
		ceilsqrt = ceil(sqrt(n));
		for (i = 2; i <= ceilsqrt; i++) {
			div = n / i;
			if (div * i == n) {
				retval = n;
				break;
			}
		}
		if (retval) {
			break;
		}
	}
	
	return retval;
}

/**
 * Finds the first occurance of a character in a string and 
 * returns the index to where it is.
 */
int
strfind(const char *str, char ch)
{
	int i;
	for (i=0; *str != '\0'; i++, str++) {
		if (*str == ch) {
			return i;
		}
	}
	return -1;
}

/**
 * Removes the \r and \n at the end of the line provided.
 * This gets rid of standards UNIX \n line endings and 
 * also DOS CRLF or \r\n line endings.
 */
void rmEndhar(char *str)
{
	char *cp;
	
	if (str && (cp = strrchr(str, '\n'))) {
		*cp = '\0';
	}
	if (str && (cp = strrchr(str, '\r'))) {
		*cp = '\0';
	}
}


/**
 * Returns the size of a file.
 */
size_t filesize(const char *file)
{
	struct stat sb;
	
	memset(&sb, 0, sizeof(struct stat));
	if (stat(file, &sb) < 0) {
		return -1;
	}
	return sb.st_size;
}

int _xvstrsep(char *buf, const char *sep, ...)
{
	va_list ap;
	char **p;
	int n;
	
	n = 0;
	va_start(ap, sep);
	while ((p = va_arg(ap, char **)) != NULL) {
		if ((*p = strsep(&buf, sep)) == NULL) break;
		++n;
	}
	va_end(ap);
	return n;
}

int x_get_mac(unsigned char *mac_address)
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024]; memset(buf, 0, sizeof(buf));
	int success = 0;
	
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		printf("sock error\n");
		return -1;
	};
	
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
		printf("ioctl sock error\n");
		return -1;
	}
	
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	
	for (; it != end; ++it) {
		strncpy(ifr.ifr_name, it->ifr_name, sizeof(ifr.ifr_name)-1);
		printf("ifr_name:[%s]\n", it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { /* don't count loopback */
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
					break;
				}
			}
		} else {
			printf("ioctl SIOCGIFFLAGS failed\n");
		}
	}
	
	if (success) 
		memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	
	return 1;
}
