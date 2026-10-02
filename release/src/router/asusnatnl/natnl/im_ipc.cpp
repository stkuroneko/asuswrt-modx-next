#include "pj/log.h"
#include "im_ipc.h"
#include "im_handler.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#if !defined(WIN32) && !defined(PJ_ANDROID)
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#endif

#define THIS_FILE "im_ipc.c"

#if !defined(WIN32) && !defined(PJ_ANDROID)

#define PROCPS_BUFSIZE 1024
#define ULLONG_MAX     (~0ULL)
#define UINT_MAX       (~0U)

pthread_t thread_control_message;
#define xrealloc_vector(vector, shift, idx) \
        xrealloc_vector_helper((vector), (sizeof((vector)[0]) << 8) + (shift), (idx))

typedef struct procps_status_t {
        DIR *dir;
        unsigned char shift_pages_to_bytes;
        unsigned char shift_pages_to_kb;
/* Fields are set to 0/NULL if failed to determine (or not requested) */
        unsigned int argv_len;
        char *argv0;
        /* Everything below must contain no ptrs to malloc'ed data:
         * it is memset(0) for each process in procps_scan() */
        unsigned long vsz, rss; /* we round it to kbytes */
        unsigned long stime, utime;
        unsigned long start_time;
        unsigned pid;
        unsigned ppid;
        unsigned pgid;
        unsigned sid;
        unsigned uid;
        unsigned gid;
        unsigned tty_major,tty_minor;
        char state[4];
        /* basename of executable in exec(2), read from /proc/N/stat
         * (if executable is symlink or script, it is NOT replaced
         * by link target or interpreter name) */
        char comm[16];
        /* user/group? - use passwd/group parsing functions */
} procps_status_t;

enum {
        PSSCAN_PID      = 1 << 0,
        PSSCAN_PPID     = 1 << 1,
        PSSCAN_PGID     = 1 << 2,
        PSSCAN_SID      = 1 << 3,
        PSSCAN_UIDGID   = 1 << 4,
        PSSCAN_COMM     = 1 << 5,
        /* PSSCAN_CMD      = 1 << 6, - use read_cmdline instead */
        PSSCAN_ARGV0    = 1 << 7,
        /* PSSCAN_EXE      = 1 << 8, - not implemented */
        PSSCAN_STATE    = 1 << 9,
        PSSCAN_VSZ      = 1 << 10,
        PSSCAN_RSS      = 1 << 11,
        PSSCAN_STIME    = 1 << 12,
        PSSCAN_UTIME    = 1 << 13,
        PSSCAN_TTY      = 1 << 14,
        PSSCAN_SMAPS    = (1 << 15) * 0,
        PSSCAN_ARGVN    = (1 << 16) * 1,
        PSSCAN_START_TIME = 1 << 18,
        /* These are all retrieved from proc/NN/stat in one go: */
        PSSCAN_STAT     = PSSCAN_PPID | PSSCAN_PGID | PSSCAN_SID
                        | PSSCAN_COMM | PSSCAN_STATE
                        | PSSCAN_VSZ | PSSCAN_RSS
                        | PSSCAN_STIME | PSSCAN_UTIME | PSSCAN_START_TIME
                        | PSSCAN_TTY,
};

static int read_to_buf(const char *filename, void *buf)
{
        int fd;
        /* open_read_close() would do two reads, checking for EOF.
         * When you have 10000 /proc/$NUM/stat to read, it isn't desirable */
        int ret = -1;
        fd = open(filename, O_RDONLY);
        if (fd >= 0) {
                ret = read(fd, buf, PROCPS_BUFSIZE-1);
                close(fd);
        }
        ((char *)buf)[ret > 0 ? ret : 0] = '\0';
        return ret;
}

void* xzalloc(size_t size)
{
        void *ptr = malloc(size);
        memset(ptr, 0, size);
        return ptr;
}

void* xrealloc(void *ptr, size_t size)
{
        ptr = realloc(ptr, size);
        if (ptr == NULL && size != 0)
                perror("no memory");
        return ptr;
}

void* xrealloc_vector_helper(void *vector, unsigned sizeof_and_shift, int idx)
{
        int mask = 1 << (unsigned char)sizeof_and_shift;

if (!(idx & (mask - 1))) {
                sizeof_and_shift >>= 8; /* sizeof(vector[0]) */
                vector = xrealloc(vector, sizeof_and_shift * (idx + mask + 1));
                memset((char*)vector + (sizeof_and_shift * idx), 0, sizeof_and_shift * (mask + 1));
        }
        return vector;
}

static procps_status_t* alloc_procps_scan(void)
{
    unsigned n = getpagesize();
    procps_status_t* sp = (procps_status_t*)xzalloc(sizeof(procps_status_t));
    sp->dir = opendir("/proc");
    while (1) {
        n >>= 1;
        if (!n) break;
        sp->shift_pages_to_bytes++;
    }
    sp->shift_pages_to_kb = sp->shift_pages_to_bytes - 10;
    return sp;
}
void BUG_comm_size(void)
{
}

static unsigned long long ret_ERANGE(void)
{
        errno = ERANGE; /* this ain't as small as it looks (on glibc) */
        return ULLONG_MAX;
}
static unsigned long long handle_errors(unsigned long long v, char **endp, char *endptr)
{
    if (endp) *endp = endptr;

    /* errno is already set to ERANGE by strtoXXX if value overflowed */
    if (endptr[0]) {
        /* "1234abcg" or out-of-range? */
        if (isalnum(endptr[0]) || errno)
            return ret_ERANGE();
        /* good number, just suspicious terminator */
        errno = EINVAL;
    }
    return v;
}
unsigned bb_strtou(const char *arg, char **endp, int base)
{
    unsigned long v;
    char *endptr;

    if (!isalnum(arg[0])) return ret_ERANGE();
    errno = 0;
    v = strtoul(arg, &endptr, base);
    if (v > UINT_MAX) return ret_ERANGE();
    return handle_errors(v, endp, endptr);
}

const char* bb_basename(const char *name)
{
        const char *cp = strrchr(name, '/');
        if (cp)
                return cp + 1;
        return name;
}

static int comm_match(procps_status_t *p, const char *procName)
{
	int argv1idx;

	/* comm does not match */
	if (strncmp(p->comm, procName, 15) != 0) {
		return 0;
	}

	/* in Linux, if comm is 15 chars, it may be a truncated */
	if (p->comm[14] == '\0') /* comm is not truncated - match */ {
		return 1;
	}

	/* comm is truncated, but first 15 chars match.
	 * This can be crazily_long_script_name.sh!
	 * The telltale sign is basename(argv[1]) == procName. */

	if (!p->argv0) {
		return 0;
	}

	argv1idx = strlen(p->argv0) + 1;
	if (argv1idx >= p->argv_len) {
		return 0;
	}

	if (strcmp(bb_basename(p->argv0 + argv1idx), procName) != 0) {
		return 0;
	}

	return 1;
}

void free_procps_scan(procps_status_t* sp)
{
        closedir(sp->dir);
        free(sp->argv0);
        free(sp);
}

procps_status_t* procps_scan(procps_status_t* sp, int flags)
{
        struct dirent *entry;
        char buf[PROCPS_BUFSIZE];
        char filename[sizeof("/proc//cmdline") + sizeof(int)*3];
        char *filename_tail;
        long tasknice;
        unsigned pid;
        int n;
        struct stat sb;

        if (!sp)
                sp = alloc_procps_scan();

        for (;;) {
                entry = readdir(sp->dir);
                if (entry == NULL) {
                        free_procps_scan(sp);
                        return NULL;
                }
                pid = bb_strtou(entry->d_name, NULL, 10);
                if (errno)
                        continue;

                /* After this point we have to break, not continue
                 * ("continue" would mean that current /proc/NNN
                 * is not a valid process info) */

                memset(&sp->vsz, 0, sizeof(*sp) - offsetof(procps_status_t, vsz));

                sp->pid = pid;
                if (!(flags & ~PSSCAN_PID)) break;

                filename_tail = filename + sprintf(filename, "/proc/%d", pid);

                if (flags & PSSCAN_UIDGID) {
                        if (stat(filename, &sb))
                                break;
                        /* Need comment - is this effective or real UID/GID? */
                        sp->uid = sb.st_uid;
                        sp->gid = sb.st_gid;
                }

                if (flags & PSSCAN_STAT) {
                        char *cp, *comm1;
                        int tty;
                        unsigned long vsz, rss;

                        /* see proc(5) for some details on this */
                        strcpy(filename_tail, "/stat");
                        n = read_to_buf(filename, buf);
                        if (n < 0)
                                break;
                        cp = strrchr(buf, ')'); /* split into "PID (cmd" and "<rest>" */
                        /*if (!cp || cp[1] != ' ')
                                break;*/
                        cp[0] = '\0';
                        if (sizeof(sp->comm) < 16)
                                BUG_comm_size();
                        comm1 = strchr(buf, '(');
                        /*if (comm1)*/
                                strncpy(sp->comm, comm1 + 1, sizeof(sp->comm));

                        n = sscanf(cp+2,
                                "%c %u "               /* state, ppid */
                                "%u %u %d %*s "        /* pgid, sid, tty, tpgid */
                                "%*s %*s %*s %*s %*s " /* flags, min_flt, cmin_flt, maj_flt, cmaj_flt */
                                "%lu %lu "             /* utime, stime */
                                "%*s %*s %*s "         /* cutime, cstime, priority */
                                "%ld "                 /* nice */
                                "%*s %*s "             /* timeout, it_real_value */
                                "%lu "                 /* start_time */
                                "%lu "                 /* vsize */
                                "%lu "                 /* rss */
                        /*  "%lu %lu %lu %lu %lu %lu " rss_rlim, start_code, end_code, start_stack, kstk_esp, kstk_eip */
                        /*  "%u %u %u %u "         signal, blocked, sigignore, sigcatch */
                        /*  "%lu %lu %lu"          wchan, nswap, cnswap */
                                ,
                                sp->state, &sp->ppid,
                                &sp->pgid, &sp->sid, &tty,
                                &sp->utime, &sp->stime,
                                &tasknice,
                                &sp->start_time,
                                &vsz,
                                &rss);
                        if (n != 11)
                                break;
                        /* vsz is in bytes and we want kb */
                        sp->vsz = vsz >> 10;
                        /* vsz is in bytes but rss is in *PAGES*! Can you believe that? */
                        sp->rss = rss << sp->shift_pages_to_kb;
                        sp->tty_major = (tty >> 8) & 0xfff;
                        sp->tty_minor = (tty & 0xff) | ((tty >> 12) & 0xfff00);

                        if (sp->vsz == 0 && sp->state[0] != 'Z')
                                sp->state[1] = 'W';
                        else
                                sp->state[1] = ' ';
                        if (tasknice < 0)
                                sp->state[2] = '<';
                        else if (tasknice) /* > 0 */
                                sp->state[2] = 'N';
                        else
                                sp->state[2] = ' ';

                }

                if (flags & (PSSCAN_ARGV0|PSSCAN_ARGVN)) {
                        free(sp->argv0);
                        sp->argv0 = NULL;
                        strcpy(filename_tail, "/cmdline");
                        n = read_to_buf(filename, buf);
                        if (n <= 0)
                                break;
                        if (flags & PSSCAN_ARGVN) {
                                sp->argv_len = n;
                                sp->argv0 = (char*)malloc(n + 1);
                                memcpy(sp->argv0, buf, n + 1);
                                /* sp->argv0[n] = '\0'; - buf has it */
                        } else {
                                sp->argv_len = 0;
                                sp->argv0 = strdup(buf);
                        }
                }
                break;
        }
        return sp;
}


pid_t* find_pid_by_name(const char *procName)
{
        pid_t* pidList;
        int i = 0;
        procps_status_t* p = NULL;

        pidList = (pid_t*)xzalloc(sizeof(*pidList));
        while ((p = procps_scan(p, PSSCAN_PID|PSSCAN_COMM|PSSCAN_ARGVN))) {
        		if (comm_match(p, procName)
                /* or we require argv0 to match (essential for matching reexeced /proc/self/exe)*/
                 || (p->argv0 && strcmp(bb_basename(p->argv0), procName) == 0)
                /* TOOD: we can also try /proc/NUM/exe link, do we want that? */
                ) {
                        if (p->state[0] != 'Z')
                        {
                                pidList = (pid_t*)xrealloc_vector(pidList, 2, i);
                                pidList[i++] = p->pid;
                        }
                }
        }

        pidList[i] = 0;
        return pidList;
}

int send_im_by_sig(void *arg)
{
    struct natnl_im_data *im_data = (struct natnl_im_data *)arg;
    int shmid, timeout_cnt = 0;
    key_t key = IM_MSG_SHM_KEY;
    char *shm, *s;
    int ret = 0;
    int st_code;
    int timeout_msec = im_data->timeout_sec * 1000;
    pjsip_msg_body *result_msg_body = NULL;
    pjsip_media_type media_type;
    pid_t *pid_to_send_list = 0;
	pid_t *pid;
    im_shm_data shm_data, *resp_shm_data;

    pid_to_send_list = find_pid_by_name(im_data->proc_name);
    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() proc_name=%s, pid_to_send_list=%p", im_data->proc_name, pid_to_send_list));
    if (!im_data->proc_name || !pid_to_send_list) {
        PJ_LOG(1, (THIS_FILE, "send_im_by_sig() failed. Can't not find pid for %s", im_data->proc_name));
        return -1;
    }
    
    const pj_str_t mime_text_plain = pj_str("text/plain");

    // Copy data to our shared memory structure.
    memset(&shm_data, 0, MAX_IM_SHM_DATA_SIZE);
    shm_data.type = IM_SHM_TYPE_REQUEST;
    shm_data.data_len = im_data->rdata->msg_info.msg->body->len;
    if (im_data->rdata->msg_info.msg->body->len > MAX_IM_MSG_SIZE)
    	memcpy(shm_data.data, im_data->rdata->msg_info.msg->body->data, MAX_IM_MSG_SIZE);
    else
    	memcpy(shm_data.data, im_data->rdata->msg_info.msg->body->data, im_data->rdata->msg_info.msg->body->len);

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 2 data_len=[%d]", shm_data.data_len));
    // Prepare shared memory and send a signal to the process.
    // Create the segment.
    if ((shmid = shmget(key, MAX_IM_SHM_DATA_SIZE, IPC_CREAT | 0666)) < 0) {
        PJ_LOG(1, (THIS_FILE, "send_im_by_sig() shmget() failed. %s", strerror(errno)));
        return -2; 
    }

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 3"));
    // Now we attach the segment to our data space.
    if ((shm = (char *)shmat(shmid, NULL, 0)) == (char *) -1) {
        PJ_LOG(1, (THIS_FILE, "send_im_by_sig() shmat() failed. %s", strerror(errno)));
        ret = -3; 
        goto on_error;
    }

    // Now put some things into the memory for the other process to read.
    s = shm;

    memset(s, 0, MAX_IM_SHM_DATA_SIZE);
    memcpy(s, &shm_data, MAX_IM_SHM_DATA_SIZE);
    
    *s = NULL;

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 3"));
    // Send notify to process
	for (pid = pid_to_send_list; *pid; pid++) {
		int ret = kill(*pid, IM_MSG_SIG_REQ);
		if (ret == 0)
			PJ_LOG(4, (THIS_FILE, "send_im_by_sig(). Signal [%d] was sent to process id=[%d].", IM_MSG_SIG_REQ, *pid));
		else
			PJ_LOG(4, (THIS_FILE, "send_im_by_sig(). Signal [%d] wasn't sent to process id=[%d]. %s", IM_MSG_SIG_REQ, *pid, strerror(errno)));
	}

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 4"));
    /*
     * Finally, we wait until the other process 
     * changes the shared memory and the type is eqaul IM_SHM_TYPE_RESPONSE.
     */
    resp_shm_data = (im_shm_data *)shm;
    while (timeout_msec > timeout_cnt && resp_shm_data->type != IM_SHM_TYPE_RESPONSE) {
        pj_thread_sleep(1);
        timeout_cnt+=1;
    	/*PJ_LOG(4, (THIS_FILE, "send_im_by_sig() wait response!!! type=%d, data_len=%d, data=[%s]", 
    		resp_shm_data->type, resp_shm_data->data_len, resp_shm_data->data));*/
    }

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 5"));
    // If the type of shared memroy didn't be changed to IM_SHM_TYPE_RESPONSE, send 408 status back.
    if (resp_shm_data->type != IM_SHM_TYPE_RESPONSE)
        st_code = 408;
    else {
		pj_str_t result;
		memset(im_data->result_body, 0, sizeof(im_data->result_body));
		if (resp_shm_data->data_len >= sizeof(im_data->result_body))
			memcpy(im_data->result_body, resp_shm_data->data, sizeof(im_data->result_body)-1);
		else
			memcpy(im_data->result_body, resp_shm_data->data, resp_shm_data->data_len);
		result = pj_str(im_data->result_body);
        st_code = 200;
        // Parse MIME type
        pjsua_parse_media_type(pjsua_var[im_data->inst_id].pool, &mime_text_plain, &media_type);

        // create sip message body
        result_msg_body = pjsip_msg_body_create(pjsua_var[im_data->inst_id].pool, &media_type.type,
                &media_type.subtype,
                &result);
    }

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 6"));
    // Send the result back.
    pjsip_endpt_respond(pjsua_var[im_data->inst_id].endpt, NULL, im_data->rdata, st_code, NULL,
            NULL, result_msg_body, NULL);

    /*if (im_data->result_body.ptr) {
            free(im_data->result_body.ptr);
            im_data->result_body.slen = 0;
    }*/
    pj_bzero(&im_data->rdata->endpt_info, sizeof(im_data->rdata->endpt_info));
	if (im_data->r_msg) {
		if (im_data->r_msg->ptr) {
			free(im_data->r_msg->ptr);
			im_data->r_msg->ptr = NULL;
		}
		free(im_data->r_msg);
		im_data->r_msg = NULL;
	}
	if (im_data->proc_name) {
		free(im_data->proc_name);
		im_data->proc_name = NULL;
	}
	free(im_data);

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 8"));
    // Now we detach the segment from our data space.
    if (shmdt(shm) < 0) {
        PJ_LOG(1, (THIS_FILE, "send_im_by_sig() shmdt() failed. %s", strerror(errno)));
        //return -2; // Acutally we done almost, don't return error.
    }

on_error:
    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 9"));
    // Mark the shared memory it can be destroyed.
    if (shmctl(shmid, IPC_RMID, NULL)) {
        PJ_LOG(1, (THIS_FILE, "send_im_by_sig() shmctl() failed. %s", strerror(errno)));
        //return -2; // Acutally we done almost, don't return error.
    }

    PJ_LOG(4, (THIS_FILE, "send_im_by_sig() 10"));
    return ret;
}

int read_im_msg_from_shm(char **msg_buf)
{
	int shmid;
    key_t key = IM_MSG_SHM_KEY;
    char *shm, *s;
    im_shm_data shm_data;

    // Locate the segment.
    if ((shmid = shmget(key, MAX_IM_SHM_DATA_SIZE, 0666)) < 0) {
        PJ_LOG(1, (THIS_FILE, "read_im_msg_from_shm() shmget() failed. %s", strerror(errno)));
        return -1; 
    }

    // Now we attach the segment to our data space.
    if ((shm = (char *)shmat(shmid, NULL, 0)) == (char *) -1) {
        PJ_LOG(1, (THIS_FILE, "read_im_msg_from_shm() shmget() failed. %s", strerror(errno)));
        return -2; 
    }

     // Now read what the client-side put in the memory.
     memcpy(&shm_data, shm, MAX_IM_SHM_DATA_SIZE);

     // We allocate the paramter so the caller must be reponsible for freeing it.
     *msg_buf = (char *)malloc(shm_data.data_len+1);
     memset(*msg_buf, 0, shm_data.data_len+1);
     memcpy(*msg_buf, shm_data.data, shm_data.data_len);

    // Now we detach the segment from our data space.
    if (shmdt(shm) < 0) {
        PJ_LOG(1, (THIS_FILE, "read_im_msg_from_shm() shmdt() failed. %s", strerror(errno)));
        //return -2; // Acutally we done almost, don't return error.
    }

    return 0;
}

int write_im_resp_to_shm(char *resp_msg)
{
	int shmid;
    key_t key = IM_MSG_SHM_KEY;
    char *shm, *s;
    im_shm_data shm_data;

    if (!resp_msg) {
        PJ_LOG(1, (THIS_FILE, "write_im_resp_to_shm() resp_msg is null."));
        return -1;
    }

    // Locate the segment.
    if ((shmid = shmget(key, MAX_IM_SHM_DATA_SIZE, 0666)) < 0) {
        PJ_LOG(1, (THIS_FILE, "write_im_resp_to_shm() shmget() failed. %s", strerror(errno)));
        return -2; 
    }

    // Now we attach the segment to our data space.
    if ((shm = (char *)shmat(shmid, NULL, 0)) == (char *) -1) {
        PJ_LOG(1, (THIS_FILE, "write_im_resp_to_shm() shmget() failed. %s", strerror(errno)));
        return -3; 
    }

    // Now write the response to the memroy.
    memset(&shm_data, 0, MAX_IM_SHM_DATA_SIZE);
    shm_data.type = IM_SHM_TYPE_RESPONSE;
    shm_data.data_len = strlen(resp_msg);
    if (shm_data.data_len > MAX_IM_MSG_SIZE)
        memcpy(shm_data.data, resp_msg, MAX_IM_MSG_SIZE);
    else
        memcpy(shm_data.data, resp_msg, shm_data.data_len);
    
    s = shm;
    memcpy(s, &shm_data, MAX_IM_SHM_DATA_SIZE);

    // Now we detach the segment from our data space.
    if (shmdt(shm) < 0) {
        PJ_LOG(1, (THIS_FILE, "write_im_resp_to_shm() shmdt() failed. %s", strerror(errno)));
        //return -2; 
    }

    return 0;
}
#else
int send_im_by_sig(void *arg)
{
    struct natnl_im_data *im_data = (struct natnl_im_data *)arg;
    free(im_data);
    return 0;
}

int read_im_msg_from_shm(char *msg_buf)
{
	return 0;
}

int write_im_resp_to_shm(const char *resp_msg)
{
	return 0;
}
#endif

