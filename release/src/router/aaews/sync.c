#include <sync.h>
#include <pthread.h>
#include <string.h>
#include <log.h>
#include <assert.h>
#include <tunnel_proc.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <errno.h>
#define SYNC_DBG 1



void* waiting_thread (void* data)
{
	sem_t* sem = (sem_t*)data;
	Cdbg(SYNC_DBG, ">>>>>>> wait sem1 start<<<<<<<");	
	sem_wait(sem);
	Cdbg(SYNC_DBG, ">>>>>>> wait sem1 end<<<<<<<");	
	return NULL;
}


int init_event(sem_t* sem)
{
	return sem_init(sem, 0, 0);
}

int set_waiting_event(sem_t* sem )
{
	pthread_t tid;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	pthread_create(&tid, &attr, waiting_thread, sem );
	pthread_attr_destroy(&attr);
	return tid; 
}


int set_event_alert(sem_t* sem)
{
	return sem_post(sem);
}

void dump_errno(int err)
{
		if(errno ==EACCES )
		{
			Cdbg(SYNC_DBG, "create SEM_FAILED EACCESS");
		}else if(err == EEXIST){
			Cdbg(SYNC_DBG, "create SEM_FAILED EEXIST");
		}else if(err == EINVAL){
			Cdbg(SYNC_DBG, "create SEM_FAILED EINVAL");
		}else if(err == EMFILE){
			Cdbg(SYNC_DBG, "create SEM_FAILED EMFILE");
		}else if(err == ENAMETOOLONG){
			Cdbg(SYNC_DBG, "create SEM_FAILED EMTOOLONG");
		}else if(err == ENFILE){
			Cdbg(SYNC_DBG, "create SEM_FAILED ENFILE");
		}else if(err == ENOENT){
			Cdbg(SYNC_DBG, "create SEM_FAILED ENOENT");
		}else if(err == ENOMEM){
			Cdbg(SYNC_DBG, "create SEM_FAILED ENOMEM");
		}else{
			Cdbg(SYNC_DBG, "create SEM_FAILED Other cases errno =%d", err);
		}

}

int deinit_semaphore(sem_t* sem, const char* name)
{
	int status = -1;
#ifdef EMBEDDED
	if(sem) {
		status = sem_destroy(sem);
		free(sem);
	}
#else
	if(sem){ 
		status = sem_close(sem);
		if(status <0) goto _DEINIT_SEM_EXIT;
		status = sem_unlink(name);
		if(status <0) goto _DEINIT_SEM_EXIT;
	}
#endif
	return status;	
}

int init_semaphore(sem_t** sem, const char* name)
{
	int status = -1;
#ifdef EMBEDDED
	*sem = malloc(sizeof(sem_t));
	memset(*sem, 0, sizeof(sem_t));
	status = sem_init(*sem, 0, 0);
	Cdbg(SYNC_DBG, "init status = %d", status );
	if(status == -1){
		dump_errno(errno);
		goto _INIT_SEM_EXIT;
	}
#else
	*sem = sem_open(name, O_CREAT |O_EXCL, 0666, 0);
	if(*sem == SEM_FAILED) {
		if(errno == EEXIST || errno == EACCES)	
		{
			*sem = sem_open(name, O_CREAT , 0666, 0);
			if(*sem == SEM_FAILED) Cdbg(SYNC_DBG, "still failed");
			sem_close(*sem);
			sem_unlink(name);
		}
		*sem = sem_open(name, O_CREAT, 0666, 0);
		if(*sem == SEM_FAILED){
			Cdbg(SYNC_DBG, "create %s SEM_FAILED %d", name, errno);
			dump_errno(errno);
			status = -1;
			goto _INIT_SEM_EXIT;
		}else{
			Cdbg(SYNC_DBG, "sem pointer =%p", *sem);
		}
	}
	status =0;	
#endif
_INIT_SEM_EXIT:
	return status;
}

int wait_event(sem_t* se)
{
	Cdbg(SYNC_DBG, "sem pointer =%p", se);
	if(!se) return -1;	
	else 	return sem_wait(se);
}

int set_event(sem_t* se)
{
	if(!se ) return -1;
	else {
		Cdbg(SYNC_DBG, "sem pointer =%p", se);
		return sem_post(se);
	}
}
