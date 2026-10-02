#include <queue_list.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>

#define LOCK_FUNC(func, lock, q ) \
	if(pthread_mutex_lock(lock) == 0){ \
		func(q); \
		pthread_mutex_unlock(lock); \
	}
 

//int _InitQueue(pthread_mutex_t* lock, QUEUE* q )
int InitQueue(pthread_mutex_t* lock, QUEUE* q )
{
//	fprintf(stderr, "q = %p, lock=%p ---> \n",q,  lock);
	if(!lock || !q ) goto _INIT_QUEUE_EXIT;
	if(pthread_mutex_lock(lock) ==0){
		initQueue(q);
		pthread_mutex_unlock(lock);
	}else{
	/*
		if(status == EINVAL) fprintf(stderr, "EINVAL \n");
		if(status == EBUSY) fprintf(stderr, "EBUSY \n");
		if(status == EAGAIN) fprintf(stderr, "EAGAIN \n");
		if(status == EDEADLK) fprintf(stderr, "EDEADLK \n");
		if(status == EPERM) fprintf(stderr, "EPERM \n");
*/
	}
_INIT_QUEUE_EXIT:
	return 0;
}

int QueueIsEmpty(pthread_mutex_t* lock, QUEUE* q)
{
	if(!lock || !q ) goto _QUEUEISEMPTY_EXIT;
	LOCK_FUNC(queueIsEmpty, lock, q);	
_QUEUEISEMPTY_EXIT:
	return 0;
}

int QueueLength(pthread_mutex_t* lock, QUEUE* q)
{
	if(!lock || !q) goto _QUEUE_LEN_EXIT;
	LOCK_FUNC(queueLength, lock, q);
_QUEUE_LEN_EXIT:
	return 0;	
} 

int PushQueue(pthread_mutex_t* lock, QUEUE* q, void* y)
{
	if(!lock || !q || !y) goto _PUSH_QUEUE_EXIT;
	if(pthread_mutex_lock(lock) == 0){ 
		pushQueue(q, y); 
		pthread_mutex_unlock(lock);
	}

_PUSH_QUEUE_EXIT:
	return 0;
} 

void* PopQueue(pthread_mutex_t* lock, QUEUE* q)
{
	void* data =NULL;
	if(!lock || !q) goto _POP_QUEUE_EXIT;
	pthread_mutex_lock(lock); 
	data = popQueue(q);
	pthread_mutex_unlock(lock);
		
_POP_QUEUE_EXIT:
	return data;	
}
