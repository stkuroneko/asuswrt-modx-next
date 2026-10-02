/*****************************************************************************
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  scapi_sh_mem.c                                    *
 *         Description  :  This file contains all the data declarations that are
                           shared across the modules                      *  
 *  *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <stdint.h>
#include <scapi_ipc.h>

#include <errno.h>
#include "ulogging.h"

#define QOS_SHM_KEY_START 1234
#define QOS_SHM_KEY_END 1235
#define QOS_SHM_PERM 0666

/* 
** =============================================================================
**   Function Name    : ipc_get_memory 
**   Description      : To get the shared memory key 
**   Return Value     : Success -> IPC_SUCCESS 
**                      Failure -> IPC_FAIL
** ===========================================================================*/


int32_t ipc_get_memory(uint32_t *shm_key, int32_t *shm_id, char **data, uint32_t size, int32_t create)
{
	int32_t flags = QOS_SHM_PERM;

	if (create) {
		flags |= IPC_CREAT | IPC_EXCL;
		*shm_key = QOS_SHM_KEY_START;
	}

for(*shm_id = shmget(*shm_key, size, flags); (*shm_id < 0); *shm_key += 1 ) 
{
	if(create != 0 && errno == EEXIST && *shm_key < QOS_SHM_KEY_END){
		continue;
	}
	LOGF_LOG_DEBUG("Could not get shared memory....\n");
	*shm_key = 0;
	return IPC_FAIL;
}
	/* attach to the segment to get a pointer to it: */
	*data = shmat(*shm_id, (void *) NULL, 0);
	if (*data == (char *)(-1)) {
		perror("shmat");
		*shm_key = 0;
		shmctl(*shm_id, IPC_RMID, NULL);
    return IPC_FAIL;
	}

	return IPC_SUCCESS;
}


/* 
** =============================================================================
**   Function Name    : ipc_delete_memory 
**   Description      : Mark the segment to be destroyed. 
			The segment will only actually be destroyed 
			after the last process detaches it 
**   Return Value     : Success -> IPC_SUCCESS 
**                      Failure -> IPC_FAIL
** ===========================================================================*/


int32_t ipc_delete_memory(int32_t shm_id, char **data, int32_t delete)
{
	/* deattach to the segment to get a pointer to it: */
	shmdt((void *) *data);

	if (delete)
		shmctl(shm_id, IPC_RMID, NULL);

	return IPC_SUCCESS;
}
