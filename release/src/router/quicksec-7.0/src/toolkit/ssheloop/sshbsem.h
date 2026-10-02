/**
   @copyright
   Copyright (c) 2011 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/*
   Binary semaphore API for inter-thread use.
*/

#ifndef SSHBSEM_H
#define SSHBSEM_H

typedef struct SshBSemRec *SshBSem;

/* Allocate binary semaphore and initialize its value to
   zero. Argument `name' is an identifier of the semaphore for
   debugging purposes. Argument `flags' is ignored. Return pointer to
   the semaphore if successful, NULL otherwise. */
SshBSem ssh_bsem_create(const char *name, uint32_t flags);

/* Destroy binary semaphore. */
void ssh_bsem_destroy(SshBSem bsem);

/* If the current value of the binary semaphore `bsem' is zero, set
   the value to one and if there is a thread waiting on the semaphore
   unblock it. If the current value is one do nothing. */
void ssh_bsem_signal(SshBSem bsem);

/* If the current value of the binary semaphore `bsem' is zero, block
   until the value becomes one. If the current value is one, do not
   block. Set the value to zero and return. */
void ssh_bsem_wait(SshBSem bsem);

/* Returns the name of the binary semaphore `bsem', or NULL if the
   semaphore does not have a name. The name returned will be valid as
   long as the semaphore is not destroyed. */
const char *ssh_bsem_get_name(SshBSem bsem);

#endif /* SSHBSEM_H */
