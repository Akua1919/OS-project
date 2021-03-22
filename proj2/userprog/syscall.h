#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#include "threads/synch.h"

typedef int pid_t;
typedef int mmapid_t;

/* Called in process.c */
bool munmap(mmapid_t mmapid);

#endif /* userprog/syscall.h */
