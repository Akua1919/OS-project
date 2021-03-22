#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/directory.h"

void syscall_init (void);
void syscall_exit (void);
struct dir * get_last_directory (const char *);
struct dir * get_last_absolute_path (const char *);
struct dir * get_last_relative_path (const char *);
int get_next_part (char part[NAME_MAX + 1], const char **);
struct dir;

#endif /* userprog/syscall.h */
