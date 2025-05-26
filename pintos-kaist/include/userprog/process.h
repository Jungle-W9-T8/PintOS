#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct kernel_args{
	int argc;
	char *argv[32];
	char raw[128];
};

void stack_update(int argc, char* argv[], void **stackptr);

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);

void processOff();
int process_wait (tid_t);
void process_exit (void);

void processOff();
void process_activate (struct thread *next);

struct thread *get_child_thread (int pid);

#endif /* userprog/process.h */
