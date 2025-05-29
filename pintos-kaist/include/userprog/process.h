#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct initial_args
{
	char *fn_copy;
	struct thread *parent;
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
struct file *process_get_file(int fd);
int process_add_file(struct file *file);

void processOff();
int process_wait (tid_t);
void process_exit (void);

void processOff();
void process_activate (struct thread *next);

struct thread *get_child_thread (tid_t pid);

#endif /* userprog/process.h */
