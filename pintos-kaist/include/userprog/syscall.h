

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <threads/thread.h>

void syscall_init (void);

void halt(void);
void exit(int status);
tid_t fork (const char *thread_name, struct intr_frame *if_);
int exec(const char *cmd_line);
int wait(tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void check_address(const uint64_t *addr);
void check_buffer(const void *buffer, unsigned size);

#endif /* userprog/syscall.h */
