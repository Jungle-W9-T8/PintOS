

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init (void);
void halt (void);
void exit (int status);
int write (int fd, const void *buffer, unsigned size);
// pid_t fork (const char *thread_name);
// int exec (const char *file);
// int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
// void seek (int fd, unsigned position);
// unsigned tell (int fd);
// void close (int fd); 
// int dup2 (int oldfd, int newfd);
// void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
// void munmap (void *addr);
// bool chdir (const char *dir);
// bool mkdir (const char *dir);
// bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
// bool isdir (int fd);
// int inumber (int fd);
// int symlink (const char* target, const char* linkpath);
// int mount (const char *path, int chan_no, int dev_no);
// int umount (const char *path);
// struct lock filesys_lock;
#endif /* userprog/syscall.h */
