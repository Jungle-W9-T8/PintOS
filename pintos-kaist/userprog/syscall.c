#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/vaddr.h"

#include "threads/init.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *f);
bool is_valid_user_pointer(const void *uaddr);
void halt (void);
void exit (int status);
 int write (int fd, const void *buffer, unsigned size);

// pid_t fork (const char *thread_name);
// int exec (const char *file);
// int wait (pid_t pid);
// bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
// int open (const char *file);
// int filesize (int fd);
// int read (int fd, void *buffer, unsigned size);
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

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	uint64_t syscall_num = f->R.rax; // 시스템콜 번호
	uint64_t arg1 = f->R.rdi; // 첫 번째 인자
	uint64_t arg2 = f->R.rsi; // 두 번째 인자
	uint64_t arg3 = f->R.rdx; // 세 번째 인자
	uint64_t arg4 = f->R.r10; // 네 번째 인자
	uint64_t arg5 = f->R.r8; // 다섯 번째 인자
	uint64_t arg6 = f->R.r9; // 여섯 번째 인자

	switch (syscall_num) {
		case SYS_HALT:
			power_off();
			break;

		case SYS_EXIT:
			exit(f->R.rdi);
			break;

		case SYS_FORK:
			// f->R.rax = fork ((const char *) arg1);
			break;

		case SYS_EXEC:
			// f->R.rax = exec ((const char *) arg1);
			break;

		case SYS_WAIT:
			// printf("wait syscall\n");
			// f->R.rax = wait ((const char *) arg1);
			break;

		case SYS_CREATE:

			f->R.rax = create(f->R.rdi, f->R.rsi);
			// f->R.rax = create ((const char *) arg1, (unsigned) arg2);
			break;

		case SYS_REMOVE:
			// f->R.rax = remove ((const char *) arg1);
			break;

		case SYS_OPEN:
			// f->R.rax = open ((const char *) arg1);
			break;

		case SYS_FILESIZE:
			// f->R.rax = filesize ((int) arg1);
			break;
			
		case SYS_READ:
			// f->R.rax = read ((int) arg1, (void *) arg2, (unsigned) arg3);
			break;

		case SYS_WRITE: 			
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;

		case SYS_SEEK:
			// syscall4 (SYS_SEEK, (int) arg1, (unsigned) arg2, 0, 0);
			break;

		case SYS_TELL:
			// f->R.rax = tell ((int) arg1);
			break;

		case SYS_CLOSE:
			// syscall1 (SYS_CLOSE, (int) arg1);
			break;
		
		default:
			printf("ERRRORRR  \n");
	}

	// printf ("system call!\n");
	// thread_exit ();
}

void halt (void) {
	power_off();
}

 void exit (int status) {
	struct thread *curr = thread_current();
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

// pid_t fork (const char *thread_name) {

// }

// int exec (const char *file) {

// }

// int wait (pid_t pid) {

// }

bool create (const char *file, unsigned initial_size) {		
	if (!is_valid_user_pointer(file)) exit(-1);
	if ((file == NULL) || !(pml4_get_page(thread_current()->pml4, file))) exit(-1); 
	return filesys_create(file, initial_size);
}

// bool remove (const char *file) {

// }

// int open (const char *file) {

// }

// int filesize (int fd) {

// }

// int read (int fd, void *buffer, unsigned size) {

// }

int write (int fd, const void *buffer, unsigned size) {
	// 파일 디스크립터가 STDOUT(1)일 경우, 콘솔에 출력
	if (fd == 1) {
		putbuf(buffer, size);
	} 
	// f->R.rax = size;  // 출력한 바이트 수 반환
	else {
		// f->R.rax = -1;  // 현재는 STDOUT만 지원
		return -1;
	}
	return size;
}
 
// void seek (int fd, unsigned position) {

// }

// unsigned tell (int fd) {

// }

// void close (int fd) {

// }

// int dup2 (int oldfd, int newfd) {

// }

// void *mmap (void *addr, size_t length, int writable, int fd, off_t offset) {

// }

// void munmap (void *addr) {

// }
 
// bool chdir (const char *dir) {

// }

// bool mkdir (const char *dir) {

// }

// bool readdir (int fd, char name[READDIR_MAX_LEN + 1]) {

// }

// bool isdir (int fd) {

// }

// int inumber (int fd) {

// }

// int symlink (const char* target, const char* linkpath) {

// }

// int mount (const char *path, int chan_no, int dev_no) {

// }

// int umount (const char *path) {

// }

bool is_valid_user_pointer(const void *uaddr) {
  return (uaddr != NULL && is_user_vaddr(uaddr));
}