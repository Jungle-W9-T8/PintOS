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
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include <string.h>

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
		
	// lock_init (&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	switch(f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		if(f->R.rdi != NULL)
		{
			memcpy(&thread_current()->parent_if, f, sizeof(struct intr_frame)); 
			f->R.rax = fork(f->R.rdi);
		}
		else
			exit(-1);
		break;
	case SYS_EXEC:
		if(f->R.rdi != NULL)
		{
			f->R.rax = exec(f->R.rdi);
		}
		else
			exit(-1);
		break;
	case SYS_WAIT:
		if(f->R.rdi != NULL)
		{
			f->R.rax = wait(f->R.rdi);
		}
		else
			exit(-1);
		break;
	case SYS_CREATE:
		 if(f->R.rdi != NULL)
		 {
		 	if(is_user_vaddr(f->R.rdi) && is_user_vaddr(f->R.rsi))
		 		f->R.rax = create(f->R.rdi, f->R.rsi);
		 	else
		 		exit(-1);
		 }
		 else
		 	exit(-1);
		 break;
	case SYS_REMOVE:
		if(f->R.rdi != NULL)
		{
			if(is_user_vaddr(f->R.rdi))
				f->R.rax = remove(f->R.rdi);
			else
				exit(-1);
		}
		else
			exit(-1);
		break;
	case SYS_OPEN:
		if(f->R.rdi != NULL)
		{
			if(is_user_vaddr(f->R.rdi) && is_user_vaddr(f->R.rsi))
				f->R.rax = open(f->R.rdi);
			else
				exit(-1);
		}
		else
			exit(-1);
			break;
	case SYS_FILESIZE:
		if(is_user_vaddr(f->R.rdi))
			f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		if(is_user_vaddr(f->R.rdi) && is_user_vaddr(f->R.rsi) && is_user_vaddr(f->R.rdx))
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);		
		break;
	case SYS_WRITE:
		if(is_user_vaddr(f->R.rdi) && is_user_vaddr(f->R.rsi) && is_user_vaddr(f->R.rdx))
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);		
		break;
	case SYS_SEEK:
		if(is_user_vaddr(f->R.rdi) && is_user_vaddr(f->R.rsi))
			seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		if(is_user_vaddr(f->R.rdi))
			f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		if(f->R.rdi != NULL)
		{
			if(is_user_vaddr(f->R.rdi))
				close(f->R.rdi);
			else
				exit(-1);
		}
		else
			exit(-1);
		break;
	default:
		printf("SERIOUS ERROR!!\n");
		break;
	}
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
    struct thread *curr = thread_current();
    if (curr->parent != NULL)
    {
        sema_up(&curr->sema_wait);
        curr->status = status;
        sema_down(&curr->parent->sema_wait);
    }
    printf("%s: exit(%d)\n", curr->name, status);
    thread_exit();
}

tid_t fork (const char *thread_name)
{
	struct thread *curr = thread_current();
	struct intr_frame if_;
	memcpy(&if_, &curr->parent_if, sizeof(struct intr_frame));
	return process_fork(thread_name, &if_);
}


int exec(const char *cmd_line)
{ 
	if(cmd_line == NULL) exit(-1);

	char *package_cmd;
	package_cmd = palloc_get_page(PAL_ZERO);

	strlcpy(package_cmd, cmd_line, strlen(cmd_line) + 1);

	int result = process_exec(package_cmd);
	if (result == -1) return result;
}


int wait (tid_t pid) {
    struct thread *cur = thread_current();
    struct thread *child = NULL;
    struct list_elem *e;
    int child_status;

    for (e = list_begin (&cur->children); e != list_end (&cur->children); e = list_next (e)) {
        struct thread *result = list_entry (e, struct thread, elem);
        if (result->tid = pid)
        {
            child = result;
            child_status = child->status;
            break;
        }
    }

    if (child == NULL) return -1;
    sema_down (&child->sema_wait);
    sema_up (&cur->sema_wait);
    return child_status;
}

bool create(const char *file, unsigned initial_size)
{
	if (pml4_get_page(thread_current()->pml4, file) == NULL) exit(-1);
	if(strlen(file) == 0) exit(-1);
	if(strlen(file) > 128) return false; // create-long 테스트 케이스 대비
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	if (pml4_get_page(thread_current()->pml4, file) == NULL) exit(-1);
	if(strlen(file) == 0) exit(-1);
	if(strlen(file) > 128) return false;
	return filesys_remove(file);
}

int open(const char *file)
{
	if (pml4_get_page(thread_current()->pml4, file) == NULL) exit(-1);
	
	struct thread *curr = thread_current();
	struct file *targetFile = filesys_open(file);
	if(targetFile == NULL) return -1;

	int i = curr->next_fd;
	curr->fd_table[i] = targetFile;
	curr->next_fd += 1;

	// 생각해보니.. fd를 64개 다쓰면? 그리고, 재활용가능한 fd가 있다면?
	// 연결된 번호를 반환하도록 하기
	return i;
}


// 파일 크기를 확인한다.
int filesize(int fd)
{
	struct file *targetView = thread_current()->fd_table[fd];
	if(targetView == NULL) exit(-1);
	off_t fileSize = file_length(targetView);
	if(fileSize == 0) return -1;
	return fileSize;
}


// 키보드 입력을 받거나 파일에서 내용을 가져온다.
int read(int fd, void *buffer, unsigned size)
{
	if ((buffer == NULL) || !(pml4_get_page(thread_current()->pml4, buffer))) exit(-1);

	if(!is_user_vaddr(buffer)) exit(-1); // write-bad-ptr 구현

	if(fd == 0)
	{
		uint8_t inputData = input_getc();
		return inputData;
	}
	else
	{
		if(fd >= 64 || fd == 1 || fd == 2) exit(-1);
		off_t inputData = file_read(thread_current()->fd_table[fd], buffer, size);
		return inputData;
	}

	// Read size bytes from the file open as fd into buffer.
	// Return the number of bytes actually read (0 at end of file), or -1 if fails.
}

// 콘솔 출력을 수행하거나 파일에 직접 작성한다.
int write(int fd, const void *buffer, unsigned size)
{
	if(fd == 0) exit(-1);
	if(fd >= 64) exit(-1);
	if(!is_user_vaddr(buffer)) exit(-1); // write-bad-ptr 구현

	if(fd == 1)
	{
		putbuf(buffer, size);
	}
	else
	{
		// fd는 open 후 값을 그대로 끌어온다고 가정. 즉, fd는 바로 해당 파일을 가리킨다.
		struct file *targetWrite = thread_current()->fd_table[fd];
		if(targetWrite == NULL) exit(-1);
		int writed = file_write(targetWrite, buffer, size);
	}
	// TODO : return 값을 -1로 정의 할 여지를 고민해야함
	return size;
}

// Changes the next byte to be rtead or written in open file fd to position.
void seek(int fd, unsigned position)
{
	struct file *targetSeek = thread_current()->fd_table[fd];
	if(targetSeek == NULL) exit(-1);

	file_seek(targetSeek, position);
}

// Return the position of the next byte to be read or written in open file fd.
unsigned tell(int fd)
{
	struct file *targetTell = thread_current()->fd_table[fd];
	if(targetTell == NULL) exit(-1);
	off_t value = file_tell(targetTell);
	return value;
}

// 해당하는 파일 디스크립터를 닫습니다.
void close(int fd)
{
	if(fd > 64) exit(-1);
	struct file *closeTarget = thread_current()->fd_table[fd];
	if (!is_user_vaddr(closeTarget)) return;
	file_close(closeTarget);
}

