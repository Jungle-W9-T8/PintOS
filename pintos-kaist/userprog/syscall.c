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
			if(is_user_vaddr(f->R.rdi))
			{
				memcpy(&thread_current()->backup_if, f, sizeof(struct intr_frame));
				f->R.rax = fork(f->R.rdi);
			}
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

void check_address(const uint64_t *addr)
{
	struct thread *cur = thread_current();

	if (addr == "" || !(is_user_vaddr(addr)) || pml4_get_page(cur->pml4, addr) == NULL)
	{
		exit(-1);
	}
}

void check_buffer(const void *buffer, unsigned size)
{
	uint8_t *start = (uint8_t *)pg_round_down(buffer);
	uint8_t *end = (uint8_t *)pg_round_down(buffer + size - 1);
	struct thread *cur = thread_current();

	for (uint8_t *addr = start; addr <= end; addr += PGSIZE)
	{
		if (!is_user_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL)
		{
			exit(-1);
		}
	}
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
    struct thread *curr = thread_current();
    curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, curr->exit_status);
    thread_exit();
}

/*
1. 유저 영역에 있을 때의 intr_frame을 전달하기 위해 fork 되자마자 inrt_frame 복제 후 저장
2. 자식 스레드 생성
3. 자식의 load()가 끝날 때까지 대기
4. 자식의 스레드 아이디 반환
*/
tid_t fork (const char *thread_name)
{
	tid_t returnTarget = process_fork(thread_name, &thread_current()->backup_if);
	if(returnTarget == TID_ERROR) exit(-1);
	return returnTarget;
}

int exec(const char *cmd_line)
{ 
	check_address(cmd_line);

	if(cmd_line == NULL) exit(-1);
	if (pml4_get_page(thread_current()->pml4, cmd_line) == NULL) exit(-1);
	

	char *package_cmd;
	package_cmd = palloc_get_page(PAL_ZERO);
	if (package_cmd == NULL) exit(-1);
	strlcpy(package_cmd, cmd_line, PGSIZE);

	int result = process_exec(package_cmd);
	if (result == -1) return result;
}


int wait (tid_t pid) {
	tid_t exitNum = process_wait(pid);
	//	if(exitNum == -1) printf("returned -1!\n");
	return exitNum;
}

bool create(const char *file, unsigned initial_size)
{
	check_address(file);

	if(strlen(file) == 0) exit(-1);
	if(strlen(file) > 128) return false; // create-long 테스트 케이스 대비
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);

	if(strlen(file) == 0) exit(-1);
	if(strlen(file) > 128) return false;
	return filesys_remove(file);
}

int open(const char *file)
{
	check_address(file);
	
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
	check_address(buffer);

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
	if ((buffer == NULL) || !(pml4_get_page(thread_current()->pml4, buffer))) exit(-1);

	if(fd == 0) exit(-1);
	if(fd >= 64) exit(-1);

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

