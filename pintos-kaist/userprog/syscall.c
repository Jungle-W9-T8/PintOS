#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
	// TODO: Your implementation goes here.
	switch(f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		printf("fork has called!\n\n");
		break;
	case SYS_EXEC:
		printf("exec has called!\n\n");
		break;
	case SYS_WAIT:
		printf("wait has called!\n\n");
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
		printf("remove has called!\n\n");
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		printf("read has called!\n\n");
		break;
	case SYS_WRITE:
		if(is_user_vaddr(f->R.rdi) && is_user_vaddr(f->R.rsi) && is_user_vaddr(f->R.rdx))
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);		
		break;
	case SYS_SEEK:
		printf("seek has called!\n\n");
		break;
	case SYS_TELL:
		printf("tell has called!\n\n");
		break;
	case SYS_CLOSE:
		printf("close has called!\n\n");
		break;
	default:
		printf("SERIOUS ERROR!!\n\n");
		break;
	}



	//printf ("system call!\n");
	//thread_exit ();
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *curr = thread_current();
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

tid_t fork (const char *thread_name)
{
	struct thread *curr = thread_current();	
	tid_t newThread = thread_create(thread_name, PRI_DEFAULT, curr->tf.R.rdi, curr->tf.R.rsi);
	if(newThread < 0)
		return TID_ERROR;

	
	
	// TODO:
	// Create child process and execute program corresponds to cmd_line on it 자식 프로세스를 생성하고 해당 cmd_line에 해당하는 프로그램을 실행하십시오.
}

int exec(const char *cmd_line)
{
	// TODO :
	// Wait for termination of child process whose process id is pid
}
// 아니 슬라이드에서는 pid_t를 리턴하는 구현을 요구하는데 뭐지?

// 여기까지 4개가 System과 직접 연관 된 내용들!

/*
	thread.h 에서 해야 할 일
	Pointer to parent process : struct thread*
	Pointer to the sibling : struct list
	Pointer to the children : struct list_elem
	추가 : 시스템 콜과 연계되어야 하여 우선 작성
*/

int wait(tid_t pid)
{
	// TODO :
	// wait for a child process pid to exit and retrieve the child's exit status.
	// IF : PID is alive
		// wait till it terminates.
		// Return the status that pid passed to exit.
	// IF : PID did not call exit but was terminated by the kernel, return -1
	// A parent process cna call wait for the cild process that has terminated
		// - return exit status of the terminated child processes.

	// After the child terminates, the parent should deallocatge its process descriptor
		// wait fails and return -1 if
			// pid does not refer to a direct child of the calling process.
			// the process that calls wait has already called wait on pid.
}
bool create(const char *file, unsigned initial_size)
{
	if (pml4_get_page(thread_current()->pml4, file) == NULL) exit(-1);
	if(strlen(file) == 0) exit(-1);
	if(strlen(file) > 128) return false; // create-long 테스트 케이스 대비

	if(is_user_vaddr(&file)) return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	// Remove file whose name is file.
	// Use bool filesys_remove(const char *name)
	// Return true if it is succeeded or false if it is not.
	// File is removed regardless of whether it is open or closed.
	return false;
}

int open(const char *file)
{
	struct thread *curr = thread_current();
	struct file *targetFile = filesys_open(file);
	if(targetFile == NULL) return -1;

	int i = curr->next_fd;

	curr->fd_table[i] = targetFile;
	curr->next_fd += 1;

	// 생각해보니.. fd를 64개 다쓰면? 그리고, 재활용가능한 fd가 있다면?
	// open msg 수정 필요
	printf("open file: %s\n",file);

	// 연결된 번호를 반환하도록 하기
	return i;
}

int filesize(int fd)
{
	off_t fileSize = file_length(thread_current()->fd_table[fd]);
	if(fileSize == 0) return -1;
	//fd를 통해 파일을 알아낸 다음, 그걸로 file_length의 매개변수를 투입시킨다. 그리고 해당 값을 리턴시킨다.
	//struct off_t a = file_length()
	// Return the size, in bytes, of the file open as fd.
	// Use off_t file_length(struct file *file).
	return fileSize;
}

int read(int fd, void *buffer, unsigned size)
{
	// Read size bytes from the file open as fd into buffer.
	// Return the number of bytes actually read (0 at end of file), or -1 if fails.
	// If fd is 0, it reads from keyboard using input_getc(), otherwise reads from file using file_read() function.
		// uint8_t input_getc(void)
		// off_t file_read(struct file *file, void *buffer, off_t size)

	return 0;
}

int write(int fd, const void *buffer, unsigned size)
{
	if(fd == 1)
	{
		putbuf(buffer, size);
	}
	else
	{
		// fd는 open 후 값을 그대로 끌어온다고 가정. 즉, fd는 바로 해당 파일을 가리킨다.
		struct file *targetWrite = thread_current()->fd_table[fd];
		int writed = file_write(targetWrite, buffer, size);
		// off_t file_write(struct file *file, const void *buffer, off_t size)

	}
	// TODO : return 값을 -1로 정의 할 여지를 고민해야함
	return size;
}

void seek(int fd, unsigned position)
{
	// Changes the next byte to be rtead or written in open file fd to position.
	// use void file_seek
}

unsigned tell(int fd)
{
	// Return the position of the next byte to be read or written in open file fd.
	// use off_t file_tell
	return 0;
}

void close(int fd)
{
	// close file descriptor fd.
	// use void file_close
}

