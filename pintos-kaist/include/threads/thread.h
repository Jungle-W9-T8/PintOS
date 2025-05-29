#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"

#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

#define FDT_PAGES 1						
#define MAX_FD (FDT_PAGES * (1 << 9))


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	int64_t wakeup_ticks;				// 일어날 시각 추가
	
	struct list donations;              /* 우선순위 donations를 추적하기 위한 리스트 */
	struct lock *wait_on_lock;          /* 대기 중인 락 */
	int base_priority;                  /* 기부 이전 우선순위 */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
	struct list_elem sema_elem;           
	struct list_elem d_elem;            /* Donations List element. */

	struct file *running;
	
	/* relations */
	int exit_status;
	struct thread *parent;
	struct intr_frame backup_if;
	struct list children;
	struct list_elem child_elem;

	/* semaphore */
	struct semaphore wait_sema;
	struct semaphore exit_sema;
	struct semaphore fork_sema;

	/* Page map level 4 */
	uint64_t *pml4;         
	struct file **FDT;				// File Descriptor Table
	int next_FD;					// 다음 사용 가능한 fd값
	struct file *running_file;		// 현재 프로세스에서 실행 중인 파일
   


#ifdef USERPROG
	/* Owned by userprog/process.c. */
	// struct thread *parentThread;
	// uint64_t *pml4;                     /* Page map level 4 */

	// struct list siblingThread;
	// struct list_elem childThread;
	// struct file fd_table[64];
	// int next_fd;
	// 초기화 구문 필요
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */

	int64_t wakeup_tick;               /* 깨어나기까지 남은 시간 */ 
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

/* THREADS #1. Alarm Clock */
void thread_sleep (int64_t ticks);
void thread_awake (int64_t global_ticks);
void update_closest_tick (int64_t ticks);
int64_t closest_tick (void);
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux);
bool cmp_priority_only(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool cmp_priority_donation(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
void preempt_priority(void);
bool cmp_sema_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);
bool cmp_wakeTick(struct list_elem *a, struct list_elem *b, void *aux UNUSED);
void thread_block (void);
void thread_unblock (struct thread *);

// 다른 곳에서도 사용처를 만들어야 하여 헤더에 선언.
void preempt_priority(void);

struct thread *thread_current (void);
tid_t thread_tid (void);
void thread_sleep(int64_t ticks);
void thread_wakeUp(int64_t curTick);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

#endif /* threads/thread.h */