#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/* ------ Project 2 ------ */
#include <string.h>
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "kernel/stdio.h"
#include "threads/synch.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
/* ------------------------ */

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

  printf("Debug: Syscall handler initialized, entry point at %p\n", 
         (void*)syscall_entry);

  lock_init(&filesys_lock);

  write_msr(MSR_SYSCALL_MASK,
         FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void syscall_handler (struct intr_frame *f UNUSED) {
  int sys_number = f->R.rax;
  
  printf("Debug: System call %d invoked\n", sys_number);
  thread_current()->saved_sp = f->rsp;

  switch (sys_number) {
    case SYS_HALT:          
      printf("Debug: SYS_HALT(0) called\n");
      halt();
      break;

    case SYS_EXIT:          
      printf("Debug: SYS_EXIT(1) called with status %d\n", f->R.rdi);
      exit(f->R.rdi);
      break;

    case SYS_FORK:          
      printf("Debug: SYS_FORK(2) called with thread_name '%s'\n", (char *)f->R.rdi);
      f->R.rax = fork((char *)f->R.rdi, f);
      break;

    case SYS_EXEC:         
      printf("Debug: SYS_EXEC(3) called with cmd '%s'\n", (char *)f->R.rdi);
      f->R.rax = exec((char *)f->R.rdi);
      break;

    case SYS_WAIT:         
      printf("Debug: SYS_WAIT(4) called with pid %d\n", f->R.rdi);
      f->R.rax = wait(f->R.rdi);
      break;

    case SYS_CREATE:       
      printf("Debug: SYS_CREATE(5) called with file '%s', size %zu\n", 
             (char *)f->R.rdi, f->R.rsi);
      f->R.rax = create((char *)f->R.rdi, f->R.rsi);
      break;

    case SYS_REMOVE:        
      printf("Debug: SYS_REMOVE(6) called with file '%s'\n", (char *)f->R.rdi);
      f->R.rax = remove((char *)f->R.rdi);
      break;

    case SYS_OPEN:          
      printf("Debug: SYS_OPEN(7) called with file '%s'\n", (char *)f->R.rdi);
      f->R.rax = open((char *)f->R.rdi);
      break;

    case SYS_FILESIZE:      
      printf("Debug: SYS_FILESIZE(8) called with fd %d\n", f->R.rdi);
      f->R.rax = filesize(f->R.rdi);
      break;

    case SYS_READ:          
      printf("Debug: SYS_READ(9) called with fd=%d, buffer=%p, size=%u\n",
             f->R.rdi, (void *)f->R.rsi, f->R.rdx);
      f->R.rax = read(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
      printf("Debug: SYS_READ returned %d\n", (int)f->R.rax);
      break;

    case SYS_WRITE:         
      printf("Debug: SYS_WRITE(10) called with fd=%d, buffer=%p, size=%u\n",
             f->R.rdi, (void *)f->R.rsi, f->R.rdx);
      if (f->R.rdi == 1) {
          printf("Debug: Writing to stdout, content: '%.20s...'\n", 
                 (char *)f->R.rsi);
      }
      f->R.rax = write(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
      printf("Debug: SYS_WRITE returned %d\n", (int)f->R.rax);
      break;

    case SYS_SEEK:          
      printf("Debug: SYS_SEEK(11) called with fd=%d, position=%zu\n", 
             f->R.rdi, f->R.rsi);
      seek(f->R.rdi, f->R.rsi);
      break;

    case SYS_TELL:          
      printf("Debug: SYS_TELL(12) called with fd=%d\n", f->R.rdi);
      f->R.rax = tell(f->R.rdi);
      break;

    case SYS_CLOSE:         
      printf("Debug: SYS_CLOSE(13) called with fd=%d\n", f->R.rsi);
      close(f->R.rsi);
      break;

    case SYS_DUP2:         
      printf("Debug: SYS_DUP2(14) called with oldfd=%d, newfd=%d\n", 
             f->R.rdi, f->R.rsi);
      f->R.rax = dup2(f->R.rdi, f->R.rsi);
      break;

    default:
      printf("Debug: Unknown system call %d!\n", sys_number);
      thread_exit();
  }
}
//! ------------------------ Project 2 : Systemcall ------------------------ *//
static void
halt (void) {
  power_off ();
}

void
exit (int status) {
  struct thread *curr = thread_current ();
  curr->exit_status = status;

  printf ("%s: exit(%d)\n", thread_name(), curr->exit_status);

  thread_exit ();
}

static pid_t
fork (const char *thread_name, struct intr_frame *f) {
  return process_fork(thread_name, f);
}

static int
exec (const char *file) {
  check_addr(file);

  int len = strlen(file) + 1;
  char *file_name = palloc_get_page(PAL_ZERO);
  if (file_name == NULL)
    exit(-1);

  strlcpy(file_name, file, len);

  if (process_exec(file_name) == -1)
    exit(-1);

  palloc_free_page(file_name);
  NOT_REACHED();
  return 0;
}

static int
wait (pid_t pid) {
  return process_wait (pid);
}

static bool
create (const char* file, unsigned initial_size) {
  check_addr(file);
  return filesys_create(file, initial_size);
}

static int
open (const char *file) {
  check_addr(file);
  struct file *f = filesys_open(file);
  if (f == NULL)
    return -1;

  struct thread *curr = thread_current();
  struct file **fdt = curr->fd_table;

  while (curr->fd_idx < FD_COUNT_LIMIT && fdt[curr->fd_idx]) {
    // printf(" ############### fd_idx = { %d }\n", curr->fd_idx);
    curr->fd_idx++;
  }
  if (curr->fd_idx >= FD_COUNT_LIMIT) {
    file_close (f);
    return -1;
  }
  fdt[curr->fd_idx] = f;

  return curr->fd_idx;
}

static bool
remove (const char *file) {
  check_addr(file);
  return filesys_remove(file);
}

static int
filesize (int fd) {
  if (fd <= 1)
    return -1;

  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (f == NULL)
    return -1;

  int size = file_length(f);
  return size;
}

static int
read (int fd, void *buffer, unsigned length) {
  check_addr(buffer);
  if (fd > FD_COUNT_LIMIT || fd == STDOUT_FILENO || fd < 0)
    return -1;

  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (f == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  int read_size = file_read(f, buffer, length);
  lock_release(&filesys_lock);

  return read_size;
}

static int
write (int fd, const void *buffer, unsigned length) {
    check_addr(buffer);
    
    if (fd >= FD_COUNT_LIMIT || fd < 0) {
        printf("write: Invalid fd %d\n", fd);
        return -1;
    }

    if (fd == STDOUT_FILENO) {
        printf("write: Writing %u bytes to stdout\n", length);
        putbuf(buffer, length);
        return length;
    }

    // 파일에 대한 처리
    struct thread *curr = thread_current();
    struct file *f = curr->fd_table[fd];

    if (f == NULL)
        return -1;

    lock_acquire(&filesys_lock);
    int write_size = file_write(f, buffer, length);
    lock_release(&filesys_lock);

    return write_size;
}

static void
seek (int fd, unsigned position) {
  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (!is_kernel_vaddr(f))
    exit(-1);

  file_seek(f, position);
}

static unsigned
tell (int fd) {
  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (!is_kernel_vaddr(f))
    exit(-1);

  return file_tell(f);
}

void
close (int fd) {
  if (fd <= 1) {
    if (fd > -1) {
      // printf(" ############## closing STDIN & STDOUT ############# ");
      thread_current ()->fd_table[fd] = NULL;
    }
    return;
  }
  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (f == NULL)
    return;

  curr->fd_table[fd] = NULL;
  file_close(f);
}

static int
dup2 (int oldfd, int newfd) {
  // printf(" ############## Start DUP2 ############# ");
  struct thread *curr = thread_current ();
  struct file **fdt = curr->fd_table;
  struct file *f = file_duplicate (curr->fd_table[oldfd]);

  if (newfd > FD_COUNT_LIMIT || !is_kernel_vaddr(f) || f == NULL) {
    // printf(" ############## Exception DUP2 ############# ");
    return 1;
  }
  if (fdt[newfd] != NULL) {                   //* newfd 가 이전에 열려있다면, 재사용 되기 전에 닫힘

    // printf(" ############## newfd{ %d } is Not Null \n ", newfd);
    close(newfd);
  }
  fdt[newfd] = f;
  // printf(" ############## Success DUP2 ############# ");
  return newfd;
}

static void
check_addr (const char *f_addr) {
  if (!is_user_vaddr(f_addr) || f_addr == NULL || !pml4_get_page(thread_current()->pml4, f_addr))
    exit(-1);
}