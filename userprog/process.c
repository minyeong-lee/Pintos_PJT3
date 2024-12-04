#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "threads/synch.h"
#include "userprog/syscall.h"
#endif
#ifdef VM
#include "vm/vm.h"
#endif

#define ARG_MAX 128                           //* Project 2 (args_passing) : strtok_r로 잘라줄 최대값

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* --- Project 2 - System call --- */
static void argument_passing (struct intr_frame *if_, int argv_cnt, char **argv_list);
static struct thread *get_child (int tid);

static void
process_init (void) {
    struct thread *curr = thread_current();
    
    printf("process_init: ENTRY POINT\n");  // 진입점 체크
    printf("process_init: Starting for thread '%s' (tid=%d)\n", curr->name, curr->tid);
    
    // pml4 생성 전 체크
    printf("process_init: Current pml4 = %p\n", (void*)curr->pml4);
    
    curr->pml4 = pml4_create();
    if (curr->pml4 == NULL) {
        printf("process_init: pml4_create failed\n");
        PANIC("Failed to create process page directory");
    }
    printf("process_init: Created new pml4 at %p\n", (void*)curr->pml4);
    
    process_activate(curr);
    printf("process_init: Process activated\n");
    
    // SPT 초기화 전 상태 확인
    printf("process_init: Current SPT = %p\n", (void*)curr->spt);
    
    curr->spt = malloc(sizeof(struct supplemental_page_table));
    if (curr->spt == NULL) {
        printf("process_init: malloc failed for SPT\n");
        pml4_destroy(curr->pml4);
        PANIC("Failed to allocate spt");
    }
    printf("process_init: Allocated new SPT at %p\n", (void*)curr->spt);
    
    supplemental_page_table_init(curr->spt);
    printf("process_init: SPT initialized\n");
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
    printf("Debug: process_create_initd starting with file_name='%s'\n", file_name);
    
    char *fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) {
        printf("Debug: Failed to allocate fn_copy\n");
        return TID_ERROR;
    }
    strlcpy(fn_copy, file_name, PGSIZE);

    char *save_ptr;
    char *f_name = strtok_r(fn_copy, " ", &save_ptr);
    printf("Debug: Parsed program name: '%s'\n", f_name);

    char *cmd_line = palloc_get_page(0);
    if (cmd_line == NULL) {
        printf("Debug: Failed to allocate cmd_line\n");
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }
    strlcpy(cmd_line, file_name, PGSIZE);
    printf("Debug: Before thread_create: f_name='%s', cmd_line='%s'\n", f_name, cmd_line);
    tid_t tid = thread_create(f_name, PRI_DEFAULT, initd, cmd_line);
    printf("Debug: After thread_create: tid=%d, cmd_line='%s', success=%s\n", 
       tid, (char*)cmd_line, tid != TID_ERROR ? "true" : "false");    if (tid == TID_ERROR) {
        printf("Debug: Thread creation failed\n");
        palloc_free_page(cmd_line);
    } else {
        printf("Debug: Thread created successfully with tid=%d\n", tid);
    }
    
    palloc_free_page(fn_copy);
    return tid;
}
static void
initd (void *f_name) {
    printf("initd: ENTRY POINT\n");  // 진입점 확인
    
    if (f_name == NULL) {
        printf("initd: f_name is NULL!\n");
        PANIC("Invalid file name in initd");
    }
    printf("initd: Starting with command: '%s'\n", (char *)f_name);
    
    struct thread *curr = thread_current();
    printf("initd: Current thread: %s (tid=%d)\n", curr->name, curr->tid);
    
    // SPT 초기화 전 상태 체크
    printf("initd: Before process_init - thread has %s SPT\n", 
           curr->spt ? "existing" : "no");
    
    process_init();
    printf("initd: process_init completed\n");
    
    printf("initd: Calling process_exec with f_name='%s'\n", (char *)f_name);
    int exec_status = process_exec(f_name);
    
    printf("initd: process_exec failed with status %d\n", exec_status);
    PANIC("Failed to launch initd\n");
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
  struct thread *curr = thread_current ();
  memcpy (&curr->parent_if, if_, sizeof(struct intr_frame));

  tid_t tid = thread_create (name, PRI_DEFAULT, __do_fork, curr);
  if (tid == TID_ERROR)
    return TID_ERROR;

  struct thread *child = get_child(tid);
  sema_down(&child->load_sema);

  if (child->exit_status == -1)
    return TID_ERROR;

  return tid;
}


#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
  struct thread *curr = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;


	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
  if (is_kernel_vaddr(va))
    return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
  if (parent_page == NULL)
    return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
  newpage = palloc_get_page(PAL_USER);
  if (newpage == NULL) {
    return false;
  }

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
  memcpy(newpage, parent_page, PGSIZE);
  writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
  if (!pml4_set_page (curr->pml4, va, newpage, writable)) {
    return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
    struct thread *curr = thread_current ();
	bool succ = true;
  /* --- Project 2 - System call --- */
  	struct intr_frame *parent_if = &parent->parent_if;

  	memcpy (&if_, parent_if, sizeof (struct intr_frame));    //* syscall : FORK
  	if_.R.rax = 0;

	/* 2. Duplicate PT */
  	curr->pml4 = pml4_create();
  	if (curr->pml4 == NULL)
		goto error;

  	process_activate (curr);
#ifdef VM
	if (!supplemental_page_table_copy (&curr->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif
  /* --- Project 2 - System call --- */
  if (parent->fd_idx >= FD_COUNT_LIMIT)
    goto error;

  for (int i = 0; i < FD_COUNT_LIMIT; i++) {
    struct file *f = parent->fd_table[i];
    if (f == NULL)
      continue;

    if (i > 1)
      f = file_duplicate(f);
    curr->fd_table[i] = f;
  }
  curr->fd_idx = parent->fd_idx;
  /* ------------------------------- */

	/* Finally, switch to the newly created process. */
	if (succ)
    sema_up(&curr->load_sema);
		do_iret (&if_);

error:
  /* --- Project 2 - System call --- */
  curr->exit_status = TID_ERROR;
  sema_up(&curr->load_sema);
  /* ------------------------------- */

  process_exit ();
}

int process_exec (void *f_name) {
    struct thread *curr = thread_current();
    char *file_name = palloc_get_page(PAL_ZERO);
    if (file_name == NULL)
        return -1;
    
    strlcpy(file_name, f_name, PGSIZE);
    printf("Debug: Starting process_exec with file_name='%s'\n", file_name);
    
    struct intr_frame _if;
    memset(&_if, 0, sizeof(_if));
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    curr->fd_table[STDIN_FILENO] = NULL;  
    curr->fd_table[STDOUT_FILENO] = NULL; 
    printf("Debug: File descriptors initialized\n");
    
    char *save_ptr;
    char *argv[64];
    int argc = 0;
    
    char *program_name = strtok_r(file_name, " ", &save_ptr);
    printf("Debug: Program name parsed: '%s'\n", program_name);
    
    if (program_name == NULL) {
        palloc_free_page(file_name);
        return -1;
    }
    
    argv[argc++] = program_name;
    
    char *token;
    while ((token = strtok_r(NULL, " ", &save_ptr)) != NULL && argc < 64) {
        argv[argc++] = token;
        printf("Debug: Parsed argument %d: '%s'\n", argc-1, token);
    }
    printf("Debug: Total arguments (argc): %d\n", argc);
    
    printf("Debug: Attempting to load program '%s'\n", program_name);
    bool success = load(program_name, &_if);
    printf("Debug: Program load %s\n", success ? "successful" : "failed");
    
    if (!success) {
        palloc_free_page(file_name);
        return -1;
    }
    
    printf("Debug: Setting up arguments on stack\n");
    argument_passing(&_if, argc, argv);
    printf("Debug: Arguments setup complete - RSP: %p, argc (rdi): %d\n", 
           (void*)_if.rsp, (int)_if.R.rdi);
    
    if (curr->runn_file != NULL)
        file_close(curr->runn_file);
    curr->runn_file = filesys_open(program_name);
    if (curr->runn_file == NULL)
        printf("Debug: Warning - Failed to open program file\n");

    printf("Debug: Ready to execute - RIP: %p, RSP: %p, argc: %d\n", 
           (void*)_if.rip, (void*)_if.rsp, (int)_if.R.rdi);

    palloc_free_page(file_name);
    do_iret(&_if);
    NOT_REACHED();
}

//! filename에서 분리한 argument들을 User Stack에 쌓기 위해 배열에 저장
static void
argument_passing (struct intr_frame *if_, int argv_cnt, char **argv_list) {
    printf("argument_passing: Starting with %d arguments\n", argv_cnt);
    
    int64_t arg_addr[ARG_MAX];
    int _ptr = sizeof(char *);
    
    /* Put command to User Stack */
    printf("argument_passing: Putting arguments on stack\n");
    for (int i = 0; i < argv_cnt; i++) {
        int arg_len = strlen(argv_list[i]) + 1;
        if_->rsp -= arg_len;
        memcpy((void *)if_->rsp, argv_list[i], arg_len);
        arg_addr[i] = if_->rsp;
        printf("argument_passing: Pushed arg %d: '%s' at %p\n", i, argv_list[i], (void*)if_->rsp);
    }

    /* SET word_align */
    if (if_->rsp % _ptr) {
        int padding = if_->rsp % _ptr;
        if_->rsp -= padding;
        memset((void *)if_->rsp, 0, padding);
        printf("argument_passing: Added %d bytes of padding\n", padding);
    }

    /* NULL sentinel */
    if_->rsp -= _ptr;
    memset((void *)if_->rsp, 0, _ptr);
    printf("argument_passing: Added NULL sentinel at %p\n", (void*)if_->rsp);

    /* Push addresses of arguments */
    printf("argument_passing: Pushing argument addresses\n");
    for (int i = argv_cnt - 1; i >= 0; i--) {
        if_->rsp -= _ptr;
        memcpy((void *)if_->rsp, &arg_addr[i], _ptr);
        printf("argument_passing: Pushed address %p for arg %d\n", (void*)arg_addr[i], i);
    }

    /* Return address */
    if_->rsp -= _ptr;
    memset((void *)if_->rsp, 0, _ptr);
    printf("argument_passing: Set return address to 0 at %p\n", (void*)if_->rsp);

    /* Set registers */
    if_->R.rdi = argv_cnt;
    if_->R.rsi = if_->rsp + _ptr;
    printf("argument_passing: Final state - RSP: %p, argc: %d, argv: %p\n", 
           (void*)if_->rsp, argv_cnt, (void*)if_->R.rsi);

    printf("Debug: Final stack setup - RSP: %p\n", (void*)if_->rsp);
    printf("Debug: argc (rdi): %d\n", (int)if_->R.rdi);
    printf("Debug: argv (rsi): %p\n", (void*)if_->R.rsi);
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
  struct thread *child = get_child(child_tid);
  if (child == NULL || child_tid < 0)
    return -1;

  sema_down (&child->wait_sema);
  list_remove(&child->c_elem);
  sema_up(&child->exit_sema);

  return child->exit_status;
}

void
process_exit (void) {
    struct thread *curr = thread_current();

    printf("%s: exit(%d)\n", curr->name, curr->exit_status);
    
    // 파일 디스크립터 정리
    if (curr->fd_table != NULL) {
        for (int fd = 0; fd < FD_COUNT_LIMIT; fd++) {
            if (curr->fd_table[fd] != NULL) {
                close(fd);
            }
        }
        // 페이지 정렬 확인 추가
        if (pg_ofs(curr->fd_table) == 0) {
            palloc_free_multiple(curr->fd_table, FDT_PAGES);
        } else {
            printf("Warning: fd_table not page aligned\n");
        }
        curr->fd_table = NULL;
    }
    
    // 실행 중인 파일 닫기
    if (curr->runn_file != NULL) {
        file_close(curr->runn_file);
        curr->runn_file = NULL;
    }

    process_cleanup();

    sema_up(&curr->wait_sema);
    sema_down(&curr->exit_sema);
}

static void
process_cleanup (void) {
    struct thread *curr = thread_current();

#ifdef VM
    if (curr->spt != NULL) {
        supplemental_page_table_kill(curr->spt);
        free(curr->spt);  // malloc으로 할당했으므로 free로 해제
        curr->spt = NULL;
    }
#endif

    uint64_t *pml4 = curr->pml4;
    if (pml4 != NULL) {
        enum intr_level old_level = intr_disable();
        curr->pml4 = NULL;
        pml4_activate(NULL);
        intr_set_level(old_level);
        
        pml4_destroy(pml4);
    }
}
/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
    printf("load: Loading program '%s'\n", file_name);
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    bool success = false;

    // SPT 상태 확인
    if (t->spt == NULL) {
        printf("load: SPT is NULL, creating new one\n");
        t->spt = malloc(sizeof(struct supplemental_page_table));
        if (t->spt == NULL) {
            printf("load: Failed to allocate SPT\n");
            goto done;
        }
        supplemental_page_table_init(t->spt);
    }

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: Failed to open file '%s'\n", file_name);
        goto done;
    }
    printf("load: Successfully opened file\n");

    /* Read and verify executable header. */
    if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
        || ehdr.e_type != 2
        || ehdr.e_machine != 0x3E // amd64
        || ehdr.e_version != 1
        || ehdr.e_phentsize != sizeof (struct Phdr)
        || ehdr.e_phnum > 1024) {
        printf ("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Set up stack. */
    if (!setup_stack (if_)) {
        printf("load: stack setup failed\n");
        goto done;
    }

    /* Start address. */
    if_->rip = ehdr.e_entry;

    /* Save the file and deny writes. */
    success = true;
    t->runn_file = file;
    if (file != NULL)
        file_deny_write (file);

done:
    printf("load: Completed with %s\n", success ? "success" : "failure");
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

//! 내 밑에 같은 자식 스레드가 존재할 경우, 반환
struct thread *get_child (int tid) {
  struct thread *curr = thread_current ();
  struct list *child_list = &curr->child_list;
  struct list_elem *e;

  if (list_empty(child_list))
    return NULL;

  for (e = list_begin (child_list); e != list_end (child_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, c_elem);
    if (t->tid == tid)
      return t;
  }

  return NULL;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2 */
static bool install_page (void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current ();
    return (pml4_get_page (t->pml4, upage) == NULL && pml4_set_page (t->pml4, upage, kpage, writable));
}

static bool setup_stack (struct intr_frame *if_) {
    printf("setup_stack: Starting\n");
    bool success = false;
    void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

    printf("setup_stack: Stack bottom at %p\n", stack_bottom);
    void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage == NULL) {
        printf("setup_stack: Page allocation failed\n");
        return false;
    }

    if (!install_page(stack_bottom, kpage, true)) {
        printf("setup_stack: Page installation failed\n");
        palloc_free_page(kpage);
        return false;
    }

    if_->rsp = USER_STACK;
    printf("setup_stack: Stack initialized. RSP = %p\n", (void*)if_->rsp);
    
    success = true;
    return success;
}

#else
/* From here, codes will be used after project 3 */
static bool lazy_load_segment (struct page *page, void *aux) {
    struct load_info *info = (struct load_info *) aux;
    
    if (info->read_bytes > 0) {
        if (file_read_at(info->file, page->frame->kva, info->read_bytes, info->ofs) != (int)info->read_bytes) {
            return false;
        }
    }

    if (info->zero_bytes > 0) {
        memset(page->frame->kva + info->read_bytes, 0, info->zero_bytes);
    }

    free(info);
    return true;
}

static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs (upage) == 0);
    ASSERT (ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct load_info *aux = malloc(sizeof(struct load_info));
        if (aux == NULL)
            return false;

        aux->file = file;
        aux->ofs = ofs;
        aux->read_bytes = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, lazy_load_segment, aux)) {
            free(aux);
            return false;
        }

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        ofs += page_read_bytes;
        upage += PGSIZE;
    }
    return true;
}

static bool setup_stack (struct intr_frame *if_) {
    printf("setup_stack: Starting\n");
    bool success = false;
    void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

    printf("setup_stack: Stack bottom at %p\n", stack_bottom);
    
    struct thread *t = thread_current();
    
    if (t->spt == NULL) {
        printf("setup_stack: Warning - SPT is NULL\n");
        return false;
    }

    if (!vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true)) {
        printf("setup_stack: vm_alloc_page failed\n");
        return false;
    }

    printf("setup_stack: Page allocated, attempting to claim\n");
    
    if (!vm_claim_page(stack_bottom)) {
        printf("setup_stack: vm_claim_page failed\n");
        vm_dealloc_page(stack_bottom);
        return false;
    }

    printf("setup_stack: Page claimed successfully\n");
    if_->rsp = USER_STACK;
    printf("setup_stack: Stack initialized. RSP = %p\n", (void*)if_->rsp);
    
    success = true;
    return success;
}
#endif