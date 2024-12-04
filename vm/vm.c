/* vm.c: Generic interface for virtual memory objects. */

// 1. 시스템 헤더
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

// 2. 커널 공통 헤더
#include "threads/malloc.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/anon.h"
#include "vm/file.h"

// 3. 디바이스/기능별 헤더
#include "devices/disk.h"
#include "vm/vm.h"
#include "vm/inspect.h"


//! 스택 접근 판단 함수(스택 접근 검사 구현 코드)
static bool
is_stack_access(void *addr, void *rsp) {

    if (!is_user_vaddr(addr))
        return false;
    
    if (addr >= (void *)USER_STACK || addr < STACK_LIMIT)
        return false;

    // rsp 아래 8바이트까지는 스택 접근으로 간주 (PUSH 연산을 위해)
    if (addr >= (void *)(rsp - 8))
        return true;

    // 현재 스택 프레임 내 접근 허용
    if (addr >= pg_round_down(rsp))
        return true;

    // saved_sp를 활용한 추가 검증
    struct thread *curr = thread_current();
    if (curr->saved_sp && addr >= pg_round_down(curr->saved_sp))
        return true;

    return false;
}

uint64_t
page_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

bool
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);
    return a->va < b->va;
}


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
    vm_anon_init ();
    vm_file_init ();
#ifdef EFILESYS
    pagecache_init ();
#endif
    register_inspect_intr ();
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */

// ! 새로운 "미초기화" 페이지를 생성하고 SPT에 추가하는 함수
// ? 이 함수가 필요한 이유가 뭐야
// ! 페이지를 직접 생성하지 않고 이 함수를 통해 생성한다.
// ! "미초기화" 페이지란 메모리 상에 할당은 되어 있지만 아직 초기화되지 않은 페이지
// ! 필요할 때 초기화되어 사용하기 위함
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
       vm_initializer *init, void *aux) {
           
   printf("Entering vm_alloc_page_with_initializer\n");
   printf("Type: %d, Page: %p, Writable: %d\n", type, upage, writable);

   ASSERT(VM_TYPE(type) != VM_UNINIT);

   struct thread *curr = thread_current();
   if (curr->spt == NULL) {
       printf("ERROR: SPT is NULL\n"); 
       return false;
   }

   void *page_aligned = pg_round_down(upage);
   printf("Aligned page address: %p\n", page_aligned);

   if (!is_user_vaddr(page_aligned)) {
       printf("ERROR: Not a valid user virtual address\n");
       return false;
   }

   if (spt_find_page(curr->spt, page_aligned) != NULL) {
       printf("ERROR: Page already exists in SPT\n");
       return false;
   }

   struct page *page = malloc(sizeof(struct page));
   if (page == NULL) {
       return false;
   }


   memset(page, 0, sizeof(struct page));
   page->va = page_aligned;
   page->writable = writable;
   page->frame = NULL;


   switch (VM_TYPE(type)) {
       case VM_ANON:
           uninit_new(page, page->va, init, type, aux, anon_initializer);
           break;
       case VM_FILE:
           uninit_new(page, page->va, init, type, aux, file_backed_initializer);
           break;
       default:
           free(page);
           return false;
   }

   if (!spt_insert_page(curr->spt, page)) {
       free(page);
       return false;
   }

   printf("Successfully initialized and inserted page\n");
   return true;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    struct page p;
    p.va = pg_round_down(va);

    struct hash_elem *e = hash_find(&spt->page_table, &p.hash_elem);
    return e ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
    lock_acquire(&spt->spt_lock);
    bool success = (hash_insert(&spt->page_table, &page->hash_elem) == NULL);
    lock_release(&spt->spt_lock);
    return success;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
}

static struct frame *
vm_get_victim (void) {
    struct frame *victim = NULL;
    struct thread *curr = thread_current();
    struct hash_iterator i;

    lock_acquire(&curr->spt->spt_lock);
    
    // SPT를 순회하면서 victim 선택
    hash_first(&i, &curr->spt->page_table);
    while (hash_next(&i)) {
        struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);
        if (page->frame != NULL) {  // 실제 프레임이 있는 페이지만 고려
            // 접근 비트를 확인하여 최근에 사용되지 않은 페이지 선택
            if (!pml4_is_accessed(curr->pml4, page->va)) {
                victim = page->frame;
                break;
            }
            // 모든 페이지가 최근에 접근되었다면 첫 번째 페이지 선택
            if (victim == NULL) {
                victim = page->frame;
            }
            // 접근 비트 초기화 (다음 선택을 위해)
            pml4_set_accessed(curr->pml4, page->va, false);
        }
    }

    lock_release(&curr->spt->spt_lock);
    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
    struct frame *victim = vm_get_victim();
    if (victim == NULL)
        return NULL;

    // 희생 페이지의 내용을 스왑 아웃
    if (victim->page != NULL) {
        if (!swap_out(victim->page)) {
            return NULL;
        }
        
        // 페이지 테이블 엔트리 업데이트
        pml4_clear_page(thread_current()->pml4, victim->page->va);
        victim->page->frame = NULL;
        victim->page = NULL;
    }

    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
    struct frame *frame = malloc(sizeof(struct frame));
    if (frame == NULL)
        return NULL;

    frame->kva = palloc_get_page(PAL_USER);
    if (frame->kva == NULL) {
        free(frame);
        return NULL;
    }

    frame->page = NULL;
    ASSERT(is_kernel_vaddr(frame->kva));
    
    memset(frame->kva, 0, PGSIZE);  // 프레임 초기화
    return frame;
}
/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
    // 페이지 정렬된 주소 계산
    void *page_addr = pg_round_down(addr);
    
    // 스택 범위 검사
    if (page_addr >= (void *)USER_STACK || page_addr < STACK_LIMIT)
        return;

    // 새로운 스택 페이지 할당
    vm_alloc_page(VM_ANON | VM_MARKER_0, page_addr, true);
    
    // 페이지 초기화 및 매핑
    vm_claim_page(page_addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
        bool user, bool write, bool not_present) {
    struct thread *curr = thread_current();
    struct supplemental_page_table *spt = curr->spt;

    void *page_addr = pg_round_down(addr);
    
    /* 주소 검증 */
    if (!is_user_vaddr(addr)) 
        return false;

    /* SPT에서 페이지 찾기 */
    struct page *page = spt_find_page(spt, page_addr);
    
    if (page == NULL) {
        /* 스택 확장 검사 */
        if (is_stack_access(addr, (void *)f->rsp)) {
            vm_stack_growth(page_addr);
            page = spt_find_page(spt, page_addr);
            if (page == NULL)
                return false;
        } else {
            /* Load 과정에서 생성된 페이지인지 확인 */
            if (!vm_alloc_page(VM_ANON, page_addr, write)) {
                return false;
            }
            page = spt_find_page(spt, page_addr);
            if (page == NULL)
                return false;
        }
    }

    /* 쓰기 권한 체크 */
    if (write && !page->writable)
        return false;

    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
    struct thread *curr = thread_current();
    struct page *page = spt_find_page(curr->spt, va);  // &제거
    if (page == NULL)
        return false;
    return vm_do_claim_page(page);
}

static bool
vm_do_claim_page (struct page *page) {
    struct frame *frame = vm_get_frame();
    if (frame == NULL)
        return false;

    frame->page = page;
    page->frame = frame;

    // 커널 가상 주소 확인
    if (!is_kernel_vaddr(frame->kva)) {
        palloc_free_page(frame->kva);
        free(frame);
        return false;
    }

    // 페이지 테이블 엔트리 설정
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
        palloc_free_page(frame->kva);
        free(frame);
        return false;
    }

    // 페이지가 VM_ANON 타입일 경우
    if (VM_TYPE(page->type) == VM_ANON) {
        memset(frame->kva, 0, PGSIZE);  // 페이지를 0으로 초기화
        return true;
    }

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
    printf("supplemental_page_table_init 실행 된다 아이가\n");
    ASSERT(spt != NULL);
    
    printf("Before hash_init - page_table address: %p\n", &spt->page_table);
    hash_init(&spt->page_table, page_hash, page_less, NULL);
    printf("After hash_init - page_table address: %p\n", &spt->page_table);
    
    // hash table의 buckets이 제대로 초기화되었는지 확인
    printf("Bucket count: %zu\n", spt->page_table.bucket_cnt);
    printf("First bucket address: %p\n", spt->page_table.buckets);
    
    lock_init(&spt->spt_lock);
}
/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;

    if (dst == NULL || src == NULL)
        return false;

    hash_first(&i, &src->page_table);

    while (hash_next(&i)) {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = page_get_type(src_page);
        
        // 새 페이지 생성
        if (!vm_alloc_page(type, src_page->va, src_page->writable))
            goto error;

        // 페이지 내용 복사
        struct page *dst_page = spt_find_page(dst, src_page->va);
        if (dst_page == NULL)
            goto error;

        // 페이지가 메모리에 있는 경우에만 복사
        if (src_page->frame != NULL) {
            if (!vm_do_claim_page(dst_page))
                goto error;
            memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
        }
    }
    return true;

error:
    // 실패 시 지금까지 할당된 모든 페이지 해제
    hash_first(&i, &dst->page_table);
    while (hash_next(&i)) {
        struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);
        vm_dealloc_page(page);
    }
    return false;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
    printf("SPT kill - spt address: %p\n", spt);
    if (spt == NULL) {
        return;
    }
    
    printf("SPT kill - page_table address: %p\n", &spt->page_table);
    printf("SPT kill - buckets address: %p\n", spt->page_table.buckets);
    printf("SPT kill - bucket_count: %zu\n", spt->page_table.bucket_cnt);
    
    // 해시 테이블의 각 엔트리를 순회하면서 해제
    struct hash_iterator i;
    hash_first(&i, &spt->page_table);
    while (hash_next(&i)) {
        struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);
        if (page->frame != NULL && page->frame->kva != NULL) {
            // palloc으로 할당된 프레임인지 확인 후 해제
            if (is_kernel_vaddr(page->frame->kva))
                palloc_free_page(page->frame->kva);
            free(page->frame);
        }
        vm_dealloc_page(page);
    }
}