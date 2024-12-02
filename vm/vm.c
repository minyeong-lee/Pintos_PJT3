/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/vm.h"
#include "vm/inspect.h"

static struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	
	vm_anon_init ();	// 익명 페이지 초기화
	vm_file_init ();	// 파일 매핑 초기화 
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();	// 디버깅 인터럽트 목록
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);	// 프레임 테이블 초기화
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
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)	// UNINIT 타입이 아닌지 확인

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* 페이지가 존재하지 않으면 새 페이지를 생성하고 초기화 */
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* project3 - Anonymous Page */
		// 페이지를 위한 메모리를 동적 할당
		struct page *page = (struct page *)malloc(sizeof(struct page));

		// 페이지 초기화를 위한 초기화 유형 선택
        typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
        initializerFunc initializer = NULL;

		// 페이지 초기화를 위한 초기화 유형 선택
        switch (VM_TYPE(type)) {
            case VM_ANON:	// 익명 페이지
                initializer = anon_initializer;
                break;
            case VM_FILE:	// 파일 매핑 페이지
                initializer = file_backed_initializer;
                break;
        }

		// "uninit" 페이지를 생성하여 초기 상태로 설정
        uninit_new(page, upage, init, type, aux, initializer);

		// 페이지의 쓰기 가능 여부 설정
        page->writable = writable;

        /* TODO: Insert the page into the spt. */
		/* 페이지를 SPT에 삽입 */
        return spt_insert_page(spt, page);

	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = (struct page *)malloc(sizeof(struct page));     // 가상 주소에 대응하는 해시 값 도출을 위해 새로운 페이지 할당
    page->va = pg_round_down(va);                                       // 가상 주소의 시작 주소를 페이지의 va에 매핑
    struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);  // spt hash 테이블에서 hash_elem과 같은 hash를 갖는 페이지를 찾아서 return
    free(page);                                                         // 복제한 페이지 삭제

    if (e != NULL)
        return hash_entry(e, struct page, hash_elem);

    return NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* TODO: Fill this function. */
	if(!hash_insert(&spt->spt_hash, &page->hash_elem))
        return true;

	return false;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;		 // 선택된 victim 프레임
	 /* TODO: The policy for eviction is up to you. */
	struct thread *curr = thread_current();	// 현재 스레드
    struct list_elem *e = list_begin(&frame_table);	// 프레임 테이블의 첫 번째 요소

	// Second-Chance 알고리즘을 사용하여 victim을 선택
    for (e; e != list_end(&frame_table); e = list_next(e)) {
        victim = list_entry(e, struct frame, frame_elem);

		// 페이지가 최근에 사용되었는지 확인
        if (pml4_is_accessed(curr->pml4, victim->page->va))
			// 최근 사용된 페이지라면 accessed 비트를 초기화
            pml4_set_accessed(curr->pml4, victim->page->va, false);  
        else
			// 사용되지 않은 페이지를 victim으로 선택
            return victim;
    }

	return victim;	 // 만약 모든 프레임이 최근 사용된 경우, 마지막 프레임 반환
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
    // 교체 대상 프레임(victim)을 선택
    struct frame *victim UNUSED = vm_get_victim();

    // TODO: swap out the victim and return the evicted frame.
    // 교체 대상 프레임의 페이지를 스왑 영역으로 내보냄
    swap_out(victim->page);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	// 새 프레임 구조체를 동적으로 할당
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    ASSERT (frame != NULL); // 할당 실패 시 종료 (디버깅 목적)

    // 유저 풀에서 페이지를 할당받아 프레임의 kva 필드에 저장
    frame->kva = palloc_get_page(PAL_USER);

    if (frame->kva == NULL) {
        // 페이지 할당 실패 시 Swap Out을 수행해 프레임 확보
        frame = vm_evict_frame();
    } else {
        // 할당 성공 시 프레임을 프레임 테이블에 추가
        list_push_back(&frame_table, &frame->frame_elem);
    }

    // 새 프레임의 page 필드를 NULL로 초기화
    frame->page = NULL;

    ASSERT (frame->page == NULL); // 디버깅용 체크
    return frame; // 새로 할당되거나 교체된 프레임 반환
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	bool success = false;

	// 새 페이지를 익명 페이지(anon)로 할당하고 SPT에 등록
    if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true)) {

		// 페이지를 물리 메모리에 매핑 (클레임)
        success = vm_claim_page(addr);

        if (success) {
            // 스택 바닥 주소를 갱신
            thread_current()->stack_bottom -= PGSIZE;
        }
    }
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	// 1. 폴트 주소가 NULL인지 확인
	if (addr == NULL)
		return false;

	// 2. 커널 주소인지 확인
	if (is_kernel_vaddr(addr))
		return false;

	// 3. 페이지가 존재하지 않는 경우 (잘못된 폴트)
	if (!not_present) 
		return false;

	// 4. 페이지 클레임: SPT에 있는 페이지를 물리 메모리로 매핑 -> demand page
	if(vm_claim_page(addr))
		return true;

	/** Project 3: Stack Growth */
	// 5. 스택 포인터와 주소 비교를 통해 스택 확장 여부 판단
    void *stack_pointer = is_kernel_vaddr(f->rsp) ? thread_current()->stack_pointer : f->rsp;
    /* stack pointer 아래 8바이트는 페이지 폴트 발생 & addr 위치를 USER_STACK에서 1MB로 제한 */

	// 주소가 스택 확장 조건에 맞는지 확인
    if (stack_pointer - 8 <= addr && addr >= STACK_LIMIT && addr <= USER_STACK) {
		// 새로운 스택 페이지 할당
        vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
		return true;
	}
	// 기타 페이지 폴트는 처리하지 않음
	return false;
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
	// 현재 스레드의 Supplemental Page Table에서 가상 주소에 해당하는 페이지를 검색
	struct page *page = spt_find_page(&thread_current()->spt, va);
	/* TODO: Fill this function */

	// 페이지가 SPT에 존재하지 않으면 실패 반환
	if (page == NULL)
        return false;
	
	// 페이지를 클레임하고 성공 여부 반환
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	// 새로운 프레임을 할당받음
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;		// 프레임에 페이지를 연결
	page->frame = frame;	// 페이지에 프레임을 연결

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* project3 - Memory Management */
    pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);

	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, hash_func, less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {

    struct hash_iterator iter;
    struct page *src_page;

    hash_first(&iter, &src->spt_hash);
    while (hash_next(&iter)) {
        src_page = hash_entry(hash_cur(&iter), struct page, hash_elem);

        if (src_page->operations->type == VM_UNINIT) {  // src 타입이 uninit인 경우
            if (!vm_alloc_page_with_initializer(page_get_type(src_page), src_page->va, src_page->writable, src_page->uninit.init, src_page->uninit.aux))
                return false;
            continue;
        }

        if (src_page->uninit.type & VM_MARKER_0) {  // src 페이지가 STACK인 경우
            setup_stack(&thread_current()->tf);
            goto done;
        }

        // src 타입이 anon인 경우
        if (!vm_alloc_page(page_get_type(src_page), src_page->va, src_page->writable))  // src를 unint 페이지로 만들고 spt 삽입
            return false;

        if (!vm_claim_page(src_page->va))  // 물리 메모리와 매핑하고 initialize 한다
            return false;
			
	struct page *dst_page;
    done:  // UNIT이 아닌 모든 페이지에 대응하는 물리 메모리 데이터 복사
        dst_page = spt_find_page(dst, src_page->va);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }

    return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// 해시 테이블 파괴
    hash_clear(&spt->spt_hash, hash_destructor);
}
