#ifndef VM_VM_H
#define VM_VM_H
#include <stdlib.h>
#include "threads/palloc.h"
#include "hash.h"
#include "threads/synch.h"

// ! 페이지 상태와 위치는 page_operations와 vm_type을 통해 관리
// ? 페이지 종류
// VM_UNINIT, VM_ANON(스왑 대상), VM_FILE, VM_PAGE_CACHE

// 페이지 타입 식별
// 해당 페이지가 어떤 타입인지 식별하는 용도
enum vm_type {
	/* page not initialized */
	VM_UNINIT = 0,
	/* page not related to the file, aka anonymous page */
	VM_ANON = 1,
	/* page that realated to the file */
	VM_FILE = 2,
	/* page that hold the page cache, for project 4 */
	VM_PAGE_CACHE = 3,

	/* Bit flags to store state */

	/* Auxillary bit flag marker for store information. You can add more
	 * markers, until the value is fit in the int. */
	// ? 이게 의미하는 건 뭐지
	// 데이터 소스, 처리 방식을 표시
	VM_MARKER_0 = (1 << 3),
	VM_MARKER_1 = (1 << 4),

	/* DO NOT EXCEED THIS VALUE. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page {
	const struct page_operations *operations;
	void *va;              /* Address in terms of user space */
	struct frame *frame;   /* Back reference for frame */

	/* Your implementation */
	
	// SPT의 해시 테이블에서 페이지를 관리하기 위해
	struct hash_elem hash_elem; // SPT 해시 테이블을 위한 요소
	// 페이지의 쓰기 권한 관리
	bool writable; 				// 쓰기 가능 여부
	// 현재 페이지의 타입을 빠르게 확인하기 위해
	enum vm_type type;			// 페이지 타입

	// 페이지 타입별 데이터
	// 각 타입별로 필요한 실제 데이터를 저장
	union {
		struct uninit_page uninit; // 초기화되지 않은 페이지
		struct anon_page anon; // 익명 페이지(스왑 가능)
		struct file_page file; // 파일 기반 페이지
#ifdef EFILESYS
		struct page_cache page_cache; // 페이지 캐시
#endif
	};
};

/* The representation of "frame" */
struct frame {
	void *kva;
	struct page *page;
};

/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
struct page_operations {
	bool (*swap_in) (struct page *, void *);
	bool (*swap_out) (struct page *);
	void (*destroy) (struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in ((page), v)
#define swap_out(page) (page)->operations->swap_out (page)
#define destroy(page) \
	if ((page)->operations->destroy) (page)->operations->destroy (page)

#define STACK_MAX (1<<20) //? 1MB
#define STACK_LIMIT ((void *)(USER_STACK - STACK_MAX))

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */

// TODO: SPT의 구조체 상세 정의 작성 코드

struct supplemental_page_table {
	// ! 해시 테이블 자료구조 사용(빠른 검색)
	struct hash page_table;
	struct lock spt_lock;
};

struct load_info {
    struct file *file;        /* 로드할 파일 */
    off_t ofs;               /* 파일 오프셋 */
    size_t read_bytes;       /* 읽어야 할 바이트 수 */
    size_t zero_bytes;       /* 0으로 채울 바이트 수 */
};

#include "threads/thread.h"

// SPT 초기화
void supplemental_page_table_init (struct supplemental_page_table *spt);

// SPT 복사 (fork 등에서 사용)
// ? 왜 사용하는가?
// src의 모든 페이지를 dst로 복사
// 각 페이지의 타입에 따라 적절하게 복사 처리(타입별 처리)
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src);

// SPT 제거(프로세스 종료 시)		
void supplemental_page_table_kill (struct supplemental_page_table *spt);

// 페이지 찾기
struct page *spt_find_page (struct supplemental_page_table *spt,
		void *va);

// 페이지 추가(해시 테이블에 삽입)
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);

// 페이지 제거(해시 테이블에서 삭제)
void spt_remove_page (struct supplemental_page_table *spt, struct page *page);

void vm_init (void);
bool vm_try_handle_fault (struct intr_frame *f, void *addr, bool user,
		bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage,
		bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page (struct page *page);
bool vm_claim_page (void *va);
enum vm_type page_get_type (struct page *page);

uint64_t page_hash(const struct hash_elem *p_, void *aux);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

#endif  /* VM_VM_H */
