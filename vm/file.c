/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

/** Project 3: Memory Mapped Files */
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;   // 페이지에 파일 관련 연산(ops) 설정

	struct file_page *file_page = &page->file;  // 페이지의 file_page 필드 참조

    // aux 구조체를 통해 파일 매핑 정보 설정
    struct aux *aux = (struct aux *)page->uninit.aux;
    file_page->file = aux->file;        // 매핑된 파일 객체
    file_page->offset = aux->offset;    // 파일에서의 시작 위치
    file_page->page_read_bytes = aux->page_read_bytes;  // 페이지에 읽어올 파일 데이터 크기

    return true;    // 초기화 성공
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
    
    // 페이지가 수정되었는지 확인
    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        // 수정된 데이터를 파일로 기록
        file_write_at(file_page->file, page->va, file_page->page_read_bytes, file_page->offset);
        // 페이지를 수정되지 않은 상태로 설정
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    }
    // 페이지 매핑 제거
    pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
/**
 * addr : 매핑을 시작할 가상 주소
 * length : 매핑할 메모리 영역 크기 (바이트 단위)
 * writable : 매핑된 메모리가 쓰기 가능한지 여부
 * file : 매핑할 파일 객체
 * offset : 파일에서 매핑을 시작할 오프셋
 */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// 파일을 재오픈하여 독립적인 파일 객체 생성
	struct file *mfile = file_reopen(file);

	// 매핑 시작 주소 저장
    void *ori_addr = addr;
	// 매핑할 바이트 수와 남는 바이트 계산
    size_t read_bytes = (length > file_length(file)) ? file_length(file) : length;
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0); // 매핑해야할 바이트가 페이지 크기의 배수인지 확인
    ASSERT(pg_ofs(addr) == 0);  // 매핑 시작 주소가 페이지 시작 주소인지 확인
    ASSERT(offset % PGSIZE == 0);   // 파일 매핑의 시작 위치가 페이지 크기의 매수인지 확인

	// 페이지 단위로 메모리 매핑
    while (read_bytes > 0 || zero_bytes > 0) {
		// 현재 페이지에서 읽을 바이트와 0으로 채울 바이트 계산
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// 페이지 초기화 정보를 담을 container 생성
        struct aux *aux = (struct aux *)malloc(sizeof(struct aux));
        aux->file = mfile;
        aux->offset = offset;
        aux->page_read_bytes = page_read_bytes;

		// 페이지를 할당하고 초기화 정보와 함께 SPT 등록
        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, aux)){
            free(aux);
            return false;
        }

        // 읽을 바이트와 남은 바이트 계산
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;

		// 다음 페이지로 이동
        addr += PGSIZE;
        offset += page_read_bytes;
    }
    
    return ori_addr;	// 매핑 시작 주소 반환
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// 현재 스레드 가져오기
	struct thread *curr = thread_current();

    while (1) {
		// 현재 주소에 해당하는 페이지 찾음
        struct page *page = spt_find_page(&curr->spt, addr);

		// 페이지가 없으면 루프 종료
        if (page == NULL)
            break;

		// 페이지의 초기화 정보(aux)를 가져옴
        struct aux *aux = (struct aux *)page->uninit.aux;

        // 페이지가 수정되었는지 확인 여부에 따라 file에 쓰고 지운다.
        if(page)
            destroy(page);
        // 다음 페이지로 이동
        addr += PGSIZE;
    }
}
