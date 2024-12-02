#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
	struct file *file;		// 매핑된 파일 객체
    off_t offset;			// 매핑된 파일에서의 시작 위치
    size_t page_read_bytes;	// 페이지에 매핑된 파일에서 읽어올 바이트 수
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
