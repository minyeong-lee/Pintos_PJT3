/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/vaddr.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	if (swap_disk==NULL) {
		PANIC("Swap disk is not available!");
	}
	
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->swap_sector = (disk_sector_t)-1;
	anon_page->is_swapped = false;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
//? 스왑 디스크에서 메모리로 내용을 읽어옴
static bool
anon_swap_in (struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
    
    // Check if page is actually in swap
    if (!anon_page->is_swapped)
        return false;
        
    // Read page content from swap disk
    for (int i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
        disk_read(swap_disk, 
                 anon_page->swap_sector + i,
                 kva + i * DISK_SECTOR_SIZE);
    }

    // Reset swap status
    anon_page->is_swapped = false;

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
//? 메모리의 내용을 스왑 디스크에 저장함
static bool
anon_swap_out (struct page *page) {
    struct anon_page *anon_page = &page->anon;
    
    // Use a static counter for swap sectors
    static disk_sector_t next_swap_sector = 1;
    
    // Write page content to swap disk
    for (int i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
        disk_write(swap_disk, 
                  next_swap_sector + i,
                  page->frame->kva + i * DISK_SECTOR_SIZE);
    }

    // Update swap information
    anon_page->swap_sector = next_swap_sector;
    anon_page->is_swapped = true;
    next_swap_sector += PGSIZE / DISK_SECTOR_SIZE;  // Move to next available sectors

    // Clear the frame
    page->frame = NULL;

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
//? 페이지 정리함
static void
anon_destroy (struct page *page) {
    struct anon_page *anon_page = &page->anon;
}
