/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* Initalize the page on first fault */
static bool
uninit_initialize (struct page *page, void *kva) {
    struct uninit_page *uninit = &page->uninit;

    /* Fetch first, page_initialize may overwrite the values */
    vm_initializer *init = uninit->init;
    void *aux = uninit->aux;
    enum vm_type type = uninit->type;     /* Save original type */

    /* Check if type includes VM_ANON or VM_FILE flag */
    if (VM_TYPE(type) == VM_ANON) {
        if (!anon_initializer(page, type, kva)) {
            goto err;
        }
    }
    else if (VM_TYPE(type) == VM_FILE) {
        if (!file_backed_initializer(page, type, kva)) {
            goto err;
        }
    }
    else {
        PANIC ("Unsupported type for uninitialized page");
    }

    /* Call the provided initializer function if exists */
    if (init != NULL && !init(page, aux)) {
        goto err;
    }

    return true;
err:
    return false;
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy (struct page *page) {
    struct uninit_page *uninit = &page->uninit;

    /* aux가 할당되어 있다면 해제 */
    if (uninit->aux != NULL) {
        // aux가 동적 할당된 메모리라면
        free(uninit->aux);
    }

    /* 프레임이 있다면 해제 */
    if (page->frame != NULL) {
        if (page->frame->kva != NULL) {
            palloc_free_page(page->frame->kva);
        }
        free(page->frame);
    }

    /* uninit 구조체 자체는 page의 일부이므로 여기서 해제하지 않음 */
    /* page는 caller에 의해 해제될 것임 */
}
