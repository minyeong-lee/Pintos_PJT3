#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"
struct page;
enum vm_type;

struct anon_page {
    //! 필요한 정보를 저장하거나 상태를 나타내는 코드를 구현해야 함
    //! struct anon_page anon 이 포함되어야 한다는 걸 잊으면 안 됨(page structure에)

    disk_sector_t swap_sector;
    bool is_swapped;

};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
