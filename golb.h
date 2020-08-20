#ifndef GOLB_H
#	define GOLB_H
#	include "common.h"
typedef struct {
	kaddr_t virt;
	size_t page_cnt;
	struct {
		kaddr_t ptep, pte;
	} *pages;
} golb_ctx_t;

kern_return_t
golb_init(void);

void
golb_term(void);

void
golb_unmap(golb_ctx_t);

kaddr_t
golb_find_phys(kaddr_t);

kern_return_t
golb_flush_core_tlb_asid(void);

kern_return_t
golb_map(golb_ctx_t *, kaddr_t, mach_vm_size_t, vm_prot_t);
#endif
