/* Copyright 2022 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef GOLB_H
#	define GOLB_H
#	include "common.h"
typedef struct {
	struct {
		kaddr_t ptep, pte;
	} *pages;
	size_t page_cnt;
	kaddr_t virt;
} golb_ctx_t;
typedef kern_return_t (*kread_func_t)(kaddr_t, void *, size_t), (*kwrite_func_t)(kaddr_t, const void *, size_t);

void
golb_term(void);

void
golb_unmap(golb_ctx_t);

kaddr_t
golb_find_phys(kaddr_t);

kern_return_t
golb_flush_core_tlb_asid(void);

kern_return_t
golb_init(kaddr_t, kread_func_t, kwrite_func_t);

kern_return_t
golb_map(golb_ctx_t *, kaddr_t, mach_vm_size_t, vm_prot_t);
#endif
