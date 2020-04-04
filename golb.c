#include "golb.h"
#include <mach-o/loader.h>

#define PROC_TASK_OFF (0x10)
#define VM_MAP_PMAP_OFF (0x48)
#define VM_MAP_FLAGS_OFF (0x10C)
#define VM_MAP_HDR_RBH_ROOT_OFF (0x38)
#ifdef __arm64e__
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x190)
#else
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x198)
#endif
#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b2 (1656)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b1 (1652.20)
#define kCFCoreFoundationVersionNumber_iOS_13_2_b1 (1673.12)
#define TASK_MAP_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0x28 : 0x20)
#define PROC_P_PID_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b2 ? 0x68 : 0x60)
#define PMAP_SW_ASID_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_2_b1 ? 0xE6 : kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0xEE : 0xDC)

#define AP_RWRW (1U)
#define AP_RORO (3U)
#define PVH_LOCK_BIT (61U)
#define PVH_TYPE_PTEP (2U)
#define ARM_PTE_AF (0x400U)
#define ARM_PTE_NG (0x800U)
#define PVH_TYPE_MASK (3ULL)
#define VM_KERN_MEMORY_CPU (9)
#define ARM64_VMADDR_BITS (48U)
#define ARM_PTE_TYPE_VALID (3U)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define ARM_PTE_AP(a) ((a) << 6U)
#define PVH_FLAG_CPU (1ULL << 62U)
#define LOWGLO_VER_CODE "Kraken  "
#define PVH_FLAG_EXEC (1ULL << 60U)
#define CACHE_ATTRINDX_DISABLE (3U)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define PVH_LIST_MASK (~PVH_TYPE_MASK)
#define VM_MAP_FLAGS_NO_ZERO_FILL (4U)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define PVH_FLAG_LOCKDOWN (1ULL << 59U)
#define ARM_PTE_ATTRINDX(a) ((a) << 2U)
#define ARM_PTE_NX (0x40000000000000ULL)
#define LOWGLO_LAYOUT_MAGIC (0xC0DEC0DE)
#define ARM_PTE_PNX (0x20000000000000ULL)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define FAULT_MAGIC (0xAAAAAAAAAAAAAAAAULL)
#define PVH_FLAG_LOCK (1ULL << PVH_LOCK_BIT)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define IS_MOV_X(a) (((a) & 0xFFE00000U) == 0xAA000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))
#define ARM_PTE_MASK trunc_page_kernel((1ULL << ARM64_VMADDR_BITS) - 1)
#define PVH_HIGH_FLAGS (PVH_FLAG_CPU | PVH_FLAG_LOCK | PVH_FLAG_EXEC | PVH_FLAG_LOCKDOWN)

#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef struct {
	struct section_64 s64;
	char *data;
} sec_64_t;

typedef struct {
	sec_64_t sec_text, sec_data, sec_cstring;
	kaddr_t pc;
} pfinder_t;

typedef struct {
	uint16_t rev, ver;
	uint32_t pad;
	kaddr_t virt_base, phys_base;
	uint64_t mem_sz;
} boot_args_t;

typedef struct {
	struct {
		kaddr_t prev, next, start, end;
	} links;
	kaddr_t rbe_left, rbe_right, rbe_parent, vme_object;
	uint64_t vme_offset;
} vm_map_entry_t;

typedef struct {
	struct {
		uint32_t next, prev;
	} vmp_q_pageq, vmp_listq, vmp_backgroundq;
	uint64_t vmp_offset;
	uint32_t vmp_object, q_flags, vmp_next_m, o_flags;
} vm_page_t;

typedef struct {
	uint8_t ver_code[8];
	kaddr_t zero, stext, ver, os_ver, kmod_ptr, trans_off, reboot_flag, manual_pkt_addr, alt_debugger, pmap_memq, pmap_mem_page_off, pmap_mem_chain_off, static_addr, static_sz, layout_major_ver, layout_magic, pmap_mem_start_addr, pmap_mem_end_addr, pmap_mem_page_sz, pmap_mem_from_array_mask, pmap_mem_first_ppnum, pmap_mem_packed_shift, pmap_mem_packed_base_addr, layout_minor_ver, page_shift;
} lowglo_t;

static lowglo_t lowglo;
static boot_args_t boot_args;
static task_t tfp0 = MACH_PORT_NULL;
static kaddr_t allproc, const_boot_args, pv_head_table_ptr, pv_head_table, our_map, our_pmap;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
	return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static kern_return_t
init_tfp0(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIX32 "\n", host);
			ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
			mach_port_deallocate(mach_task_self(), host);
		}
	}
	if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
		if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
			return ret;
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	return KERN_FAILURE;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz != 0) {
		read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
	return kread_buf(addr, val, sizeof(*val));
}

static kern_return_t
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_msg_type_number_t write_sz;

	while(sz != 0) {
		write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
		p += write_sz;
		sz -= write_sz;
		addr += write_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kwrite_addr(kaddr_t addr, kaddr_t val) {
	return kwrite_buf(addr, &val, sizeof(val));
}

static kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	vm_region_extended_info_data_t extended_info;
	task_dyld_info_data_t dyld_info;
	kaddr_t addr, rtclock_datap;
	struct mach_header_64 mh64;
	mach_port_t obj_nm;
	mach_vm_size_t sz;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS && dyld_info.all_image_info_size != 0) {
		*kslide = dyld_info.all_image_info_size;
		return VM_KERNEL_LINK_ADDRESS + *kslide;
	}
	cnt = VM_REGION_EXTENDED_INFO_COUNT;
	for(addr = 0; mach_vm_region(tfp0, &addr, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&extended_info, &cnt, &obj_nm) == KERN_SUCCESS; addr += sz) {
		mach_port_deallocate(mach_task_self(), obj_nm);
		if(extended_info.user_tag == VM_KERN_MEMORY_CPU && extended_info.protection == VM_PROT_DEFAULT) {
			if(kread_addr(addr + CPU_DATA_RTCLOCK_DATAP_OFF, &rtclock_datap) != KERN_SUCCESS) {
				break;
			}
			printf("rtclock_datap: " KADDR_FMT "\n", rtclock_datap);
			rtclock_datap = trunc_page_kernel(rtclock_datap);
			do {
				if(rtclock_datap <= VM_KERNEL_LINK_ADDRESS) {
					return 0;
				}
				rtclock_datap -= vm_kernel_page_size;
				if(kread_buf(rtclock_datap, &mh64, sizeof(mh64)) != KERN_SUCCESS) {
					return 0;
				}
			} while(mh64.magic != MH_MAGIC_64 || mh64.cputype != CPU_TYPE_ARM64 || mh64.filetype != MH_EXECUTE);
			*kslide = rtclock_datap - VM_KERNEL_LINK_ADDRESS;
			return rtclock_datap;
		}
	}
	return 0;
}

static kern_return_t
find_section(kaddr_t sg64_addr, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
	kaddr_t s64_addr, s64_end;

	for(s64_addr = sg64_addr + sizeof(sg64), s64_end = s64_addr + (sg64.cmdsize - sizeof(*sp)); s64_addr < s64_end; s64_addr += sizeof(*sp)) {
		if(kread_buf(s64_addr, sp, sizeof(*sp)) != KERN_SUCCESS) {
			break;
		}
		if(strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static void
sec_reset(sec_64_t *sec) {
	memset(&sec->s64, '\0', sizeof(sec->s64));
	sec->data = NULL;
}

static void
sec_term(sec_64_t *sec) {
	free(sec->data);
	sec_reset(sec);
}

static kern_return_t
sec_init(sec_64_t *sec) {
	if((sec->data = malloc(sec->s64.size)) != NULL) {
		if(kread_buf(sec->s64.addr, sec->data, sec->s64.size) == KERN_SUCCESS) {
			return KERN_SUCCESS;
		}
		sec_term(sec);
	}
	return KERN_FAILURE;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	pfinder->pc = 0;
	sec_reset(&pfinder->sec_text);
	sec_reset(&pfinder->sec_data);
	sec_reset(&pfinder->sec_cstring);
}

static void
pfinder_term(pfinder_t *pfinder) {
	sec_term(&pfinder->sec_text);
	sec_term(&pfinder->sec_data);
	sec_term(&pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase, kaddr_t kslide) {
	arm_unified_thread_state_t state;
	kern_return_t ret = KERN_FAILURE;
	struct segment_command_64 sg64;
	kaddr_t sg64_addr, sg64_end;
	struct mach_header_64 mh64;
	struct section_64 s64;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
		for(sg64_addr = kbase + sizeof(mh64), sg64_end = sg64_addr + (mh64.sizeofcmds - sizeof(sg64)); sg64_addr < sg64_end; sg64_addr += sg64.cmdsize) {
			if(kread_buf(sg64_addr, &sg64, sizeof(sg64)) != KERN_SUCCESS) {
				break;
			}
			if(sg64.cmd == LC_SEGMENT_64) {
				if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_TEXT, &s64) == KERN_SUCCESS) {
					pfinder->sec_text.s64 = s64;
					printf("sec_text_addr: " KADDR_FMT ", sec_text_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				} else if(strncmp(sg64.segname, SEG_DATA, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_DATA, &s64) == KERN_SUCCESS) {
					pfinder->sec_data.s64 = s64;
					printf("sec_data_addr: " KADDR_FMT ", sec_data_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				} else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_CSTRING, &s64) == KERN_SUCCESS) {
					pfinder->sec_cstring.s64 = s64;
					printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				}
			} else if(sg64.cmd == LC_UNIXTHREAD) {
				if(kread_buf(sg64_addr + sizeof(struct thread_command), &state, sizeof(state)) != KERN_SUCCESS) {
					break;
				}
#undef ts_64
				pfinder->pc = state.uts.ts_64.__pc + kslide;
			}
			if(pfinder->sec_text.s64.size != 0 && pfinder->sec_data.s64.size != 0 && pfinder->sec_cstring.s64.size != 0 && pfinder->pc != 0) {
				if(sec_init(&pfinder->sec_text) == KERN_SUCCESS && sec_init(&pfinder->sec_data) == KERN_SUCCESS) {
					ret = sec_init(&pfinder->sec_cstring);
				}
				break;
			}
		}
	}
	if(ret != KERN_SUCCESS) {
		pfinder_term(pfinder);
	}
	return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	uint64_t x[32] = { 0 };
	uint32_t insn;

	for(; start >= pfinder.sec_text.s64.addr && start < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insn)); start += sizeof(insn)) {
		memcpy(&insn, pfinder.sec_text.data + (start - pfinder.sec_text.s64.addr), sizeof(insn));
		if(IS_LDR_X(insn)) {
			x[RD(insn)] = start + LDR_X_IMM(insn);
		} else if(IS_ADR(insn)) {
			x[RD(insn)] = start + ADR_IMM(insn);
		} else if(IS_ADRP(insn)) {
			x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
			continue;
		} else if(IS_ADD_X(insn)) {
			x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
		} else if(IS_RET(insn)) {
			memset(x, '\0', sizeof(x));
		}
		if(RD(insn) == rd) {
			if(to == 0) {
				return x[rd];
			}
			if(x[rd] == to) {
				return start;
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
	const char *p, *e;
	size_t len;

	for(p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p < e; p += len) {
		len = strlen(p) + 1;
		if(strncmp(str, p, len) == 0) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
		}
	}
	return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

	if(ref == 0) {
		ref = pfinder_xref_str(pfinder, "shutdownwait", 3); /* msleep */
	}
	return pfinder_xref_rd(pfinder, 8, ref, 0);
}

static kaddr_t
pfinder_pv_head_table_ptr(pfinder_t pfinder) {
	uint32_t insns[3];
	kaddr_t ref;

	for(ref = pfinder_xref_str(pfinder, "pmap_iommu_ioctl_internal", 8); ref >= pfinder.sec_text.s64.addr && ref < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insns)); ref -= sizeof(*insns)) {
		memcpy(insns, pfinder.sec_text.data + (ref - pfinder.sec_text.s64.addr), sizeof(insns));
		if(IS_ADRP(insns[0]) && IS_LDR_X_UNSIGNED_IMM(insns[1]) && IS_MOV_X(insns[2]) && RD(insns[2]) == 0) {
			return pfinder_xref_rd(pfinder, RD(insns[1]), ref, 0);
		}
	}
	return 0;
}

static kaddr_t
pfinder_const_boot_args(pfinder_t pfinder) {
	return pfinder_xref_rd(pfinder, 20, ADRP_ADDR(pfinder.pc), 0);
}

static kern_return_t
pfinder_lowglo(pfinder_t pfinder) {
	const char *p, *e;

	for(p = pfinder.sec_data.data, e = p + (pfinder.sec_data.s64.size - sizeof(lowglo)); p < e; p += PAGE_MAX_SIZE) {
		memcpy(&lowglo, p, sizeof(lowglo));
		if(memcmp(&lowglo.ver_code, LOWGLO_VER_CODE, sizeof(lowglo.ver_code)) == 0 && lowglo.layout_major_ver == 3 && lowglo.layout_magic == LOWGLO_LAYOUT_MAGIC && lowglo.pmap_mem_page_sz == sizeof(vm_page_t) && lowglo.layout_minor_ver == 0) {
			printf("lowglo: " KADDR_FMT "\n", pfinder.sec_data.s64.addr + (kaddr_t)(p - pfinder.sec_data.data));
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
pfinder_init_offsets(kaddr_t kbase, kaddr_t kslide) {
	kern_return_t ret = KERN_FAILURE;
	pfinder_t pfinder;

	if(pfinder_init(&pfinder, kbase, kslide) == KERN_SUCCESS) {
		if((allproc = pfinder_allproc(pfinder)) != 0) {
			printf("allproc: " KADDR_FMT "\n", allproc);
			if((pv_head_table_ptr = pfinder_pv_head_table_ptr(pfinder)) != 0) {
				printf("pv_head_table_ptr: " KADDR_FMT "\n", pv_head_table_ptr);
				if((const_boot_args = pfinder_const_boot_args(pfinder)) != 0) {
					printf("const_boot_args: " KADDR_FMT "\n", const_boot_args);
					ret = pfinder_lowglo(pfinder);
				}
			}
		}
		pfinder_term(&pfinder);
	}
	return ret;
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc != 0) {
		if(kread_buf(proc + PROC_P_PID_OFF, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
			return kread_addr(proc + PROC_TASK_OFF, task);
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
vm_map_lookup_entry(kaddr_t vm_map, kaddr_t virt, vm_map_entry_t *vm_entry) {
	kaddr_t rb_entry;

	if(kread_addr(vm_map + VM_MAP_HDR_RBH_ROOT_OFF, &rb_entry) == KERN_SUCCESS) {
		while(rb_entry != sizeof(vm_entry->links)) {
			printf("rb_entry: " KADDR_FMT "\n", rb_entry);
			if(kread_buf(rb_entry - sizeof(vm_entry->links), vm_entry, sizeof(*vm_entry)) != KERN_SUCCESS) {
				break;
			}
			printf("start: " KADDR_FMT ", end: " KADDR_FMT ", vme_object: " KADDR_FMT ", vme_offset: 0x%" PRIX64 "\n", vm_entry->links.start, vm_entry->links.end, vm_entry->vme_object, vm_entry->vme_offset);
			if(virt >= vm_entry->links.start) {
				if(virt < vm_entry->links.end) {
					return KERN_SUCCESS;
				}
				rb_entry = vm_entry->rbe_right;
			} else {
				rb_entry = vm_entry->rbe_left;
			}
		}
	}
	return KERN_FAILURE;
}

static kaddr_t
vm_page_unpack_ptr(kaddr_t p) {
	if(p != 0) {
		if(p & lowglo.pmap_mem_from_array_mask) {
			return lowglo.pmap_mem_start_addr + lowglo.pmap_mem_page_sz * (p & ~lowglo.pmap_mem_from_array_mask);
		}
		return lowglo.pmap_mem_packed_base_addr + (p << lowglo.pmap_mem_packed_shift);
	}
	return 0;
}

static kaddr_t
vm_page_get_phys_addr(kaddr_t vm_page) {
	ppnum_t phys_page;

	if(vm_page >= lowglo.pmap_mem_start_addr && vm_page < lowglo.pmap_mem_end_addr) {
		phys_page = (ppnum_t)((vm_page - lowglo.pmap_mem_start_addr) / lowglo.pmap_mem_page_sz + lowglo.pmap_mem_first_ppnum);
	} else if(kread_buf(vm_page + lowglo.pmap_mem_page_sz, &phys_page, sizeof(phys_page)) != KERN_SUCCESS) {
		phys_page = 0;
	}
	return (kaddr_t)phys_page << vm_kernel_page_shift;
}

void
golb_term(void) {
	uint32_t flags;

	if(kread_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags)) == KERN_SUCCESS) {
		printf("flags: 0x%" PRIX32 "\n", flags);
		flags &= ~VM_MAP_FLAGS_NO_ZERO_FILL;
		kwrite_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags));
	}
	mach_port_deallocate(mach_task_self(), tfp0);
}

kern_return_t
golb_init(void) {
	kaddr_t kbase, kslide, our_task;
	uint32_t flags;

	if(init_tfp0() == KERN_SUCCESS) {
		printf("tfp0: 0x%" PRIX32 "\n", tfp0);
		if((kbase = get_kbase(&kslide))) {
			printf("kbase: " KADDR_FMT ", kslide: " KADDR_FMT "\n", kbase, kslide);
			if(pfinder_init_offsets(kbase, kslide) == KERN_SUCCESS && kread_addr(pv_head_table_ptr, &pv_head_table) == KERN_SUCCESS) {
				printf("pv_head_table: " KADDR_FMT "\n", pv_head_table);
				if(kread_buf(const_boot_args, &boot_args, sizeof(boot_args)) == KERN_SUCCESS) {
					printf("virt_base: " KADDR_FMT ", phys_base: " KADDR_FMT ", mem_sz: 0x%" PRIX64 "\n", boot_args.virt_base, boot_args.phys_base, boot_args.mem_sz);
					if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
						printf("our_task: " KADDR_FMT "\n", our_task);
						if(kread_addr(our_task + TASK_MAP_OFF, &our_map) == KERN_SUCCESS) {
							printf("our_map: " KADDR_FMT "\n", our_map);
							if(kread_addr(our_map + VM_MAP_PMAP_OFF, &our_pmap) == KERN_SUCCESS) {
								printf("our_pmap: " KADDR_FMT "\n", our_pmap);
								if(kread_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags)) == KERN_SUCCESS) {
									printf("flags: 0x%" PRIX32 "\n", flags);
									flags |= VM_MAP_FLAGS_NO_ZERO_FILL;
									return kwrite_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags));
								}
							}
						}
					}
				}
			}
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	return KERN_FAILURE;
}

kern_return_t
golb_flush_core_tlb_asid(void) {
	uint8_t orig_sw_asid, fake_sw_asid = UINT8_MAX;

	if(kread_buf(our_pmap + PMAP_SW_ASID_OFF, &orig_sw_asid, sizeof(orig_sw_asid)) == KERN_SUCCESS) {
		printf("orig_sw_asid: 0x%" PRIX8 "\n", orig_sw_asid);
		if(orig_sw_asid != fake_sw_asid && kwrite_buf(our_pmap + PMAP_SW_ASID_OFF, &fake_sw_asid, sizeof(fake_sw_asid)) == KERN_SUCCESS) {
			return kwrite_buf(our_pmap + PMAP_SW_ASID_OFF, &orig_sw_asid, sizeof(orig_sw_asid));
		}
	}
	return KERN_FAILURE;
}

kaddr_t
golb_find_phys(kaddr_t virt) {
	kaddr_t vphys, vm_page, virt_off = virt & vm_kernel_page_mask;
	vm_map_entry_t vm_entry;
	vm_page_t m;

	virt -= virt_off;
	if(vm_map_lookup_entry(our_map, virt, &vm_entry) == KERN_SUCCESS && vm_entry.vme_object != 0 && vm_entry.vme_offset == 0 && kread_buf(vm_entry.vme_object, &m.vmp_listq.next, sizeof(m.vmp_listq.next)) == KERN_SUCCESS) {
		while((vm_page = vm_page_unpack_ptr(m.vmp_listq.next)) != 0 && vm_page != vm_entry.vme_object) {
			printf("vm_page: " KADDR_FMT "\n", vm_page);
			if(kread_buf(vm_page, &m, sizeof(m)) != KERN_SUCCESS) {
				break;
			}
			printf("vmp_offset: 0x%" PRIX64 ", vmp_object: 0x%" PRIX32 "\n", m.vmp_offset, m.vmp_object);
			if(m.vmp_offset == virt - vm_entry.links.start && vm_page_unpack_ptr(m.vmp_object) == vm_entry.vme_object && (vphys = vm_page_get_phys_addr(vm_page)) != 0) {
				return vphys + virt_off;
			}
		}
	}
	return 0;
}

void
golb_unmap(golb_ctx_t ctx) {
	size_t i;

	for(i = 0; i < ctx.orig_cnt; ++i) {
		kwrite_addr(ctx.orig[i].ptep, ctx.orig[i].pte);
	}
	golb_flush_core_tlb_asid();
	free(ctx.orig);
}

kern_return_t
golb_map(golb_ctx_t *ctx, kaddr_t virt, kaddr_t phys, mach_vm_size_t sz, vm_prot_t prot) {
	kaddr_t phys_off, vm_page, vphys, pv_h, ptep, orig_pte, fake_pte;
	mach_vm_offset_t map_off;
	vm_map_entry_t vm_entry;
	vm_page_t m;

	if((virt & vm_kernel_page_mask) != 0) {
		return KERN_FAILURE;
	}
	phys_off = phys & vm_kernel_page_mask;
	if((sz = round_page_kernel(sz + phys_off)) == 0) {
		return KERN_FAILURE;
	}
	phys -= phys_off;
	for(map_off = 0; map_off < sz; map_off += vm_kernel_page_size) {
		*(volatile kaddr_t *)(virt + map_off) = FAULT_MAGIC;
	}
	if(vm_map_lookup_entry(our_map, virt, &vm_entry) != KERN_SUCCESS || vm_entry.vme_object == 0 || vm_entry.vme_offset != 0 || (vm_entry.links.end - virt) < sz || kread_buf(vm_entry.vme_object, &m.vmp_listq.next, sizeof(m.vmp_listq.next)) != KERN_SUCCESS || (ctx->orig = calloc(sz >> vm_kernel_page_shift, sizeof(ctx->orig[0]))) == NULL) {
		return KERN_FAILURE;
	}
	ctx->orig_cnt = 0;
	for(map_off = 0; map_off < sz; map_off += vm_kernel_page_size) {
		if((vm_page = vm_page_unpack_ptr(m.vmp_listq.next)) == 0) {
			break;
		}
		printf("vm_page: " KADDR_FMT "\n", vm_page);
		if(vm_page == vm_entry.vme_object || kread_buf(vm_page, &m, sizeof(m)) != KERN_SUCCESS) {
			break;
		}
		printf("vmp_offset: 0x%" PRIX64 ", vmp_object: 0x%" PRIX32 "\n", m.vmp_offset, m.vmp_object);
		if(m.vmp_offset != map_off + (virt - vm_entry.links.start) || vm_page_unpack_ptr(m.vmp_object) != vm_entry.vme_object || (vphys = vm_page_get_phys_addr(vm_page)) == 0) {
			break;
		}
		printf("vphys: " KADDR_FMT "\n", vphys);
		if(vphys < boot_args.phys_base || vphys >= trunc_page_kernel(boot_args.phys_base + boot_args.mem_sz) || kread_addr(pv_head_table + ((vphys - boot_args.phys_base) >> vm_kernel_page_shift) * sizeof(kaddr_t), &pv_h) != KERN_SUCCESS) {
			break;
		}
		printf("pv_h: " KADDR_FMT "\n", pv_h);
		if((pv_h & PVH_TYPE_MASK) != PVH_TYPE_PTEP) {
			break;
		}
		ptep = (pv_h & PVH_LIST_MASK) | PVH_HIGH_FLAGS;
		printf("ptep: " KADDR_FMT "\n", ptep);
		if(kread_addr(ptep, &orig_pte) != KERN_SUCCESS) {
			break;
		}
		printf("orig_pte: " KADDR_FMT "\n", orig_pte);
		if((orig_pte & ARM_PTE_TYPE_VALID) == 0 || (orig_pte & ARM_PTE_MASK) != vphys) {
			break;
		}
		ctx->orig[ctx->orig_cnt].ptep = ptep;
		ctx->orig[ctx->orig_cnt++].pte = orig_pte;
		fake_pte = ((phys + map_off) & ARM_PTE_MASK) | ARM_PTE_TYPE_VALID | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE) | ARM_PTE_AF | ARM_PTE_AP((prot & VM_PROT_WRITE) != 0 ? AP_RWRW : AP_RORO) | ARM_PTE_PNX | ARM_PTE_NG;
		if((prot & VM_PROT_EXECUTE) == 0) {
			fake_pte |= ARM_PTE_NX;
		}
		if(kwrite_addr(ptep, fake_pte) != KERN_SUCCESS) {
			break;
		}
	}
	if(map_off != sz || golb_flush_core_tlb_asid() != KERN_SUCCESS) {
		golb_unmap(*ctx);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}
