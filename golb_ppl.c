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
#include "golb.h"
#include <dlfcn.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#define PROC_P_LIST_LE_PREV_OFF (0x8)
#define VM_MAP_HDR_RBH_ROOT_OFF (0x38)
#define PROC_P_LIST_LH_FIRST_OFF (0x0)
#define LOADED_KEXT_SUMMARY_HDR_NAME_OFF (0x10)
#define LOADED_KEXT_SUMMARY_HDR_ADDR_OFF (0x60)

#define VM_WIMG_IO (7U)
#define PROC_PIDREGIONINFO (7)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define VM_KERN_MEMORY_OSKEXT (5)
#define LOWGLO_VER_CODE "Kraken  "
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define LOWGLO_LAYOUT_MAGIC (0xC0DEC0DEU)
#define FAULT_MAGIC (0xAAAAAAAAAAAAAAAAULL)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define kOSBundleLoadAddressKey "OSBundleLoadAddress"
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define IS_SUBS_X(a) (((a) & 0xFF200000U) == 0xEB000000U)
#define LDR_W_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 2U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_LDR_W_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xB9400000U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef kern_return_t (*kernrw_0_kbase_func_t)(kaddr_t *);
typedef int (*krw_0_kbase_func_t)(kaddr_t *), (*krw_0_kread_func_t)(kaddr_t, void *, size_t), (*krw_0_kwrite_func_t)(const void *, kaddr_t, size_t), (*kernrw_0_req_kernrw_func_t)(void);

typedef struct {
	struct section_64 sec_text, sec_data, sec_cstring;
} pfinder_t;

typedef struct {
	struct {
		uint32_t next, prev;
	} vmp_q_pageq, vmp_listq, vmp_backgroundq;
	uint64_t vmp_offset;
	uint32_t vmp_object, q_flags, vmp_next_m, o_flags;
} vm_page_t;

typedef struct {
	struct {
		kaddr_t prev, next, start, end;
	} links;
	kaddr_t rbe_left, rbe_right, rbe_parent, vme_object;
	uint64_t vme_offset;
} vm_map_entry_t;

typedef struct {
	uint8_t ver_code[8];
	kaddr_t zero, stext, ver, os_ver, kmod_ptr, trans_off, reboot_flag, manual_pkt_addr, alt_debugger, pmap_memq, pmap_mem_page_off, pmap_mem_chain_off, static_addr, static_sz, layout_major_ver, layout_magic, pmap_mem_start_addr, pmap_mem_end_addr, pmap_mem_page_sz, pmap_mem_from_array_mask, pmap_mem_first_ppnum, pmap_mem_packed_shift, pmap_mem_packed_base_addr, layout_minor_ver, page_shift;
} lowglo_t;

kern_return_t
mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);

kern_return_t
mach_vm_remap(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int, vm_map_t, mach_vm_address_t, boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);

static lowglo_t lowglo;
static sigjmp_buf jbuf;
static int kmem_fd = -1;
static unsigned t1sz_boot;
static void *krw_0, *kernrw_0;
static kread_func_t kread_buf;
static task_t tfp0 = TASK_NULL;
static uint64_t proc_struct_sz;
static ppnum_t target_phys_page;
static kwrite_func_t kwrite_buf;
static krw_0_kread_func_t krw_0_kread;
static krw_0_kwrite_func_t krw_0_kwrite;
static bool has_proc_struct_sz, has_vm_obj_packed_ptr;
static size_t task_map_off, proc_task_off, proc_p_pid_off, vm_object_wimg_bits_off;
static kaddr_t kbase, kernproc, lowglo_ptr, proc_struct_sz_ptr, vm_kernel_link_addr, our_map, target_virt, target_vm_page;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
	return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static void
kxpacd(kaddr_t *addr) {
	if(t1sz_boot != 0) {
		*addr |= ~((1ULL << (64U - t1sz_boot)) - 1U);
	}
}

static kern_return_t
kread_buf_krw_0(kaddr_t addr, void *buf, size_t sz) {
	return krw_0_kread(addr, buf, sz) == 0 ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t
kwrite_buf_krw_0(kaddr_t addr, const void *buf, size_t sz) {
	return krw_0_kwrite(buf, addr, sz) == 0 ? KERN_SUCCESS : KERN_FAILURE;
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
		if(pid_for_task(tfp0, &pid) == KERN_SUCCESS) {
			return ret;
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	return KERN_FAILURE;
}

static kern_return_t
kread_buf_tfp0(kaddr_t addr, void *buf, size_t sz) {
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
kwrite_buf_tfp0(kaddr_t addr, const void *buf, size_t sz) {
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
kread_buf_kmem(kaddr_t addr, void *buf, size_t sz) {
	mach_vm_size_t read_sz;
	char *p = buf;
	ssize_t n;

	while(sz != 0) {
		read_sz = (mach_vm_size_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if((n = pread(kmem_fd, p, read_sz, (off_t)addr)) < 0 || (size_t)n != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kwrite_buf_kmem(kaddr_t addr, const void *buf, size_t sz) {
	mach_msg_type_number_t write_sz;
	const char *p = buf;
	ssize_t n;

	while(sz != 0) {
		write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if((n = pwrite(kmem_fd, p, write_sz, (off_t)addr)) < 0 || (size_t)n != write_sz) {
			return KERN_FAILURE;
		}
		p += write_sz;
		sz -= write_sz;
		addr += write_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
	return kread_buf(addr, val, sizeof(*val));
}

static kern_return_t
find_section(kaddr_t p, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
	for(; sg64.nsects-- != 0; p += sizeof(*sp)) {
		if(kread_buf(p, sp, sizeof(*sp)) != KERN_SUCCESS) {
			break;
		}
		if((sp->flags & SECTION_TYPE) != S_ZEROFILL) {
			if(sp->offset < sg64.fileoff || sp->size > sg64.filesize || sp->offset - sg64.fileoff > sg64.filesize - sp->size) {
				break;
			}
			if(sp->size != 0 && strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
				return KERN_SUCCESS;
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
sec_read_buf(struct section_64 sec, kaddr_t addr, void *buf, size_t sz) {
	size_t off;

	if(addr >= sec.addr && sz <= sec.size && (off = addr - sec.addr) <= sec.size - sz) {
		return kread_buf(sec.addr + off, buf, sz);
	}
	return KERN_FAILURE;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	memset(&pfinder->sec_text, '\0', sizeof(pfinder->sec_text));
	memset(&pfinder->sec_data, '\0', sizeof(pfinder->sec_data));
	memset(&pfinder->sec_cstring, '\0', sizeof(pfinder->sec_cstring));
}

static void
pfinder_term(pfinder_t *pfinder) {
	pfinder_reset(pfinder);
}

static size_t
kstrlen(kaddr_t p) {
	size_t i;
	char c;

	for(i = 0; kread_buf(p + i, &c, 1) == KERN_SUCCESS; ++i) {
		if(c == '\0') {
			break;
		}
	}
	return i;
}

static int
kstrncmp(kaddr_t p, const char *s0, size_t len) {
	char *s = malloc(len);
	int ret = 1;

	if(s != NULL) {
		if(kread_buf(p, s, len) == KERN_SUCCESS) {
			ret = strncmp(s, s0, len);
		}
		free(s);
	}
	return ret;
}

#if TARGET_OS_OSX
static int
kstrcmp(kaddr_t p, const char *s0) {
	return kstrncmp(p, s0, strlen(s0));
}
#endif

static kern_return_t
pfinder_init_macho(pfinder_t *pfinder, size_t off) {
#if TARGET_OS_OSX
	struct fileset_entry_command fec;
#endif
	struct segment_command_64 sg64;
	kaddr_t p = kbase + off, e;
	struct mach_header_64 mh64;
	struct load_command lc;
	struct section_64 s64;

	if(kread_buf(p, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 &&
#if TARGET_OS_OSX
	   (mh64.filetype == MH_EXECUTE || (off == 0 && mh64.filetype == MH_FILESET))
#else
	   mh64.filetype == MH_EXECUTE
#endif
	   ) {
		for(p += sizeof(mh64), e = p + mh64.sizeofcmds; mh64.ncmds-- != 0 && e - p >= sizeof(lc); p += lc.cmdsize) {
			if(kread_buf(p, &lc, sizeof(lc)) != KERN_SUCCESS || lc.cmdsize < sizeof(lc) || e - p < lc.cmdsize) {
				break;
			}
			if(lc.cmd == LC_SEGMENT_64) {
				if(lc.cmdsize < sizeof(sg64) || kread_buf(p, &sg64, sizeof(sg64)) != KERN_SUCCESS) {
					break;
				}
				if(sg64.vmsize == 0) {
					continue;
				}
				if(sg64.nsects != (lc.cmdsize - sizeof(sg64)) / sizeof(s64)) {
					break;
				}
				if(mh64.filetype == MH_EXECUTE) {
					if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0) {
						if(find_section(p + sizeof(sg64), sg64, SECT_TEXT, &s64) != KERN_SUCCESS) {
							break;
						}
						pfinder->sec_text = s64;
						printf("sec_text_addr: " KADDR_FMT ", sec_text_off: 0x%" PRIX32 ", sec_text_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
					} else if(strncmp(sg64.segname, SEG_DATA, sizeof(sg64.segname)) == 0) {
						if(find_section(p + sizeof(sg64), sg64, SECT_DATA, &s64) != KERN_SUCCESS) {
							break;
						}
						pfinder->sec_data = s64;
						printf("sec_data_addr: " KADDR_FMT ", sec_data_off: 0x%" PRIX32 ", sec_data_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
					} else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0) {
						if(find_section(p + sizeof(sg64), sg64, SECT_CSTRING, &s64) != KERN_SUCCESS) {
							break;
						}
						pfinder->sec_cstring = s64;
						printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_off: 0x%" PRIX32 ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
					}
				}
			}
#if TARGET_OS_OSX
			else if(mh64.filetype == MH_FILESET && lc.cmd == LC_FILESET_ENTRY) {
				if(lc.cmdsize < sizeof(fec) || kread_buf(p, &fec, sizeof(fec)) != KERN_SUCCESS) {
					break;
				}
				if(fec.fileoff == 0 || fec.entry_id.offset > fec.cmdsize) {
					break;
				}
				if(kstrcmp(p + fec.entry_id.offset, "com.apple.kernel") == 0 && pfinder_init_macho(pfinder, fec.fileoff) == KERN_SUCCESS) {
					return KERN_SUCCESS;
				}
			}
#endif
			if(pfinder->sec_text.size != 0 && pfinder->sec_data.size != 0 && pfinder->sec_cstring.size != 0) {
				return KERN_SUCCESS;
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
pfinder_init(pfinder_t *pfinder) {
	pfinder_reset(pfinder);
	if(pfinder_init_macho(pfinder, 0) == KERN_SUCCESS) {
		return KERN_SUCCESS;
	}
	pfinder_term(pfinder);
	return KERN_FAILURE;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	kaddr_t x[32] = { 0 };
	uint32_t insn;

	for(; sec_read_buf(pfinder.sec_text, start, &insn, sizeof(insn)) == KERN_SUCCESS; start += sizeof(insn)) {
		if(IS_LDR_X(insn)) {
			x[RD(insn)] = start + LDR_X_IMM(insn);
		} else if(IS_ADR(insn)) {
			x[RD(insn)] = start + ADR_IMM(insn);
		} else if(IS_ADD_X(insn)) {
			x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
		} else if(IS_LDR_W_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_W_UNSIGNED_IMM(insn);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
		} else {
			if(IS_ADRP(insn)) {
				x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
			}
			continue;
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
	kaddr_t p, e;
	size_t len;

	for(p = pfinder.sec_cstring.addr, e = p + pfinder.sec_cstring.size; p != e; p += len) {
		len = kstrlen(p) + 1;
		if(kstrncmp(p, str, len) == 0) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.addr, pfinder.sec_cstring.addr + (p - pfinder.sec_cstring.addr));
		}
	}
	return 0;
}

static kaddr_t
pfinder_kernproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "Should never have an EVFILT_READ except for reg or fifo. @%s:%d", 0);
	uint32_t insns[2];

	if(ref == 0) {
		ref = pfinder_xref_str(pfinder, "\"Should never have an EVFILT_READ except for reg or fifo.\"", 0);
	}
	for(; sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref -= sizeof(*insns)) {
		if(IS_ADRP(insns[0]) && IS_LDR_X_UNSIGNED_IMM(insns[1]) && RD(insns[1]) == 3) {
			return pfinder_xref_rd(pfinder, RD(insns[1]), ref, 0);
		}
	}
	return 0;
}

static kaddr_t
pfinder_lowglo_ptr(pfinder_t pfinder) {
	kaddr_t ref;

	for(ref = pfinder.sec_data.addr; sec_read_buf(pfinder.sec_data, ref, &lowglo, sizeof(lowglo)) == KERN_SUCCESS; ref += PAGE_MAX_SIZE) {
		if(memcmp(&lowglo.ver_code, LOWGLO_VER_CODE, sizeof(lowglo.ver_code)) == 0 && lowglo.layout_magic == LOWGLO_LAYOUT_MAGIC && lowglo.pmap_mem_page_sz == sizeof(vm_page_t)) {
			return ref;
		}
	}
	return 0;
}

static kaddr_t
pfinder_proc_struct_sz_ptr(pfinder_t pfinder) {
	uint32_t insns[3];
	kaddr_t ref;

	for(ref = pfinder_xref_str(pfinder, "panic: ticket lock acquired check done outside of kernel debugger @%s:%d", 0); sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref -= sizeof(*insns)) {
		if(IS_ADRP(insns[0]) && IS_LDR_X_UNSIGNED_IMM(insns[1]) && IS_SUBS_X(insns[2]) && RD(insns[2]) == 1) {
			return pfinder_xref_rd(pfinder, RD(insns[1]), ref, 0);
		}
	}
	return 0;
}

static kern_return_t
init_kbase(void) {
	struct {
		uint32_t pri_prot, pri_max_prot, pri_inheritance, pri_flags;
		uint64_t pri_offset;
		uint32_t pri_behavior, pri_user_wired_cnt, pri_user_tag, pri_pages_resident, pri_pages_shared_now_private, pri_pages_swapped_out, pri_pages_dirtied, pri_ref_cnt, pri_shadow_depth, pri_share_mode, pri_private_pages_resident, pri_shared_pages_resident, pri_obj_id, pri_depth;
		kaddr_t pri_addr;
		uint64_t pri_sz;
	} pri;
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	CFDictionaryRef kexts_info, kext_info;
	kernrw_0_kbase_func_t kernrw_0_kbase;
	kaddr_t kext_addr, kext_addr_slid;
	task_dyld_info_data_t dyld_info;
	krw_0_kbase_func_t krw_0_kbase;
	char kext_name[KMOD_MAX_NAME];
	struct mach_header_64 mh64;
	CFStringRef kext_name_cf;
	CFNumberRef kext_addr_cf;
	CFArrayRef kext_names;

	if(kbase == 0) {
		if((((kernrw_0 == NULL || (kernrw_0_kbase = (kernrw_0_kbase_func_t)dlsym(kernrw_0, "kernRW_getKernelBase")) == NULL || kernrw_0_kbase(&kbase) != KERN_SUCCESS)) && (krw_0 == NULL || (krw_0_kbase = (krw_0_kbase_func_t)dlsym(krw_0, "kbase")) == NULL || krw_0_kbase(&kbase) != 0)) || tfp0 == TASK_NULL || task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) != KERN_SUCCESS || (kbase = vm_kernel_link_addr + dyld_info.all_image_info_size) == 0) {
			for(pri.pri_addr = 0; proc_pidinfo(0, PROC_PIDREGIONINFO, pri.pri_addr, &pri, sizeof(pri)) == sizeof(pri); pri.pri_addr += pri.pri_sz) {
				if(pri.pri_prot == VM_PROT_READ && pri.pri_user_tag == VM_KERN_MEMORY_OSKEXT) {
					if(kread_buf(pri.pri_addr + LOADED_KEXT_SUMMARY_HDR_NAME_OFF, kext_name, sizeof(kext_name)) == KERN_SUCCESS) {
						printf("kext_name: %s\n", kext_name);
						if(kread_addr(pri.pri_addr + LOADED_KEXT_SUMMARY_HDR_ADDR_OFF, &kext_addr_slid) == KERN_SUCCESS) {
							printf("kext_addr_slid: " KADDR_FMT "\n", kext_addr_slid);
							if((kext_name_cf = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, kext_name, kCFStringEncodingUTF8, kCFAllocatorNull)) != NULL) {
								if((kext_names = CFArrayCreate(kCFAllocatorDefault, (const void **)&kext_name_cf, 1, &kCFTypeArrayCallBacks)) != NULL) {
									if((kexts_info = OSKextCopyLoadedKextInfo(kext_names, NULL)) != NULL) {
										if(CFGetTypeID(kexts_info) == CFDictionaryGetTypeID() && CFDictionaryGetCount(kexts_info) == 1 && (kext_info = CFDictionaryGetValue(kexts_info, kext_name_cf)) != NULL && CFGetTypeID(kext_info) == CFDictionaryGetTypeID() && (kext_addr_cf = CFDictionaryGetValue(kext_info, CFSTR(kOSBundleLoadAddressKey))) != NULL && CFGetTypeID(kext_addr_cf) == CFNumberGetTypeID() && CFNumberGetValue(kext_addr_cf, kCFNumberSInt64Type, &kext_addr) && kext_addr_slid > kext_addr) {
											kbase = vm_kernel_link_addr + (kext_addr_slid - kext_addr);
										}
										CFRelease(kexts_info);
									}
									CFRelease(kext_names);
								}
								CFRelease(kext_name_cf);
							}
						}
					}
					break;
				}
			}
		}
	}
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype ==
#if TARGET_OS_OSX
	   MH_FILESET
#else
	   MH_EXECUTE
#endif
	   ) {
		printf("kbase: " KADDR_FMT "\n", kbase);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

static kern_return_t
pfinder_init_offsets(void) {
	kern_return_t ret = KERN_FAILURE;
	struct utsname uts;
	CFStringRef cf_str;
	pfinder_t pfinder;
	char *p, *e;

	if(uname(&uts) == 0 && (p = strstr(uts.version, "root:xnu-")) != NULL && (e = strchr(p += strlen("root:xnu-"), '~')) != NULL) {
		*e = '\0';
		if((cf_str = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, p, kCFStringEncodingASCII, kCFAllocatorNull)) != NULL) {
			task_map_off = 0x20;
			proc_task_off = 0x18;
			proc_p_pid_off = 0x10;
			vm_object_wimg_bits_off = 0xB8;
#if TARGET_OS_OSX
			vm_kernel_link_addr = 0xFFFFFE0007004000ULL;
#else
			vm_kernel_link_addr = 0xFFFFFFF007004000ULL;
#endif
			if(CFStringCompare(cf_str, CFSTR("4397.0.0.2.4"), kCFCompareNumerically) != kCFCompareLessThan) {
				vm_object_wimg_bits_off = 0xA8;
				if(CFStringCompare(cf_str, CFSTR("4903.200.199.12.3"), kCFCompareNumerically) != kCFCompareLessThan) {
					proc_task_off = 0x10;
					proc_p_pid_off = 0x60;
					if(CFStringCompare(cf_str, CFSTR("6041.0.0.110.11"), kCFCompareNumerically) != kCFCompareLessThan) {
						task_map_off = 0x28;
						if(CFStringCompare(cf_str, CFSTR("6110.0.0.120.8"), kCFCompareNumerically) != kCFCompareLessThan) {
							proc_p_pid_off = 0x68;
							if(CFStringCompare(cf_str, CFSTR("6153.40.121.0.1"), kCFCompareNumerically) != kCFCompareLessThan) {
								vm_object_wimg_bits_off = 0xA4;
								if(CFStringCompare(cf_str, CFSTR("7195.100.326.0.1"), kCFCompareNumerically) != kCFCompareLessThan) {
									task_map_off = 0x20;
									if(CFStringCompare(cf_str, CFSTR("7938.0.0.111.2"), kCFCompareNumerically) != kCFCompareLessThan) {
										task_map_off = 0x28;
										if(CFStringCompare(cf_str, CFSTR("8792.0.50.111.3"), kCFCompareNumerically) != kCFCompareLessThan) {
											proc_p_pid_off = 0x60;
											has_vm_obj_packed_ptr = has_proc_struct_sz = true;
										}
									}
								}
							}
						}
					}
				}
			}
			CFRelease(cf_str);
			if(init_kbase() == KERN_SUCCESS && pfinder_init(&pfinder) == KERN_SUCCESS) {
				if((kernproc = pfinder_kernproc(pfinder)) != 0) {
					printf("kernproc: " KADDR_FMT "\n", kernproc);
					if((lowglo_ptr = pfinder_lowglo_ptr(pfinder)) != 0) {
						printf("lowglo_ptr: " KADDR_FMT "\n", lowglo_ptr);
						if(!has_proc_struct_sz) {
							ret = KERN_SUCCESS;
						} else if((proc_struct_sz_ptr = pfinder_proc_struct_sz_ptr(pfinder)) != 0) {
							printf("proc_struct_sz_ptr: " KADDR_FMT "\n", proc_struct_sz_ptr);
							ret = KERN_SUCCESS;
						}
					}
				}
				pfinder_term(&pfinder);
			}
		}
	}
	return ret;
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	pid_t cur_pid;
	kaddr_t proc;

	if(kread_addr(kernproc + PROC_P_LIST_LH_FIRST_OFF, &proc) == KERN_SUCCESS) {
		while(proc != 0 && kread_buf(proc + proc_p_pid_off, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS) {
			if(cur_pid == pid) {
				if(has_proc_struct_sz) {
					*task = proc + proc_struct_sz;
					return KERN_SUCCESS;
				}
				return kread_addr(proc + proc_task_off, task);
			}
			if(pid == 0 || kread_addr(proc + PROC_P_LIST_LE_PREV_OFF, &proc) != KERN_SUCCESS) {
				break;
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
vm_map_lookup_entry(kaddr_t vm_map, kaddr_t virt, vm_map_entry_t *vm_entry) {
	kaddr_t rb_entry;

	if(kread_addr(vm_map + VM_MAP_HDR_RBH_ROOT_OFF, &rb_entry) == KERN_SUCCESS) {
		while(rb_entry != 0 && rb_entry != sizeof(vm_entry->links)) {
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
vm_obj_unpack_ptr(kaddr_t p) {
	return has_vm_obj_packed_ptr ? lowglo.pmap_mem_packed_base_addr + (uint64_t)((int64_t)(p >> (32U - lowglo.pmap_mem_packed_shift))) : p;
}

static kaddr_t
vm_page_unpack_ptr(kaddr_t p) {
	if(p != 0) {
		if((p & lowglo.pmap_mem_from_array_mask) != 0) {
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
	kwrite_buf(target_vm_page + lowglo.pmap_mem_page_sz, &target_phys_page, sizeof(target_phys_page));
	mach_vm_deallocate(mach_task_self(), target_virt, vm_page_size);
	if(tfp0 != TASK_NULL) {
		mach_port_deallocate(mach_task_self(), tfp0);
	} else if(kernrw_0 != NULL) {
		dlclose(kernrw_0);
	} else if(krw_0 != NULL) {
		dlclose(krw_0);
	} else if(kmem_fd != -1) {
		close(kmem_fd);
	}
	setpriority(PRIO_PROCESS, 0, 0);
}

kern_return_t
golb_init(kaddr_t _kbase, kread_func_t _kread_buf, kwrite_func_t _kwrite_buf) {
	kernrw_0_req_kernrw_func_t kernrw_0_req;
	uint8_t wimg_bits = VM_WIMG_IO;
	vm_map_entry_t vm_entry;
	cpu_subtype_t subtype;
	uint32_t packed_ptr;
	kaddr_t our_task;
	size_t sz;

	sz = sizeof(subtype);
	if(sysctlbyname("hw.cpusubtype", &subtype, &sz, NULL, 0) == 0) {
		if(subtype == CPU_SUBTYPE_ARM64E) {
#if TARGET_OS_OSX
			t1sz_boot = 17;
#else
			t1sz_boot = 25;
#endif
		}
		kbase = _kbase;
		if(_kread_buf != NULL && _kwrite_buf != NULL) {
			kread_buf = _kread_buf;
			kwrite_buf = _kwrite_buf;
		} else if(init_tfp0() == KERN_SUCCESS) {
			printf("tfp0: 0x%" PRIX32 "\n", tfp0);
			kread_buf = kread_buf_tfp0;
			kwrite_buf = kwrite_buf_tfp0;
		} else if((kernrw_0 = dlopen("/usr/lib/libkernrw.0.dylib", RTLD_LAZY)) != NULL && (kernrw_0_req = (kernrw_0_req_kernrw_func_t)dlsym(kernrw_0, "requestKernRw")) != NULL && kernrw_0_req() == 0) {
			kread_buf = (kread_func_t)dlsym(kernrw_0, "kernRW_readbuf");
			kwrite_buf = (kwrite_func_t)dlsym(kernrw_0, "kernRW_writebuf");
		} else if((krw_0 = dlopen("/usr/lib/libkrw.0.dylib", RTLD_LAZY)) != NULL && (krw_0_kread = (krw_0_kread_func_t)dlsym(krw_0, "kread")) != NULL && (krw_0_kwrite = (krw_0_kwrite_func_t)dlsym(krw_0, "kwrite")) != NULL) {
			kread_buf = kread_buf_krw_0;
			kwrite_buf = kwrite_buf_krw_0;
		} else if((kmem_fd = open("/dev/kmem", O_RDWR | O_CLOEXEC)) != -1) {
			kread_buf = kread_buf_kmem;
			kwrite_buf = kwrite_buf_kmem;
		}
		if(kread_buf != NULL && kwrite_buf != NULL) {
			setpriority(PRIO_PROCESS, 0, PRIO_MIN);
			if(pfinder_init_offsets() == KERN_SUCCESS && kread_buf(lowglo_ptr, &lowglo, sizeof(lowglo)) == KERN_SUCCESS && (!has_proc_struct_sz || kread_buf(proc_struct_sz_ptr, &proc_struct_sz, sizeof(proc_struct_sz)) == KERN_SUCCESS) && find_task(getpid(), &our_task) == KERN_SUCCESS) {
				kxpacd(&our_task);
				printf("our_task: " KADDR_FMT "\n", our_task);
				if(kread_addr(our_task + task_map_off, &our_map) == KERN_SUCCESS) {
					kxpacd(&our_map);
					printf("our_map: " KADDR_FMT "\n", our_map);
					while(mach_vm_allocate(mach_task_self(), &target_virt, vm_page_size, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
						*(volatile kaddr_t *)target_virt = FAULT_MAGIC;
						if(vm_map_lookup_entry(our_map, target_virt, &vm_entry) == KERN_SUCCESS && (vm_entry.vme_object = vm_obj_unpack_ptr(vm_entry.vme_object)) != 0 && trunc_page_kernel(vm_entry.vme_offset) == 0 && kread_buf(vm_entry.vme_object, &packed_ptr, sizeof(packed_ptr)) == KERN_SUCCESS && (target_vm_page = vm_page_unpack_ptr(packed_ptr)) != 0 && target_vm_page != vm_entry.vme_object && (target_vm_page < lowglo.pmap_mem_start_addr || target_vm_page >= lowglo.pmap_mem_end_addr) && kread_buf(target_vm_page + lowglo.pmap_mem_page_sz, &target_phys_page, sizeof(target_phys_page)) == KERN_SUCCESS && kwrite_buf(vm_entry.vme_object + vm_object_wimg_bits_off, &wimg_bits, sizeof(wimg_bits)) == KERN_SUCCESS) {
							printf("target_virt: " KADDR_FMT ", target_vm_page: " KADDR_FMT ", target_phys: " KADDR_FMT "\n", target_virt, target_vm_page, (kaddr_t)target_phys_page << vm_kernel_page_shift);
							return KERN_SUCCESS;
						}
						mach_vm_deallocate(mach_task_self(), target_virt, vm_page_size);
					}
				}
			}
			setpriority(PRIO_PROCESS, 0, 0);
		}
		if(tfp0 != TASK_NULL) {
			mach_port_deallocate(mach_task_self(), tfp0);
		} else if(kernrw_0 != NULL) {
			dlclose(kernrw_0);
		} else if(krw_0 != NULL) {
			dlclose(krw_0);
		} else if(kmem_fd != -1) {
			close(kmem_fd);
		}
	}
	return KERN_FAILURE;
}

kern_return_t
golb_flush_core_tlb_asid(void) {
	return KERN_SUCCESS;
}

kaddr_t
golb_find_phys(kaddr_t virt) {
	kaddr_t vphys, vm_page, virt_off = virt & vm_page_mask;
	vm_map_entry_t vm_entry;
	vm_page_t m;

	virt -= virt_off;
	if(vm_map_lookup_entry(our_map, virt, &vm_entry) == KERN_SUCCESS && (vm_entry.vme_object = vm_obj_unpack_ptr(vm_entry.vme_object)) != 0 && trunc_page_kernel(vm_entry.vme_offset) == 0 && kread_buf(vm_entry.vme_object, &m.vmp_listq.next, sizeof(m.vmp_listq.next)) == KERN_SUCCESS) {
		while((vm_page = vm_page_unpack_ptr(m.vmp_listq.next)) != 0) {
			printf("vm_page: " KADDR_FMT "\n", vm_page);
			if(vm_page == vm_entry.vme_object || kread_buf(vm_page, &m, sizeof(m)) != KERN_SUCCESS) {
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
	mach_vm_deallocate(mach_task_self(), trunc_page(ctx.virt), ctx.page_cnt << vm_page_shift);
}

__attribute__((__noreturn__)) static void
sigbus_handler(int signo) {
	siglongjmp(jbuf, signo);
}

kern_return_t
golb_map(golb_ctx_t *ctx, kaddr_t phys, mach_vm_size_t sz, vm_prot_t prot) {
	kaddr_t phys_off = phys & vm_page_mask, virt;
	struct sigaction old_act, new_act;
	vm_prot_t cur_prot, max_prot;
	ppnum_t phys_page;

	phys -= phys_off;
	if((sz = round_page(sz + phys_off)) != 0 && mach_vm_protect(mach_task_self(), target_virt, vm_page_size, FALSE, prot) == KERN_SUCCESS && mach_vm_allocate(mach_task_self(), &ctx->virt, sz, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
		printf("virt: " KADDR_FMT "\n", ctx->virt);
		if(sigaction(SIGBUS, NULL, &old_act) != -1) {
			new_act.sa_flags = 0;
			new_act.sa_handler = sigbus_handler;
			if(sigemptyset(&new_act.sa_mask) != -1 && sigaction(SIGBUS, &new_act, NULL) != -1) {
				for(phys_page = (ppnum_t)(phys >> vm_kernel_page_shift), virt = ctx->virt; virt - ctx->virt < sz; ++phys_page, virt += vm_page_size) {
					if(kwrite_buf(target_vm_page + lowglo.pmap_mem_page_sz, &phys_page, sizeof(phys_page)) != KERN_SUCCESS || mach_vm_remap(mach_task_self(), &virt, vm_page_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(), target_virt, FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE) != KERN_SUCCESS) {
						break;
					}
					if(sigsetjmp(jbuf, 1) == 0) {
						*(volatile kaddr_t *)(virt + 1);
					}
				}
				if(sigaction(SIGBUS, &old_act, NULL) != -1 && virt - ctx->virt == sz) {
					ctx->page_cnt = sz >> vm_page_shift;
					ctx->virt += phys_off;
					return KERN_SUCCESS;
				}
			}
		}
		mach_vm_deallocate(mach_task_self(), ctx->virt, sz);
	}
	return KERN_FAILURE;
}
