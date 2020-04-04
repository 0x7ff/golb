#include "common.h"
#include <mach-o/loader.h>

#define PROC_TASK_OFF (0x10)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#ifdef __arm64e__
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x190)
#else
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x198)
#endif
#define IO_AES_ACCELERATOR_SPECIAL_KEYS_OFF (0xD0)
#define IO_AES_ACCELERATOR_SPECIAL_KEY_CNT_OFF (0xD8)
#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b2 (1656)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b1 (1652.20)
#define PROC_P_PID_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b2 ? 0x68 : 0x60)
#define TASK_ITK_REGISTERED_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0x308 : 0x2E8)

#define VM_KERN_MEMORY_CPU (9)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define IO_OBJECT_NULL ((io_object_t)0)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))

#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;

typedef struct {
	struct section_64 s64;
	char *data;
} sec_64_t;

typedef struct {
	sec_64_t sec_text, sec_cstring;
} pfinder_t;

typedef struct {
	uint32_t generated, key_id, key_sz, val[4], key[4], zero, pad;
} aes_special_key_t;

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

extern const mach_port_t kIOMasterPortDefault;

static kaddr_t allproc;
static task_t tfp0 = MACH_PORT_NULL;

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

static void *
kread_buf_alloc(kaddr_t addr, mach_vm_size_t read_sz) {
	void *buf = malloc(read_sz);

	if(buf != NULL) {
		if(kread_buf(addr, buf, read_sz) == KERN_SUCCESS) {
			return buf;
		}
		free(buf);
	}
	return NULL;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
	return kread_buf(addr, val, sizeof(*val));
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
	sec_reset(&pfinder->sec_text);
	sec_reset(&pfinder->sec_cstring);
}

static void
pfinder_term(pfinder_t *pfinder) {
	sec_term(&pfinder->sec_text);
	sec_term(&pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase) {
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
				} else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_CSTRING, &s64) == KERN_SUCCESS) {
					pfinder->sec_cstring.s64 = s64;
					printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				}
			}
			if(pfinder->sec_text.s64.size != 0 && pfinder->sec_cstring.s64.size != 0) {
				if(sec_init(&pfinder->sec_text) == KERN_SUCCESS) {
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

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder)) != 0) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
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

static kaddr_t
get_port(kaddr_t our_task, mach_port_t port) {
	kaddr_t ipc_port = 0;

	if(mach_ports_register(mach_task_self(), &port, 1) == KERN_SUCCESS) {
		if(kread_addr(our_task + TASK_ITK_REGISTERED_OFF, &ipc_port) != KERN_SUCCESS) {
			ipc_port = 0;
		}
		mach_ports_register(mach_task_self(), NULL, 0);
	}
	return ipc_port;
}

static void
key_dumper(void) {
	io_service_t serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOAESAccelerator"));
	kaddr_t our_task, ipc_port, object, keys_ptr;
	aes_special_key_t *keys;
	uint32_t i, key_cnt;

	if(serv != IO_OBJECT_NULL) {
		printf("serv: 0x%" PRIX32 "\n", serv);
		if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
			printf("our_task: " KADDR_FMT "\n", our_task);
			if((ipc_port = get_port(our_task, serv)) != 0) {
				printf("ipc_port: " KADDR_FMT "\n", ipc_port);
				if(kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, &object) == KERN_SUCCESS) {
					printf("object: " KADDR_FMT "\n", object);
					if(kread_buf(object + IO_AES_ACCELERATOR_SPECIAL_KEY_CNT_OFF, &key_cnt, sizeof(key_cnt)) == KERN_SUCCESS && key_cnt != 0) {
						printf("key_cnt: 0x%" PRIX32 "\n", key_cnt);
						if(kread_addr(object + IO_AES_ACCELERATOR_SPECIAL_KEYS_OFF, &keys_ptr) == KERN_SUCCESS) {
							printf("keys_ptr: " KADDR_FMT "\n", keys_ptr);
							if((keys = kread_buf_alloc(keys_ptr, key_cnt * sizeof(*keys))) != NULL) {
								for(i = 0; i < key_cnt; ++i) {
									printf("generated: 0x%" PRIX32 ", key_id: 0x%" PRIX32 ", key_sz: 0x%" PRIX32 ", val: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", keys[i].generated, keys[i].key_id, keys[i].key_sz, keys[i].val[0], keys[i].val[1], keys[i].val[2], keys[i].val[3]);
								}
								free(keys);
							}
						}
					}
				}
			}
		}
		IOObjectRelease(serv);
	}
}

int
main(void) {
	kaddr_t kbase, kslide;
	pfinder_t pfinder;

	if(init_tfp0() == KERN_SUCCESS) {
		printf("tfp0: 0x%" PRIX32 "\n", tfp0);
		if((kbase = get_kbase(&kslide)) != 0) {
			printf("kbase: " KADDR_FMT ", kslide: " KADDR_FMT "\n", kbase, kslide);
			if(pfinder_init(&pfinder, kbase) == KERN_SUCCESS) {
				if(pfinder_init_offsets(pfinder) == KERN_SUCCESS) {
					key_dumper();
				}
				pfinder_term(&pfinder);
			}
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
}
