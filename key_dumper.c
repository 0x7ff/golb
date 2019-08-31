#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

#define PROC_TASK_OFF (0x10)
#define PROC_P_PID_OFF (0x60)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#define TASK_ITK_REGISTERED_OFF (0x2E8)
#define IO_AES_ACCELERATOR_SPECIAL_KEYS_OFF (0xD0)
#define IO_AES_ACCELERATOR_SPECIAL_KEY_CNT_OFF (0xD8)

#define ARM_PGSHIFT_4K (12U)
#define ARM_PGSHIFT_16K (14U)
#define KADDR_FMT "0x%" PRIx64
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ARM_PGMASK (ARM_PGBYTES - 1ULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define ARM_PGBYTES (1U << arm_pgshift)
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

typedef uint64_t kaddr_t;
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;

typedef struct {
	kaddr_t sec_text_start;
	uint64_t sec_text_sz;
	void *sec_text;
	kaddr_t sec_cstring_start;
	uint64_t sec_cstring_sz;
	void *sec_cstring;
	kaddr_t pc;
} pfinder_t;

typedef struct {
	uint32_t generated;
	uint32_t key_id;
	uint32_t key_size;
	uint32_t val[4];
	uint32_t key[4];
	uint32_t zero;
	uint32_t padding;
} aes_special_key_t;

kern_return_t
mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

extern const mach_port_t kIOMasterPortDefault;

static kaddr_t allproc;
static unsigned arm_pgshift;
static task_t tfp0 = MACH_PORT_NULL;

static uint32_t
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0U >> (32U - length));
}

static uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64U - length - start)) >> (64U - length));
}

static kern_return_t
init_arm_pgshift(void) {
	int cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);

	if(!sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0)) {
		switch(cpufamily) {
			case CPUFAMILY_ARM_CYCLONE:
			case CPUFAMILY_ARM_TYPHOON:
				arm_pgshift = ARM_PGSHIFT_4K;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_TWISTER:
			case CPUFAMILY_ARM_HURRICANE:
			case CPUFAMILY_ARM_MONSOON_MISTRAL:
			case CPUFAMILY_ARM_VORTEX_TEMPEST:
				arm_pgshift = ARM_PGSHIFT_16K;
				return KERN_SUCCESS;
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
init_tfp0(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIx32 "\n", host);
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

static kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	task_dyld_info_data_t dyld_info;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS) {
		*kslide = dyld_info.all_image_info_size;
		return dyld_info.all_image_info_addr;
	}
	return 0;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz) {
		read_sz = MIN(sz, ARM_PGBYTES - (addr & ARM_PGMASK));
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

	if(buf) {
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

static const struct section_64 *
find_section(const struct segment_command_64 *sgp, const char *sect_name) {
	const struct section_64 *sp = (const struct section_64 *)(sgp + 1);
	uint32_t i;

	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	pfinder->sec_text = pfinder->sec_cstring = NULL;
	pfinder->sec_text_start = pfinder->sec_text_sz = 0;
	pfinder->sec_cstring_start = pfinder->sec_cstring_sz = 0;
	pfinder->pc = 0;
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase, kaddr_t kslide) {
	const arm_unified_thread_state_t *state;
	const struct segment_command_64 *sgp;
	kern_return_t ret = KERN_FAILURE;
	const struct section_64 *sp;
	struct mach_header_64 mh64;
	uint32_t i;
	void *ptr;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && (ptr = kread_buf_alloc(kbase + sizeof(mh64), mh64.sizeofcmds))) {
		sgp = (const struct segment_command_64 *)ptr;
		for(i = 0; i < mh64.ncmds; ++i) {
			if(sgp->cmd == LC_SEGMENT_64) {
				if(!strncmp(sgp->segname, SEG_TEXT_EXEC, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_TEXT))) {
					pfinder->sec_text_start = sp->addr;
					pfinder->sec_text_sz = sp->size;
					printf("sec_text_start: " KADDR_FMT ", sec_text_sz: 0x%" PRIx64 "\n", pfinder->sec_text_start, pfinder->sec_text_sz);
				} else if(!strncmp(sgp->segname, SEG_TEXT, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_CSTRING))) {
					pfinder->sec_cstring_start = sp->addr;
					pfinder->sec_cstring_sz = sp->size;
					printf("sec_cstring_start: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIx64 "\n", pfinder->sec_cstring_start, pfinder->sec_cstring_sz);
				}
			} else if(sgp->cmd == LC_UNIXTHREAD) {
				state = (const arm_unified_thread_state_t *)((uintptr_t)sgp + sizeof(struct thread_command));
				pfinder->pc = state->ts_64.__pc + kslide;
			}
			if(pfinder->sec_text_sz && pfinder->sec_cstring_sz && pfinder->pc) {
				if((pfinder->sec_text = kread_buf_alloc(pfinder->sec_text_start, pfinder->sec_text_sz))) {
					if((pfinder->sec_cstring = kread_buf_alloc(pfinder->sec_cstring_start, pfinder->sec_cstring_sz))) {
						ret = KERN_SUCCESS;
					} else {
						free(pfinder->sec_text);
					}
				}
				break;
			}
			sgp = (const struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
		}
		free(ptr);
	}
	return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	const uint32_t *insn = pfinder.sec_text;
	uint64_t x[32] = { 0 };
	size_t i;

	for(i = (start - pfinder.sec_text_start) / sizeof(*insn); i < pfinder.sec_text_sz / sizeof(*insn); ++i) {
		if(IS_LDR_X(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + LDR_X_IMM(insn[i]);
		} else if(IS_ADR(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + ADR_IMM(insn[i]);
		} else if(IS_ADRP(insn[i])) {
			x[RD(insn[i])] = ADRP_ADDR(pfinder.sec_text_start + (i * sizeof(*insn))) + ADRP_IMM(insn[i]);
			continue;
		} else if(IS_ADD_X(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + ADD_X_IMM(insn[i]);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + LDR_X_UNSIGNED_IMM(insn[i]);
		} else if(IS_RET(insn[i])) {
			memset(x, '\0', sizeof(x));
		}
		if(RD(insn[i]) == rd) {
			if(to) {
				if(x[rd] == to) {
					return pfinder.sec_text_start + (i * sizeof(*insn));
				}
			} else {
				return x[rd];
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
	const char *p = pfinder.sec_cstring, *e = p + pfinder.sec_cstring_sz;
	size_t len;

	do {
		len = strlen(p) + 1;
		if(!strncmp(str, p, len)) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text_start, pfinder.sec_cstring_start + (kaddr_t)(p - (const char *)pfinder.sec_cstring));
		}
		p += len;
	} while(p < e);
	return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

	if(!ref) {
		ref = pfinder_xref_str(pfinder, "shutdownwait", 3); /* msleep */
	}
	return ref ? pfinder_xref_rd(pfinder, 8, ref, 0) : 0;
}

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder))) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

static void
pfinder_term(pfinder_t *pfinder) {
	free(pfinder->sec_text);
	free(pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc) {
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
		printf("serv: 0x%" PRIx32 "\n", serv);
		if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
			printf("our_task: " KADDR_FMT "\n", our_task);
			if((ipc_port = get_port(our_task, serv))) {
				printf("ipc_port: " KADDR_FMT "\n", ipc_port);
				if(kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, &object) == KERN_SUCCESS) {
					printf("object: " KADDR_FMT "\n", object);
					if(kread_buf(object + IO_AES_ACCELERATOR_SPECIAL_KEY_CNT_OFF, &key_cnt, sizeof(key_cnt)) == KERN_SUCCESS && key_cnt) {
						printf("key_cnt: 0x%" PRIx32 "\n", key_cnt);
						if(kread_addr(object + IO_AES_ACCELERATOR_SPECIAL_KEYS_OFF, &keys_ptr) == KERN_SUCCESS) {
							printf("keys_ptr: " KADDR_FMT "\n", keys_ptr);
							if((keys = kread_buf_alloc(keys_ptr, key_cnt * sizeof(*keys)))) {
								for(i = 0; i < key_cnt; ++i) {
									printf("generated: 0x%" PRIx32 ", key_id: 0x%" PRIx32 ", key_size: 0x%" PRIx32 ", val: 0x%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "\n", keys[i].generated, keys[i].key_id, keys[i].key_size, keys[i].val[0], keys[i].val[1], keys[i].val[2], keys[i].val[3]);
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

	if(init_arm_pgshift() == KERN_SUCCESS) {
		printf("arm_pgshift: %u\n", arm_pgshift);
		if(init_tfp0() == KERN_SUCCESS) {
			printf("tfp0: 0x%" PRIx32 "\n", tfp0);
			if((kbase = get_kbase(&kslide))) {
				printf("kbase: " KADDR_FMT "\n", kbase);
				printf("kslide: " KADDR_FMT "\n", kslide);
				if(pfinder_init(&pfinder, kbase, kslide) == KERN_SUCCESS) {
					if(pfinder_init_offsets(pfinder) == KERN_SUCCESS) {
						key_dumper();
					}
					pfinder_term(&pfinder);
				}
			}
			mach_port_deallocate(mach_task_self(), tfp0);
		}
	}
}
